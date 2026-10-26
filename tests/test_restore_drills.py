"""Tests for scheduled restore drills, drill summaries, and the durability badge."""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ghostdrive.database.db import GhostDriveDB
from ghostdrive.services import restore_drills
from ghostdrive.web.routes import monitoring
from ghostdrive.web.state import state

PASSPHRASE = "correct horse battery staple"


# ─── DB helpers: copied from tests/test_durability.py ────────────────────────


def _make_db(tmp_path: Path) -> GhostDriveDB:
    db = GhostDriveDB(
        path=tmp_path / "durability.db",
        ledger_key=bytes(range(32)),
        genesis_seed=bytes(range(32, 64)),
        master_key=bytes(range(32)),
    )
    db.open()
    return db


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _backend(db, backend_type: str, credentials_ref: str = "ref:test", **overrides) -> str:
    backend_id = str(uuid.uuid4())
    values = {
        "id": backend_id,
        "type": backend_type,
        "credentials_ref": credentials_ref,
        "status": "healthy",
        "priority": 100,
        "quota_used": 0,
        "quota_limit": 1024 ** 3,
        "quota_reserved": 0,
    }
    values.update(overrides)
    columns = ", ".join(values)
    marks = ", ".join("?" for _ in values)
    db._conn.execute("BEGIN")
    db._conn.execute(
        f"INSERT INTO backends ({columns}) VALUES ({marks})", tuple(values.values())
    )
    db._conn.execute("COMMIT")
    return backend_id


def _file(db, tier: str = "CRITICAL") -> str:
    file_id = str(uuid.uuid4())
    now = _now()
    db._conn.execute("BEGIN")
    db._conn.execute(
        """INSERT INTO files (id, name, path, size, mime_type, tier, created_at, modified_at)
           VALUES (?, 'test.bin', '/tmp/test.bin', 128, 'application/octet-stream', ?, ?, ?)""",
        (file_id, tier, now, now),
    )
    db._conn.execute("COMMIT")
    return file_id


def _chunk(db, file_id: str, sub_block_count: int = 1, chunk_index: int = 0) -> str:
    chunk_id = str(uuid.uuid4())
    db._conn.execute("BEGIN")
    db._conn.execute(
        """INSERT INTO chunks
           (id, file_id, chunk_index, total_chunks, blake3_hash, size,
            nonce_counter, sub_block_count)
           VALUES (?, ?, ?, 1, ?, 128, 1, ?)""",
        (chunk_id, file_id, chunk_index, "0" * 64, sub_block_count),
    )
    db._conn.execute("COMMIT")
    return chunk_id


def _location(db, chunk_id: str, backend_id: str, sub_block_index: int, status: str = "confirmed") -> None:
    db._conn.execute("BEGIN")
    db._conn.execute(
        """INSERT INTO chunk_locations
           (chunk_id, sub_block_index, backend_id, reference_id, upload_date, status)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (chunk_id, sub_block_index, backend_id, f"ref-{sub_block_index}", _now(), status),
    )
    db._conn.execute("COMMIT")


def _snapshot(db, backend_id: str) -> str:
    snapshot_id = str(uuid.uuid4())
    db._conn.execute("BEGIN")
    db._conn.execute(
        """INSERT INTO index_snapshots
           (id, snapshot_at, blake3_hash, hash_backend_id, wal_checkpointed)
           VALUES (?, ?, ?, ?, 1)""",
        (snapshot_id, _now(), "a" * 64, backend_id),
    )
    db._conn.execute("COMMIT")
    return snapshot_id


def _insert_drill(db, result: str, at: datetime, detail: str = "") -> str:
    """Seed one restore_drills row directly (mirrors the production INSERT)."""
    drill_id = str(uuid.uuid4())
    stamp = at.isoformat()
    db._conn.execute("BEGIN")
    db._conn.execute(
        """INSERT INTO restore_drills
           (id, started_at, completed_at, snapshot_id, file_id, chunk_id,
            shards_used, domains_used, bytes_restored, duration_ms, result, detail)
           VALUES (?, ?, ?, NULL, NULL, NULL, 0, 0, 0, 0, ?, ?)""",
        (drill_id, stamp, stamp, result, detail),
    )
    db._conn.execute("COMMIT")
    return drill_id


# ─── Hermetic seams for the real drill ───────────────────────────────────────


def _patch_drill_seams(monkeypatch) -> None:
    """Patch the drill's I/O boundaries so run_restore_drill runs for real.

    Only network/crypto boundaries are replaced (snapshot download, shard
    download, chunk decrypt); the drill's own selection, verification, and
    restore_drills bookkeeping all execute unchanged.
    """
    from ghostdrive.services import context, files, snapshots

    async def _fake_verify(db=None, objects=None, master_key=None, salt=None, snapshot_id=None):
        # Return the real seeded snapshot id so the drill's FK-checked INSERT
        # resolves; the actual download/decrypt is what we stub out.
        row = db._conn.execute(
            "SELECT id FROM index_snapshots ORDER BY snapshot_at DESC LIMIT 1"
        ).fetchone()
        return {
            "status": "verified",
            "snapshot_id": str(row["id"]) if row else "seeded-snapshot",
            "plaintext_size": 2048,
        }

    async def _fake_assemble(chunk, objects):
        return b"\x00" * 64  # >= 16 bytes so the decrypt path is happy

    async def _fake_active(connect_remote: bool = True, timeout: float = 8.0):
        return [], {}

    monkeypatch.setattr(snapshots, "verify_snapshot", _fake_verify)
    monkeypatch.setattr(
        snapshots,
        "_decrypt_and_hash",
        lambda ciphertext, chunk, key: (str(chunk["blake3_hash"]), 128),
    )
    monkeypatch.setattr(files, "_assemble_chunk", _fake_assemble)
    monkeypatch.setattr(context, "get_master_key", lambda: bytes(range(32)))
    monkeypatch.setattr(context, "hkdf_salt", lambda: bytes(range(32)))
    monkeypatch.setattr(context, "active_backends", _fake_active)


# ─── Unlocked-vault fixture (function-scoped, clean_shutdown both ends) ──────


def _open_vault(tmp_path: Path) -> GhostDriveDB:
    """Create an unlocked keystore + open DB directly, without importing the
    web server (keeps these tests hermetic to the monitoring router only)."""
    from ghostdrive.crypto.credential_store import credential_store
    from ghostdrive.crypto.hkdf import derive_index_mac_key
    from ghostdrive.crypto.keystore import KeystoreManager

    state.clean_shutdown()
    state.app_data_dir = tmp_path
    state.keystore_path = tmp_path / "keystore.json"
    state.db_path = tmp_path / "ghostdrive.db"

    km = KeystoreManager(state.keystore_path)
    seed_phrase = km.create_new(PASSPHRASE.encode("utf-8"), calibrate=False)
    km.verify_and_save(seed_phrase)
    state.km = km

    master_key = km._master_key_buf.key
    hkdf_salt = km._hkdf_salt
    genesis_seed = km._genesis_seed
    db = GhostDriveDB(
        state.db_path,
        derive_index_mac_key(master_key, hkdf_salt),
        genesis_seed,
        master_key,
    )
    db.open()
    state.db = db
    credential_store.set_active_key(bytes(master_key), bytes(hkdf_salt))
    state.load_persisted_settings()
    return db


@pytest.fixture
def monitor(tmp_path):
    """Unlocked vault + a local FastAPI app exposing ONLY the monitoring router."""
    _open_vault(tmp_path)
    app = FastAPI()
    app.include_router(monitoring.router)
    client = TestClient(app)
    yield client
    state.clean_shutdown()


# ─── run_drill ───────────────────────────────────────────────────────────────


def test_run_drill_with_no_snapshot_records_skipped(tmp_path):
    db = _make_db(tmp_path)

    result = asyncio.run(restore_drills.run_drill(db=db))

    assert result["result"] == "skipped"
    assert "nothing to drill" in result["detail"].lower()
    row = db._conn.execute("SELECT * FROM restore_drills").fetchone()
    assert row is not None
    assert row["result"] == "skipped"


def test_run_drill_with_seeded_snapshot_and_chunk_passes(tmp_path, monkeypatch):
    db = _make_db(tmp_path)
    backend_id = _backend(db, "local")
    _snapshot(db, backend_id)
    file_id = _file(db)
    chunk_id = _chunk(db, file_id, sub_block_count=1)
    _location(db, chunk_id, backend_id, 0)
    _patch_drill_seams(monkeypatch)

    result = asyncio.run(restore_drills.run_drill(db=db))

    assert result["result"] == "passed"
    assert result["bytes_restored"] > 0
    assert result["chunk_id"] == chunk_id
    row = db._conn.execute(
        "SELECT * FROM restore_drills WHERE id = ?", (result["id"],)
    ).fetchone()
    assert row["result"] == "passed"


def test_run_drill_deep_drills_every_chunk(tmp_path, monkeypatch):
    db = _make_db(tmp_path)
    backend_id = _backend(db, "local")
    _snapshot(db, backend_id)
    file_id = _file(db)
    # Distinct chunk_index values: (file_id, chunk_index) is UNIQUE, and the
    # drill selects chunks with ORDER BY chunk_index DESC deterministically.
    chunk_one = _chunk(db, file_id, sub_block_count=1, chunk_index=0)
    chunk_two = _chunk(db, file_id, sub_block_count=1, chunk_index=1)
    _location(db, chunk_one, backend_id, 0)
    _location(db, chunk_two, backend_id, 0)
    _patch_drill_seams(monkeypatch)

    result = asyncio.run(restore_drills.run_drill(db=db, deep=True))

    assert result["result"] == "passed"
    assert result["deep"] is True
    assert result["chunks_drilled"] == 2
    rows = db._conn.execute(
        "SELECT result, chunk_id FROM restore_drills ORDER BY started_at"
    ).fetchall()
    assert len(rows) == 2
    assert {row["chunk_id"] for row in rows} == {chunk_one, chunk_two}
    assert all(row["result"] == "passed" for row in rows)


def test_drill_summary_counts_consecutive_failures(tmp_path):
    db = _make_db(tmp_path)
    base = datetime.now(timezone.utc) - timedelta(days=3)
    _insert_drill(db, "passed", base - timedelta(days=10))
    _insert_drill(db, "failed", base - timedelta(days=2), detail="shard unavailable")
    _insert_drill(db, "failed", base - timedelta(days=1), detail="backend offline")

    summary = restore_drills.drill_summary(db)

    assert summary["total"] == 3
    assert summary["passed"] == 1
    assert summary["failed"] == 2
    assert summary["consecutive_failures"] == 2
    assert summary["last"]["result"] == "failed"
    assert summary["last_success_at"] is not None
    # Last success was 11 days ago: within the 14-day window, not stale.
    assert summary["stale"] is False

    # A passing drill ends the streak.
    _insert_drill(db, "passed", base)
    summary = restore_drills.drill_summary(db)
    assert summary["consecutive_failures"] == 0


def test_drill_summary_stale_flips_after_fourteen_days(tmp_path):
    db = _make_db(tmp_path)
    now = datetime.now(timezone.utc)
    _insert_drill(db, "passed", now - timedelta(days=13, hours=23))

    assert restore_drills.drill_summary(db, now=now)["stale"] is False
    assert (
        restore_drills.drill_summary(db, now=now + timedelta(days=1, seconds=2))["stale"]
        is True
    )


def test_drill_summary_not_stale_without_a_real_drill(tmp_path):
    """Never-drilled / only-skipped systems are unproven, not stale."""
    db = _make_db(tmp_path)
    assert restore_drills.drill_summary(db)["stale"] is False

    _insert_drill(db, "skipped", datetime.now(timezone.utc))
    summary = restore_drills.drill_summary(db)
    assert summary["total"] == 1
    assert summary["stale"] is False


def test_drill_history_is_newest_first_and_bounded(tmp_path):
    db = _make_db(tmp_path)
    base = datetime.now(timezone.utc)
    _insert_drill(db, "passed", base - timedelta(days=2))
    _insert_drill(db, "failed", base - timedelta(days=1))
    _insert_drill(db, "passed", base)

    history = restore_drills.drill_history(db, limit=2)

    assert len(history) == 2
    assert history[0]["result"] == "passed"
    assert history[1]["result"] == "failed"
    assert history[0]["started_at"] >= history[1]["started_at"]


# ─── Scheduler ───────────────────────────────────────────────────────────────


def test_drill_scheduler_start_is_idempotent_and_stop_clears(tmp_path):
    db = _make_db(tmp_path)

    async def scenario():
        task = restore_drills.start_drill_scheduler(interval_hours=1e-4, db=db)
        assert task is not None
        assert not task.done()

        # Double-start returns the very same task (no second loop).
        again = restore_drills.start_drill_scheduler(interval_hours=1e-4, db=db)
        assert again is task

        # Let the loop tick into its first sleep; keep test sleeps tiny.
        await asyncio.sleep(0.05)

        restore_drills.stop_drill_scheduler()
        assert restore_drills._drill_task is None
        await asyncio.sleep(0.01)  # let the cancellation actually process

    asyncio.run(scenario())


# ─── Badge routes (hermetic local app) ───────────────────────────────────────


def test_badge_green_on_fresh_healthy_state(monitor):
    res = monitor.get("/api/monitoring/badge")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["overall"] == "green"
    assert body["active_alerts"] == 0
    assert body["drill"]["total"] == 0
    assert body["contract"]["meets"] is True
    assert body["checked_at"]


def test_badge_green_with_recent_passing_drill(monitor):
    passed_at = datetime.now(timezone.utc) - timedelta(days=2)
    _insert_drill(state.db, "passed", passed_at)

    res = monitor.get("/api/monitoring/badge")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["overall"] == "green"
    assert body["label"].startswith("VERIFIED")
    assert "2d ago" in body["label"]


def test_badge_red_when_latest_drill_failed(monitor):
    now = datetime.now(timezone.utc)
    _insert_drill(state.db, "passed", now - timedelta(days=2))
    _insert_drill(state.db, "failed", now, detail="shard unavailable")

    res = monitor.get("/api/monitoring/badge")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["overall"] == "red"
    assert body["label"] == "RESTORE DRILL FAILED"
    assert body["drill"]["last"]["result"] == "failed"


def test_badge_svg_renders_with_label(monitor):
    label = monitor.get("/api/monitoring/badge").json()["label"]

    res = monitor.get("/api/monitoring/badge.svg")

    assert res.status_code == 200
    assert res.headers["content-type"].startswith("image/svg")
    assert label in res.text
    assert "<svg" in res.text


def test_drill_routes_smoke(monitor):
    res = monitor.get("/api/monitoring/drills")
    assert res.status_code == 200
    assert res.json() == []

    res = monitor.get("/api/monitoring/drills/summary")
    assert res.status_code == 200
    assert res.json()["total"] == 0

    # Fresh vault: no snapshot and no chunks -> honest "skipped" row.
    res = monitor.post("/api/monitoring/drills/run")
    assert res.status_code == 200, res.text
    assert res.json()["result"] == "skipped"

    res = monitor.get("/api/monitoring/drills")
    assert res.status_code == 200
    assert len(res.json()) == 1

    res = monitor.get("/api/monitoring/scheduler")
    assert res.status_code == 200
    body = res.json()
    assert body["drills"]["running"] is False
    assert body["drills"]["enabled"] is True
    assert body["drills"]["interval_hours"] == 168
    assert body["alerts"]["running"] is False
    assert body["alerts"]["interval_minutes"] == 15
