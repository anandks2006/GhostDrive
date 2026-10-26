"""Tests for hostile/withholding backend detection and the immutable offsite copy.

Covers the two gaps: (1) integrity_log rows are correlated across backends so
a withholding or corrupting backend is distinguished from one that is merely
failing, and (2) an index snapshot gets one immutable offsite copy under a
unique chunk_id that slot rotation can never overwrite, hash-verifiable later.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import blake3
import pytest
from fastapi.testclient import TestClient

from ghostdrive.database.db import GhostDriveDB
from ghostdrive.services import snapshots
from ghostdrive.services.hostility import (
    clear_quarantine,
    detect_withholding,
    quarantine_backend,
)
from ghostdrive.web.server import app
from ghostdrive.web.state import state

# ─── DB helpers (copied from tests/test_durability.py) ──────────────────────

TOTAL_SHARDS = 6


def _make_db(tmp_path: Path) -> GhostDriveDB:
    db = GhostDriveDB(
        path=tmp_path / "hostility.db",
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


def _chunk(db, file_id: str, sub_block_count: int = TOTAL_SHARDS, chunk_index: int = 0) -> str:
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


# ─── Hostility-specific helpers ─────────────────────────────────────────────

def _integrity(db, chunk_id: str, backend_id: str, result: str, checked_at: str) -> None:
    db._conn.execute("BEGIN")
    db._conn.execute(
        """INSERT INTO integrity_log (id, chunk_id, checked_at, result, backend_id)
           VALUES (?, ?, ?, ?, ?)""",
        (str(uuid.uuid4()), chunk_id, checked_at, result, backend_id),
    )
    db._conn.execute("COMMIT")


def _chunks(db, count: int) -> list[str]:
    file_id = _file(db)
    return [_chunk(db, file_id, chunk_index=i) for i in range(count)]


def _verdicts(report: dict) -> dict:
    return {entry["backend_id"]: entry["verdict"] for entry in report["backends"]}


def _entry(report: dict, backend_id: str) -> dict:
    return next(e for e in report["backends"] if e["backend_id"] == backend_id)


# ─── detect_withholding ─────────────────────────────────────────────────────

def test_detect_withholding_peer_control(tmp_path):
    """Failures only count as hostility when a peer served the same chunk ok."""
    db = _make_db(tmp_path)
    now = datetime(2026, 1, 12, tzinfo=timezone.utc)
    inside = (now - timedelta(hours=1)).isoformat()
    outside = (now - timedelta(days=30)).isoformat()

    x = _backend(db, "telegram")
    y = _backend(db, "telegram")
    z = _backend(db, "discord")
    w = _backend(db, "telegram")
    h = _backend(db, "telegram")

    # X: 10 in-window checks -- 7 not_found across 5 distinct chunks where Y
    # logged 'ok' for the same chunks, plus 3 of its own ok checks.
    x_failed = _chunks(db, 5)
    for chunk_id in x_failed:
        _integrity(db, chunk_id, x, "not_found", inside)
        _integrity(db, chunk_id, y, "ok", inside)
    _integrity(db, x_failed[0], x, "not_found", inside)  # repeat checks
    _integrity(db, x_failed[1], x, "not_found", inside)
    for chunk_id in _chunks(db, 3):
        _integrity(db, chunk_id, x, "ok", inside)
    # Two failures far outside the window must NOT be counted.
    stale = _chunks(db, 2)
    for chunk_id in stale:
        _integrity(db, chunk_id, x, "not_found", outside)

    # Y: everything ok (its own checks plus the peer-control ok rows above).
    for chunk_id in _chunks(db, 4):
        _integrity(db, chunk_id, y, "ok", inside)

    # Z: only 3 checks -- below min_checks, cannot be judged either way.
    z_chunks = _chunks(db, 1)
    _integrity(db, z_chunks[0], z, "not_found", inside)
    for chunk_id in _chunks(db, 2):
        _integrity(db, chunk_id, z, "ok", inside)

    # W: rate 0.9 but no peer ever served its failed chunks -- unreliable,
    # not proven hostile.
    w_failed = _chunks(db, 9)
    for chunk_id in w_failed:
        _integrity(db, chunk_id, w, "not_found", inside)
    ok_chunk = _chunks(db, 1)[0]
    _integrity(db, ok_chunk, w, "ok", inside)

    # H: hash_mismatch-dominant with peer exoneration -- corrupting.
    h_failed = _chunks(db, 4)
    for chunk_id in h_failed:
        _integrity(db, chunk_id, h, "hash_mismatch", inside)
        _integrity(db, chunk_id, y, "ok", inside)
    for chunk_id in _chunks(db, 2):
        _integrity(db, chunk_id, h, "ok", inside)

    report = detect_withholding(db, window_hours=168, now=now, min_checks=6)

    verdicts = _verdicts(report)
    assert verdicts[x] == "withholding"
    assert verdicts[y] == "ok"
    assert verdicts[z] == "insufficient_data"
    assert verdicts[w] == "failing"
    assert verdicts[h] == "corrupting"

    flagged = {item["backend_id"]: item["verdict"] for item in report["flagged"]}
    assert flagged == {x: "withholding", w: "failing", h: "corrupting"}

    entry_x = _entry(report, x)
    # 10 in-window checks: the two stale rows are excluded by the window.
    assert entry_x["checks"] == 10
    assert entry_x["failures"] == 7
    assert entry_x["failure_rate"] == pytest.approx(0.7)
    assert entry_x["peer_ok_failures"] == 5
    assert len(entry_x["evidence_chunks"]) == 5
    assert entry_x["type"] == "telegram"

    assert report["window_hours"] == 168
    assert report["min_checks"] == 6
    assert report["evaluated_at"] == now.isoformat()


def test_detect_withholding_dominant_tie_prefers_hash_mismatch(tmp_path):
    """On equal counts the fixed order hash_mismatch > auth_failed > not_found wins."""
    db = _make_db(tmp_path)
    now = datetime(2026, 1, 12, tzinfo=timezone.utc)
    inside = (now - timedelta(hours=1)).isoformat()

    t = _backend(db, "telegram")
    y = _backend(db, "telegram")

    # 2 not_found vs 2 hash_mismatch, both peer-corroborated, plus 2 ok.
    denied = _chunks(db, 2)
    corrupted = _chunks(db, 2)
    for chunk_id in denied:
        _integrity(db, chunk_id, t, "not_found", inside)
        _integrity(db, chunk_id, y, "ok", inside)
    for chunk_id in corrupted:
        _integrity(db, chunk_id, t, "hash_mismatch", inside)
        _integrity(db, chunk_id, y, "ok", inside)
    for chunk_id in _chunks(db, 2):
        _integrity(db, chunk_id, t, "ok", inside)

    report = detect_withholding(db, now=now)
    assert _verdicts(report)[t] == "corrupting"


# ─── quarantine ─────────────────────────────────────────────────────────────

def test_quarantine_and_clear(tmp_path):
    db = _make_db(tmp_path)
    backend_id = _backend(db, "telegram")

    result = quarantine_backend(db, backend_id, reason="peer-corroborated denial")
    assert result["status"] == "deprecated"
    assert result["already_quarantined"] is False
    assert result["reason"] == "peer-corroborated denial"

    row = db._conn.execute("SELECT * FROM backends WHERE id = ?", (backend_id,)).fetchone()
    assert row["status"] == "deprecated"
    assert row["deprecated_at"]
    assert row["last_error"] == "peer-corroborated denial"

    # Upload routing only selects healthy backends -- quarantine must evict it.
    healthy = [
        r["id"]
        for r in db._conn.execute("SELECT id FROM backends WHERE status = 'healthy'").fetchall()
    ]
    assert backend_id not in healthy

    # Idempotent second call.
    second = quarantine_backend(db, backend_id, reason="again")
    assert second["status"] == "deprecated"
    assert second["already_quarantined"] is True
    assert second["quarantined_at"] == result["quarantined_at"]

    # Clearing restores upload eligibility.
    cleared = clear_quarantine(db, backend_id)
    assert cleared["status"] == "healthy"
    row = db._conn.execute("SELECT * FROM backends WHERE id = ?", (backend_id,)).fetchone()
    assert row["status"] == "healthy"
    assert row["deprecated_at"] is None
    # last_error is kept as diagnostic history.
    assert row["last_error"] == "peer-corroborated denial"
    healthy = [
        r["id"]
        for r in db._conn.execute("SELECT id FROM backends WHERE status = 'healthy'").fetchall()
    ]
    assert backend_id in healthy

    with pytest.raises(FileNotFoundError):
        quarantine_backend(db, "no-such-backend")
    with pytest.raises(FileNotFoundError):
        clear_quarantine(db, "no-such-backend")


# ─── immutable offsite copy ─────────────────────────────────────────────────

def _mock_backend(payload: bytes, upload_ref: str = "ref-1") -> MagicMock:
    """Backend mock: serves `payload` on download, acknowledges any upload."""
    obj = MagicMock()
    obj._connected = True
    obj.upload = AsyncMock(return_value=upload_ref)

    async def _download(_reference_id):
        yield payload

    obj.download = _download
    return obj


def _snapshot(db, backend_id: str, snapshot_at: str) -> str:
    snapshot_id = str(uuid.uuid4())
    db._conn.execute("BEGIN")
    db._conn.execute(
        """INSERT INTO index_snapshots
           (id, snapshot_at, blake3_hash, hash_backend_id, wal_checkpointed, slot, snapshot_size)
           VALUES (?, ?, ?, ?, 1, 0, 8)""",
        (snapshot_id, snapshot_at, "a" * 64, backend_id),
    )
    db._conn.execute(
        """INSERT INTO index_snapshot_copies
           (snapshot_id, backend_id, domain_id, reference_id, blake3_hash, size,
            status, created_at, verified_at)
           VALUES (?, ?, ?, ?, ?, 8, 'confirmed', ?, ?)""",
        (snapshot_id, backend_id, "provider:telegram", "ref-snap", "b" * 64, snapshot_at, snapshot_at),
    )
    db._conn.execute("COMMIT")
    return snapshot_id


def _immutable_fixture(tmp_path):
    db = _make_db(tmp_path)
    src = _backend(db, "telegram", priority=100)
    dst = _backend(db, "telegram", priority=200)
    blob = b"sealed-snapshot-payload" * 4
    snapshot_id = _snapshot(db, src, _now())
    objects = {src: _mock_backend(blob), dst: _mock_backend(blob, upload_ref="ref-imm")}
    return db, src, dst, blob, snapshot_id, objects


async def test_create_immutable_copy_unique_chunk_id_and_persistence(tmp_path):
    db, src, dst, blob, snapshot_id, objects = _immutable_fixture(tmp_path)

    record = await snapshots.create_immutable_copy(snapshot_id=snapshot_id, db=db, objects=objects)

    # Targets the highest-priority healthy offsite (provider) backend.
    assert record["backend_id"] == dst
    assert record["domain_id"] == "provider:telegram"
    assert record["status"] == "sealed"
    assert record["chunk_id"].startswith(f"immutable-{snapshot_id}-")
    assert record["blake3_hash"] == blake3.blake3(blob).hexdigest()
    assert record["reference_id"] == "ref-imm"
    assert record["size"] == len(blob)
    assert record["sealed_at"]

    # The record is persisted under the documented settings key.
    persisted = json.loads(db.get_setting(snapshots.IMMUTABLE_COPY_KEY, ""))
    assert persisted == {
        key: record[key]
        for key in (
            "snapshot_id", "backend_id", "domain_id", "reference_id",
            "blake3_hash", "size", "sealed_at", "chunk_id",
        )
    }

    # Re-sealing the same snapshot is a no-op on an already-healthy target.
    again = await snapshots.create_immutable_copy(snapshot_id=snapshot_id, db=db, objects=objects)
    assert again["unchanged"] is True
    assert again["chunk_id"] == record["chunk_id"]

    # A different snapshot seals under a fresh, unique chunk_id.
    second_snapshot = _snapshot(db, src, _now())
    other = await snapshots.create_immutable_copy(snapshot_id=second_snapshot, db=db, objects=objects)
    assert other["snapshot_id"] == second_snapshot
    assert other["chunk_id"].startswith(f"immutable-{second_snapshot}-")
    assert other["chunk_id"] != record["chunk_id"]
    assert other["chunk_id"] != again["chunk_id"]

    # Status + orphan detection.
    status = snapshots.immutable_copy_status(db)
    assert status["status"] == "sealed"
    assert status["snapshot_exists"] is True
    assert status["record"]["chunk_id"] == other["chunk_id"]
    assert status["age_hours"] >= 0

    db._conn.execute("DELETE FROM index_snapshot_copies WHERE snapshot_id = ?", (second_snapshot,))
    db._conn.execute("DELETE FROM index_snapshots WHERE id = ?", (second_snapshot,))
    status = snapshots.immutable_copy_status(db)
    assert status["status"] == "orphaned"
    assert status["snapshot_exists"] is False


async def test_verify_immutable_copy_valid_tampered_unreachable(tmp_path):
    db, src, dst, blob, snapshot_id, objects = _immutable_fixture(tmp_path)
    record = await snapshots.create_immutable_copy(snapshot_id=snapshot_id, db=db, objects=objects)

    now = datetime(2026, 1, 12, tzinfo=timezone.utc)
    result = await snapshots.verify_immutable_copy(db=db, objects=objects, now=now)
    assert result["status"] == "valid"
    assert result["expected"] == record["blake3_hash"]
    assert result["actual"] == record["blake3_hash"]
    assert result["snapshot_id"] == snapshot_id
    assert result["checked_at"] == now.isoformat()
    # The blob itself must never leak through the report.
    assert blob.decode() not in json.dumps(result)

    # Tamper: the backend now serves mutated bytes.
    tampered = {src: _mock_backend(blob), dst: _mock_backend(blob + b"!")}
    result = await snapshots.verify_immutable_copy(db=db, objects=tampered)
    assert result["status"] == "tampered"
    assert result["actual"] != record["blake3_hash"]

    # Backend not connected: reported, never raised.
    result = await snapshots.verify_immutable_copy(db=db, objects={src: _mock_backend(blob)})
    assert result == {"status": "unreachable", "backend_id": dst}

    # Download failure: reported with a detail, never raised.
    async def _boom(_reference_id):
        raise OSError("network down")
        yield b""  # pragma: no cover

    broken = MagicMock()
    broken.download = _boom
    result = await snapshots.verify_immutable_copy(db=db, objects={dst: broken})
    assert result["status"] == "error"
    assert "network down" in result["detail"]

    # Nothing sealed yet -> absent.
    (tmp_path / "fresh").mkdir()
    fresh_db = _make_db(tmp_path / "fresh")
    assert await snapshots.verify_immutable_copy(db=fresh_db, objects={}) == {"status": "absent"}


async def test_create_immutable_copy_failure_paths(tmp_path):
    # No snapshot at all -> ValueError (route maps it to 400).
    db = _make_db(tmp_path)
    with pytest.raises(ValueError):
        await snapshots.create_immutable_copy(db=db, objects={})

    # Snapshot exists but nothing is retrievable -> RuntimeError telling the
    # caller to create a snapshot first (we never re-encode the index here).
    backend_id = _backend(db, "telegram")
    snapshot_id = _snapshot(db, backend_id, _now())
    with pytest.raises(RuntimeError):
        await snapshots.create_immutable_copy(snapshot_id=snapshot_id, db=db, objects={})

    # No healthy offsite (provider) backend among the objects -> RuntimeError.
    local = _backend(db, "local_fs")
    local_snapshot = _snapshot(db, local, _now())
    blob = b"payload"
    objects = {local: _mock_backend(blob)}
    with pytest.raises(RuntimeError):
        await snapshots.create_immutable_copy(snapshot_id=local_snapshot, db=db, objects=objects)


def test_immutable_copy_status_absent(tmp_path):
    db = _make_db(tmp_path)
    status = snapshots.immutable_copy_status(db)
    assert status == {"status": "absent", "record": None}


# ─── route smoke tests ──────────────────────────────────────────────────────

PASSPHRASE = "correct horse battery staple"


@pytest.fixture
def hostility_client(tmp_path):
    """Fresh unlocked vault in a temp dir (function-scoped: these tests lock it)."""
    state.clean_shutdown()
    state.app_data_dir = tmp_path
    state.keystore_path = tmp_path / "keystore.json"
    state.db_path = tmp_path / "ghostdrive.db"

    client = TestClient(app)
    res = client.post("/api/auth/setup", json={"passphrase": PASSPHRASE})
    assert res.status_code == 200, res.text

    yield client

    state.clean_shutdown()


def test_route_immutable_status_absent_on_fresh_vault(hostility_client):
    res = hostility_client.get("/api/resilience/offsite/immutable")
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["status"] == "absent"
    assert data["record"] is None


def test_route_hostility_report_shape(hostility_client):
    res = hostility_client.get("/api/resilience/hostility/report")
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["window_hours"] == 168
    assert data["min_checks"] == 6
    assert "evaluated_at" in data
    assert data["backends"] == []
    assert data["flagged"] == []


def test_route_quarantine_unknown_backend_404(hostility_client):
    res = hostility_client.post("/api/resilience/hostility/quarantine/does-not-exist")
    assert res.status_code == 404


def test_route_quarantine_and_clear_roundtrip(hostility_client):
    backend_id = _backend(state.db, "telegram")

    res = hostility_client.post(
        f"/api/resilience/hostility/quarantine/{backend_id}",
        json={"reason": "withholding (peer-corroborated)"},
    )
    assert res.status_code == 200, res.text
    assert res.json()["status"] == "deprecated"
    row = state.db.get_backend(backend_id)
    assert row["status"] == "deprecated"

    res = hostility_client.post(f"/api/resilience/hostility/clear/{backend_id}")
    assert res.status_code == 200, res.text
    assert res.json()["status"] == "healthy"
    row = state.db.get_backend(backend_id)
    assert row["status"] == "healthy"
