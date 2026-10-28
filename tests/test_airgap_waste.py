"""
tests/test_airgap_waste.py -- Air-gap export service/routes and the waste report.

Covers the settings/router contracts, the waste report over a real vault
(two uploads of identical bytes exercising content-identity dedup, zero Trash
at first, then a real files-service trash move making trash bytes nonzero),
a full air-gap export (atomic chunk files behind the GDC1 magic, HMAC-signed
manifest with per-file content hashes, state append, verify passing on an
intact drive), verify detecting both corruption (flipped byte -> content-hash
mismatch on the deterministic sample) and deletion (missing), the restore
drill passing intact then failing on a damaged archive with the critical
airgap_drill_failed alert recorded (and state.last_drill.ok False), the HTTP
routes (/api/waste/report, /api/waste/status, /api/airgap/status, export 400
when unconfigured / 200 when targeted, verify + drill), and the scheduler
lifecycle (start -> task exists -> stop -> cancelled) plus the cycle helper
skipping cleanly while disabled or untargeted.

No network anywhere: the export reads only local backend bytes and alert
dispatch has no deliverers or webhook configured.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ghostdrive.services import airgap as airgap_service
from ghostdrive.services import alerts as alerts_service
from ghostdrive.services import files as files_service
from ghostdrive.services import waste as waste_service
from ghostdrive.web.routes import airgap as airgap_routes
from ghostdrive.web.routes import waste as waste_routes
from ghostdrive.web.server import app as server_app
from ghostdrive.web.state import state

PASSPHRASE = "correct horse battery staple"


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def vault(tmp_path_factory):
    """Module-scoped unlocked vault (same pattern as tests/test_sync.py).

    Air-gap exports run through the real files service, which needs an open
    database and local backend -- unlocked once here via the real server app.
    """
    data_dir = tmp_path_factory.mktemp("ghostdrive_airgap")
    state.clean_shutdown()
    state.app_data_dir = data_dir
    state.keystore_path = data_dir / "keystore.json"
    state.db_path = data_dir / "ghostdrive.db"

    client = TestClient(server_app)
    response = client.post("/api/auth/setup", json={"passphrase": PASSPHRASE})
    assert response.status_code == 200, response.text

    yield

    airgap_service.stop_airgap_scheduler()
    state.clean_shutdown()


@pytest.fixture
def db(vault):
    from ghostdrive.services.context import require_db

    return require_db()


@pytest.fixture
def client(vault):
    """Local app carrying ONLY the airgap + waste routers (one TestClient loop)."""
    local_app = FastAPI()
    local_app.include_router(airgap_routes.router)
    local_app.include_router(waste_routes.router)
    with TestClient(local_app) as local:
        yield local


# ── Helpers ───────────────────────────────────────────────────────────────────


def _set_target(db, target: Path, *, enabled: bool = False) -> None:
    """Deterministic air-gap settings for one test (target exists on disk)."""
    with db.transaction():
        db.set_setting(airgap_service.KEY_AIRGAP_TARGET_DIR, str(target))
        db.set_setting(airgap_service.KEY_AIRGAP_ENABLED, "true" if enabled else "false")
        db.set_setting(airgap_service.KEY_AIRGAP_INTERVAL_HOURS, "168")


def _upload(directory: Path, name: str, content: bytes) -> str:
    """Upload bytes through the real files service; returns the file_id."""
    directory.mkdir(parents=True, exist_ok=True)
    source = directory / name
    source.write_bytes(content)
    result = asyncio.run(
        files_service.upload_stream(source, name, None, "IMPORTANT", "/")
    )
    return str(result["file_id"])


# ── Contracts ─────────────────────────────────────────────────────────────────


def test_settings_keys_and_router_contract():
    assert airgap_service.KEY_AIRGAP_ENABLED == "airgap_enabled"
    assert airgap_service.KEY_AIRGAP_TARGET_DIR == "airgap_target_dir"
    assert airgap_service.KEY_AIRGAP_INTERVAL_HOURS == "airgap_interval_hours"
    assert airgap_service.KEY_AIRGAP_STATE == "airgap_state"
    assert airgap_service.DEFAULT_INTERVAL_HOURS == 168.0
    assert airgap_service.ALERT_KIND_DRILL_FAILED == "airgap_drill_failed"
    assert airgap_routes.router.prefix == "/api/airgap"
    assert waste_routes.router.prefix == "/api/waste"


# ── Waste report ──────────────────────────────────────────────────────────────


def test_waste_report_duplicate_and_trash(db, tmp_path):
    src = tmp_path / "src"
    duplicate = b"the very same bytes stored twice -- waste probe"
    first = _upload(src, "dup_one.txt", duplicate)
    second = _upload(src, "dup_two.txt", duplicate)

    report = waste_service.report(db)
    for key in (
        "generated_at",
        "dedup",
        "trash",
        "versions",
        "envelope_links",
        "total_reclaimable_bytes",
        "top_duplicates",
    ):
        assert key in report, f"missing waste report key: {key}"

    assert isinstance(report["total_reclaimable_bytes"], int)
    assert report["total_reclaimable_bytes"] >= 0

    # Two uploads of identical bytes: the content identity is duplicated.
    dedup = report["dedup"]
    assert dedup["duplicated_contents"] >= 1
    assert dedup["duplicated_chunks"] >= 1
    assert dedup["wasted_bytes"] >= len(duplicate)
    assert dedup["potential_reclaim_bytes"] == dedup["wasted_bytes"]
    assert report["total_reclaimable_bytes"] >= dedup["wasted_bytes"]

    # Nothing in Trash yet, and versions/links start empty but well-formed.
    assert report["trash"] == {
        "files": 0,
        "bytes": 0,
        "oldest_age_days": None,
    }
    assert report["versions"]["count"] == 0
    assert report["envelope_links"]["alive"] == 0

    top = [entry for entry in report["top_duplicates"] if entry["copies"] >= 2]
    assert top, "the duplicated upload should surface in top_duplicates"
    assert top[0]["size"] == len(duplicate)
    assert top[0]["sample_paths"]  # both duplicate paths resolvable via JOIN

    # Trash a file through the real service: bytes become reclaimable-later.
    outcome = asyncio.run(files_service.delete_file(first))
    assert outcome["status"] == "success"
    report = waste_service.report(db)
    assert report["trash"]["files"] >= 1
    assert report["trash"]["bytes"] >= len(duplicate)
    assert report["trash"]["oldest_age_days"] is not None
    assert report["total_reclaimable_bytes"] >= report["trash"]["bytes"]
    # The surviving duplicate still counts as waste (its pair is in Trash but
    # chunks are only purged on retention, not on tombstone).
    assert report["dedup"]["duplicated_chunks"] >= 1
    del second


# ── Air-gap export + verify ───────────────────────────────────────────────────


def test_airgap_export_and_verify(db, tmp_path):
    target = tmp_path / "drive"
    target.mkdir()
    _set_target(db, target)
    src = tmp_path / "src"
    content = b"air-gap export probe payload"
    file_id = _upload(src, "airgap.txt", content)

    outcome = asyncio.run(airgap_service.export_airgap(db))
    assert outcome["ok"] is True, outcome["error"]
    assert outcome["error"] == ""
    assert outcome["target"] == str(target)
    assert outcome["file_count"] >= 1
    assert outcome["bytes"] > 0
    assert outcome["chunks_written"] >= 1
    assert outcome["chunks_reused"] >= 0

    manifest_path = Path(outcome["manifest_path"])
    assert manifest_path.is_file()
    assert manifest_path.name == "manifest.json"
    assert manifest_path.parent.name.startswith("ghostdrive-export-")
    assert manifest_path.parent.parent == target

    manifest = json.loads(manifest_path.read_bytes())
    assert manifest["v"] == 1
    assert manifest["file_count"] == outcome["file_count"]
    assert manifest["total_bytes"] == outcome["bytes"]
    assert len(bytes.fromhex(manifest["master_salt_hex"])) == 32
    assert manifest["hmac_hex"]
    assert manifest["chunk_files"]
    for item in manifest["chunk_files"]:
        assert set(item) == {"name", "size"}
        assert item["name"].endswith(".gdc")
        assert len(item["name"]) == len("a" * 64) + len(".gdc")  # sha256 hex

    entry = next(f for f in manifest["files"] if f["file_id"] == file_id)
    assert entry["path"] == "/airgap.txt"
    assert entry["size"] == len(content)
    assert entry["chunks"] >= 1
    assert entry["chunks"] == len(entry["chunk_names"])
    assert len(entry["content_hash_hex"]) == 64  # BLAKE3 hex

    # Chunk file layout: GDC1 magic + verbatim ciphertext, named by sha256 of
    # the file's own bytes (the manifest's content-addressed identity).
    chunk_path = manifest_path.parent / entry["chunk_names"][0]
    raw = chunk_path.read_bytes()
    assert raw.startswith(b"GDC1")
    assert hashlib.sha256(raw).hexdigest() + ".gdc" == chunk_path.name

    # Re-reading the archive from disk: HMAC recomputes, every chunk present.
    verification = asyncio.run(airgap_service.verify_airgap(db))
    assert verification["ok"] is True, verification
    assert verification["manifest_ok"] is True
    assert verification["checked_chunks"] == len(manifest["chunk_files"])
    assert verification["missing"] == 0
    assert verification["corrupt"] == 0
    assert verification["error"] == ""

    state_json = json.loads(db.get_setting(airgap_service.KEY_AIRGAP_STATE, "{}"))
    assert state_json["exports"]
    assert len(state_json["exports"]) <= airgap_service.STATE_EXPORT_CAP
    assert state_json["exports"][-1]["ok"] is True
    assert state_json["last_ok_at"]
    assert state_json["last_drill"] is None


def test_airgap_verify_detects_corruption(db, tmp_path):
    target = tmp_path / "drive"
    target.mkdir()
    _set_target(db, target)
    src = tmp_path / "src"
    _upload(src, "corrupt_me.txt", b"bytes whose export copy will be damaged")

    outcome = asyncio.run(airgap_service.export_airgap(db))
    assert outcome["ok"] is True, outcome["error"]
    export_dir = Path(outcome["manifest_path"]).parent
    manifest = json.loads(Path(outcome["manifest_path"]).read_bytes())
    assert manifest["chunk_files"]
    victim = export_dir / manifest["chunk_files"][0]["name"]

    # Flip a byte in the middle: size is unchanged, so only the sampled
    # content check (sha256 of payload vs the content-addressed name) catches it.
    data = bytearray(victim.read_bytes())
    data[len(data) // 2] ^= 0xFF
    victim.write_bytes(bytes(data))

    verification = asyncio.run(airgap_service.verify_airgap(db, str(export_dir)))
    assert verification["ok"] is False
    assert verification["manifest_ok"] is True  # manifest untouched
    assert verification["missing"] + verification["corrupt"] >= 1

    # Deletion is caught by the exists+size pass over EVERY chunk file.
    victim.unlink()
    verification = asyncio.run(airgap_service.verify_airgap(db, str(export_dir)))
    assert verification["ok"] is False
    assert verification["missing"] >= 1


# ── Restore drill ─────────────────────────────────────────────────────────────


def test_restore_drill_alerts_on_failure(db, tmp_path):
    target = tmp_path / "drive"
    target.mkdir()
    _set_target(db, target)
    src = tmp_path / "src"
    _upload(src, "drill.txt", b"payload the drill will restore from the export")

    outcome = asyncio.run(airgap_service.export_airgap(db))
    assert outcome["ok"] is True, outcome["error"]
    export_dir = Path(outcome["manifest_path"]).parent
    manifest = json.loads(Path(outcome["manifest_path"]).read_bytes())
    candidate_ids = {f["file_id"] for f in manifest["files"]}
    failed_ids = {
        alerts_service.alert_id(airgap_service.ALERT_KIND_DRILL_FAILED, file_id)
        for file_id in candidate_ids
    }

    # Intact export: drill decrypts one file out of the archive and matches
    # both the live digests and the manifest's content hash -- no alert.
    drill = asyncio.run(airgap_service.restore_drill_airgap(db))
    assert drill["ok"] is True, drill["error"]
    assert drill["error"] == ""
    assert drill["file"]
    assert not (failed_ids & set(alerts_service.alert_state(db)["seen"]))
    state_json = json.loads(db.get_setting(airgap_service.KEY_AIRGAP_STATE, "{}"))
    assert state_json["last_drill"]["ok"] is True
    assert state_json["last_drill"]["file"]

    # Damage every chunk file in place (ciphertext body, magic kept): Poly1305
    # auth must fail for whichever file the drill picks.
    for item in manifest["chunk_files"]:
        path = export_dir / item["name"]
        data = bytearray(path.read_bytes())
        assert len(data) > 4
        data[4] ^= 0xFF
        path.write_bytes(bytes(data))

    failed = asyncio.run(airgap_service.restore_drill_airgap(db, str(export_dir)))
    assert failed["ok"] is False
    assert failed["error"]
    assert failed["file"] in {f["path"] for f in manifest["files"]}

    # Critical alert recorded under the stable (kind, file_id) id...
    seen = alerts_service.alert_state(db)["seen"]
    assert failed_ids & set(seen)
    # ...and the persisted drill outcome says so too.
    state_json = json.loads(db.get_setting(airgap_service.KEY_AIRGAP_STATE, "{}"))
    assert state_json["last_drill"]["ok"] is False
    assert state_json["last_drill"]["error"]


# ── Routes ────────────────────────────────────────────────────────────────────


def test_routes_waste_and_airgap(client, db, tmp_path):
    res = client.get("/api/waste/report")
    assert res.status_code == 200, res.text
    body = res.json()
    assert set(body) >= {
        "generated_at",
        "dedup",
        "trash",
        "versions",
        "envelope_links",
        "total_reclaimable_bytes",
        "top_duplicates",
    }
    assert isinstance(body["total_reclaimable_bytes"], int)

    res = client.get("/api/waste/status")
    assert res.status_code == 200
    assert res.json() == {"last_run": None, "cheap": True}

    res = client.get("/api/airgap/status")
    assert res.status_code == 200, res.text
    status = res.json()
    assert set(status) == {
        "enabled",
        "target_dir",
        "target_exists",
        "interval_hours",
        "last",
        "last_ok_at",
        "last_drill",
    }
    assert isinstance(status["enabled"], bool)
    assert isinstance(status["target_exists"], bool)
    assert status["interval_hours"] >= 1

    # Unconfigured target: the export route refuses to guess -> 400.
    with db.transaction():
        db.set_setting(airgap_service.KEY_AIRGAP_TARGET_DIR, "")
    res = client.post("/api/airgap/export")
    assert res.status_code == 400
    assert "not configured" in res.json()["detail"]

    target = tmp_path / "route_drive"
    target.mkdir()
    with db.transaction():
        db.set_setting(airgap_service.KEY_AIRGAP_TARGET_DIR, str(target))
    res = client.post("/api/airgap/export")
    assert res.status_code == 200, res.text
    exported = res.json()
    assert exported["ok"] is True, exported["error"]
    assert exported["manifest_path"]

    res = client.post("/api/airgap/verify")
    assert res.status_code == 200, res.text
    assert res.json()["ok"] is True

    res = client.post("/api/airgap/drill")
    assert res.status_code == 200, res.text
    assert res.json()["ok"] is True


# ── Scheduler ─────────────────────────────────────────────────────────────────


async def test_airgap_scheduler_lifecycle(vault):
    from ghostdrive.services.context import require_db

    db = require_db()
    assert airgap_service.stop_airgap_scheduler() is None  # nothing running yet

    try:
        task = airgap_service.start_airgap_scheduler(db=db)
        assert task is not None and not task.done()
        assert airgap_service._airgap_task is task
        # Double start is a no-op returning the same task.
        assert airgap_service.start_airgap_scheduler(db=db) is task

        airgap_service.stop_airgap_scheduler()
        assert airgap_service._airgap_task is None
        with contextlib.suppress(asyncio.CancelledError):
            await task  # reap the cancelled loop (no pending-task warning)
        assert task.cancelled()
        # Stop again: no task, nothing to cancel.
        assert airgap_service.stop_airgap_scheduler() is None
    finally:
        airgap_service.stop_airgap_scheduler()


async def test_airgap_cycle_honors_enabled_flag(db, tmp_path):
    target = tmp_path / "cycle_drive"
    target.mkdir()

    # Disabled -> skipped cleanly, nothing written.
    _set_target(db, target, enabled=False)
    assert await airgap_service._airgap_cycle(db) is None
    assert not any(target.iterdir())

    # Enabled but untargeted -> skipped cleanly too.
    with db.transaction():
        db.set_setting(airgap_service.KEY_AIRGAP_ENABLED, "true")
        db.set_setting(airgap_service.KEY_AIRGAP_TARGET_DIR, "")
    assert await airgap_service._airgap_cycle(db) is None

    # Enabled + targeted -> full export -> verify -> drill chain.
    with db.transaction():
        db.set_setting(airgap_service.KEY_AIRGAP_TARGET_DIR, str(target))
    result = await airgap_service._airgap_cycle(db)
    assert result is not None
    assert result["export"]["ok"] is True, result["export"]["error"]
    assert result["verify"]["ok"] is True, result["verify"]
    assert result["drill"]["ok"] is True, result["drill"]
    assert any(p.name.startswith("ghostdrive-export-") for p in target.iterdir())
