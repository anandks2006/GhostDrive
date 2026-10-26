"""
tests/test_sync.py -- Real-time folder sync service and /api/sync routes.

Covers one reconciliation pass (first upload, unchanged, modify -> versioned +
re-upload, touch, local delete -> snapshot + Trash), the feedback-loop guard,
sync status shape, the scheduler lifecycle, and the router endpoints (status,
settings validation/clamping, run, start/stop, versions list/restore/prune).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import uuid
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ghostdrive.services import files as files_service
from ghostdrive.services import sync as sync_service
from ghostdrive.services import versions as versions_service
from ghostdrive.web.routes import sync as sync_routes
from ghostdrive.web.server import app as server_app
from ghostdrive.web.state import state

PASSPHRASE = "correct horse battery staple"


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def vault(tmp_path_factory):
    """Module-scoped unlocked vault.

    Sync uploads run through the real files service, which needs an open
    database and local backend -- unlocked once here via the real server app.
    """
    data_dir = tmp_path_factory.mktemp("ghostdrive_sync")
    state.clean_shutdown()
    state.app_data_dir = data_dir
    state.keystore_path = data_dir / "keystore.json"
    state.db_path = data_dir / "ghostdrive.db"

    client = TestClient(server_app)
    response = client.post("/api/auth/setup", json={"passphrase": PASSPHRASE})
    assert response.status_code == 200, response.text

    yield

    sync_service.stop_sync_scheduler()
    state.clean_shutdown()


@pytest.fixture
def sync_root(tmp_path) -> Path:
    root = tmp_path / "sync_root"
    root.mkdir()
    return root


@pytest.fixture
def sync_client(vault):
    """Local app carrying ONLY the sync router.

    The TestClient context manager is mandatory: without it every request gets
    a fresh event loop, so the scheduler task started by POST /start would be
    orphaned before GET /status could see it.
    """
    local_app = FastAPI()
    local_app.include_router(sync_routes.router)
    with TestClient(local_app) as client:
        try:
            yield client
        finally:
            client.post("/api/sync/stop")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _db():
    from ghostdrive.services.context import require_db

    return require_db()


def _reset_sync_settings(db) -> None:
    """Deterministic settings + empty detector state for one test."""
    db.set_setting(sync_service.SETTING_ENABLED, "false")
    db.set_setting(sync_service.SETTING_ROOT, "")
    db.set_setting(sync_service.SETTING_INTERVAL, "60")
    db.set_setting(sync_service.SETTING_ON_CHANGE, "true")
    db.set_setting(sync_service.SETTING_VERSION_KEEP, "10")
    db.set_setting(sync_service.SETTING_LAST_RUN_AT, "")
    db.set_setting(sync_service.SETTING_LAST_RESULT, "")
    db.set_setting(sync_service.SETTING_STATE, "")
    db.set_setting(sync_routes.VERSION_KEEP_SETTING, "10")


def _active_rows(db, vpath: str):
    """Active index rows at one virtual path, newest first (sync semantics)."""
    return db._conn.execute(
        """SELECT * FROM files
           WHERE path = ? AND tombstone = 0
           ORDER BY modified_at DESC, created_at DESC""",
        (vpath,),
    ).fetchall()


def _counters(result: dict) -> dict:
    return {key: result[key] for key in
            ("scanned", "uploaded", "unchanged", "versioned", "trashed")}


def _seed_history(source_dir: Path) -> str:
    """Two real generations of hist.txt, versioned and re-homed like sync."""
    db = _db()
    src = source_dir / "hist.txt"
    src.write_bytes(b"generation one")
    first = asyncio.run(
        files_service.upload_stream(src, "hist.txt", None, "IMPORTANT", "/")
    )
    asyncio.run(versions_service.snapshot_current_file(db, first["file_id"], reason="manual"))

    src.write_bytes(b"generation two -- with different content!")
    second = asyncio.run(
        files_service.upload_stream(src, "hist.txt", None, "IMPORTANT", "/")
    )
    with db.transaction():
        db.rehome_file_versions(first["file_id"], second["file_id"])
    asyncio.run(versions_service.snapshot_current_file(db, second["file_id"], reason="sync"))
    return second["file_id"]


# ── Contracts ─────────────────────────────────────────────────────────────────

def test_settings_keys_and_router_contract():
    assert sync_service.SETTING_ENABLED == "sync_enabled"
    assert sync_service.SETTING_ROOT == "sync_root"
    assert sync_service.SETTING_INTERVAL == "sync_interval_seconds"
    assert sync_service.SETTING_ON_CHANGE == "sync_on_change"
    assert sync_service.SETTING_VERSION_KEEP == "sync_version_keep"
    assert sync_routes.VERSION_KEEP_SETTING == "version_keep"

    assert sync_routes.router.prefix == "/api/sync"
    paths = {route.path for route in sync_routes.router.routes}
    assert {
        "/api/sync/status",
        "/api/sync/start",
        "/api/sync/stop",
        "/api/sync/run",
        "/api/sync/settings",
        "/api/sync/versions/{file_id}",
        "/api/sync/versions/{file_id}/restore",
        "/api/sync/versions/{file_id}/prune",
    } <= paths


# ── sync_status ───────────────────────────────────────────────────────────────

async def test_sync_status_defaults(vault):
    db = _db()
    _reset_sync_settings(db)
    sync_service.stop_sync_scheduler()

    status = sync_service.sync_status(db)
    assert status == {
        "enabled": False,
        "root": "",
        "interval_seconds": 60,
        "on_change": True,
        "running": False,
        "last_run_at": None,
        "last_result": None,
        "watched": False,
    }


# ── One reconciliation pass ───────────────────────────────────────────────────

async def test_first_pass_uploads_then_second_pass_is_unchanged(vault, sync_root):
    db = _db()
    _reset_sync_settings(db)
    (sync_root / "alpha.txt").write_bytes(b"alpha payload")
    (sync_root / "beta.txt").write_bytes(b"beta payload")
    nested = sync_root / "sub"
    nested.mkdir()
    (nested / "nested.txt").write_bytes(b"payload in a subdirectory")

    first = await sync_service.run_sync_pass(db, root=sync_root)
    assert first["errors"] == []
    assert _counters(first) == {
        "scanned": 3, "uploaded": 3, "unchanged": 0, "versioned": 0, "trashed": 0,
    }
    assert len(_active_rows(db, "/alpha.txt")) == 1
    assert len(_active_rows(db, "/sub/nested.txt")) == 1

    state_map = json.loads(db.get_setting(sync_service.SETTING_STATE, "{}"))
    assert set(state_map) == {"alpha.txt", "beta.txt", "sub/nested.txt"}
    assert db.get_setting(sync_service.SETTING_LAST_RUN_AT, "") != ""

    second = await sync_service.run_sync_pass(db, root=sync_root)
    assert second["errors"] == []
    assert _counters(second) == {
        "scanned": 3, "uploaded": 0, "unchanged": 3, "versioned": 0, "trashed": 0,
    }


async def test_modify_versions_old_content_then_uploads_new(vault, sync_root):
    db = _db()
    _reset_sync_settings(db)
    path = sync_root / "doc.txt"
    gen1 = b"first generation"
    gen2 = b"second generation -- now with substantially more bytes!"
    path.write_bytes(gen1)

    initial = await sync_service.run_sync_pass(db, root=sync_root)
    assert initial["uploaded"] == 1 and initial["versioned"] == 0

    path.write_bytes(gen2)
    result = await sync_service.run_sync_pass(db, root=sync_root)
    assert result["errors"] == []
    assert _counters(result) == {
        "scanned": 1, "uploaded": 1, "unchanged": 0, "versioned": 1, "trashed": 0,
    }

    rows = _active_rows(db, "/doc.txt")
    # A modify supersedes the row but never trashes it: both generations are live.
    assert len(rows) == 2
    # History follows the path: the fresh row carries the re-homed version.
    fresh = next(r for r in rows if db.latest_file_version(r["id"]) is not None)
    assert fresh["id"] == rows[0]["id"]  # newest row wins the path lookup
    assert fresh["size"] == len(gen2)
    assert rows[1]["id"] != fresh["id"]

    versions = db.list_file_versions(fresh["id"])
    assert [v["version"] for v in versions] == [1]
    assert versions[0]["reason"] == "sync"
    assert versions[0]["size"] == len(gen1)  # the OUTGOING bytes were preserved


async def test_touch_triggers_reupload_without_duplicate_content(vault, sync_root):
    db = _db()
    _reset_sync_settings(db)
    path = sync_root / "touch.txt"
    path.write_bytes(b"stable content")

    initial = await sync_service.run_sync_pass(db, root=sync_root)
    assert initial["uploaded"] == 1

    st = path.stat()
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 5_000_000_000))

    result = await sync_service.run_sync_pass(db, root=sync_root)
    assert result["errors"] == []
    assert result["uploaded"] == 1
    assert result["unchanged"] == 0
    # No previous version existed, so the snapshot before re-upload is v1.
    assert result["versioned"] == 1
    rows = _active_rows(db, "/touch.txt")
    assert len(rows) == 2


async def test_local_delete_snapshots_then_trashes(vault, sync_root):
    db = _db()
    _reset_sync_settings(db)
    path = sync_root / "gone.txt"
    path.write_bytes(b"bytes that malware will delete")

    initial = await sync_service.run_sync_pass(db, root=sync_root)
    assert initial["uploaded"] == 1
    live = _active_rows(db, "/gone.txt")[0]

    path.unlink()
    result = await sync_service.run_sync_pass(db, root=sync_root)
    assert result["errors"] == []
    assert _counters(result) == {
        "scanned": 0, "uploaded": 0, "unchanged": 0, "versioned": 1, "trashed": 1,
    }

    # The row is in Trash (tombstoned), not hard-deleted...
    tombstoned = {row["id"] for row in db.list_tombstoned_files()}
    assert live["id"] in tombstoned
    assert _active_rows(db, "/gone.txt") == []
    # ...its chunks are still resolvable, and the version preserved it.
    assert db.get_file_chunks(live["id"]) != []
    latest = db.latest_file_version(live["id"])
    assert latest is not None and latest["reason"] == "sync"
    assert json.loads(latest["manifest"]) != []


async def test_unconfigured_root_reports_error(vault):
    db = _db()
    _reset_sync_settings(db)
    result = await sync_service.run_sync_pass(db)  # root comes from settings
    assert result["scanned"] == 0 and result["uploaded"] == 0
    assert result["errors"] == ["Sync root is not configured."]


# ── Feedback-loop guard ───────────────────────────────────────────────────────

async def test_guard_refuses_app_data_as_root(vault):
    db = _db()
    _reset_sync_settings(db)
    result = await sync_service.run_sync_pass(db, root=Path(state.app_data_dir))
    assert result["uploaded"] == 0 and result["scanned"] == 0
    assert any("feedback-loop guard" in err for err in result["errors"])


async def test_guard_refuses_root_inside_app_data(vault):
    db = _db()
    _reset_sync_settings(db)
    inner = Path(state.app_data_dir) / "inner"
    result = await sync_service.run_sync_pass(db, root=inner)
    assert result["uploaded"] == 0 and result["scanned"] == 0
    assert any("feedback-loop guard" in err for err in result["errors"])


async def test_guard_refuses_root_containing_app_data(vault):
    db = _db()
    _reset_sync_settings(db)
    parent = Path(state.app_data_dir).parent
    result = await sync_service.run_sync_pass(db, root=parent)
    assert result["uploaded"] == 0 and result["scanned"] == 0
    assert any("feedback-loop guard" in err for err in result["errors"])


# ── Scheduler ─────────────────────────────────────────────────────────────────

async def test_scheduler_start_stop_and_double_start(vault):
    db = _db()
    _reset_sync_settings(db)
    assert sync_service.stop_sync_scheduler() is None  # nothing running yet

    try:
        task = sync_service.start_sync_scheduler(db)
        assert task is not None and not task.done()
        assert sync_service._scheduler_task is task
        # Double start is a no-op returning the same task.
        assert sync_service.start_sync_scheduler(db) is task
        assert sync_service.sync_status(db)["running"] is True

        sync_service.stop_sync_scheduler()
        assert sync_service._scheduler_task is None
        with contextlib.suppress(asyncio.CancelledError):
            await task  # reap the cancelled loop (no pending-task warning)
        assert task.cancelled()
        assert sync_service.sync_status(db)["running"] is False
    finally:
        sync_service.stop_sync_scheduler()


# ── /api/sync routes ──────────────────────────────────────────────────────────

def test_route_status_shape(sync_client):
    res = sync_client.get("/api/sync/status")
    assert res.status_code == 200, res.text
    data = res.json()
    assert set(data) == {
        "enabled", "root", "interval_seconds", "on_change", "running",
        "last_run_at", "last_result", "watched",
    }
    assert isinstance(data["running"], bool)


def test_route_settings_validate_and_clamp(sync_client, sync_root):
    db = _db()
    _reset_sync_settings(db)

    res = sync_client.post("/api/sync/settings", json={
        "root": str(sync_root),
        "interval_seconds": 5,
        "enabled": True,
        "on_change": False,
    })
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["root"] == str(Path(sync_root).resolve())
    assert data["interval_seconds"] == 15  # clamped to the scheduler floor
    assert data["enabled"] is True
    assert data["on_change"] is False
    assert data["watched"] is False  # enabled but not watching (on_change off)

    # A root that does not exist is rejected with 400.
    missing = Path(sync_root).parent / "does-not-exist"
    res = sync_client.post("/api/sync/settings", json={"root": str(missing)})
    assert res.status_code == 400
    assert "does not exist" in res.json()["detail"]


def test_route_run_executes_one_pass(sync_client, sync_root):
    db = _db()
    _reset_sync_settings(db)
    (sync_root / "route.txt").write_bytes(b"payload sent through the route")

    res = sync_client.post("/api/sync/settings", json={"root": str(sync_root)})
    assert res.status_code == 200, res.text

    res = sync_client.post("/api/sync/run")
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["scanned"] == 1 and data["uploaded"] == 1
    assert data["errors"] == []
    assert "duration_ms" in data

    status = sync_client.get("/api/sync/status").json()
    assert status["last_result"]["uploaded"] == 1
    assert status["last_run_at"]


def test_route_start_and_stop_scheduler(sync_client):
    db = _db()
    _reset_sync_settings(db)

    res = sync_client.post("/api/sync/start")
    assert res.status_code == 200, res.text
    assert res.json()["sync"]["running"] is True

    res = sync_client.post("/api/sync/start")  # idempotent
    assert res.status_code == 200
    assert res.json()["sync"]["running"] is True

    res = sync_client.post("/api/sync/stop")
    assert res.status_code == 200, res.text
    assert res.json()["sync"]["running"] is False
    assert sync_service._scheduler_task is None


def test_route_versions_list(sync_client, tmp_path):
    db = _db()
    _reset_sync_settings(db)
    file_id = _seed_history(tmp_path)

    res = sync_client.get(f"/api/sync/versions/{file_id}")
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["file_id"] == file_id
    versions = data["versions"]
    assert [v["version"] for v in versions] == [2, 1]
    assert {v["reason"] for v in versions} == {"sync", "manual"}
    for version in versions:
        assert set(version) >= {
            "id", "file_id", "version", "reason", "size", "blake3_hash",
            "manifest", "created_at", "unchanged",
        }
        assert isinstance(version["manifest"], list)
        assert version["manifest"] and {"chunk_id", "size"} <= set(version["manifest"][0])


def test_route_versions_unknown_file_404(sync_client):
    res = sync_client.get(f"/api/sync/versions/{uuid.uuid4()}")
    assert res.status_code == 404
    assert "not found" in res.json()["detail"]


def test_route_version_restore(sync_client, tmp_path):
    db = _db()
    _reset_sync_settings(db)
    file_id = _seed_history(tmp_path)

    res = sync_client.post(
        f"/api/sync/versions/{file_id}/restore", json={"version": 1}
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data == {
        "status": "success",
        "file_id": file_id,
        "restored_version": 1,
        "new_version": 3,
    }

    # Append-only history: the restore appended v3 instead of rewriting v1/v2.
    versions = sync_client.get(f"/api/sync/versions/{file_id}").json()["versions"]
    assert [v["version"] for v in versions] == [3, 2, 1]
    assert versions[0]["reason"] == "restore"
    assert versions[0]["manifest"] == versions[2]["manifest"]  # v3 mirrors v1


def test_route_version_restore_404s(sync_client, tmp_path):
    file_id = _seed_history(tmp_path)
    res = sync_client.post(
        f"/api/sync/versions/{file_id}/restore", json={"version": 99}
    )
    assert res.status_code == 404
    assert "Version 99" in res.json()["detail"]

    res = sync_client.post(
        f"/api/sync/versions/{uuid.uuid4()}/restore", json={"version": 1}
    )
    assert res.status_code == 404


def test_route_version_prune(sync_client, tmp_path):
    db = _db()
    _reset_sync_settings(db)
    file_id = _seed_history(tmp_path)

    # Default keep comes from the version_keep setting ("10") -> nothing goes.
    res = sync_client.post(f"/api/sync/versions/{file_id}/prune")
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["status"] == "success"
    assert data["file_id"] == file_id
    assert data["keep"] == 10 and data["removed"] == 0

    res = sync_client.post(
        f"/api/sync/versions/{file_id}/prune", json={"keep": 1}
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["keep"] == 1 and data["removed"] == 1

    versions = sync_client.get(f"/api/sync/versions/{file_id}").json()["versions"]
    assert [v["version"] for v in versions] == [2]  # oldest dropped, live kept
