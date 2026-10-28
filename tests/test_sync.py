"""
tests/test_sync.py -- Multi-folder auto-vault service and /api/sync routes.

Covers per-root reconciliation (first upload, unchanged, modify -> versioned +
re-upload, touch, local delete -> snapshot + Trash), root slugs (stable
per-folder vault namespaces), multi-root isolation (independent state, same
filename in two folders stays distinct, deletion in one folder never trashes
another's rows, a bad root does not block the others), legacy single-root
compat (sync_root fallback + flat detector-state migration), the
feedback-loop guard, sync status shape, the scheduler lifecycle, and the
router endpoints (status, settings validation/clamping incl. the roots list,
run, start/stop, versions list/restore/prune).
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
    db.set_setting(sync_service.SETTING_ROOTS, "[]")
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


def _vp(root: Path, rel: str = "") -> str:
    """Vault path of a file under one sync root's namespace (per-root slug)."""
    slug = sync_service.root_slug(root)
    return f"/{slug}/{rel}" if rel else f"/{slug}"


def _state_roots(db) -> dict:
    """Detector state: {slug: {rel: fingerprint}} (current persisted format)."""
    data = json.loads(db.get_setting(sync_service.SETTING_STATE, "{}") or "{}")
    assert data.get("v") == sync_service.STATE_VERSION
    return data["roots"]


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
    assert sync_service.SETTING_ROOTS == "sync_roots"
    assert sync_service.STATE_VERSION == 2
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
        "roots": [],
        "root_details": [],
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
    assert len(_active_rows(db, _vp(sync_root, "alpha.txt"))) == 1
    assert len(_active_rows(db, _vp(sync_root, "sub/nested.txt"))) == 1

    # Each root owns a namespace: files land under /<slug>/..., state keyed by slug.
    assert first["per_root"][0]["slug"] == sync_service.root_slug(sync_root)
    state_map = _state_roots(db)
    assert set(state_map) == {sync_service.root_slug(sync_root)}
    assert set(state_map[sync_service.root_slug(sync_root)]) == {
        "alpha.txt", "beta.txt", "sub/nested.txt",
    }
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

    rows = _active_rows(db, _vp(sync_root, "doc.txt"))
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
    rows = _active_rows(db, _vp(sync_root, "touch.txt"))
    assert len(rows) == 2


async def test_local_delete_snapshots_then_trashes(vault, sync_root):
    db = _db()
    _reset_sync_settings(db)
    path = sync_root / "gone.txt"
    path.write_bytes(b"bytes that malware will delete")

    initial = await sync_service.run_sync_pass(db, root=sync_root)
    assert initial["uploaded"] == 1
    live = _active_rows(db, _vp(sync_root, "gone.txt"))[0]

    path.unlink()
    result = await sync_service.run_sync_pass(db, root=sync_root)
    assert result["errors"] == []
    assert _counters(result) == {
        "scanned": 0, "uploaded": 0, "unchanged": 0, "versioned": 1, "trashed": 1,
    }

    # The row is in Trash (tombstoned), not hard-deleted...
    tombstoned = {row["id"] for row in db.list_tombstoned_files()}
    assert live["id"] in tombstoned
    assert _active_rows(db, _vp(sync_root, "gone.txt")) == []
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
        "enabled", "root", "roots", "root_details", "interval_seconds",
        "on_change", "running", "last_run_at", "last_result", "watched",
    }
    assert isinstance(data["running"], bool)
    assert data["roots"] == [] and data["root"] == ""
    assert data["root_details"] == []


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
    assert data["roots"] == [str(Path(sync_root).resolve())]  # legacy field feeds the list
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


# ── Root slugs (per-folder vault namespaces) ──────────────────────────────────

def test_root_slug_is_stable_per_path(tmp_path):
    docs_a = tmp_path / "one" / "Docs"
    docs_b = tmp_path / "two" / "Docs"
    docs_a.mkdir(parents=True)
    docs_b.mkdir(parents=True)

    slug_a = sync_service.root_slug(docs_a)
    # Readable prefix + 8 hex chars of path digest.
    assert slug_a.startswith("Docs-") and len(slug_a) == len("Docs-") + 8
    # Deterministic: any spelling of the same path maps to the same slug...
    assert sync_service.root_slug(str(docs_a)) == slug_a
    assert sync_service.root_slug(Path(str(docs_a) + os.sep)) == slug_a
    if os.name == "nt":
        assert sync_service.root_slug(str(docs_a).upper()) == slug_a
    # ...but the same folder NAME on another path gets its own namespace, so
    # C:\Docs and D:\Docs can be watched side by side without colliding.
    assert sync_service.root_slug(docs_b) != slug_a
    # The slug depends only on this path -- re-running (i.e. any other roots
    # coming and going) can never change it.
    assert sync_service.root_slug(docs_a) == slug_a


def test_root_slug_drive_root_falls_back_to_drive_prefix():
    slug = sync_service.root_slug(Path("/"))
    assert slug.startswith("drive-") and len(slug) == len("drive-") + 8


# ── Multi-folder auto-vault (service) ─────────────────────────────────────────

@pytest.fixture
def root_a(tmp_path) -> Path:
    path = tmp_path / "folder_a"
    path.mkdir()
    return path


@pytest.fixture
def root_b(tmp_path) -> Path:
    path = tmp_path / "folder_b"
    path.mkdir()
    return path


async def test_two_roots_sync_independently(vault, root_a, root_b):
    db = _db()
    _reset_sync_settings(db)
    (root_a / "a.txt").write_bytes(b"content from folder a")
    (root_b / "b.txt").write_bytes(b"content from folder b")
    sync_service.set_sync_roots(db, [str(root_a), str(root_b)])

    result = await sync_service.run_sync_pass(db)  # config-driven: all roots
    assert result["errors"] == []
    assert _counters(result) == {
        "scanned": 2, "uploaded": 2, "unchanged": 0, "versioned": 0, "trashed": 0,
    }
    assert [entry["root"] for entry in result["per_root"]] == [
        str(root_a), str(root_b),
    ]

    slug_a = sync_service.root_slug(root_a)
    slug_b = sync_service.root_slug(root_b)
    assert len(_active_rows(db, f"/{slug_a}/a.txt")) == 1
    assert len(_active_rows(db, f"/{slug_b}/b.txt")) == 1

    # Detector state is namespaced per root -- no shared key space.
    state_map = _state_roots(db)
    assert set(state_map) == {slug_a, slug_b}
    assert set(state_map[slug_a]) == {"a.txt"}
    assert set(state_map[slug_b]) == {"b.txt"}

    status = sync_service.sync_status(db)
    assert status["roots"] == [str(root_a), str(root_b)]
    assert status["root"] == str(root_a)
    assert [d["tracked"] for d in status["root_details"]] == [1, 1]


async def test_same_filename_in_two_roots_stays_distinct(vault, root_a, root_b):
    db = _db()
    _reset_sync_settings(db)
    content_a = b"folder a copy of the shared file"
    content_b = b"folder B copy -- deliberately different and longer!"
    (root_a / "shared.txt").write_bytes(content_a)
    (root_b / "shared.txt").write_bytes(content_b)
    sync_service.set_sync_roots(db, [str(root_a), str(root_b)])

    first = await sync_service.run_sync_pass(db)
    assert first["uploaded"] == 2
    rows_a = _active_rows(db, _vp(root_a, "shared.txt"))
    rows_b = _active_rows(db, _vp(root_b, "shared.txt"))
    assert len(rows_a) == 1 and len(rows_b) == 1
    assert rows_a[0]["id"] != rows_b[0]["id"]
    assert rows_a[0]["size"] == len(content_a)
    assert rows_b[0]["size"] == len(content_b)
    untouched_b = rows_b[0]["id"]

    # Editing folder A's copy versions/supersedes ONLY A's row.
    (root_a / "shared.txt").write_bytes(b"folder a copy -- EDITED and now grown in size")
    second = await sync_service.run_sync_pass(db)
    assert second["errors"] == []
    assert _counters(second) == {
        "scanned": 2, "uploaded": 1, "unchanged": 1, "versioned": 1, "trashed": 0,
    }
    assert len(_active_rows(db, _vp(root_a, "shared.txt"))) == 2  # fresh + superseded
    rows_b_after = _active_rows(db, _vp(root_b, "shared.txt"))
    assert len(rows_b_after) == 1 and rows_b_after[0]["id"] == untouched_b


async def test_delete_from_one_root_never_trashes_another(vault, root_a, root_b):
    db = _db()
    _reset_sync_settings(db)
    (root_a / "shared.txt").write_bytes(b"folder a keeps this file until deleted")
    (root_b / "shared.txt").write_bytes(b"folder b has an identically named file")
    sync_service.set_sync_roots(db, [str(root_a), str(root_b)])
    assert (await sync_service.run_sync_pass(db))["uploaded"] == 2
    survivor = _active_rows(db, _vp(root_b, "shared.txt"))[0]["id"]

    (root_a / "shared.txt").unlink()  # only folder A's copy disappears
    result = await sync_service.run_sync_pass(db)
    assert result["errors"] == []
    assert _counters(result) == {
        "scanned": 1, "uploaded": 0, "unchanged": 1, "versioned": 1, "trashed": 1,
    }
    assert [entry["trashed"] for entry in result["per_root"]] == [1, 0]

    # A's row went to Trash (snapshot first)...
    assert _active_rows(db, _vp(root_a, "shared.txt")) == []
    # ...B's identically named row is untouched and still active.
    rows_b = _active_rows(db, _vp(root_b, "shared.txt"))
    assert len(rows_b) == 1 and rows_b[0]["id"] == survivor
    assert survivor not in {row["id"] for row in db.list_tombstoned_files()}


async def test_bad_root_is_isolated_while_other_roots_sync(vault, root_a):
    db = _db()
    _reset_sync_settings(db)
    (root_a / "good.txt").write_bytes(b"the healthy folder still syncs")
    bad = Path(state.app_data_dir)
    sync_service.set_sync_roots(db, [str(bad), str(root_a)])

    result = await sync_service.run_sync_pass(db)
    assert result["uploaded"] == 1
    assert any("feedback-loop guard" in err for err in result["errors"])

    bad_entry, good_entry = result["per_root"]
    assert bad_entry["slug"] == sync_service.root_slug(bad)
    assert bad_entry["scanned"] == 0 and bad_entry["uploaded"] == 0
    assert any("feedback-loop guard" in err for err in bad_entry["errors"])
    assert good_entry["errors"] == [] and good_entry["uploaded"] == 1
    assert len(_active_rows(db, _vp(root_a, "good.txt"))) == 1


async def test_legacy_single_root_setting_still_drives_pass(vault, sync_root):
    """Pre-multi-folder configs (only sync_root set) keep working unmodified."""
    db = _db()
    _reset_sync_settings(db)
    (sync_root / "legacy.txt").write_bytes(b"configured the old way")
    db.set_setting(sync_service.SETTING_ROOT, str(sync_root))  # sync_roots stays "[]"

    assert sync_service.get_sync_roots(db) == [str(sync_root)]
    result = await sync_service.run_sync_pass(db)
    assert result["errors"] == []
    assert result["uploaded"] == 1
    assert result["per_root"][0]["root"] == str(sync_root)
    assert sync_service.sync_status(db)["roots"] == [str(sync_root)]


async def test_legacy_flat_detector_state_migrates_to_slug(vault, sync_root):
    """The single-root flat state map re-homes under the root's slug instead
    of forcing a full re-upload after the multi-folder upgrade."""
    db = _db()
    _reset_sync_settings(db)
    (sync_root / "old.txt").write_bytes(b"content from the single-root era")
    first = await sync_service.run_sync_pass(db, root=sync_root)
    assert first["uploaded"] == 1

    slug = sync_service.root_slug(sync_root)
    flat = _state_roots(db)[slug]                                 # current format...
    db.set_setting(sync_service.SETTING_STATE, json.dumps(flat))  # ...rewritten legacy
    db.set_setting(sync_service.SETTING_ROOT, str(sync_root))

    second = await sync_service.run_sync_pass(db)  # config-driven, no explicit root
    assert second["errors"] == []
    assert _counters(second) == {
        "scanned": 1, "uploaded": 0, "unchanged": 1, "versioned": 0, "trashed": 0,
    }
    # The pass persisted the current format again, under the same slug.
    assert set(_state_roots(db)) == {slug}


# ── Multi-folder /api/sync routes ─────────────────────────────────────────────

def test_route_roots_list_roundtrip(sync_client, tmp_path):
    db = _db()
    _reset_sync_settings(db)
    folder_a = tmp_path / "list_a"
    folder_b = tmp_path / "list_b"
    folder_a.mkdir()
    folder_b.mkdir()

    res = sync_client.post("/api/sync/settings", json={
        "roots": [str(folder_a), str(folder_b)],
    })
    assert res.status_code == 200, res.text
    data = res.json()
    expected = [str(folder_a.resolve()), str(folder_b.resolve())]
    assert data["roots"] == expected
    assert data["root"] == expected[0]  # legacy mirror = first entry
    assert [detail["path"] for detail in data["root_details"]] == expected
    assert [detail["tracked"] for detail in data["root_details"]] == [0, 0]

    status = sync_client.get("/api/sync/status").json()
    assert status["roots"] == expected
    assert sync_service.get_sync_roots(db) == expected

    # The same folder listed twice is stored once (deduplicated).
    res = sync_client.post("/api/sync/settings", json={
        "roots": [str(folder_a), str(folder_a)],
    })
    assert res.json()["roots"] == [str(folder_a.resolve())]


def test_route_roots_validates_every_entry(sync_client, tmp_path):
    db = _db()
    _reset_sync_settings(db)
    good = tmp_path / "good"
    good.mkdir()
    missing = tmp_path / "missing"

    # One bad entry rejects the whole list before anything is persisted.
    res = sync_client.post("/api/sync/settings", json={
        "roots": [str(good), str(missing)],
    })
    assert res.status_code == 400
    assert "does not exist" in res.json()["detail"]
    assert sync_service.get_sync_roots(db) == []

    # Feedback-loop guard applies per entry at configuration time.
    res = sync_client.post("/api/sync/settings", json={
        "roots": [str(Path(state.app_data_dir))],
    })
    assert res.status_code == 400
    assert "feedback-loop guard" in res.json()["detail"]

    res = sync_client.post("/api/sync/settings", json={"roots": ["   "]})
    assert res.status_code == 400
    assert "empty" in res.json()["detail"]


def test_route_run_syncs_every_configured_root(sync_client, tmp_path):
    db = _db()
    _reset_sync_settings(db)
    folder_a = tmp_path / "run_a"
    folder_b = tmp_path / "run_b"
    folder_a.mkdir()
    folder_b.mkdir()
    (folder_a / "one.txt").write_bytes(b"payload from the first folder")
    (folder_b / "two.txt").write_bytes(b"payload from the second folder")

    res = sync_client.post("/api/sync/settings", json={
        "roots": [str(folder_a), str(folder_b)],
    })
    assert res.status_code == 200, res.text

    res = sync_client.post("/api/sync/run")
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["scanned"] == 2 and data["uploaded"] == 2
    assert data["errors"] == []
    assert len(data["per_root"]) == 2
    assert [entry["uploaded"] for entry in data["per_root"]] == [1, 1]
    assert len(_active_rows(db, _vp(folder_a, "one.txt"))) == 1
    assert len(_active_rows(db, _vp(folder_b, "two.txt"))) == 1


def test_route_removing_root_keeps_vault_rows(sync_client, tmp_path):
    db = _db()
    _reset_sync_settings(db)
    folder_a = tmp_path / "keep_a"
    folder_b = tmp_path / "keep_b"
    folder_a.mkdir()
    folder_b.mkdir()
    (folder_a / "one.txt").write_bytes(b"folder a payload")
    (folder_b / "two.txt").write_bytes(b"folder b payload")

    sync_client.post("/api/sync/settings", json={
        "roots": [str(folder_a), str(folder_b)],
    })
    assert sync_client.post("/api/sync/run").json()["uploaded"] == 2

    # Removing a folder from the config stops watching it -- it does NOT
    # delete or trash what was already vaulted from it.
    res = sync_client.post("/api/sync/settings", json={"roots": [str(folder_b)]})
    assert res.json()["roots"] == [str(folder_b.resolve())]

    data = sync_client.post("/api/sync/run").json()
    assert _counters(data) == {
        "scanned": 1, "uploaded": 0, "unchanged": 1, "versioned": 0, "trashed": 0,
    }
    assert len(_active_rows(db, _vp(folder_a, "one.txt"))) == 1
    assert len(_active_rows(db, _vp(folder_b, "two.txt"))) == 1
