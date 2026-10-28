"""tests/test_worm.py -- WORM / append-only backend enforcement (schema v15).

Covers the v15 schema (fresh install + the guarded-ALTER upgrade rung from
v14), the files-service guard helpers (WormViolationError, assert_backend_writable,
filter_deletable), end-to-end purge behaviour with and without the flag (bytes
retained on WORM, removed otherwise), the /api/backends routes that expose and
toggle the flag, and the retention dedup sweep skipping WORM copies.

Honest scope: WORM here is application-level enforcement, not hardware WORM;
a machine attacker with disk access can still delete files. Its purpose is to
stop accidents, ransomware-driven cleanup, and hostile insiders using the app
itself. WORM protects bytes, not the index.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ghostdrive.database.db import GhostDriveDB
from ghostdrive.database.schema import SCHEMA_VERSION
from ghostdrive.services import files as files_service
from ghostdrive.services import retention as retention_service
from ghostdrive.services.context import ensure_local_backend, require_db
from ghostdrive.web.server import app as server_app
from ghostdrive.web.state import state

PASSPHRASE = "correct horse battery staple"


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def vault(tmp_path_factory):
    """Module-scoped unlocked vault (same pattern as tests/test_sync.py).

    Needed by the end-to-end purge tests and the routes test; the schema and
    retention tests build their own standalone GhostDriveDB instances.
    """
    data_dir = tmp_path_factory.mktemp("ghostdrive_worm")
    state.clean_shutdown()
    state.app_data_dir = data_dir
    state.keystore_path = data_dir / "keystore.json"
    state.db_path = data_dir / "ghostdrive.db"

    client = TestClient(server_app)
    response = client.post("/api/auth/setup", json={"passphrase": PASSPHRASE})
    assert response.status_code == 200, response.text

    yield

    state.clean_shutdown()


def _db():
    return require_db()


def _make_db(tmp_path, name: str = "worm_standalone.db") -> GhostDriveDB:
    """Standalone unlocked DB for schema/migration/retention unit tests."""
    db = GhostDriveDB(tmp_path / name, os.urandom(32), os.urandom(32), os.urandom(32))
    db.open()
    return db


def _vault_dir() -> Path:
    return Path(state.app_data_dir) / "vault"


def _chunk_paths_for(db, file_id: str) -> list[Path]:
    """On-disk local-backend paths backing one file's confirmed locations."""
    paths = []
    for chunk in db.get_file_chunks(file_id):
        for loc in db.get_chunk_locations(chunk["id"]):
            if loc["status"] == "confirmed" and loc["reference_id"].startswith("local:"):
                paths.append(_vault_dir() / loc["reference_id"].split("local:", 1)[1])
    return paths


class _RecordingBackend:
    """Stub backend object recording delete() calls for the retention sweep."""

    def __init__(self) -> None:
        self.deleted: list[str] = []

    async def delete(self, reference_id: str) -> bool:
        self.deleted.append(reference_id)
        return True


def _seed_backend(db, backend_id: str, append_only: int = 0) -> None:
    with db.transaction():
        db._conn.execute(
            """INSERT INTO backends (id, type, credentials_ref, status, priority, append_only)
               VALUES (?, 'local_fs', 'scratch', 'healthy', 100, ?)""",
            (backend_id, append_only),
        )


def _seed_file_chunk(db) -> tuple[str, str]:
    """Minimal file + single-chunk rows; returns (file_id, chunk_id)."""
    file_id = str(uuid.uuid4())
    chunk_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    with db.transaction():
        db._conn.execute(
            """INSERT INTO files (id, name, path, size, mime_type, tier, created_at, modified_at)
               VALUES (?, 'ret.bin', '/ret.bin', 128, 'application/octet-stream', 'IMPORTANT', ?, ?)""",
            (file_id, now, now),
        )
        db._conn.execute(
            """INSERT INTO chunks (id, file_id, chunk_index, total_chunks, blake3_hash, size,
                                   nonce_counter, sub_block_count)
               VALUES (?, ?, 0, 1, ?, 128, 1, 1)""",
            (chunk_id, file_id, "0" * 64),
        )
    return file_id, chunk_id


def _seed_location(db, chunk_id: str, backend_id: str, upload_date: str) -> str:
    reference = f"ref-{backend_id[:8]}"
    with db.transaction():
        db._conn.execute(
            """INSERT INTO chunk_locations
               (chunk_id, sub_block_index, backend_id, reference_id, upload_date, status, quota_reserved)
               VALUES (?, 0, ?, ?, ?, 'confirmed', 0)""",
            (chunk_id, backend_id, reference, upload_date),
        )
    return reference


# ── 1-2. Schema: fresh install + migration rung ──────────────────────────────

def test_fresh_db_is_schema_v15_with_append_only(tmp_path):
    """Fresh installs carry the backends.append_only column at schema v15."""
    db = _make_db(tmp_path)
    try:
        cols = [r["name"] for r in db._conn.execute("PRAGMA table_info(backends)").fetchall()]
        assert "append_only" in cols
        version = db._conn.execute("SELECT version FROM schema_version").fetchone()["version"]
        assert version == SCHEMA_VERSION == 15

        # Idempotency: re-running the ladder on an up-to-date DB is a no-op.
        db._run_migrations()
        cols = [r["name"] for r in db._conn.execute("PRAGMA table_info(backends)").fetchall()]
        assert "append_only" in cols
        version = db._conn.execute("SELECT version FROM schema_version").fetchone()["version"]
        assert version == 15
    finally:
        db.close()


def test_v14_upgrade_run_adds_append_only(tmp_path):
    """A v14-shaped DB (no append_only column) gains it via the v15 rung.

    Simulated by rolling a fresh v15 DB back to the v14 shape (version stamp
    14, column dropped), then reopening through the normal GhostDriveDB path.
    The rollback goes through GhostDriveDB itself because the file may be
    SQLCipher-encrypted when sqlcipher3 is installed -- a raw sqlite3
    connection cannot read it.
    """
    path = tmp_path / "worm_upgrade.db"
    ledger_key, genesis_seed, master_key = os.urandom(32), os.urandom(32), os.urandom(32)
    db = GhostDriveDB(path, ledger_key, genesis_seed, master_key)
    db.open()
    db.close()

    # Roll back to the v14 shape using the same keys (same encryption).
    rolled = GhostDriveDB(path, ledger_key, genesis_seed, master_key)
    rolled.open()
    with rolled.transaction():
        rolled._conn.execute("ALTER TABLE backends DROP COLUMN append_only")
        rolled._conn.execute("UPDATE schema_version SET version = 14")
    cols = [r["name"] for r in rolled._conn.execute("PRAGMA table_info(backends)").fetchall()]
    assert "append_only" not in cols  # sanity: the rollback really removed it
    rolled.close()

    upgraded = GhostDriveDB(path, ledger_key, genesis_seed, master_key)
    upgraded.open()
    try:
        cols = [r["name"] for r in upgraded._conn.execute("PRAGMA table_info(backends)").fetchall()]
        assert "append_only" in cols
        version = upgraded._conn.execute("SELECT version FROM schema_version").fetchone()["version"]
        assert version == 15
        # Upgraded rows default to OFF: an upgrade never surprise-locks a vault
        # into refusing deletions.
        probe = str(uuid.uuid4())
        with upgraded.transaction():
            upgraded._conn.execute(
                "INSERT INTO backends (id, type, credentials_ref) VALUES (?, 'local_fs', 'scratch')",
                (probe,),
            )
        row = upgraded._conn.execute(
            "SELECT append_only FROM backends WHERE id = ?", (probe,)
        ).fetchone()
        assert row["append_only"] == 0
    finally:
        upgraded.close()


# ── 5. Guard helpers (unit) ───────────────────────────────────────────────────

def test_worm_guard_helpers(tmp_path):
    """assert_backend_writable / filter_deletable / WormViolationError."""
    db = _make_db(tmp_path, "worm_helpers.db")
    try:
        worm_id = str(uuid.uuid4())
        plain_id = str(uuid.uuid4())
        _seed_backend(db, worm_id, append_only=1)
        _seed_backend(db, plain_id, append_only=0)

        assert files_service.worm_backend_ids(db) == {worm_id}

        with pytest.raises(files_service.WormViolationError) as excinfo:
            files_service.assert_backend_writable(worm_id, "local:.abc_0000.gdc", db=db)
        assert excinfo.value.backend_id == worm_id
        assert excinfo.value.reference_id == "local:.abc_0000.gdc"
        assert "append-only" in str(excinfo.value)

        # Non-WORM backends pass silently.
        files_service.assert_backend_writable(plain_id, db=db)

        deletable, skipped = files_service.filter_deletable(
            [{"backend_id": worm_id, "reference_id": "r1"},
             {"backend_id": plain_id, "reference_id": "r2"}],
            db=db,
        )
        assert [loc["backend_id"] for loc in deletable] == [plain_id]
        assert [loc["backend_id"] for loc in skipped] == [worm_id]
    finally:
        db.close()


# ── 3-4. End-to-end purge: WORM retains bytes, default deletes them ──────────

def test_purge_retains_bytes_on_worm_backend(vault, tmp_path):
    """Tombstone + permanent purge on a WORM backend: bytes kept, index gone."""
    db = _db()
    backend_id = ensure_local_backend()
    with db.transaction():
        db._conn.execute("UPDATE backends SET append_only = 1 WHERE id = ?", (backend_id,))
    try:
        source = tmp_path / "worm_payload.bin"
        source.write_bytes(os.urandom(300_000))
        upload = asyncio.run(
            files_service.upload_stream(str(source), "worm_payload.bin", None, "IMPORTANT")
        )
        file_id = upload["file_id"]
        chunk_paths = _chunk_paths_for(db, file_id)
        assert chunk_paths and all(p.exists() for p in chunk_paths)

        # Tombstone (trash) is a metadata op -- always allowed, bytes untouched.
        tomb = asyncio.run(files_service.delete_file(file_id))
        assert tomb["status"] == "success"
        assert all(p.exists() for p in chunk_paths)

        # Permanent purge: metadata gone, WORM bytes retained and reported.
        purge = asyncio.run(files_service.delete_file(file_id, purge=True))
        assert purge["status"] == "success"
        assert purge["skipped_worm"] >= 1
        assert "retained" in purge["message"]
        assert db.get_file(file_id) is None  # index purged...
        assert all(p.exists() for p in chunk_paths)  # ...bytes retained (WORM)
    finally:
        with db.transaction():
            db._conn.execute("UPDATE backends SET append_only = 0 WHERE id = ?", (backend_id,))


def test_purge_removes_bytes_without_worm_flag(vault, tmp_path):
    """Control case: the default (append_only=0) backend does lose its bytes."""
    db = _db()
    backend_id = ensure_local_backend()
    assert db.get_backend(backend_id)["append_only"] == 0  # opt-in, not default

    source = tmp_path / "plain_payload.bin"
    source.write_bytes(os.urandom(137_001))
    upload = asyncio.run(
        files_service.upload_stream(str(source), "plain_payload.bin", None, "IMPORTANT")
    )
    file_id = upload["file_id"]
    chunk_paths = _chunk_paths_for(db, file_id)
    assert chunk_paths and all(p.exists() for p in chunk_paths)

    purge = asyncio.run(files_service.delete_file(file_id, purge=True))
    assert purge["skipped_worm"] == 0
    assert db.get_file(file_id) is None
    assert all(not p.exists() for p in chunk_paths)


# ── 6. Routes: create with flag, list shows it, dedicated toggle flips it ────

def test_routes_create_list_and_toggle_worm(vault, tmp_path):
    """POST /save (append_only field), GET /list (flag exposed), POST /{id}/worm."""
    local_app = FastAPI()
    from ghostdrive.web.routes import backends as backends_routes

    local_app.include_router(backends_routes.router)
    worm_id = None
    with TestClient(local_app) as client:
        saved = client.post(
            "/api/backends/save",
            json={
                "provider": "local",
                "name": "WORM test vault",
                "tier": "LOCAL_LOCKER",
                "enabled": True,
                "credentials": {"path": str(tmp_path / "worm_route_vault")},
                "append_only": True,
            },
        )
        assert saved.status_code == 200, saved.text
        worm_id = saved.json()["backend_id"]
        assert saved.json()["append_only"] is True

        try:
            listing = client.get("/api/backends/list")
            assert listing.status_code == 200
            entry = next(b for b in listing.json()["configured_backends"] if b["id"] == worm_id)
            assert entry["append_only"] is True

            # Dedicated toggle route flips it OFF...
            toggled = client.post(f"/api/backends/{worm_id}/worm", json={"enabled": False})
            assert toggled.status_code == 200, toggled.text
            assert toggled.json()["append_only"] is False
            entry = next(
                b for b in client.get("/api/backends/list").json()["configured_backends"]
                if b["id"] == worm_id
            )
            assert entry["append_only"] is False

            # ...and back ON.
            toggled = client.post(f"/api/backends/{worm_id}/worm", json={"enabled": True})
            assert toggled.status_code == 200
            assert toggled.json()["append_only"] is True

            # Unknown backend -> 404.
            missing = client.post(f"/api/backends/{uuid.uuid4()}/worm", json={"enabled": True})
            assert missing.status_code == 404
        finally:
            removed = client.delete(f"/api/backends/remove/{worm_id}", params={"force": True})
            if removed.status_code != 200:
                # Best-effort direct cleanup so a route failure cannot leak a
                # WORM-flagged backend into the rest of the module vault.
                db = _db()
                with db.transaction():
                    db._conn.execute("DELETE FROM drive_registry WHERE backend_id = ?", (worm_id,))
                    db._conn.execute("DELETE FROM backends WHERE id = ?", (worm_id,))
                db.set_setting(f"backend_label_{worm_id}", "")


# ── 7. Retention sweep: WORM copies are never deleted ────────────────────────

def test_retention_dedup_skips_worm_loser(tmp_path):
    """A losing duplicate copy on a WORM backend keeps bytes AND index row."""
    db = _make_db(tmp_path, "worm_retention_skip.db")
    try:
        worm_id = str(uuid.uuid4())
        plain_id = str(uuid.uuid4())
        _seed_backend(db, worm_id, append_only=1)
        _seed_backend(db, plain_id, append_only=0)
        _file_id, chunk_id = _seed_file_chunk(db)

        base = datetime.now(timezone.utc)
        # WORM copy is OLDER -> the plain copy wins -> WORM copy is the loser.
        _seed_location(db, chunk_id, worm_id, base.isoformat())
        dup_ref = _seed_location(
            db, chunk_id, plain_id, (base + timedelta(hours=1)).isoformat()
        )

        worm_stub = _RecordingBackend()
        plain_stub = _RecordingBackend()
        objects = {worm_id: worm_stub, plain_id: plain_stub}
        res = asyncio.run(
            retention_service.deduplicate_confirmed_locations(db, objects)
        )
        assert res.get("skipped_worm", 0) == 1
        assert res["removed"] == 0
        assert worm_stub.deleted == []  # bytes never touched
        assert plain_stub.deleted == []  # winner's copy stays too
        # Index row for the retained copy is kept, so a post-WORM cleanup can
        # still find the bytes.
        backends = {
            r["backend_id"]
            for r in db.get_chunk_locations(chunk_id)
            if r["status"] == "confirmed"
        }
        assert backends == {worm_id, plain_id}
        assert dup_ref  # referenced only to keep the seed explicit
    finally:
        db.close()


def test_retention_dedup_still_deletes_non_worm_loser(tmp_path):
    """Control: a losing duplicate on a NORMAL backend is deleted remotely."""
    db = _make_db(tmp_path, "worm_retention_control.db")
    try:
        worm_id = str(uuid.uuid4())
        plain_id = str(uuid.uuid4())
        _seed_backend(db, worm_id, append_only=1)
        _seed_backend(db, plain_id, append_only=0)
        _file_id, chunk_id = _seed_file_chunk(db)

        base = datetime.now(timezone.utc)
        # WORM copy is NEWER -> wins; plain copy loses and IS deleted.
        _seed_location(
            db, chunk_id, worm_id, (base + timedelta(hours=1)).isoformat()
        )
        dup_ref = _seed_location(db, chunk_id, plain_id, base.isoformat())

        worm_stub = _RecordingBackend()
        plain_stub = _RecordingBackend()
        objects = {worm_id: worm_stub, plain_id: plain_stub}
        res = asyncio.run(
            retention_service.deduplicate_confirmed_locations(db, objects)
        )
        assert res.get("skipped_worm", 0) == 0
        assert res["removed"] == 1
        assert plain_stub.deleted == [dup_ref]
        assert worm_stub.deleted == []
        backends = {
            r["backend_id"]
            for r in db.get_chunk_locations(chunk_id)
            if r["status"] == "confirmed"
        }
        assert backends == {worm_id}
    finally:
        db.close()
