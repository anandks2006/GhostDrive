"""
tests/test_versions.py -- File version history service.

Covers snapshot idempotence, content-change versioning, restore (append-only
history + chunk-set swap with rollback on pruned chunks), prune (keeps newest
K, never the live version), and the v13 -> v14 schema migration.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from ghostdrive.crypto.nonce import NonceManager
from ghostdrive.database.db import GhostDriveDB
from ghostdrive.pipeline.chunker import split_file
from ghostdrive.pipeline.upload import ChunkUploader
from ghostdrive.services.versions import (
    prune_versions,
    restore_version,
    snapshot_current_file,
)

CHUNK_BYTES = 1024 * 1024


# ── Helpers (DB + mock-backend upload harness, mirrored from
#    tests/test_durability.py and tests/test_pipeline.py) ─────────────────────

def _make_db(tmp_path: Path) -> GhostDriveDB:
    db = GhostDriveDB(
        path=tmp_path / "versions.db",
        ledger_key=bytes(range(32)),
        genesis_seed=bytes(range(32, 64)),
        master_key=bytes(range(32)),
    )
    db.open()
    return db


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_backend_row(db, quota_limit=1024 * 1024 * 1024) -> str:
    bid = str(uuid.uuid4())
    db._conn.execute("BEGIN")
    db._conn.execute(
        """INSERT INTO backends
           (id, type, credentials_ref, status, priority, quota_used, quota_limit, quota_reserved)
           VALUES (?, 'telegram', 'ref:test', 'healthy', 1, 0, ?, 0)""",
        (bid, quota_limit),
    )
    db._conn.execute("COMMIT")
    return bid


async def _upload_generation(
    db: GhostDriveDB,
    nonce_manager: NonceManager,
    tmp_path: Path,
    content: bytes,
    *,
    name: str = "f.txt",
    path: str = "/f.txt",
    tier: str = "DISPOSABLE",
) -> str:
    """Create one file row and fill it with real chunks via a mock backend.

    Mirrors tests/test_pipeline.py's ChunkUploader harness so version tests
    run against index state produced by the actual pipeline.
    """
    src = tmp_path / f"{uuid.uuid4()}.bin"
    src.write_bytes(content)

    file_id = str(uuid.uuid4())
    now = _now()
    with db.transaction():
        db.insert_file({
            "id": file_id, "name": name, "path": path,
            "size": len(content), "mime_type": "text/plain", "tier": tier,
            "created_at": now, "modified_at": now,
            "version": 1, "version_of": None,
            "tombstone": 0, "tombstone_at": None,
        })

    backend_id = _make_backend_row(db)
    mock_backend = MagicMock()
    mock_backend.id = backend_id
    mock_backend.upload = AsyncMock(return_value=f"ref-{backend_id[:8]}")

    uploader = ChunkUploader(
        db=db,
        backend=mock_backend,
        master_key=bytes(range(32)),
        hkdf_salt=bytes(range(32, 64)),
        nonce_manager=nonce_manager,
    )
    for descriptor in split_file(src, CHUNK_BYTES):
        await uploader.upload_chunk(
            path=src, descriptor=descriptor, file_id=file_id, mime_type="text/plain"
        )
    return file_id


def _chunk_ids(db, file_id: str) -> list[str]:
    return [row["id"] for row in db.get_file_chunks(file_id)]


@pytest.fixture
def nonce_manager(tmp_path) -> NonceManager:
    return NonceManager(data_dir=tmp_path)


# ── snapshot_current_file ─────────────────────────────────────────────────────

class TestSnapshot:
    async def test_snapshot_records_first_version(self, tmp_path, nonce_manager):
        db = _make_db(tmp_path)
        try:
            file_id = await _upload_generation(db, nonce_manager, tmp_path, b"hello world")
            result = await snapshot_current_file(db, file_id, reason="manual")
            assert result["version"] == 1
            assert result["reason"] == "manual"
            assert result["unchanged"] is False
            assert result["size"] == len(b"hello world")
            # Manifest mirrors the live ordered chunk list.
            assert [m["chunk_id"] for m in result["manifest"]] == _chunk_ids(db, file_id)
            assert len(db.list_file_versions(file_id)) == 1
        finally:
            db.close()

    async def test_second_snapshot_is_unchanged(self, tmp_path, nonce_manager):
        db = _make_db(tmp_path)
        try:
            file_id = await _upload_generation(db, nonce_manager, tmp_path, b"stable bytes")
            first = await snapshot_current_file(db, file_id)
            second = await snapshot_current_file(db, file_id)
            assert second["unchanged"] is True
            assert second["id"] == first["id"]
            assert second["version"] == 1
            assert len(db.list_file_versions(file_id)) == 1  # no duplicate v2
        finally:
            db.close()

    async def test_content_change_creates_v2(self, tmp_path, nonce_manager):
        db = _make_db(tmp_path)
        try:
            gen1 = await _upload_generation(db, nonce_manager, tmp_path, b"first generation")
            v1 = await snapshot_current_file(db, gen1)
            # A content change lands on a fresh row (sync re-upload) and the
            # history is re-homed onto it, exactly like services/sync.py does.
            gen2 = await _upload_generation(
                db, nonce_manager, tmp_path, b"second generation, different!"
            )
            with db.transaction():
                db.rehome_file_versions(gen1, gen2)
            v2 = await snapshot_current_file(db, gen2, reason="sync")
            assert v2["version"] == 2
            assert v2["unchanged"] is False
            assert v2["blake3_hash"] != v1["blake3_hash"]
            versions = db.list_file_versions(gen2)
            assert [row["version"] for row in versions] == [2, 1]
        finally:
            db.close()

    async def test_snapshot_missing_file_raises(self, tmp_path):
        db = _make_db(tmp_path)
        try:
            with pytest.raises(FileNotFoundError):
                await snapshot_current_file(db, str(uuid.uuid4()))
        finally:
            db.close()

    async def test_snapshot_invalid_reason_raises(self, tmp_path, nonce_manager):
        db = _make_db(tmp_path)
        try:
            file_id = await _upload_generation(db, nonce_manager, tmp_path, b"x")
            with pytest.raises(ValueError):
                await snapshot_current_file(db, file_id, reason="bogus")
        finally:
            db.close()

    async def test_snapshot_file_without_chunks_raises(self, tmp_path):
        db = _make_db(tmp_path)
        try:
            file_id = str(uuid.uuid4())
            now = _now()
            with db.transaction():
                db.insert_file({
                    "id": file_id, "name": "empty.bin", "path": "/empty.bin",
                    "size": 0, "mime_type": "", "tier": "IMPORTANT",
                    "created_at": now, "modified_at": now,
                    "version": 1, "version_of": None,
                    "tombstone": 0, "tombstone_at": None,
                })
            with pytest.raises(RuntimeError, match="no stored chunks"):
                await snapshot_current_file(db, file_id)
        finally:
            db.close()


# ── Shared two-generation history fixture ─────────────────────────────────────

@pytest.fixture
async def history(tmp_path, nonce_manager):
    """gen1 (v1) superseded by gen2 (v2, live); history re-homed like sync."""
    db = _make_db(tmp_path)
    gen1 = await _upload_generation(db, nonce_manager, tmp_path, b"generation one payload")
    v1 = await snapshot_current_file(db, gen1, reason="manual")
    gen2 = await _upload_generation(
        db, nonce_manager, tmp_path, b"generation two payload -- longer!"
    )
    with db.transaction():
        db.rehome_file_versions(gen1, gen2)
    v2 = await snapshot_current_file(db, gen2, reason="sync")
    yield SimpleNamespace(
        db=db, gen1=gen1, gen2=gen2, v1=v1, v2=v2,
        nonce_manager=nonce_manager, tmp_path=tmp_path,
    )
    db.close()


# ── restore_version ───────────────────────────────────────────────────────────

class TestRestore:
    async def test_restore_repoints_file_and_appends_restore_version(self, history):
        db, gen1, gen2 = history.db, history.gen1, history.gen2
        gen2_chunk_ids = _chunk_ids(db, gen2)
        gen1_chunk_ids = _chunk_ids(db, gen1)

        result = await restore_version(db, gen2, 1)
        assert result == {
            "file_id": gen2,
            "restored_version": 1,
            "new_version": 3,
        }

        # The live file now replays v1's exact ordered chunk set.
        assert _chunk_ids(db, gen2) == [
            m["chunk_id"] for m in history.v1["manifest"]
        ]
        assert _chunk_ids(db, gen2) == gen1_chunk_ids
        assert db.get_file(gen2)["size"] == history.v1["size"]

        # The pre-restore generation is parked (still resolvable) on gen1's row.
        assert set(_chunk_ids(db, gen1)) == set(gen2_chunk_ids)

        # History is append-only: v1 and v2 untouched, v3 records the restore.
        versions = db.list_file_versions(gen2)
        assert [row["version"] for row in versions] == [3, 2, 1]
        assert versions[0]["reason"] == "restore"
        assert json.loads(versions[0]["manifest"]) == history.v1["manifest"]
        assert db.get_file_version(gen2, 1)["reason"] == "manual"
        assert db.get_file_version(gen2, 2)["reason"] == "sync"

    async def test_restore_missing_file_raises(self, tmp_path):
        db = _make_db(tmp_path)
        try:
            with pytest.raises(FileNotFoundError, match="not found"):
                await restore_version(db, str(uuid.uuid4()), 1)
        finally:
            db.close()

    async def test_restore_missing_version_raises(self, history):
        with pytest.raises(FileNotFoundError, match="Version 99"):
            await restore_version(history.db, history.gen2, 99)

    async def test_restore_with_pruned_chunk_raises_and_rolls_back(self, history):
        db, gen1, gen2 = history.db, history.gen1, history.gen2
        live_before = _chunk_ids(db, gen2)

        # Simulate the chunks behind v1 being garbage-collected.
        manifest = history.v1["manifest"]
        with db.transaction():
            for entry in manifest:
                db._conn.execute(
                    "DELETE FROM chunk_locations WHERE chunk_id = ?", (entry["chunk_id"],)
                )
                db._conn.execute(
                    "DELETE FROM chunks WHERE id = ?", (entry["chunk_id"],)
                )

        with pytest.raises(RuntimeError, match="no longer available -- pruned"):
            await restore_version(db, gen2, 1)

        # The failed restore rolled back: the live file is untouched.
        assert _chunk_ids(db, gen2) == live_before
        assert db.list_file_versions(gen2)[-1]["version"] == 1  # no restore row


# ── prune_versions ────────────────────────────────────────────────────────────

class TestPrune:
    async def test_prune_keeps_newest_and_never_the_live_version(self, history):
        db, gen2 = history.db, history.gen2
        # Restore v1 so the LIVE state anchor is version 1 while v3 is newest.
        await restore_version(db, gen2, 1)

        result = prune_versions(db, file_id=gen2, keep=1)
        # keep=1 would drop v1 and v2, but v1 IS the live file's chunk set --
        # it must survive; only v2 (old, not live) is removed.
        assert result["removed"] == 1
        remaining = {row["version"] for row in db.list_file_versions(gen2)}
        assert remaining == {1, 3}

    async def test_prune_removes_older_versions_beyond_keep(self, history):
        db, gen2 = history.db, history.gen2
        result = prune_versions(db, file_id=gen2, keep=1)
        # v1 (old generation, not live) falls outside keep=1; v2 is live+newest.
        assert result["removed"] == 1
        remaining = {row["version"] for row in db.list_file_versions(gen2)}
        assert remaining == {2}

    async def test_prune_with_generous_keep_removes_nothing(self, history):
        result = prune_versions(history.db, file_id=history.gen2, keep=10)
        assert result["removed"] == 0
        assert len(history.db.list_file_versions(history.gen2)) == 2

    async def test_global_prune_covers_every_file(self, history):
        db, gen2 = history.db, history.gen2
        # A second file with its own two-generation history.
        other1 = await _upload_generation(
            db, history.nonce_manager, history.tmp_path,
            b"other file gen one", name="other.txt", path="/other.txt",
        )
        await snapshot_current_file(db, other1, reason="manual")
        other2 = await _upload_generation(
            db, history.nonce_manager, history.tmp_path,
            b"other file gen two -- content changed!",
            name="other.txt", path="/other.txt",
        )
        with db.transaction():
            db.rehome_file_versions(other1, other2)
        await snapshot_current_file(db, other2, reason="sync")

        # Generous keep touches neither file.
        result = prune_versions(db, file_id=None, keep=10)
        assert result["file_id"] is None
        assert result["keep"] == 10
        assert result["removed"] == 0
        assert len(db.list_file_versions(gen2)) == 2
        assert len(db.list_file_versions(other2)) == 2

        # keep=1 drops each file's superseded gen1 row -- both files, one pass.
        result = prune_versions(db, file_id=None, keep=1)
        assert result["removed"] == 2
        assert {row["version"] for row in db.list_file_versions(gen2)} == {2}
        assert {row["version"] for row in db.list_file_versions(other2)} == {2}


# ── v13 -> v14 migration ──────────────────────────────────────────────────────

def test_v13_database_migrates_to_file_version_history(tmp_path):
    """A pre-version-history database gains file_versions (and its index)."""
    from ghostdrive.database.schema import SCHEMA_VERSION

    db = _make_db(tmp_path)
    # Simulate a v13 database: drop the v14 table, stamp the old version.
    with db.transaction():
        db._conn.execute("DROP TABLE IF EXISTS file_versions")
        db._conn.execute("UPDATE schema_version SET version = 13")
    db.close()

    db = _make_db(tmp_path)  # reopening runs the migration
    try:
        version = db._conn.execute(
            "SELECT version FROM schema_version"
        ).fetchone()[0]
        assert version == SCHEMA_VERSION
        # v14 introduced file_versions; the ladder has since advanced (v15
        # added the WORM backends.append_only column), so assert the migrated
        # DB matches the current constant rather than a hardcoded number.
        assert SCHEMA_VERSION >= 14

        tables = {
            row[0]
            for row in db._conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        assert "file_versions" in tables

        indexes = {
            row[0]
            for row in db._conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            ).fetchall()
        }
        assert "idx_file_versions_file" in indexes

        # The migrated table is usable: the same CRUD path still works.
        assert db.list_file_versions(str(uuid.uuid4())) == []
    finally:
        db.close()
