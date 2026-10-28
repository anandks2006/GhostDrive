"""
tests/test_schema_sync.py -- SCHEMA_VERSION 15 and the file_versions table.

Covers the fresh-database DDL (STRICT table + descending index), the
v13 -> v14 migration path (dropped table is recreated on reopen), reopen
idempotence, and the table's constraints: UNIQUE(file_id, version), the
foreign key into files(id), and ON DELETE CASCADE so purging a file cannot
wedge on its history.
"""

from __future__ import annotations

import sqlcipher3 as sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ghostdrive.database.db import GhostDriveDB
from ghostdrive.database.schema import SCHEMA_VERSION

FILE_VERSION_COLUMNS = {
    "id", "file_id", "version", "reason", "size", "blake3_hash",
    "manifest", "created_at",
}


def _make_db(tmp_path: Path, name: str = "schema_sync.db") -> GhostDriveDB:
    db = GhostDriveDB(
        path=tmp_path / name,
        ledger_key=bytes(range(32)),
        genesis_seed=bytes(range(32, 64)),
        master_key=bytes(range(32)),
    )
    db.open()
    return db


def _schema_version(db: GhostDriveDB) -> int:
    row = db._conn.execute("SELECT version FROM schema_version").fetchone()
    return int(row[0])


def _objects(db: GhostDriveDB, kind: str) -> set[str]:
    return {
        row[0]
        for row in db._conn.execute(
            "SELECT name FROM sqlite_master WHERE type = ?", (kind,)
        ).fetchall()
    }


def _insert_minimal_file(db: GhostDriveDB) -> str:
    file_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    with db.transaction():
        db.insert_file({
            "id": file_id, "name": "v.txt", "path": "/v.txt",
            "size": 5, "mime_type": "text/plain", "tier": "IMPORTANT",
            "created_at": now, "modified_at": now,
            "version": 1, "version_of": None,
            "tombstone": 0, "tombstone_at": None,
        })
    return file_id


def _version_record(file_id: str, version: int = 1) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "file_id": file_id,
        "version": version,
        "reason": "manual",
        "size": 5,
        "blake3_hash": "a" * 64,
        "manifest": '[{"chunk_id":"c1","size":5}]',
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


# ── Schema version + fresh DDL ────────────────────────────────────────────────

def test_schema_version_is_15(tmp_path):
    assert SCHEMA_VERSION == 15
    db = _make_db(tmp_path)
    try:
        assert _schema_version(db) == 15
    finally:
        db.close()


def test_fresh_database_has_file_versions_table_and_index(tmp_path):
    db = _make_db(tmp_path)
    try:
        assert "file_versions" in _objects(db, "table")
        assert "idx_file_versions_file" in _objects(db, "index")

        table_sql = db._conn.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'file_versions'"
        ).fetchone()["sql"]
        assert "STRICT" in table_sql
        assert "UNIQUE(file_id, version)" in table_sql.replace("\n", " ")
        assert "ON DELETE CASCADE" in table_sql

        columns = {
            row["name"]
            for row in db._conn.execute("PRAGMA table_info(file_versions)").fetchall()
        }
        assert columns == FILE_VERSION_COLUMNS

        index_sql = db._conn.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type = 'index' AND name = 'idx_file_versions_file'"
        ).fetchone()["sql"]
        assert "file_id" in index_sql and "version DESC" in index_sql
    finally:
        db.close()


# ── Migration ─────────────────────────────────────────────────────────────────

def test_v13_migration_recreates_file_versions(tmp_path):
    """A v13 database (table missing, version stamped 13) upgrades to the
    current schema (v15: file_versions at v14, backends.append_only at v15)."""
    db = _make_db(tmp_path)
    with db.transaction():
        db._conn.execute("DROP TABLE IF EXISTS file_versions")
        db._conn.execute("UPDATE schema_version SET version = 13")
    assert _schema_version(db) == 13
    assert "file_versions" not in _objects(db, "table")
    db.close()

    db = _make_db(tmp_path)  # reopening runs the v13 -> ... -> v15 ladder
    try:
        assert _schema_version(db) == SCHEMA_VERSION
        assert "file_versions" in _objects(db, "table")
        assert "idx_file_versions_file" in _objects(db, "index")
        # The v15 rung added the WORM capability column along the way.
        cols = {
            row["name"]
            for row in db._conn.execute("PRAGMA table_info(backends)").fetchall()
        }
        assert "append_only" in cols
    finally:
        db.close()


def test_reopen_is_idempotent(tmp_path):
    db = _make_db(tmp_path)
    db.close()
    db = _make_db(tmp_path)
    try:
        assert _schema_version(db) == SCHEMA_VERSION
        assert "file_versions" in _objects(db, "table")
        # Repeated opens never run destructive DDL: CRUD still answers.
        assert db.list_file_versions(str(uuid.uuid4())) == []
    finally:
        db.close()


# ── Table constraints ─────────────────────────────────────────────────────────

def test_unique_file_id_version_pair(tmp_path):
    db = _make_db(tmp_path)
    try:
        file_id = _insert_minimal_file(db)
        record = _version_record(file_id)
        with db.transaction():
            db.insert_file_version(record)
        assert len(db.list_file_versions(file_id)) == 1

        duplicate = _version_record(file_id, version=1)
        with db.transaction():
            with pytest.raises(sqlite3.IntegrityError):
                db.insert_file_version(duplicate)
        assert len(db.list_file_versions(file_id)) == 1
    finally:
        db.close()


def test_strict_table_rejects_wrong_column_type(tmp_path):
    db = _make_db(tmp_path)
    try:
        file_id = _insert_minimal_file(db)
        record = _version_record(file_id)
        record["size"] = "not-a-number"  # STRICT: TEXT into INTEGER column
        with db.transaction():
            with pytest.raises(sqlite3.IntegrityError):
                db.insert_file_version(record)
        assert db.list_file_versions(file_id) == []
    finally:
        db.close()


def test_file_versions_requires_existing_file(tmp_path):
    db = _make_db(tmp_path)
    try:
        with db.transaction():
            with pytest.raises(sqlite3.IntegrityError):
                db.insert_file_version(_version_record(str(uuid.uuid4())))
    finally:
        db.close()


def test_purge_file_cascades_to_its_versions(tmp_path):
    """purge_file_permanently must not wedge on file_versions (FK CASCADE)."""
    db = _make_db(tmp_path)
    try:
        file_id = _insert_minimal_file(db)
        with db.transaction():
            db.insert_file_version(_version_record(file_id, version=1))
            db.insert_file_version(_version_record(file_id, version=2))
        assert len(db.list_file_versions(file_id)) == 2

        with db.transaction():
            db.purge_file_permanently(file_id)

        assert db.get_file(file_id) is None
        assert db.list_file_versions(file_id) == []
    finally:
        db.close()
