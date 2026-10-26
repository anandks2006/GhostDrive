"""Tests for failure-domain placement and worst-case readiness auditing."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from ghostdrive.database.db import GhostDriveDB
from ghostdrive.pipeline.upload import _quota_sizes
from ghostdrive.services.durability import (
    DATA_SHARDS,
    TOTAL_SHARDS,
    assign_shards_to_backends,
    audit_readiness,
    backend_failure_domain,
    confirm_recovery_saved,
    save_contract,
)


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


def _chunk(db, file_id: str, sub_block_count: int = TOTAL_SHARDS) -> str:
    chunk_id = str(uuid.uuid4())
    db._conn.execute("BEGIN")
    db._conn.execute(
        """INSERT INTO chunks
           (id, file_id, chunk_index, total_chunks, blake3_hash, size,
            nonce_counter, sub_block_count)
           VALUES (?, ?, 0, 1, ?, 128, 1, ?)""",
        (chunk_id, file_id, "0" * 64, sub_block_count),
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


def _snapshot(db, backend_id: str) -> None:
    db._conn.execute("BEGIN")
    db._conn.execute(
        """INSERT INTO index_snapshots
           (id, snapshot_at, blake3_hash, hash_backend_id, wal_checkpointed)
           VALUES (?, ?, ?, ?, 1)""",
        (str(uuid.uuid4()), _now(), "a" * 64, backend_id),
    )
    db._conn.execute("COMMIT")


class TestFailureDomains:
    def test_local_folders_on_same_device_share_a_domain(self, tmp_path):
        first = tmp_path / "first"
        second = tmp_path / "second"
        first.mkdir()
        second.mkdir()
        row_one = {"id": "one", "type": "local", "credentials_ref": str(first)}
        row_two = {"id": "two", "type": "local", "credentials_ref": str(second)}

        domain_one = backend_failure_domain(row_one, SimpleNamespace(root_path=first))
        domain_two = backend_failure_domain(row_two, SimpleNamespace(root_path=second))

        assert domain_one["id"] == domain_two["id"]
        assert str(tmp_path) not in domain_one["label"]

    def test_external_drives_are_grouped_by_uuid(self):
        first = backend_failure_domain(
            {"id": "one", "type": "external_drive", "credentials_ref": "uuid-one"}
        )
        second = backend_failure_domain(
            {"id": "two", "type": "external_drive", "credentials_ref": "uuid-one"}
        )

        assert first["id"] == second["id"] == "external:uuid-one"

    def test_nas_devices_are_grouped_by_host(self):
        first = backend_failure_domain({"id": "one", "type": "nas", "credentials_ref": "nas.local"})
        second = backend_failure_domain({"id": "two", "type": "nas", "credentials_ref": "nas.local"})

        assert first["id"] == second["id"] == "nas:nas.local"


class TestShardAssignment:
    def test_spreads_shards_across_provider_and_nas_domains(self):
        rows = [
            {"id": "telegram-a", "type": "telegram", "credentials_ref": "ref:a"},
            {"id": "telegram-b", "type": "telegram", "credentials_ref": "ref:b"},
            {"id": "discord-a", "type": "discord", "credentials_ref": "ref:c"},
            {"id": "nas-a", "type": "nas", "credentials_ref": "nas-one"},
        ]

        assigned = assign_shards_to_backends(rows, TOTAL_SHARDS)

        assert len(assigned) == TOTAL_SHARDS
        assert assigned[0]["id"] == "telegram-a"
        assert assigned[1]["id"] == "discord-a"
        assert assigned[2]["id"] == "nas-a"
        assert assigned[3]["id"] == "telegram-b"
        assert assigned[4]["id"] == "discord-a"
        assert assigned[5]["id"] == "nas-a"

    def test_duplicate_provider_backends_are_one_failure_domain(self):
        rows = [
            {"id": "telegram-a", "type": "telegram", "credentials_ref": "ref:a"},
            {"id": "telegram-b", "type": "telegram", "credentials_ref": "ref:b"},
        ]

        assigned = assign_shards_to_backends(rows, TOTAL_SHARDS)

        assert [row["id"] for row in assigned] == [
            "telegram-a",
            "telegram-b",
            "telegram-a",
            "telegram-b",
            "telegram-a",
            "telegram-b",
        ]


class TestQuotaSizes:
    def test_erasure_reserves_all_six_shards(self):
        descriptor = SimpleNamespace(size=1_000_000)
        sizes = _quota_sizes(descriptor, sub_block_bytes=10_000_000, is_erasure=True)

        expected = -(-(1_000_000 + 16) // DATA_SHARDS)
        assert len(sizes) == TOTAL_SHARDS
        assert sizes == [expected] * TOTAL_SHARDS

    def test_non_erasure_includes_authentication_tag(self):
        descriptor = SimpleNamespace(size=1_000_000)
        sizes = _quota_sizes(descriptor, sub_block_bytes=10_000_000, is_erasure=False)

        assert sizes == [1_000_016]

    def test_non_erasure_splits_exact_encrypted_size(self):
        descriptor = SimpleNamespace(size=1_000_016)
        sizes = _quota_sizes(descriptor, sub_block_bytes=500_000, is_erasure=False)

        assert len(sizes) == 3
        assert sum(sizes) == 1_000_032
        assert max(sizes) <= 500_000


class TestContract:
    def test_contract_rejects_impossible_domain_losses(self, tmp_path):
        db = _make_db(tmp_path)
        try:
            save_contract(db, required_domain_losses=3, requires_offsite=False)
        except ValueError as exc:
            assert "at most 2" in str(exc)
        else:
            raise AssertionError("An impossible contract was accepted")


class TestReadinessAudit:
    def test_no_chunks_is_unknown(self, tmp_path):
        db = _make_db(tmp_path)
        audit = audit_readiness(db)
        assert audit["state"] == "UNKNOWN"
        assert audit["total_chunks"] == 0

    def test_zero_loss_contract_does_not_hide_missing_shards(self, tmp_path):
        db = _make_db(tmp_path)
        _backend(db, "telegram")
        file_id = _file(db)
        _chunk(db, file_id)
        save_contract(db, required_domain_losses=0, requires_offsite=False)

        audit = audit_readiness(db)

        assert audit["state"] == "UNPROTECTED"
        assert audit["chunks"][0]["meets_contract"] is False

    def test_single_domain_layout_is_unprotected(self, tmp_path):
        db = _make_db(tmp_path)
        backend_id = _backend(db, "telegram")
        _backend(db, "nas", "unused-nas.local")
        file_id = _file(db)
        chunk_id = _chunk(db, file_id)
        for index in range(TOTAL_SHARDS):
            _location(db, chunk_id, backend_id, index)

        audit = audit_readiness(db)

        assert audit["state"] == "UNPROTECTED"
        assert audit["failure_domain_count"] == 1
        assert audit["configured_failure_domain_count"] == 2
        assert audit["unprotected_chunks"] == 1
        assert "single failure domain" in " ".join(audit["findings"])

    def test_six_domains_meet_default_contract_with_metadata_and_recovery(self, tmp_path):
        db = _make_db(tmp_path)
        backend_ids = [_backend(db, "nas", f"nas-{index}.local") for index in range(TOTAL_SHARDS)]
        file_id = _file(db)
        chunk_id = _chunk(db, file_id)
        for index, backend_id in enumerate(backend_ids):
            _location(db, chunk_id, backend_id, index)

        _snapshot(db, backend_ids[0])
        confirm_recovery_saved(db)
        audit = audit_readiness(db)

        assert audit["state"] == "PROTECTED"
        assert audit["failure_domain_count"] == TOTAL_SHARDS
        assert audit["protected_chunks"] == 1
        assert audit["chunks"][0]["survivable_domain_losses"] >= 2

    def test_six_domains_without_metadata_are_degraded(self, tmp_path):
        db = _make_db(tmp_path)
        backend_ids = [_backend(db, "nas", f"nas-{index}.local") for index in range(TOTAL_SHARDS)]
        file_id = _file(db)
        chunk_id = _chunk(db, file_id)
        for index, backend_id in enumerate(backend_ids):
            _location(db, chunk_id, backend_id, index)
        confirm_recovery_saved(db)

        audit = audit_readiness(db)

        assert audit["state"] == "DEGRADED"
        assert audit["metadata_ok"] is False
        assert any("index" in finding.lower() for finding in audit["findings"])

    def test_three_domains_survive_one_loss_but_not_default_contract(self, tmp_path):
        db = _make_db(tmp_path)
        backend_ids = [_backend(db, "nas", f"nas-{index}.local") for index in range(3)]
        file_id = _file(db)
        chunk_id = _chunk(db, file_id)
        for index in range(TOTAL_SHARDS):
            _location(db, chunk_id, backend_ids[index % 3], index)
        _snapshot(db, backend_ids[0])
        confirm_recovery_saved(db)

        audit = audit_readiness(db)

        assert audit["state"] == "DEGRADED"
        assert audit["chunks"][0]["survivable_domain_losses"] == 1

    def test_configured_provider_without_shards_does_not_satisfy_offsite(self, tmp_path):
        db = _make_db(tmp_path)
        backend_ids = [_backend(db, "nas", f"nas-{index}.local") for index in range(TOTAL_SHARDS)]
        _backend(db, "telegram")
        file_id = _file(db)
        chunk_id = _chunk(db, file_id)
        for index, backend_id in enumerate(backend_ids):
            _location(db, chunk_id, backend_id, index)
        _snapshot(db, backend_ids[0])
        confirm_recovery_saved(db)
        save_contract(db, required_domain_losses=2, requires_offsite=True)

        audit = audit_readiness(db)

        assert audit["state"] == "DEGRADED"
        assert audit["offsite_domain_count"] == 1
        assert audit["offsite_ok"] is False
        assert audit["offsite_chunks_missing"] == 1

    def test_confirmed_provider_shard_satisfies_offsite_requirement(self, tmp_path):
        db = _make_db(tmp_path)
        backend_ids = [_backend(db, "nas", f"nas-{index}.local") for index in range(TOTAL_SHARDS - 1)]
        backend_ids.append(_backend(db, "telegram"))
        file_id = _file(db)
        chunk_id = _chunk(db, file_id)
        for index, backend_id in enumerate(backend_ids):
            _location(db, chunk_id, backend_id, index)
        _snapshot(db, backend_ids[0])
        confirm_recovery_saved(db)
        save_contract(db, required_domain_losses=2, requires_offsite=True)

        audit = audit_readiness(db)

        assert audit["state"] == "PROTECTED"
        assert audit["offsite_ok"] is True
        assert audit["offsite_chunks_missing"] == 0

    def test_contract_can_require_offsite_provider(self, tmp_path):
        db = _make_db(tmp_path)
        backend_ids = [_backend(db, "nas", f"nas-{index}.local") for index in range(TOTAL_SHARDS)]
        file_id = _file(db)
        chunk_id = _chunk(db, file_id)
        for index, backend_id in enumerate(backend_ids):
            _location(db, chunk_id, backend_id, index)
        _snapshot(db, backend_ids[0])
        confirm_recovery_saved(db)
        save_contract(db, required_domain_losses=2, requires_offsite=True)

        audit = audit_readiness(db)

        assert audit["state"] == "DEGRADED"
        assert audit["offsite_ok"] is False
        assert audit["contract"]["requires_offsite"] is True
