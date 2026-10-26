"""Tests for adaptive erasure-coding plans, cold-shard placement, and reporting."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from ghostdrive.database.db import GhostDriveDB
from ghostdrive.pipeline.coding import (
    DATA_SHARDS,
    TOTAL_SHARDS,
    padlen_for,
    plan_coding,
)
from ghostdrive.pipeline.upload import _quota_sizes
from ghostdrive.services.durability import assign_shards_to_backends


# ── Helpers (copied from tests/test_durability.py) ────────────────────────────

def _make_db(tmp_path: Path) -> GhostDriveDB:
    db = GhostDriveDB(
        path=tmp_path / "adaptive.db",
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


def _location(db, chunk_id: str, backend_id: str, sub_block_index: int, status: str = "confirmed") -> None:
    db._conn.execute("BEGIN")
    db._conn.execute(
        """INSERT INTO chunk_locations
           (chunk_id, sub_block_index, backend_id, reference_id, upload_date, status)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (chunk_id, sub_block_index, backend_id, f"ref-{sub_block_index}", _now(), status),
    )
    db._conn.execute("COMMIT")


# ── plan_coding ───────────────────────────────────────────────────────────────

class TestPlanCoding:
    def test_default_is_four_plus_two_floor(self):
        assert plan_coding("IMPORTANT", 1) == (4, 6)
        assert plan_coding("DISPOSABLE", 1) == (4, 6)
        assert plan_coding("CRITICAL", 1) == (4, 6)

    def test_auto_upgrades_critical_with_eight_domains(self):
        assert plan_coding("CRITICAL", 8, {"erasure_scheme": "auto"}) == (4, 8)
        # No config at all still means auto.
        assert plan_coding("CRITICAL", 8) == (4, 8)

    def test_auto_keeps_floor_for_important_tier(self):
        assert plan_coding("IMPORTANT", 8, {"erasure_scheme": "auto"}) == (4, 6)

    def test_auto_keeps_floor_fewer_than_eight_domains(self):
        assert plan_coding("CRITICAL", 7, {"erasure_scheme": "auto"}) == (4, 6)

    def test_forced_4_plus_2_wins_even_with_many_domains(self):
        assert plan_coding("CRITICAL", 16, {"erasure_scheme": "4+2"}) == (4, 6)

    def test_forced_4_plus_4_overrides_everything(self):
        assert plan_coding("IMPORTANT", 1, {"erasure_scheme": "4+4"}) == (4, 8)
        assert plan_coding("DISPOSABLE", 2, {"erasure_scheme": "4+4"}) == (4, 8)

    def test_unknown_or_empty_scheme_falls_back_to_auto(self):
        assert plan_coding("IMPORTANT", 8, {"erasure_scheme": "bogus"}) == (4, 6)
        assert plan_coding("CRITICAL", 8, {"erasure_scheme": ""}) == (4, 8)
        assert plan_coding("CRITICAL", 8, {"erasure_scheme": None}) == (4, 8)
        assert plan_coding("CRITICAL", 8, {"erasure_scheme": "bogus"}) == (4, 8)
        assert plan_coding("CRITICAL", 1, {"erasure_scheme": "bogus"}) == (4, 6)

    def test_single_domain_never_below_floor(self):
        assert plan_coding("CRITICAL", 1, {"erasure_scheme": "auto"}) == (4, 6)

    def test_k_is_always_four_and_n_is_bounded(self):
        for tier in ("CRITICAL", "IMPORTANT", "DISPOSABLE", "WEIRD"):
            for domains in (0, 1, 7, 8, 64):
                for scheme in (None, "", "auto", "4+2", "4+4", "junk"):
                    config = {} if scheme is None else {"erasure_scheme": scheme}
                    k, n = plan_coding(tier, domains, config)
                    assert k == DATA_SHARDS
                    assert n in (6, 8)


# ── padlen_for ────────────────────────────────────────────────────────────────

class TestPadlenFor:
    def test_aligned_length_needs_no_padding(self):
        assert padlen_for(8, 4) == 0
        assert padlen_for(0, 4) == 0

    def test_small_lengths(self):
        assert padlen_for(1, 4) == 3
        assert padlen_for(2, 4) == 2
        assert padlen_for(3, 4) == 1
        assert padlen_for(5, 4) == 3

    def test_matches_legacy_formula_for_k4(self):
        for length in range(0, 64):
            assert padlen_for(length, 4) == (4 - (length % 4)) % 4

    def test_generalizes_to_other_k(self):
        assert padlen_for(9, 8) == 7
        assert padlen_for(16, 8) == 0


# ── _quota_sizes backward compatibility ───────────────────────────────────────

class TestQuotaSizesBackwardCompat:
    def test_default_is_six_shards(self):
        descriptor = SimpleNamespace(size=1_000_000)
        sizes = _quota_sizes(descriptor, 10_000_000, True)
        assert len(sizes) == TOTAL_SHARDS == 6

    def test_total_shards_keyword_yields_eight(self):
        descriptor = SimpleNamespace(size=1_000_000)
        sizes = _quota_sizes(descriptor, 10_000_000, True, total_shards=8)
        assert len(sizes) == 8

    def test_non_erasure_unchanged(self):
        descriptor = SimpleNamespace(size=1_000_000)
        assert _quota_sizes(descriptor, 10_000_000, False) == [1_000_016]


# ── Cold-shard placement ──────────────────────────────────────────────────────

def _cold_rows():
    """Three backends in the provider domain; middle one is cold."""
    rows = [
        {"id": "tg-hot-a", "type": "telegram", "credentials_ref": "ref:a"},
        {"id": "tg-cold", "type": "telegram", "credentials_ref": "ref:b"},
        {"id": "tg-hot-b", "type": "telegram", "credentials_ref": "ref:c"},
    ]
    objects = {"tg-cold": SimpleNamespace(is_cold_storage=True)}
    return rows, objects


class TestColdPlacement:
    def test_critical_puts_cold_last_within_domain(self):
        rows, objects = _cold_rows()
        assigned = assign_shards_to_backends(rows, 6, objects, tier="CRITICAL")
        assert [row["id"] for row in assigned] == [
            "tg-hot-a", "tg-hot-b", "tg-cold",
            "tg-hot-a", "tg-hot-b", "tg-cold",
        ]

    def test_important_also_puts_cold_last(self):
        rows, objects = _cold_rows()
        assigned = assign_shards_to_backends(rows, 6, objects, tier="IMPORTANT")
        assert [row["id"] for row in assigned][0] == "tg-hot-a"
        assert assigned[-1]["id"] == "tg-cold"

    def test_disposable_puts_cold_first(self):
        rows, objects = _cold_rows()
        assigned = assign_shards_to_backends(rows, 6, objects, tier="DISPOSABLE")
        assert [row["id"] for row in assigned] == [
            "tg-cold", "tg-hot-a", "tg-hot-b",
            "tg-cold", "tg-hot-a", "tg-hot-b",
        ]

    def test_embedded_row_cold_flag_is_honored(self):
        rows = [
            {"id": "a", "type": "telegram", "credentials_ref": "ref:a"},
            {"id": "b", "type": "telegram", "credentials_ref": "ref:b", "is_cold_storage": True},
        ]
        assigned = assign_shards_to_backends(rows, 4, tier="CRITICAL")
        assert [row["id"] for row in assigned] == ["a", "b", "a", "b"]

    def test_no_cold_rows_order_identical_to_legacy_call(self):
        rows = [
            {"id": "telegram-a", "type": "telegram", "credentials_ref": "ref:a"},
            {"id": "telegram-b", "type": "telegram", "credentials_ref": "ref:b"},
            {"id": "discord-a", "type": "discord", "credentials_ref": "ref:c"},
            {"id": "nas-a", "type": "nas", "credentials_ref": "nas-one"},
        ]
        without_tier = assign_shards_to_backends(rows, TOTAL_SHARDS)
        with_tier = assign_shards_to_backends(rows, TOTAL_SHARDS, tier="CRITICAL")
        assert [row["id"] for row in with_tier] == [row["id"] for row in without_tier]
        disposable = assign_shards_to_backends(rows, TOTAL_SHARDS, tier="DISPOSABLE")
        assert [row["id"] for row in disposable] == [row["id"] for row in without_tier]

    def test_cold_rows_across_multiple_domains(self):
        rows = [
            {"id": "tg-cold", "type": "telegram", "credentials_ref": "ref:a"},
            {"id": "tg-hot", "type": "telegram", "credentials_ref": "ref:b"},
            {"id": "dc-hot", "type": "discord", "credentials_ref": "ref:c"},
            {"id": "dc-cold", "type": "discord", "credentials_ref": "ref:d"},
        ]
        objects = {
            "tg-cold": SimpleNamespace(is_cold_storage=True),
            "dc-cold": SimpleNamespace(is_cold_storage=True),
        }
        assigned = assign_shards_to_backends(rows, 4, objects, tier="CRITICAL")
        # Round-robin: one shard per domain; within each domain hot first.
        assert [row["id"] for row in assigned] == ["tg-hot", "dc-hot", "tg-cold", "dc-cold"]


# ── Adaptive upload integration ───────────────────────────────────────────────

class TestAdaptiveUpload:
    def test_single_backend_critical_stays_at_floor(self, tmp_path):
        from ghostdrive.crypto.nonce import NonceManager
        from ghostdrive.pipeline.chunker import ChunkDescriptor
        from ghostdrive.pipeline.upload import ChunkUploader
        import asyncio

        db = _make_db(tmp_path)
        backend_id = _backend(db, "discord")

        mock_backend = MagicMock()
        mock_backend.id = backend_id
        mock_backend.type = "discord"
        mock_backend._connected = True

        uploaded_shards = {}

        async def mock_upload(stream, chunk_id, sub_block_index):
            data = bytearray()
            async for chunk in stream:
                data.extend(chunk)
            uploaded_shards[sub_block_index] = bytes(data)
            return f"ref-{sub_block_index}"

        mock_backend.upload = MagicMock(side_effect=mock_upload)

        nm = NonceManager(data_dir=tmp_path)
        file_path = tmp_path / "source.txt"
        file_path.write_bytes(b"A" * 1024)
        descriptor = ChunkDescriptor(
            chunk_index=0, offset=0, size=1024, total_chunks=1, is_manifest=False
        )

        file_id = str(uuid.uuid4())
        now = _now()
        with db.transaction():
            db.insert_file({
                "id": file_id, "name": "source.txt", "path": "/source.txt",
                "size": 1024, "mime_type": "text/plain", "tier": "CRITICAL",
                "created_at": now, "modified_at": now,
                "version": 1, "version_of": None,
                "tombstone": 0, "tombstone_at": None,
            })

        uploader = ChunkUploader(
            db=db, backend=mock_backend,
            master_key=bytes(range(32)), hkdf_salt=bytes(range(32, 64)),
            nonce_manager=nm,
            active_backends={backend_id: mock_backend, "discord": mock_backend},
        )
        chunk_id = asyncio.run(uploader.upload_chunk(
            path=file_path, descriptor=descriptor, file_id=file_id, mime_type="text/plain",
        ))

        chunk_row = db._conn.execute(
            "SELECT erasure_k, erasure_n FROM chunks WHERE id = ?", (chunk_id,)
        ).fetchone()
        assert chunk_row["erasure_k"] == 4
        assert chunk_row["erasure_n"] == 6
        locs = db._conn.execute(
            "SELECT COUNT(*) FROM chunk_locations WHERE chunk_id = ?", (chunk_id,)
        ).fetchone()[0]
        assert locs == 6
        db.close()

    def test_eight_domains_critical_upgrades_to_4plus4(self, tmp_path):
        from ghostdrive.crypto.nonce import NonceManager
        from ghostdrive.pipeline.chunker import ChunkDescriptor
        from ghostdrive.pipeline.upload import ChunkUploader
        import asyncio

        db = _make_db(tmp_path)
        # Eight NAS rows with distinct credentials_ref -> eight distinct
        # 'nas:<host>' failure domains, so auto+CRITICAL upgrades to 4+4.
        backend_ids = [_backend(db, "nas", credentials_ref=f"nas-{i}") for i in range(8)]

        mock_backend = MagicMock()
        mock_backend.type = "nas"
        mock_backend._connected = True

        uploaded = {}

        async def mock_upload(stream, chunk_id, sub_block_index):
            async for _ in stream:
                pass
            uploaded[sub_block_index] = True
            return f"ref-{sub_block_index}"

        mock_backend.upload = MagicMock(side_effect=mock_upload)

        nm = NonceManager(data_dir=tmp_path)
        file_path = tmp_path / "source.txt"
        file_path.write_bytes(b"A" * 1024)
        descriptor = ChunkDescriptor(
            chunk_index=0, offset=0, size=1024, total_chunks=1, is_manifest=False
        )

        file_id = str(uuid.uuid4())
        now = _now()
        with db.transaction():
            db.insert_file({
                "id": file_id, "name": "source.txt", "path": "/source.txt",
                "size": 1024, "mime_type": "text/plain", "tier": "CRITICAL",
                "created_at": now, "modified_at": now,
                "version": 1, "version_of": None,
                "tombstone": 0, "tombstone_at": None,
            })

        # Only the type key maps to the mock object: mapping backend ids would
        # make backend_failure_domain read the mock's (auto-truthy) .host and
        # collapse all eight rows into one domain. Upload resolution falls
        # back from id -> type key, so shards still reach the mock.
        active_backends = {"nas": mock_backend}
        uploader = ChunkUploader(
            db=db, backend=mock_backend,
            master_key=bytes(range(32)), hkdf_salt=bytes(range(32, 64)),
            nonce_manager=nm,
            active_backends=active_backends,
        )
        chunk_id = asyncio.run(uploader.upload_chunk(
            path=file_path, descriptor=descriptor, file_id=file_id, mime_type="text/plain",
        ))

        chunk_row = db._conn.execute(
            "SELECT erasure_k, erasure_n FROM chunks WHERE id = ?", (chunk_id,)
        ).fetchone()
        assert chunk_row["erasure_k"] == 4
        assert chunk_row["erasure_n"] == 8
        locs = db._conn.execute(
            "SELECT COUNT(*) FROM chunk_locations WHERE chunk_id = ?", (chunk_id,)
        ).fetchone()[0]
        assert locs == 8
        assert len(uploaded) == 8
        db.close()

    def test_forced_4plus4_scheme_with_one_backend(self, tmp_path):
        from ghostdrive.crypto.nonce import NonceManager
        from ghostdrive.pipeline.chunker import ChunkDescriptor
        from ghostdrive.pipeline.upload import ChunkUploader
        import asyncio

        db = _make_db(tmp_path)
        backend_id = _backend(db, "discord")
        db.set_setting("erasure_scheme", "4+4")

        mock_backend = MagicMock()
        mock_backend.id = backend_id
        mock_backend.type = "discord"
        mock_backend._connected = True

        uploaded = {}

        async def mock_upload(stream, chunk_id, sub_block_index):
            async for _ in stream:
                pass
            uploaded[sub_block_index] = True
            return f"ref-{sub_block_index}"

        mock_backend.upload = MagicMock(side_effect=mock_upload)

        nm = NonceManager(data_dir=tmp_path)
        file_path = tmp_path / "source.txt"
        file_path.write_bytes(b"A" * 1024)
        descriptor = ChunkDescriptor(
            chunk_index=0, offset=0, size=1024, total_chunks=1, is_manifest=False
        )

        file_id = str(uuid.uuid4())
        now = _now()
        with db.transaction():
            db.insert_file({
                "id": file_id, "name": "source.txt", "path": "/source.txt",
                "size": 1024, "mime_type": "text/plain", "tier": "IMPORTANT",
                "created_at": now, "modified_at": now,
                "version": 1, "version_of": None,
                "tombstone": 0, "tombstone_at": None,
            })

        uploader = ChunkUploader(
            db=db, backend=mock_backend,
            master_key=bytes(range(32)), hkdf_salt=bytes(range(32, 64)),
            nonce_manager=nm,
            active_backends={backend_id: mock_backend, "discord": mock_backend},
        )
        chunk_id = asyncio.run(uploader.upload_chunk(
            path=file_path, descriptor=descriptor, file_id=file_id, mime_type="text/plain",
        ))

        chunk_row = db._conn.execute(
            "SELECT erasure_k, erasure_n FROM chunks WHERE id = ?", (chunk_id,)
        ).fetchone()
        assert chunk_row["erasure_k"] == 4
        assert chunk_row["erasure_n"] == 8
        locs = db._conn.execute(
            "SELECT COUNT(*) FROM chunk_locations WHERE chunk_id = ?", (chunk_id,)
        ).fetchone()[0]
        assert locs == 8
        assert len(uploaded) == 8
        db.close()


# ── status() reporting ────────────────────────────────────────────────────────

class TestStatusReporting:
    def _status(self, db, monkeypatch):
        from ghostdrive.services import resilience
        monkeypatch.setattr(resilience, "require_db", lambda: db)
        return resilience.status()

    def _insert_erasure_chunk(self, db, file_id, k, n, chunk_index=0):
        chunk_id = _chunk(db, file_id, sub_block_count=n, chunk_index=chunk_index)
        db._conn.execute(
            "UPDATE chunks SET erasure_k = ?, erasure_n = ? WHERE id = ?",
            (k, n, chunk_id),
        )
        return chunk_id

    def test_mixed_profiles_reported(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path)
        file_id = _file(db, "CRITICAL")
        self._insert_erasure_chunk(db, file_id, 4, 6, chunk_index=0)
        self._insert_erasure_chunk(db, file_id, 4, 8, chunk_index=1)
        # Legacy chunk: inferred 4+2 from the overloaded counter.
        _chunk(db, file_id, sub_block_count=6, chunk_index=2)

        ec = self._status(db, monkeypatch)["erasure_coding"]

        assert ec["enabled"] is True
        assert ec["adaptive"] is True
        assert ec["data_shards"] == 4
        assert ec["parity_shards"] == 2
        assert ec["total_shards"] == 6
        # Legacy + explicit 4+2 chunk dominate the single 4+4 chunk.
        assert ec["scheme"] == "Reed-Solomon (zfec 4+2)"
        assert ec["recovery_threshold"] == "4 of 6 shards required for full recovery"
        by_profile = {(s["data_shards"], s["parity_shards"]): s["chunks"] for s in ec["schemes"]}
        assert by_profile == {(4, 2): 2, (4, 4): 1}
        db.close()

    def test_only_floor_chunks_are_not_adaptive(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path)
        file_id = _file(db, "IMPORTANT")
        self._insert_erasure_chunk(db, file_id, 4, 6, chunk_index=0)
        _chunk(db, file_id, sub_block_count=6, chunk_index=1)  # legacy 4+2

        ec = self._status(db, monkeypatch)["erasure_coding"]

        assert ec["adaptive"] is False
        assert ec["scheme"] == "Reed-Solomon (zfec 4+2)"
        assert ec["schemes"] == [{"data_shards": 4, "parity_shards": 2, "chunks": 2}]
        db.close()

    def test_dominant_4plus4_when_it_outnumbers(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path)
        file_id = _file(db, "CRITICAL")
        self._insert_erasure_chunk(db, file_id, 4, 8, chunk_index=0)
        self._insert_erasure_chunk(db, file_id, 4, 8, chunk_index=1)
        self._insert_erasure_chunk(db, file_id, 4, 6, chunk_index=2)

        ec = self._status(db, monkeypatch)["erasure_coding"]

        assert ec["scheme"] == "Reed-Solomon (zfec 4+4)"
        assert ec["data_shards"] == 4
        assert ec["parity_shards"] == 4
        assert ec["total_shards"] == 8
        assert ec["recovery_threshold"] == "4 of 8 shards required for full recovery"
        assert ec["adaptive"] is True
        db.close()

    def test_no_chunks_preserves_legacy_shape(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path)
        ec = self._status(db, monkeypatch)["erasure_coding"]

        assert ec["enabled"] is True
        assert ec["scheme"] == "Reed-Solomon (zfec 4+2)"
        assert ec["data_shards"] == 4
        assert ec["parity_shards"] == 2
        assert ec["total_shards"] == 6
        assert ec["schemes"] == []
        assert ec["adaptive"] is False
        assert ec["recovery_threshold"] == "4 of 6 shards required for full recovery"
        db.close()

    def test_non_erasure_chunks_disable_coding(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path)
        file_id = _file(db, "DISPOSABLE")
        _chunk(db, file_id, sub_block_count=1)  # non-erasure mirror chunk

        ec = self._status(db, monkeypatch)["erasure_coding"]

        assert ec["enabled"] is False
        assert ec["schemes"] == []
        db.close()
