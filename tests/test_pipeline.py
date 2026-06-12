"""
tests/test_pipeline.py -- Unit tests for the upload pipeline modules.

Covers:
  - compressor.py: ZSTD_LEVEL constant, skip pre-compressed MIME types,
    round-trip compress/decompress, streaming output
  - dedup.py: BLAKE3 on original bytes, file hasher, DedupChecker, DedupResult
  - quota.py: QuotaManager reserve/confirm/restore, QuotaReservationError
  - chunker.py: correct split sizes, empty file manifest, symlink resolution,
    unicode filenames, read_chunk_async block size
  - upload.py: pending intent written before upload, cancellation cleanup,
    fail + restore on backend error
"""

import asyncio
import os
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ghostdrive.database.db import GhostDriveDB
from ghostdrive.exceptions import QuotaReservationError
from ghostdrive.pipeline.compressor import (
    ZSTD_LEVEL,
    compress_bytes,
    decompress_bytes,
    should_skip_compression,
)
from ghostdrive.pipeline.chunker import (
    ChunkDescriptor,
    read_chunk_async,
    resolve_path,
    split_file,
)
from ghostdrive.pipeline.dedup import (
    DedupChecker,
    compute_blake3,
    compute_blake3_async,
    compute_blake3_file,
)
from ghostdrive.pipeline.quota import QuotaManager


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_db(tmp_path: Path) -> GhostDriveDB:
    db = GhostDriveDB(
        path=tmp_path / "test.db",
        ledger_key=bytes(range(32)),
        genesis_seed=bytes(range(32, 64)),
    )
    db.open()
    return db


def _make_backend_row(db, bid=None, quota_limit=1024 * 1024 * 1024):
    bid = bid or str(uuid.uuid4())
    db._conn.execute("BEGIN")
    db._conn.execute(
        """INSERT INTO backends
           (id, type, credentials_ref, status, priority, quota_used, quota_limit, quota_reserved)
           VALUES (?, 'telegram', 'ref:test', 'healthy', 1, 0, ?, 0)""",
        (bid, quota_limit),
    )
    db._conn.execute("COMMIT")
    return bid


# ── compressor.py tests ───────────────────────────────────────────────────────

class TestCompressor:
    def test_zstd_level_is_3(self):
        """Compression level is a fixed constant -- NEVER user-configurable."""
        assert ZSTD_LEVEL == 3

    def test_compress_decompress_roundtrip(self):
        data = b"Hello, GhostDrive! " * 10_000
        compressed   = compress_bytes(data)
        decompressed = decompress_bytes(compressed)
        assert decompressed == data

    def test_compressed_smaller_than_original_for_repetitive_data(self):
        data = b"AAAAAAAAA" * 100_000
        assert len(compress_bytes(data)) < len(data)

    def test_compress_random_data_roundtrip(self):
        data = os.urandom(64 * 1024)
        assert decompress_bytes(compress_bytes(data)) == data

    def test_skip_compression_jpeg(self):
        assert should_skip_compression("image/jpeg") is True

    def test_skip_compression_png(self):
        assert should_skip_compression("image/png") is True

    def test_skip_compression_mp4(self):
        assert should_skip_compression("video/mp4") is True

    def test_skip_compression_zip(self):
        assert should_skip_compression("application/zip") is True

    def test_skip_compression_pdf(self):
        assert should_skip_compression("application/pdf") is True

    def test_skip_compression_audio(self):
        assert should_skip_compression("audio/mpeg") is True

    def test_no_skip_for_text(self):
        assert should_skip_compression("text/plain") is False

    def test_no_skip_for_json(self):
        assert should_skip_compression("application/json") is False

    def test_no_skip_for_octet_stream(self):
        assert should_skip_compression("application/octet-stream") is False

    def test_skip_compression_ignores_charset_param(self):
        assert should_skip_compression("image/jpeg; charset=utf-8") is True

    def test_passthrough_for_skipped_mime(self):
        """Pre-compressed data passed through unchanged."""
        data = os.urandom(1024)
        assert compress_bytes(data, mime_type="image/jpeg") == data
        assert decompress_bytes(data, mime_type="image/jpeg") == data

    @pytest.mark.asyncio
    async def test_compress_stream_roundtrip(self):
        from ghostdrive.pipeline.compressor import compress_stream, decompress_stream

        original = b"GhostDrive streaming test " * 5_000

        async def source():
            block_size = 4096
            offset = 0
            while offset < len(original):
                yield original[offset : offset + block_size]
                offset += block_size

        compressed_chunks = []
        async for block in compress_stream(source()):
            compressed_chunks.append(block)

        compressed = b"".join(compressed_chunks)

        async def compressed_source():
            yield compressed

        decompressed_chunks = []
        async for block in decompress_stream(compressed_source()):
            decompressed_chunks.append(block)

        assert b"".join(decompressed_chunks) == original

    @pytest.mark.asyncio
    async def test_compress_stream_passthrough_for_skipped_mime(self):
        from ghostdrive.pipeline.compressor import compress_stream

        data = os.urandom(512)

        async def source():
            yield data

        result = b""
        async for block in compress_stream(source(), mime_type="image/jpeg"):
            result += block

        assert result == data


# ── dedup.py tests ────────────────────────────────────────────────────────────

class TestDedup:
    def test_blake3_deterministic(self):
        data = b"test data for dedup"
        assert compute_blake3(data) == compute_blake3(data)

    def test_blake3_different_for_different_data(self):
        assert compute_blake3(b"aaa") != compute_blake3(b"bbb")

    def test_blake3_returns_hex_string(self):
        h = compute_blake3(b"hello")
        assert all(c in "0123456789abcdef" for c in h)

    def test_blake3_length(self):
        # BLAKE3 output is 32 bytes = 64 hex chars
        assert len(compute_blake3(b"x")) == 64

    @pytest.mark.asyncio
    async def test_compute_blake3_async_matches_sync(self):
        data = os.urandom(1024)
        sync_hash  = compute_blake3(data)
        async_hash = await compute_blake3_async(data)
        assert sync_hash == async_hash

    def test_compute_blake3_file(self, tmp_path):
        content = b"file content for blake3 test" * 1000
        f = tmp_path / "test.bin"
        f.write_bytes(content)
        assert compute_blake3_file(f) == compute_blake3(content)

    def test_dedup_checker_no_match(self, tmp_path):
        db = _make_db(tmp_path)
        try:
            checker = DedupChecker(db)
            result = checker.check("no_such_hash", 1234)
            assert result.is_duplicate is False
            assert result.existing_chunk_id is None
        finally:
            db.close()

    def test_dedup_checker_finds_existing_chunk(self, tmp_path):
        db = _make_db(tmp_path)
        try:
            # Insert a file and chunk
            now = "2024-01-01T00:00:00+00:00"
            fid = str(uuid.uuid4())
            with db.transaction():
                db.insert_file({
                    "id": fid, "name": "f.txt", "path": "/f.txt",
                    "size": 9999, "mime_type": "text/plain", "tier": "IMPORTANT",
                    "created_at": now, "modified_at": now,
                    "version": 1, "version_of": None,
                    "tombstone": 0, "tombstone_at": None,
                })
            cid = str(uuid.uuid4())
            with db.transaction():
                db.insert_chunk({
                    "id": cid, "file_id": fid, "chunk_index": 0,
                    "total_chunks": 1, "blake3_hash": "deadbeef99", "size": 9999,
                    "nonce_counter": 7, "sub_block_count": 1,
                    "is_manifest": 0, "ref_count": 1,
                })

            checker = DedupChecker(db)
            result = checker.check("deadbeef99", 9999)
            assert result.is_duplicate is True
            assert result.existing_chunk_id == cid
        finally:
            db.close()

    def test_dedup_result_repr_new(self):
        from ghostdrive.pipeline.dedup import DedupResult
        r = DedupResult(is_duplicate=False, existing_chunk_id=None)
        assert "NEW" in repr(r)

    def test_dedup_result_repr_duplicate(self):
        from ghostdrive.pipeline.dedup import DedupResult
        r = DedupResult(is_duplicate=True, existing_chunk_id="uuid-123")
        assert "DUPLICATE" in repr(r)


# ── quota.py tests ────────────────────────────────────────────────────────────

class TestQuotaManager:
    def test_reserve_succeeds(self, tmp_path):
        db = _make_db(tmp_path)
        try:
            bid = _make_backend_row(db, quota_limit=1024)
            qm = QuotaManager(db)
            with db.transaction():
                qm.reserve(bid, 500)  # Should not raise
        finally:
            db.close()

    def test_reserve_raises_on_insufficient_space(self, tmp_path):
        db = _make_db(tmp_path)
        try:
            bid = _make_backend_row(db, quota_limit=100)
            qm = QuotaManager(db)
            with pytest.raises(QuotaReservationError):
                with db.transaction():
                    qm.reserve(bid, 500)  # 500 > 100
        finally:
            db.close()

    def test_confirm_moves_reserved_to_used(self, tmp_path):
        db = _make_db(tmp_path)
        try:
            bid = _make_backend_row(db, quota_limit=1024)
            qm = QuotaManager(db)
            with db.transaction():
                qm.reserve(bid, 200)
            with db.transaction():
                qm.confirm(bid, 200)

            row = db._conn.execute(
                "SELECT quota_used, quota_reserved FROM backends WHERE id = ?", (bid,)
            ).fetchone()
            assert row["quota_used"] == 200
            assert row["quota_reserved"] == 0
        finally:
            db.close()

    def test_restore_returns_reserved(self, tmp_path):
        db = _make_db(tmp_path)
        try:
            bid = _make_backend_row(db, quota_limit=1024)
            qm = QuotaManager(db)
            with db.transaction():
                qm.reserve(bid, 300)
            with db.transaction():
                qm.restore(bid, 300)

            row = db._conn.execute(
                "SELECT quota_reserved FROM backends WHERE id = ?", (bid,)
            ).fetchone()
            assert row["quota_reserved"] == 0
        finally:
            db.close()

    def test_double_spend_prevention(self, tmp_path):
        """Two reserves that together exceed quota -- second raises."""
        db = _make_db(tmp_path)
        try:
            bid = _make_backend_row(db, quota_limit=1000)
            qm = QuotaManager(db)
            with db.transaction():
                qm.reserve(bid, 700)
            with pytest.raises(QuotaReservationError):
                with db.transaction():
                    qm.reserve(bid, 400)  # 700 + 400 > 1000
        finally:
            db.close()

    def test_available_space(self, tmp_path):
        db = _make_db(tmp_path)
        try:
            bid = _make_backend_row(db, quota_limit=1000)
            qm = QuotaManager(db)
            assert qm.available_space(bid) == 1000
            with db.transaction():
                qm.reserve(bid, 200)
            assert qm.available_space(bid) == 800
        finally:
            db.close()


# ── chunker.py tests ──────────────────────────────────────────────────────────

class TestChunker:
    def test_single_chunk_for_small_file(self, tmp_path):
        f = tmp_path / "small.bin"
        f.write_bytes(b"x" * 1024)
        chunks = list(split_file(f, logical_chunk_bytes=1024 * 1024))
        assert len(chunks) == 1
        assert chunks[0].chunk_index == 0
        assert chunks[0].total_chunks == 1
        assert chunks[0].size == 1024

    def test_multiple_chunks_for_large_file(self, tmp_path):
        f = tmp_path / "large.bin"
        f.write_bytes(b"x" * (3 * 1024 * 1024 + 1))  # 3 MB + 1 byte
        chunks = list(split_file(f, logical_chunk_bytes=1024 * 1024))
        assert len(chunks) == 4
        assert chunks[0].size == 1024 * 1024
        assert chunks[3].size == 1  # Last chunk is 1 byte

    def test_chunks_cover_full_file(self, tmp_path):
        size = 7 * 1024 * 1024 + 512
        f = tmp_path / "test.bin"
        f.write_bytes(b"a" * size)
        chunks = list(split_file(f, logical_chunk_bytes=2 * 1024 * 1024))
        total = sum(c.size for c in chunks)
        assert total == size

    def test_empty_file_returns_manifest_entry(self, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_bytes(b"")
        chunks = list(split_file(f, logical_chunk_bytes=1024 * 1024))
        assert len(chunks) == 1
        assert chunks[0].is_manifest is True
        assert chunks[0].size == 0

    def test_chunk_offsets_are_contiguous(self, tmp_path):
        size = 5 * 1024 * 1024
        f = tmp_path / "test.bin"
        f.write_bytes(b"y" * size)
        chunks = list(split_file(f, logical_chunk_bytes=1024 * 1024))
        expected_offset = 0
        for c in chunks:
            assert c.offset == expected_offset
            expected_offset += c.size

    def test_total_chunks_consistent(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"z" * (3 * 1024))
        chunks = list(split_file(f, logical_chunk_bytes=1024))
        for c in chunks:
            assert c.total_chunks == 3

    def test_unicode_filename(self, tmp_path):
        f = tmp_path / "测试_ファイル_тест.bin"
        f.write_bytes(b"hello unicode")
        chunks = list(split_file(f, logical_chunk_bytes=1024))
        assert len(chunks) == 1

    def test_resolve_path_regular_file(self, tmp_path):
        f = tmp_path / "regular.txt"
        f.write_bytes(b"data")
        resolved = resolve_path(f)
        assert resolved == f

    def test_resolve_path_symlink(self, tmp_path):
        target = tmp_path / "real.txt"
        target.write_bytes(b"data")
        link = tmp_path / "link.txt"
        link.symlink_to(target)
        resolved = resolve_path(link)
        assert resolved == target.resolve()  # Use .resolve() to handle Windows //?/ prefix

    def test_resolve_path_missing_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            resolve_path(tmp_path / "nonexistent.txt")

    @pytest.mark.asyncio
    async def test_read_chunk_async_yields_correct_bytes(self, tmp_path):
        content = os.urandom(200 * 1024)  # 200 KB
        f = tmp_path / "test.bin"
        f.write_bytes(content)

        chunks = []
        async for block in read_chunk_async(f, offset=0, size=len(content)):
            chunks.append(block)

        assert b"".join(chunks) == content

    @pytest.mark.asyncio
    async def test_read_chunk_async_respects_offset(self, tmp_path):
        content = b"AAAA" + b"BBBB" + b"CCCC"
        f = tmp_path / "test.bin"
        f.write_bytes(content)

        result = b""
        async for block in read_chunk_async(f, offset=4, size=4):
            result += block

        assert result == b"BBBB"

    @pytest.mark.asyncio
    async def test_read_chunk_async_64kb_blocks(self, tmp_path):
        content = os.urandom(3 * 65_536)  # 3 x 64 KB
        f = tmp_path / "test.bin"
        f.write_bytes(content)

        blocks = []
        async for block in read_chunk_async(f, offset=0, size=len(content), block_size=65_536):
            blocks.append(block)

        assert len(blocks) == 3
        assert all(len(b) == 65_536 for b in blocks)
        assert b"".join(blocks) == content


class TestChunkUploader:
    @pytest.mark.asyncio
    async def test_upload_chunk_success(self, tmp_path):
        from ghostdrive.pipeline.upload import ChunkUploader
        from ghostdrive.crypto.nonce import NonceManager
        
        db = _make_db(tmp_path)
        backend_id = _make_backend_row(db)
        
        # Mock backend
        mock_backend = MagicMock()
        mock_backend.id = backend_id
        mock_backend.upload = AsyncMock(return_value="ref-12345")
        
        # Nonce manager
        nm = NonceManager(data_dir=tmp_path)
        
        # Test file
        file_path = tmp_path / "source.txt"
        file_path.write_bytes(b"A" * 1024)
        
        descriptor = ChunkDescriptor(
            chunk_index=0,
            offset=0,
            size=1024,
            total_chunks=1,
            is_manifest=False,
        )
        
        file_id = str(uuid.uuid4())
        
        # We need to insert a file record first because of foreign key constraint
        # from chunks to files
        now = "2024-01-01T00:00:00+00:00"
        with db.transaction():
            db.insert_file({
                "id": file_id, "name": "source.txt", "path": "/source.txt",
                "size": 1024, "mime_type": "text/plain", "tier": "IMPORTANT",
                "created_at": now, "modified_at": now,
                "version": 1, "version_of": None,
                "tombstone": 0, "tombstone_at": None,
            })
            
        uploader = ChunkUploader(
            db=db,
            backend=mock_backend,
            master_key=bytes(range(32)),
            hkdf_salt=bytes(range(32, 64)),
            nonce_manager=nm,
        )
        
        chunk_id = await uploader.upload_chunk(
            path=file_path,
            descriptor=descriptor,
            file_id=file_id,
            mime_type="text/plain",
        )
        
        assert chunk_id is not None
        
        # Verify DB entries
        # Verify chunk record exists
        chunk_row = db._conn.execute(
            "SELECT id, nonce_counter, size FROM chunks WHERE id = ?", (chunk_id,)
        ).fetchone()
        assert chunk_row is not None
        assert chunk_row["size"] == 1024
        assert chunk_row["nonce_counter"] == 1
        
        # Verify chunk location is confirmed
        loc_row = db._conn.execute(
            "SELECT status, reference_id FROM chunk_locations WHERE chunk_id = ?", (chunk_id,)
        ).fetchone()
        assert loc_row is not None
        assert loc_row["status"] == "confirmed"
        assert loc_row["reference_id"] == "ref-12345"
        
        # Verify quota used
        backend_row = db._conn.execute(
            "SELECT quota_used, quota_reserved FROM backends WHERE id = ?", (backend_id,)
        ).fetchone()
        assert backend_row["quota_used"] == 1024
        assert backend_row["quota_reserved"] == 0
        
        db.close()

    @pytest.mark.asyncio
    async def test_upload_chunk_backend_connection_error(self, tmp_path):
        from ghostdrive.pipeline.upload import ChunkUploader
        from ghostdrive.crypto.nonce import NonceManager
        from ghostdrive.exceptions import BackendConnectionError
        
        db = _make_db(tmp_path)
        backend_id = _make_backend_row(db)
        
        # Mock backend
        mock_backend = MagicMock()
        mock_backend.id = backend_id
        mock_backend.upload = AsyncMock(side_effect=BackendConnectionError("connection failed"))
        
        nm = NonceManager(data_dir=tmp_path)
        file_path = tmp_path / "source.txt"
        file_path.write_bytes(b"B" * 1024)
        
        descriptor = ChunkDescriptor(
            chunk_index=0,
            offset=0,
            size=1024,
            total_chunks=1,
            is_manifest=False,
        )
        file_id = str(uuid.uuid4())
        
        now = "2024-01-01T00:00:00+00:00"
        with db.transaction():
            db.insert_file({
                "id": file_id, "name": "source.txt", "path": "/source.txt",
                "size": 1024, "mime_type": "text/plain", "tier": "IMPORTANT",
                "created_at": now, "modified_at": now,
                "version": 1, "version_of": None,
                "tombstone": 0, "tombstone_at": None,
            })
            
        uploader = ChunkUploader(
            db=db,
            backend=mock_backend,
            master_key=bytes(range(32)),
            hkdf_salt=bytes(range(32, 64)),
            nonce_manager=nm,
        )
        
        with pytest.raises(BackendConnectionError):
            await uploader.upload_chunk(
                path=file_path,
                descriptor=descriptor,
                file_id=file_id,
                mime_type="text/plain",
            )
            
        # Verify status is failed
        loc_row = db._conn.execute(
            "SELECT status FROM chunk_locations"
        ).fetchone()
        assert loc_row is not None
        assert loc_row["status"] == "failed"
        
        # Verify quota restored
        backend_row = db._conn.execute(
            "SELECT quota_used, quota_reserved FROM backends WHERE id = ?", (backend_id,)
        ).fetchone()
        assert backend_row["quota_used"] == 0
        assert backend_row["quota_reserved"] == 0
        
        db.close()

    @pytest.mark.asyncio
    async def test_upload_chunk_unexpected_error(self, tmp_path):
        from ghostdrive.pipeline.upload import ChunkUploader
        from ghostdrive.crypto.nonce import NonceManager
        from ghostdrive.exceptions import ChunkError
        
        db = _make_db(tmp_path)
        backend_id = _make_backend_row(db)
        
        mock_backend = MagicMock()
        mock_backend.id = backend_id
        mock_backend.upload = AsyncMock(side_effect=ValueError("unexpected crash"))
        
        nm = NonceManager(data_dir=tmp_path)
        file_path = tmp_path / "source.txt"
        file_path.write_bytes(b"C" * 1024)
        
        descriptor = ChunkDescriptor(
            chunk_index=0,
            offset=0,
            size=1024,
            total_chunks=1,
            is_manifest=False,
        )
        file_id = str(uuid.uuid4())
        
        now = "2024-01-01T00:00:00+00:00"
        with db.transaction():
            db.insert_file({
                "id": file_id, "name": "source.txt", "path": "/source.txt",
                "size": 1024, "mime_type": "text/plain", "tier": "IMPORTANT",
                "created_at": now, "modified_at": now,
                "version": 1, "version_of": None,
                "tombstone": 0, "tombstone_at": None,
            })
            
        uploader = ChunkUploader(
            db=db,
            backend=mock_backend,
            master_key=bytes(range(32)),
            hkdf_salt=bytes(range(32, 64)),
            nonce_manager=nm,
        )
        
        with pytest.raises(ChunkError) as exc_info:
            await uploader.upload_chunk(
                path=file_path,
                descriptor=descriptor,
                file_id=file_id,
                mime_type="text/plain",
            )
        assert "unexpected crash" in str(exc_info.value)
            
        # Verify status is failed
        loc_row = db._conn.execute(
            "SELECT status FROM chunk_locations"
        ).fetchone()
        assert loc_row is not None
        assert loc_row["status"] == "failed"
        
        db.close()

    @pytest.mark.asyncio
    async def test_upload_chunk_cancellation(self, tmp_path):
        from ghostdrive.pipeline.upload import ChunkUploader
        from ghostdrive.crypto.nonce import NonceManager
        
        db = _make_db(tmp_path)
        backend_id = _make_backend_row(db)
        
        mock_backend = MagicMock()
        mock_backend.id = backend_id
        mock_backend.upload = AsyncMock(side_effect=asyncio.CancelledError())
        mock_backend.delete = AsyncMock(return_value=True)
        
        nm = NonceManager(data_dir=tmp_path)
        file_path = tmp_path / "source.txt"
        file_path.write_bytes(b"D" * 1024)
        
        descriptor = ChunkDescriptor(
            chunk_index=0,
            offset=0,
            size=1024,
            total_chunks=1,
            is_manifest=False,
        )
        file_id = str(uuid.uuid4())
        
        now = "2024-01-01T00:00:00+00:00"
        with db.transaction():
            db.insert_file({
                "id": file_id, "name": "source.txt", "path": "/source.txt",
                "size": 1024, "mime_type": "text/plain", "tier": "IMPORTANT",
                "created_at": now, "modified_at": now,
                "version": 1, "version_of": None,
                "tombstone": 0, "tombstone_at": None,
            })
            
        uploader = ChunkUploader(
            db=db,
            backend=mock_backend,
            master_key=bytes(range(32)),
            hkdf_salt=bytes(range(32, 64)),
            nonce_manager=nm,
        )
        
        with pytest.raises(asyncio.CancelledError):
            await uploader.upload_chunk(
                path=file_path,
                descriptor=descriptor,
                file_id=file_id,
                mime_type="text/plain",
            )
            
        # Verify status is cancelled
        loc_row = db._conn.execute(
            "SELECT status FROM chunk_locations"
        ).fetchone()
        assert loc_row is not None
        assert loc_row["status"] == "cancelled"
        
        # Verify quota restored
        backend_row = db._conn.execute(
            "SELECT quota_used, quota_reserved FROM backends WHERE id = ?", (backend_id,)
        ).fetchone()
        assert backend_row["quota_used"] == 0
        assert backend_row["quota_reserved"] == 0
        
        db.close()
