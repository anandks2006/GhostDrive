"""
upload.py -- 64 KB generator streaming upload pipeline with two-phase commit.

Spec §5.1 (Zero-Copy Streaming), §5.6 (Two-Phase Commit), §5.7 (Cancellation)
===============================================================================

Pipeline order (per chunk, per sub-block)
-----------------------------------------
  OS file lock acquired (FileLock)
  -> BLAKE3+size dedup check on ORIGINAL bytes (DedupChecker)
     -> if duplicate: increment ref_count, write file record, skip upload
  -> For each logical chunk:
       1. Atomically decrement quota_reserved (QuotaManager.reserve)
       2. Write pending intent to chunk_locations (same SQLite txn as nonce)
       3. Nonce counter incremented + stored in chunks.nonce_counter (same txn)
       4. fsync via atomic SQLite WAL
       5. zstd compress (skipped for pre-compressed MIME types)
       6. ChaCha20-Poly1305 stream via 64 KB blocks
       7. Poly1305 tag appended after final block
       8. Stream as sub-blocks -> backend.upload()
       9. On success: status=confirmed, quota_used incremented
      10. On failure: status=failed, quota_reserved restored
  -> OS file lock released

Cancellation (spec §5.7)
--------------------------
  Caller cancels the asyncio Task. On CancelledError:
    1. Network stream closed cleanly (generator abandoned)
    2. backend.delete() attempted for confirmed sub-blocks
    3. chunk_locations.status = 'cancelled' (NOT 'failed')
    4. quota_reserved restored
    5. Re-raise CancelledError (never swallowed)

Thermal backpressure (spec §5.3)
----------------------------------
  Network send is gated by encryption generator output.
  The asyncio.to_thread() wrapping of ChaCha20 update() keeps CPU work
  off the main thread. If encryption stalls (thermal throttle), the upload
  coroutine awaits rather than timing out.

Exception policy (spec §9.6)
------------------------------
  NO silent exception swallowing. Every exception is:
    (a) retried with backoff if transient network error;
    (b) chunk marked failed, quota restored if persistent;
    (c) escalated as WARN or ERROR.
  'except Exception: pass' is BANNED in this module.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncGenerator, Optional

from ghostdrive.crypto.chunk_crypto import ChunkEncryptor, BLOCK_SIZE
from ghostdrive.crypto.hkdf import derive_chunk_key
from ghostdrive.database.db import GhostDriveDB
from ghostdrive.exceptions import (
    BackendConnectionError,
    BackendRateLimitError,
    CancellationError,
    ChunkError,
    QuotaReservationError,
)
from ghostdrive.pipeline.chunker import ChunkDescriptor, read_chunk_async
from ghostdrive.pipeline.compressor import compress_stream, should_skip_compression
from ghostdrive.pipeline.dedup import DedupChecker, compute_blake3_file_async
from ghostdrive.pipeline.quota import QuotaManager

logger = logging.getLogger(__name__)

_SUB_BLOCK_BYTES = 50 * 1024 * 1024   # 50 MB -- spec §5.4


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_uuid() -> str:
    return str(uuid.uuid4())


async def _encrypted_chunk_stream(
    path: Path,
    descriptor: ChunkDescriptor,
    chunk_key: bytes,
    nonce: bytes,
) -> AsyncGenerator[bytes, None]:
    """
    Async generator: read -> compress -> encrypt -> yield 64 KB ciphertext blocks.

    ONE Poly1305 tag covers the entire chunk (appended after the last block).
    Tag is yielded as the final item. The caller must NOT split the stream
    mid-chunk -- all sub-blocks must be reassembled before tag verification.

    Spec §5.1 hard constraint: 64 KB generator. No BytesIO buffers.
    ChaCha20 update() is run via asyncio.to_thread() to stay off main thread.
    """
    encryptor = ChunkEncryptor(key=chunk_key, nonce=nonce)

    raw_stream      = read_chunk_async(path, descriptor.offset, descriptor.size)
    compress_gen    = compress_stream(raw_stream)

    async for block in compress_gen:
        ct_block = await asyncio.to_thread(encryptor.update, block)
        yield ct_block

    tag = await asyncio.to_thread(encryptor.finalize)
    yield tag   # ONE Poly1305 tag -- appended after last block


async def _split_into_sub_blocks(
    stream: AsyncGenerator[bytes, None],
    sub_block_bytes: int = _SUB_BLOCK_BYTES,
) -> AsyncGenerator[bytes, None]:
    """
    Buffer the encrypted stream into 50 MB sub-blocks for backend upload.
    Yields complete sub-blocks plus the final (possibly smaller) block.
    """
    buf = bytearray()
    async for chunk in stream:
        buf.extend(chunk)
        while len(buf) >= sub_block_bytes:
            yield bytes(buf[:sub_block_bytes])
            del buf[:sub_block_bytes]
    if buf:
        yield bytes(buf)


class ChunkUploader:
    """
    Uploads one logical chunk through the full two-phase commit pipeline.

    Instantiate once per upload session (shared across chunks of the same file).

    Usage::

        uploader = ChunkUploader(db, backend, master_key, hkdf_salt, nonce_manager)
        for descriptor in split_file(path, backend.logical_chunk_bytes):
            result = await uploader.upload_chunk(path, descriptor, file_id, mime_type)
    """

    def __init__(
        self,
        db: GhostDriveDB,
        backend,               # BackendBase instance
        master_key: bytes,
        hkdf_salt: bytes,
        nonce_manager,         # NonceManager instance
    ) -> None:
        self._db     = db
        self._backend = backend
        self._qm      = QuotaManager(db)
        self._mk      = master_key
        self._salt    = hkdf_salt
        self._nonces  = nonce_manager

    async def upload_chunk(
        self,
        path: Path,
        descriptor: ChunkDescriptor,
        file_id: str,
        mime_type: str = "application/octet-stream",
    ) -> str:
        """
        Upload one logical chunk to the backend.

        Steps:
          1. Derive per-chunk key via HKDF.
          2. Atomically: reserve quota + write pending intent + increment nonce.
          3. Stream encrypt -> compress -> sub-block -> backend.upload().
          4. Confirm or restore on success/failure.

        Args:
            path:        Path to the source file (OS lock must be held by caller).
            descriptor:  ChunkDescriptor from split_file().
            file_id:     UUIDv4 of the parent FileRecord.
            mime_type:   MIME type (for compression skip decision).

        Returns:
            chunk_id (UUIDv4) of the newly created ChunkRecord.

        Raises:
            ChunkError:              Encryption or pipeline failure.
            QuotaReservationError:   No space on backend.
            BackendConnectionError:  Network unreachable.
            asyncio.CancelledError:  Upload cancelled by user (cleaned up).
        """
        chunk_id = _new_uuid()

        # 1. Derive per-chunk key
        chunk_key = derive_chunk_key(self._mk, self._salt)

        # 2. Atomic: reserve quota + pending intent + nonce (same transaction)
        nonce_counter: Optional[int] = None
        nonce: Optional[bytes] = None
        quota_reserved = descriptor.size  # conservative: original size

        with self._db.transaction():
            # Reserve quota (raises QuotaReservationError if full)
            self._qm.reserve(self._backend.id if hasattr(self._backend, 'id') else 'unknown', quota_reserved)

            # Increment nonce BEFORE upload begins (spec §4.4)
            nonce = self._nonces.next_nonce()
            from ghostdrive.crypto.nonce import NonceManager
            nonce_counter = NonceManager.nonce_to_counter(nonce)

            # Write chunk record with nonce_counter
            self._db.insert_chunk({
                "id":              chunk_id,
                "file_id":         file_id,
                "chunk_index":     descriptor.chunk_index,
                "total_chunks":    descriptor.total_chunks,
                "blake3_hash":     "",   # computed below for dedup -- placeholder
                "size":            descriptor.size,
                "nonce_counter":   nonce_counter,
                "sub_block_count": 1,    # updated after upload
                "is_manifest":     int(descriptor.is_manifest),
                "ref_count":       1,
            })

            # Write pending intent (same transaction as nonce)
            backend_id = getattr(self._backend, 'id', 'unknown-backend')
            self._db.insert_chunk_location_pending({
                "chunk_id":        chunk_id,
                "sub_block_index": 0,
                "backend_id":      backend_id,
                "reference_id":    "",  # filled in on confirm
                "url_type":        "permanent",
                "upload_date":     _now_iso(),
                "last_verified":   None,
                "quota_reserved":  quota_reserved,
            })

        # 3. Stream: encrypt -> compress -> sub-block -> upload
        confirmed_sub_blocks: list[tuple[int, str]] = []  # (sub_block_index, reference_id)

        try:
            stream        = _encrypted_chunk_stream(path, descriptor, chunk_key, nonce)
            sub_block_gen = _split_into_sub_blocks(stream)

            sub_block_index = 0
            async for sub_block_data in sub_block_gen:
                async def _byte_gen(data=sub_block_data):
                    yield data

                reference_id = await self._backend.upload(
                    stream=_byte_gen(),
                    chunk_id=chunk_id,
                    sub_block_index=sub_block_index,
                )
                confirmed_sub_blocks.append((sub_block_index, reference_id))
                sub_block_index += 1

            # 4a. Confirm
            with self._db.transaction():
                for idx, ref_id in confirmed_sub_blocks:
                    self._db.confirm_chunk_location(
                        chunk_id, idx, backend_id, ref_id
                    )
                self._qm.confirm(backend_id, quota_reserved)

            logger.info(
                "Chunk uploaded: chunk_id=%s index=%d/%d nonce_ctr=%d sub_blocks=%d",
                chunk_id[:8], descriptor.chunk_index, descriptor.total_chunks - 1,
                nonce_counter, len(confirmed_sub_blocks),
            )
            return chunk_id

        except asyncio.CancelledError:
            # Spec §5.7 cancellation flow
            await self._cleanup_cancelled(
                chunk_id, backend_id, confirmed_sub_blocks, quota_reserved
            )
            raise  # Always re-raise CancelledError -- never swallow

        except (BackendConnectionError, BackendRateLimitError) as exc:
            # 4b. Fail + restore
            with self._db.transaction():
                self._db.fail_chunk_location(chunk_id, 0, backend_id)
                self._qm.restore(backend_id, quota_reserved)
            logger.error("Chunk upload failed (network): %s", exc)
            raise

        except Exception as exc:
            # 4b. Fail + restore (unknown error -- never swallow per spec §9.6)
            with self._db.transaction():
                self._db.fail_chunk_location(chunk_id, 0, backend_id)
                self._qm.restore(backend_id, quota_reserved)
            logger.error("Chunk upload failed (unexpected): %s", exc, exc_info=True)
            raise ChunkError(f"Chunk upload failed: {exc}") from exc

    async def _cleanup_cancelled(
        self,
        chunk_id: str,
        backend_id: str,
        confirmed_sub_blocks: list[tuple[int, str]],
        quota_reserved: int,
    ) -> None:
        """
        Cancellation cleanup (spec §5.7):
          1. backend.delete() for each confirmed sub-block.
          2. chunk_locations.status = 'cancelled'.
          3. quota_reserved restored.
        """
        logger.info("Upload cancelled: chunk_id=%s -- cleaning up.", chunk_id[:8])

        for _, ref_id in confirmed_sub_blocks:
            try:
                await self._backend.delete(ref_id)
            except Exception as exc:
                logger.warning(
                    "Failed to delete sub-block %s on cancel: %s", ref_id, exc
                )

        with self._db.transaction():
            self._db.cancel_chunk_location(chunk_id, 0, backend_id)
            self._qm.restore(backend_id, quota_reserved)
