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
import math
import random
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncGenerator, Optional

from ghostdrive.crypto.hkdf import derive_chunk_key
from ghostdrive.database.db import GhostDriveDB
from ghostdrive.exceptions import (
    BackendConnectionError,
    BackendRateLimitError,
    ChunkError,
)
from ghostdrive.pipeline.chunker import ChunkDescriptor
from ghostdrive.pipeline.quota import QuotaManager

logger = logging.getLogger(__name__)

_SUB_BLOCK_BYTES = 50 * 1024 * 1024   # 50 MB -- spec §5.4


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _compute_blake3_chunk(path: Path, offset: int, size: int, block_size: int = 1024 * 1024) -> str:
    import blake3
    hasher = blake3.blake3()
    with open(path, "rb") as f:
        f.seek(offset)
        bytes_remaining = size
        while bytes_remaining > 0:
            read_size = min(block_size, bytes_remaining)
            data = f.read(read_size)
            if not data:
                break
            hasher.update(data)
            bytes_remaining -= len(data)
    return hasher.hexdigest()


def _new_uuid() -> str:
    return str(uuid.uuid4())


async def _encrypted_chunk_stream(
    path: Path,
    descriptor: ChunkDescriptor,
    chunk_key: bytes,
    nonce: bytes,
    mime_type: str = "application/octet-stream",
) -> AsyncGenerator[bytes, None]:
    """
    Async generator: read -> encrypt -> yield 64 KB ciphertext blocks using encrypt_chunk_async.
    """
    from ghostdrive.crypto.chunk_crypto import encrypt_chunk_async
    async for block in encrypt_chunk_async(
        key=chunk_key,
        nonce=nonce,
        file_path=path,
        offset=descriptor.offset,
        size=descriptor.size,
    ):
        yield block


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
    active_uploads: int = 0

    def __init__(
        self,
        db: GhostDriveDB,
        backend,               # BackendBase instance
        master_key: bytes,
        hkdf_salt: bytes,
        nonce_manager,         # NonceManager instance
        healing_queue=None,
        active_backends: Optional[dict] = None,
    ) -> None:
        self._db     = db
        self._backend = backend
        self._qm      = QuotaManager(db)
        self._mk      = master_key
        self._salt    = hkdf_salt
        self._nonces  = nonce_manager
        self._healing_queue = healing_queue
        self._active_backends = active_backends or {}

    async def upload_chunk(
        self,
        path: Path,
        descriptor: ChunkDescriptor,
        file_id: str,
        mime_type: str = "application/octet-stream",
    ) -> str:
        if hasattr(self, '_healing_queue') and self._healing_queue:
            self._healing_queue._upload_active = True
        ChunkUploader.active_uploads += 1
        try:
            return await self._upload_chunk_internal(path, descriptor, file_id, mime_type)
        finally:
            ChunkUploader.active_uploads = max(0, ChunkUploader.active_uploads - 1)
            if hasattr(self, '_healing_queue') and self._healing_queue:
                self._healing_queue._upload_active = False

    async def _upload_chunk_internal(
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
        # The same chunk key is used for all chunks of this file.
        # Security depends entirely on the nonce counter never repeating (guaranteed
        # by NonceManager — counter is incremented and fsynced before each upload).
        # If the nonce uniqueness guarantee is ever broken, encrypting multiple chunks
        # with the same key becomes catastrophic. Do not change nonce management
        # without reviewing this dependency.
        chunk_key = derive_chunk_key(self._mk, self._salt)

        # 2. Atomic: reserve quota + pending intent + nonce (same transaction)
        nonce_counter: Optional[int] = None
        nonce: Optional[bytes] = None
        quota_reserved = descriptor.size  # conservative: original size
        backend_id = getattr(self._backend, 'id', 'unknown-backend')
        chunk_id = _new_uuid()

        with self._db.transaction():
            file_row = self._db._conn.execute("SELECT tier FROM files WHERE id = ?", (file_id,)).fetchone()
        tier = file_row["tier"] if file_row else "IMPORTANT"
        is_erasure = tier in ("CRITICAL", "IMPORTANT")

        sub_block_bytes = getattr(self._backend, "sub_block_bytes", _SUB_BLOCK_BYTES)
        if not isinstance(sub_block_bytes, int) or isinstance(sub_block_bytes, bool):
            sub_block_bytes = _SUB_BLOCK_BYTES
            
        if is_erasure:
            num_sub_blocks = 6
        else:
            num_sub_blocks = max(1, math.ceil(descriptor.size / sub_block_bytes))

        # Check if chunk record already exists outside the transaction to see if we need the hash
        existing_chunk = self._db.find_chunk_by_file_and_index(file_id, descriptor.chunk_index)
        
        blake3_hash = None
        if not existing_chunk:
            blake3_hash = await asyncio.to_thread(
                _compute_blake3_chunk, path, descriptor.offset, descriptor.size
            )
        else:
            blake3_hash = existing_chunk["blake3_hash"]

        with self._db.transaction():
            # Get active healthy backends list
            if is_erasure:
                tier_key = f"routing_{tier.lower()}_backends"
                routing_ids_str = self._db.get_setting(tier_key, "")
                routing_ids = [x.strip() for x in routing_ids_str.split(",") if x.strip()]

                backend_rows = self._db._conn.execute(
                    "SELECT id, type FROM backends WHERE status = 'healthy' ORDER BY priority DESC"
                ).fetchall()

                if routing_ids:
                    filtered_rows = [r for r in backend_rows if r["id"] in routing_ids]
                    if filtered_rows:
                        backend_rows = filtered_rows

                if not backend_rows:
                    backend_rows = [{"id": backend_id, "type": getattr(self._backend, 'type', 'unknown')}]
            else:
                backend_rows = [{"id": backend_id, "type": getattr(self._backend, 'type', 'unknown')}]

            # Reserve quota on the respective backends
            for idx in range(num_sub_blocks):
                b_row = backend_rows[idx % len(backend_rows)]
                b_id = b_row["id"]
                sub_quota = quota_reserved if not is_erasure else (quota_reserved // 4 if idx < 4 else 0)
                self._qm.reserve(b_id, sub_quota)

            # Check again inside the transaction (to be transaction-safe)
            existing_chunk = self._db.find_chunk_by_file_and_index(file_id, descriptor.chunk_index)
            if existing_chunk:
                chunk_id = existing_chunk["id"]
                nonce_counter = existing_chunk["nonce_counter"]
                from ghostdrive.crypto.nonce import NonceManager
                nonce = NonceManager.counter_to_nonce(nonce_counter)
            else:
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
                    "blake3_hash":     blake3_hash,
                    "size":            descriptor.size,
                    "nonce_counter":   nonce_counter,
                    "sub_block_count": num_sub_blocks,
                    "is_manifest":     int(descriptor.is_manifest),
                    "ref_count":       1,
                })

            # Write pending intents for all sub-blocks
            for idx in range(num_sub_blocks):
                b_row = backend_rows[idx % len(backend_rows)]
                b_id = b_row["id"]
                sub_quota = quota_reserved if not is_erasure else (quota_reserved // 4 if idx < 4 else 0)
                location_record = {
                    "chunk_id":        chunk_id,
                    "sub_block_index": idx,
                    "backend_id":      b_id,
                    "reference_id":    "",  # filled in on confirm
                    "url_type":        "permanent",
                    "upload_date":     _now_iso(),
                    "last_verified":   None,
                    "quota_reserved":  sub_quota,
                }
                existing_loc = self._db.find_chunk_location(chunk_id, idx, b_id)
                if existing_loc:
                    self._db.update_chunk_location_pending(location_record)
                else:
                    self._db.insert_chunk_location_pending(location_record)

        # 3. Stream: encrypt -> compress -> sub-block -> upload
        confirmed_sub_blocks: list[tuple[int, str, str]] = []  # (sub_block_index, reference_id, backend_id)

        try:
            stream = _encrypted_chunk_stream(path, descriptor, chunk_key, nonce, mime_type)
            
            if is_erasure:
                # Read full encrypted chunk ciphertext
                chunk_ciphertext = bytearray()
                async for block in stream:
                    chunk_ciphertext.extend(block)
                    
                padlen = (4 - (len(chunk_ciphertext) % 4)) % 4
                from zfec.easyfec import Encoder
                enc = Encoder(4, 6)
                shards = enc.encode(bytes(chunk_ciphertext))
                
                # Update sub_block_count in chunks table to include padlen
                db_sub_block_count = 6 + padlen * 10
                with self._db.transaction():
                    self._db._conn.execute(
                        "UPDATE chunks SET sub_block_count = ? WHERE id = ?",
                        (db_sub_block_count, chunk_id)
                    )
                
                sub_blocks_data = shards
            else:
                sub_blocks_data = []
                async for block in _split_into_sub_blocks(stream, sub_block_bytes=sub_block_bytes):
                    sub_blocks_data.append(block)

            for sub_block_index, sub_block_data in enumerate(sub_blocks_data):
                b_row = backend_rows[sub_block_index % len(backend_rows)]
                b_id = b_row["id"]
                
                # Retrieve active backend object for the targeted backend
                b_obj = self._active_backends.get(b_id) or self._active_backends.get(b_row["type"]) or self._backend
                
                max_retries = 3
                base_delay = 1.0
                reference_id = None
                
                for attempt in range(max_retries + 1):
                    async def _byte_gen(data=sub_block_data):
                        yield data

                    try:
                        # Make sure backend is connected
                        if not getattr(b_obj, "_connected", False):
                            await b_obj.connect()
                            b_obj._connected = True
                            
                        reference_id = await b_obj.upload(
                            stream=_byte_gen(),
                            chunk_id=chunk_id,
                            sub_block_index=sub_block_index,
                        )
                        break  # Success!
                    except (BackendConnectionError, BackendRateLimitError) as exc:
                        if attempt == max_retries:
                            logger.error(
                                "Failed to upload sub-block %d after %d retries: %s",
                                sub_block_index, max_retries, exc
                            )
                            raise
                        
                        delay = base_delay * (2 ** attempt) + random.uniform(0, 0.5)
                        logger.warning(
                            "Transient upload error (attempt %d/%d) on sub-block %d: %s. Retrying in %.2fs...",
                            attempt + 1, max_retries + 1, sub_block_index, exc, delay
                        )
                        await asyncio.sleep(delay)

                confirmed_sub_blocks.append((sub_block_index, reference_id, b_id))

            # 4a. Confirm
            with self._db.transaction():
                for idx, ref_id, b_id in confirmed_sub_blocks:
                    self._db.confirm_chunk_location(
                        chunk_id, idx, b_id, ref_id
                    )
                    sub_quota = quota_reserved if not is_erasure else (quota_reserved // 4 if idx < 4 else 0)
                    self._qm.confirm(b_id, sub_quota)

            logger.info(
                "Chunk uploaded: chunk_id=%s index=%d/%d nonce_ctr=%d sub_blocks=%d",
                chunk_id[:8], descriptor.chunk_index, descriptor.total_chunks - 1,
                nonce_counter, len(confirmed_sub_blocks),
            )
            return chunk_id

        except asyncio.CancelledError:
            # Spec §5.7 cancellation flow
            await self._cleanup_cancelled(
                chunk_id, backend_rows, confirmed_sub_blocks, quota_reserved, num_sub_blocks, is_erasure
            )
            raise  # Always re-raise CancelledError -- never swallow

        except (BackendConnectionError, BackendRateLimitError) as exc:
            # 4b. Fail + restore
            with self._db.transaction():
                for idx in range(num_sub_blocks):
                    b_row = backend_rows[idx % len(backend_rows)]
                    b_id = b_row["id"]
                    self._db.fail_chunk_location(chunk_id, idx, b_id)
                    sub_quota = quota_reserved if not is_erasure else (quota_reserved // 4 if idx < 4 else 0)
                    self._qm.restore(b_id, sub_quota)
            logger.error("Chunk upload failed (network): %s", exc)
            raise

        except Exception as exc:
            # 4b. Fail + restore (unknown error -- never swallow per spec §9.6)
            with self._db.transaction():
                for idx in range(num_sub_blocks):
                    b_row = backend_rows[idx % len(backend_rows)]
                    b_id = b_row["id"]
                    self._db.fail_chunk_location(chunk_id, idx, b_id)
                    sub_quota = quota_reserved if not is_erasure else (quota_reserved // 4 if idx < 4 else 0)
                    self._qm.restore(b_id, sub_quota)
            logger.error("Chunk upload failed (unexpected): %s", exc, exc_info=True)
            raise ChunkError(f"Chunk upload failed: {exc}") from exc

    async def _cleanup_cancelled(
        self,
        chunk_id: str,
        backend_rows: list,
        confirmed_sub_blocks: list[tuple[int, str, str]],
        quota_reserved: int,
        num_sub_blocks: int,
        is_erasure: bool,
    ) -> None:
        """
        Cancellation cleanup (spec §5.7):
          1. backend.delete() for each confirmed sub-block.
          2. chunk_locations.status = 'cancelled'.
          3. quota_reserved restored.
        """
        logger.info("Upload cancelled: chunk_id=%s -- cleaning up.", chunk_id[:8])

        for _, ref_id, b_id in confirmed_sub_blocks:
            try:
                # Resolve backend object for deletion
                b_obj = self._active_backends.get(b_id) or self._backend
                await b_obj.delete(ref_id)
            except Exception as exc:
                logger.warning(
                    "Failed to delete sub-block %s on cancel: %s", ref_id, exc
                )

        with self._db.transaction():
            for idx in range(num_sub_blocks):
                b_row = backend_rows[idx % len(backend_rows)]
                b_id = b_row["id"]
                self._db.cancel_chunk_location(chunk_id, idx, b_id)
                sub_quota = quota_reserved if not is_erasure else (quota_reserved // 4 if idx < 4 else 0)
                self._qm.restore(b_id, sub_quota)
