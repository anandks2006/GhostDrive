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
          (erasure chunks fan the n shard writes out concurrently, bounded
           by _MAX_PARALLEL_SHARD_WRITES -- see the fan-out comment)
       9. On success: status=confirmed, quota_used incremented
          (all DB bookkeeping runs AFTER every shard write finished,
           sequentially in the main task)
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
from ghostdrive.pipeline.coding import DATA_SHARDS, TOTAL_SHARDS, padlen_for, plan_coding
from ghostdrive.pipeline.quota import QuotaManager
from ghostdrive.services.durability import (
    assign_shards_to_backends,
    backend_failure_domain,
)

logger = logging.getLogger(__name__)

_SUB_BLOCK_BYTES = 50 * 1024 * 1024   # 50 MB -- spec §5.4

# Upper bound on concurrent shard writes during the erasure fan-out. Why 4:
# an 8-shard CRITICAL chunk would otherwise open 8 sockets at once, and those
# shards can land on the same provider (fewer failure domains than shards, or
# one operator behind several backend rows). Four keeps the parallelism where
# it pays -- across independent failure domains -- without saturating a single
# provider's connection or rate limits.
_MAX_PARALLEL_SHARD_WRITES = 4


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


def _erasure_shard_bytes(chunk_size: int, k: int = DATA_SHARDS) -> int:
    """Exact zfec shard size, including the Poly1305 tag and 4-byte padding."""
    return max(1, math.ceil((chunk_size + 16) / k))


def _quota_sizes(
    descriptor: ChunkDescriptor,
    sub_block_bytes: int,
    is_erasure: bool,
    total_shards: int = TOTAL_SHARDS,
) -> list[int]:
    """Per-sub-block reservation sizes.

    Erasure-coded chunks write all ``total_shards`` shards (6 for the 4+2
    floor, 8 when the adaptive planner chose 4+4), not just the data shards.
    Non-erasure chunks reserve the actual encrypted sub-block sizes, including
    the final 16-byte tag.
    """
    if is_erasure:
        return [_erasure_shard_bytes(descriptor.size)] * total_shards

    encrypted_size = descriptor.size + 16
    sub_blocks = max(1, math.ceil(encrypted_size / sub_block_bytes))
    return [
        min(sub_block_bytes, encrypted_size - (index * sub_block_bytes))
        for index in range(sub_blocks)
    ]


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
        backend_id = getattr(self._backend, 'id', 'unknown-backend')
        chunk_id = _new_uuid()

        with self._db.transaction():
            file_row = self._db._conn.execute("SELECT tier FROM files WHERE id = ?", (file_id,)).fetchone()
        tier = file_row["tier"] if file_row else "IMPORTANT"
        is_erasure = tier in ("CRITICAL", "IMPORTANT")

        sub_block_bytes = getattr(self._backend, "sub_block_bytes", _SUB_BLOCK_BYTES)
        if not isinstance(sub_block_bytes, int) or isinstance(sub_block_bytes, bool):
            sub_block_bytes = _SUB_BLOCK_BYTES

        # Candidate backend selection is read-only, so it is safe to run it
        # before the write transaction. The adaptive coding planner needs the
        # number of distinct failure domains the candidates span in order to
        # pick (k, n) before quota sizing.
        candidate_rows = None
        k, n = DATA_SHARDS, TOTAL_SHARDS
        if is_erasure:
            tier_key = f"routing_{tier.lower()}_backends"
            routing_ids_str = self._db.get_setting(tier_key, "")
            routing_ids = [x.strip() for x in routing_ids_str.split(",") if x.strip()]

            candidate_rows = self._db._conn.execute(
                "SELECT * FROM backends WHERE status = 'healthy' ORDER BY priority DESC"
            ).fetchall()

            if routing_ids:
                filtered_rows = [r for r in candidate_rows if r["id"] in routing_ids]
                if filtered_rows:
                    candidate_rows = filtered_rows

            if not candidate_rows:
                candidate_rows = [{
                    "id": backend_id,
                    "type": getattr(self._backend, 'type', 'unknown'),
                    "credentials_ref": "",
                }]

            domain_count = len({
                backend_failure_domain(row, self._active_backends.get(str(row["id"])))["id"]
                for row in candidate_rows
            })
            scheme = self._db.get_setting("erasure_scheme", "auto")
            k, n = plan_coding(tier, domain_count, {"erasure_scheme": scheme})

        quota_sizes = _quota_sizes(descriptor, sub_block_bytes, is_erasure, total_shards=n)
        num_sub_blocks = len(quota_sizes)

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
            if is_erasure:
                # One shard per failure domain per round. Separate backend rows
                # that share a disk do not count as separate domains.
                backend_rows = assign_shards_to_backends(
                    candidate_rows, num_sub_blocks, self._active_backends, tier=tier
                )
                if not backend_rows:
                    backend_rows = [candidate_rows[0]] * num_sub_blocks
            else:
                backend_rows = [{
                    "id": backend_id,
                    "type": getattr(self._backend, 'type', 'unknown'),
                    "credentials_ref": "",
                }] * num_sub_blocks

            # Reserve quota for every shard on its assigned backend. The old
            # 4-of-6 accounting under-reserved the two parity shards.
            for idx in range(num_sub_blocks):
                self._qm.reserve(backend_rows[idx]["id"], quota_sizes[idx])

            # Check again inside the transaction (to be transaction-safe)
            existing_chunk = self._db.find_chunk_by_file_and_index(file_id, descriptor.chunk_index)
            if existing_chunk:
                chunk_id = existing_chunk["id"]
                nonce_counter = existing_chunk["nonce_counter"]
                from ghostdrive.crypto.nonce import NonceManager
                nonce = NonceManager.counter_to_nonce(nonce_counter)
            else:
                # Increment nonce BEFORE upload begins (spec A4.4)
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
                b_id = backend_rows[idx]["id"]
                location_record = {
                    "chunk_id":        chunk_id,
                    "sub_block_index": idx,
                    "backend_id":      b_id,
                    "reference_id":    "",  # filled in on confirm
                    "url_type":        "permanent",
                    "upload_date":     _now_iso(),
                    "last_verified":   None,
                    "quota_reserved":  quota_sizes[idx],
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
                    
                padlen = padlen_for(len(chunk_ciphertext), k)
                from zfec.easyfec import Encoder
                enc = Encoder(k, n)
                shards = enc.encode(bytes(chunk_ciphertext))
                
                # Store the legacy counter and explicit coding parameters.
                db_sub_block_count = n + padlen * 10
                with self._db.transaction():
                    self._db._conn.execute(
                        "UPDATE chunks SET sub_block_count = ?, erasure_k = ?, erasure_n = ?, erasure_padlen = ? WHERE id = ?",
                        (db_sub_block_count, k, n, padlen, chunk_id)
                    )
                
                sub_blocks_data = shards
            else:
                sub_blocks_data = []
                async for block in _split_into_sub_blocks(stream, sub_block_bytes=sub_block_bytes):
                    sub_blocks_data.append(block)

            # ── Shard write fan-out ──────────────────────────────────────────
            # Concurrency decision: gather tasks do ONLY backend I/O; every DB
            # write happens sequentially here in the main task afterwards
            # (option (b), chosen for safety). Why: GhostDriveDB.transaction()
            # serialises writers with a *threading* RLock around BEGIN/COMMIT
            # on ONE shared sqlite3 connection (db.py _Transaction). asyncio
            # sibling tasks all run on the same thread, and an RLock is
            # re-entrant per thread -- so a second task could acquire it while
            # the first still holds it and interleave statements inside an open
            # transaction (BEGIN would even raise "cannot start a transaction
            # within a transaction"), and the BEGIN retry path time.sleep()s,
            # which would stall the event loop. Running confirm/quota/HMAC
            # writes inside the gather tasks is therefore unsafe; correctness
            # over concurrency.
            #
            # Only the erasure path fans out: its shards are laid out one per
            # failure domain across DIFFERENT backends, which is where
            # parallelism pays (2-4x on 6-8 shard uploads). A non-erasure
            # chunk's sub-blocks all target a single backend -- fanning those
            # out would only open several sockets to one provider -- so that
            # path keeps its original strict sequencing (and still aborts at
            # the first failed sub-block).
            connect_locks: dict[int, asyncio.Lock] = {}
            if is_erasure:
                semaphore = asyncio.Semaphore(
                    min(_MAX_PARALLEL_SHARD_WRITES, len(sub_blocks_data))
                )

                async def _write_bounded(sub_block_index, sub_block_data):
                    async with semaphore:
                        await self._write_shard(
                            chunk_id, sub_block_index, sub_block_data,
                            backend_rows[sub_block_index], connect_locks,
                            confirmed_sub_blocks,
                        )

                # return_exceptions=True is required: with fail-fast gather a
                # single failed shard would let the handlers below run (DB
                # writes + backend deletes) while sibling uploads were still in
                # flight. Gathering everything first keeps failure handling
                # strictly after all I/O, mirroring the sequential loop.
                shard_results = await asyncio.gather(
                    *(
                        _write_bounded(idx, data)
                        for idx, data in enumerate(sub_blocks_data)
                    ),
                    return_exceptions=True,
                )
                failures = [
                    result for result in shard_results
                    if isinstance(result, BaseException)
                ]
                if failures:
                    # gather preserves submission order (== shard index order),
                    # so this is the LOWEST-index failed shard -- deterministic,
                    # exactly which shard aborted the old sequential loop. The
                    # handlers below then run unchanged: shards that already
                    # reached a backend are deleted, ALL chunk_locations are
                    # marked failed, quota is restored and the error re-raised
                    # (the current design has no partial-success tolerance --
                    # mirror it, do not invent it here).
                    raise failures[0]
            else:
                for sub_block_index, sub_block_data in enumerate(sub_blocks_data):
                    await self._write_shard(
                        chunk_id, sub_block_index, sub_block_data,
                        backend_rows[sub_block_index], connect_locks,
                        confirmed_sub_blocks,
                    )

            # 4a. Confirm
            # Shards may have COMPLETED out of order; confirm in shard-index
            # order so the chunk_locations rows, quota_used totals AND the HMAC
            # ledger entry order are byte-identical to a sequential run
            # (determinism for tests; a plain sort is a no-op on the
            # non-erasure path, which was never out of order).
            confirmed_sub_blocks.sort(key=lambda entry: entry[0])
            with self._db.transaction():
                for idx, ref_id, b_id in confirmed_sub_blocks:
                    self._db.confirm_chunk_location(
                        chunk_id, idx, b_id, ref_id
                    )
                    self._qm.confirm(b_id, quota_sizes[idx])

            logger.info(
                "Chunk uploaded: chunk_id=%s index=%d/%d nonce_ctr=%d sub_blocks=%d",
                chunk_id[:8], descriptor.chunk_index, descriptor.total_chunks - 1,
                nonce_counter, len(confirmed_sub_blocks),
            )
            return chunk_id

        except asyncio.CancelledError:
            # Spec A5.7 cancellation flow
            await self._cleanup_cancelled(
                chunk_id, backend_rows, confirmed_sub_blocks, quota_sizes, num_sub_blocks
            )
            raise  # Always re-raise CancelledError -- never swallow

        except (BackendConnectionError, BackendRateLimitError) as exc:
            # 4b. Delete shards that already reached a backend, then fail + restore.
            await self._delete_confirmed_sub_blocks(confirmed_sub_blocks)
            with self._db.transaction():
                for idx in range(num_sub_blocks):
                    b_id = backend_rows[idx]["id"]
                    self._db.fail_chunk_location(chunk_id, idx, b_id)
                    self._qm.restore(b_id, quota_sizes[idx])
            logger.error("Chunk upload failed (network): %s", exc)
            raise

        except Exception as exc:
            # 4b. Fail + restore (unknown error -- never swallow per spec A9.6)
            await self._delete_confirmed_sub_blocks(confirmed_sub_blocks)
            with self._db.transaction():
                for idx in range(num_sub_blocks):
                    b_id = backend_rows[idx]["id"]
                    self._db.fail_chunk_location(chunk_id, idx, b_id)
                    self._qm.restore(b_id, quota_sizes[idx])
            logger.error("Chunk upload failed (unexpected): %s", exc, exc_info=True)
            raise ChunkError(f"Chunk upload failed: {exc}") from exc

    async def _write_shard(
        self,
        chunk_id: str,
        sub_block_index: int,
        sub_block_data: bytes,
        b_row,
        connect_locks: dict[int, asyncio.Lock],
        confirmed_sub_blocks: list[tuple[int, str, str]],
    ) -> None:
        """Upload one shard/sub-block with retry + backoff (spec §5.1, §9.6).

        This coroutine is the body of the erasure fan-out, and it deliberately
        performs NO database access: only connect/upload/retry I/O. All DB
        bookkeeping (confirm/fail, quota_used, HMAC chain) stays in the main
        task after gather -- see the fan-out comment in _upload_chunk_internal.

        On success it appends ``(sub_block_index, reference_id, backend_id)``
        to the shared ``confirmed_sub_blocks`` list. The append happens
        synchronously after the upload await (no await around it), so under
        single-threaded asyncio it is atomic w.r.t. sibling tasks and the
        cancellation cleanup sees exactly the shards whose uploads finished.

        Args:
            b_row:         assigned backend row (dict-like) for this shard.
            connect_locks: per-upload-session locks keyed by ``id(backend obj)``.
                Several shards can resolve to the SAME backend object (fewer
                failure domains than shards); without the lock, sibling tasks
                would race two concurrent connect() calls on one object.
            confirmed_sub_blocks: shared success bookkeeping list (mutated here).
        """
        b_id = b_row["id"]

        # Retrieve active backend object for the targeted backend
        b_obj = self._active_backends.get(b_id) or self._active_backends.get(b_row["type"]) or self._backend

        max_retries = 3
        base_delay = 1.0
        reference_id = None

        async def _ensure_connected() -> None:
            if getattr(b_obj, "_connected", False):
                return
            lock = connect_locks.setdefault(id(b_obj), asyncio.Lock())
            async with lock:
                # Double-checked: while we waited for the lock a sibling shard
                # task may already have connected this object.
                if not getattr(b_obj, "_connected", False):
                    await b_obj.connect()
                    b_obj._connected = True

        for attempt in range(max_retries + 1):
            async def _byte_gen(data=sub_block_data):
                yield data

            try:
                # Make sure backend is connected
                await _ensure_connected()

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

    async def _delete_confirmed_sub_blocks(
        self,
        confirmed_sub_blocks: list[tuple[int, str, str]],
    ) -> None:
        """Best-effort removal of shards uploaded before a failed commit."""
        for _, ref_id, b_id in confirmed_sub_blocks:
            try:
                b_obj = self._active_backends.get(b_id) or self._backend
                await b_obj.delete(ref_id)
            except Exception as exc:
                logger.warning("Failed to delete failed-upload sub-block %s: %s", ref_id, exc)

    async def _cleanup_cancelled(
        self,
        chunk_id: str,
        backend_rows: list,
        confirmed_sub_blocks: list[tuple[int, str, str]],
        quota_sizes: list[int],
        num_sub_blocks: int,
    ) -> None:
        """
        Cancellation cleanup (spec §5.7):
          1. backend.delete() for each confirmed sub-block.
          2. chunk_locations.status = 'cancelled'.
          3. quota_reserved restored.
        """
        logger.info("Upload cancelled: chunk_id=%s -- cleaning up.", chunk_id[:8])

        await self._delete_confirmed_sub_blocks(confirmed_sub_blocks)

        with self._db.transaction():
            for idx in range(num_sub_blocks):
                b_id = backend_rows[idx]["id"]
                self._db.cancel_chunk_location(chunk_id, idx, b_id)
                self._qm.restore(b_id, quota_sizes[idx])
