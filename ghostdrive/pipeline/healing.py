"""
healing.py -- Background health checker (leaky bucket) and trickle healing queue.
"""

import asyncio
import logging
import random
import time
from pathlib import Path
from datetime import datetime, timezone
import uuid

from PyQt6.QtCore import QObject, pyqtSignal

from ghostdrive.database.db import GhostDriveDB
from ghostdrive.crypto.nonce import NonceManager
from ghostdrive.crypto.chunk_crypto import ChunkDecryptor, ChunkEncryptor
from ghostdrive.crypto.hkdf import derive_chunk_key
from ghostdrive.exceptions import AuthenticationError, BackendError
from ghostdrive.pipeline.quota import QuotaManager

logger = logging.getLogger("ghostdrive.healing")

SUB_BLOCK_BYTES = 50 * 1024 * 1024  # 50 MB standard sub-block size

class DaemonSignals(QObject):
    refresh_backends = pyqtSignal()
    refresh_files = pyqtSignal()
    trigger_health_alert = pyqtSignal(int)

def _now_iso() -> str:
    from datetime import timezone
    return datetime.now(timezone.utc).isoformat()

def _new_uuid() -> str:
    return str(uuid.uuid4())


async def verify_chunk_location(
    db: GhostDriveDB,
    loc: dict,
    km,
    active_backends: dict
) -> str:
    """
    Downloads and decrypts a chunk location to verify its Poly1305 authentication tag.
    Returns: 'ok', 'not_found', 'auth_failed', or 'error' (if other/transient errors).
    """
    b_type = loc["backend_type"]
    backend_obj = active_backends.get(b_type)
    if not backend_obj:
        return "not_found"

    try:
        if not getattr(backend_obj, "_connected", False):
            await backend_obj.connect()
            backend_obj._connected = True

        # Download the ciphertext blocks without single massive bytearray conversion
        blocks = []
        async for block in backend_obj.download(loc["reference_id"]):
            if block:
                blocks.append(block)

        if not blocks:
            return "not_found"

        # Extract 16-byte Poly1305 tag from end of block list
        tag_parts = []
        needed = 16
        for block in reversed(blocks):
            if len(block) >= needed:
                tag_parts.append(block[-needed:])
                needed = 0
                break
            else:
                tag_parts.append(block)
                needed -= len(block)
        if needed > 0:
            return "not_found"
        tag = b"".join(reversed(tag_parts))

        # Decrypt chunk ciphertext in-memory via block-by-block feed
        chunk_key = derive_chunk_key(km.master_key, km.hkdf_salt)
        nonce = NonceManager.counter_to_nonce(loc["nonce_counter"])

        decryptor = ChunkDecryptor(key=chunk_key, nonce=nonce, expected_tag=tag)
        total_ct_len = sum(len(b) for b in blocks) - 16
        total_fed = 0
        for block in blocks:
            if total_fed + len(block) <= total_ct_len:
                decryptor.feed(block)
                total_fed += len(block)
            else:
                take = total_ct_len - total_fed
                if take > 0:
                    decryptor.feed(block[:take])
                break
        
        # This will raise AuthenticationError if tag is invalid — consume generator to verify and discard plaintext
        def _run_verify(d):
            for _ in d.verify_and_decrypt_streaming():
                pass
        await asyncio.to_thread(_run_verify, decryptor)
        return "ok"

    except AuthenticationError as exc:
        logger.error("Auth verification failed for chunk %s on %s: %s", loc["chunk_id"][:8], b_type, exc)
        return "auth_failed"
    except Exception as exc:
        exc_str = str(exc).lower()
        if "not found" in exc_str or "404" in exc_str or "does not exist" in exc_str:
            logger.error("Chunk %s not found on %s: %s", loc["chunk_id"][:8], b_type, exc)
            return "not_found"
        else:
            logger.warning("Transient/network error verifying chunk %s on %s: %s", loc["chunk_id"][:8], b_type, exc)
            return "error"


class HealthDaemon:
    """
    Background daemon verifying chunk integrity via a leaky bucket 1% daily sweep.
    Also continuously checks Chunk 0 of all active files on every cycle.
    """
    def __init__(
        self,
        db: GhostDriveDB,
        active_backends: dict,
        km,
        notifications,
        main_view,
        loop_interval: float = 30.0
    ) -> None:
        self.db = db
        self.active_backends = active_backends
        self.km = km
        self.notifications = notifications
        self.main_view = main_view
        self.loop_interval = loop_interval
        self._task = None
        self._running = False
        self.signals = DaemonSignals()

    def start(self) -> None:
        if not self._running:
            self._running = True
            self._task = asyncio.create_task(self._run_loop())
            logger.info("HealthDaemon background checker started.")

    def stop(self) -> None:
        if self._running:
            self._running = False
            if self._task:
                self._task.cancel()
            logger.info("HealthDaemon background checker stopped.")

    async def _run_loop(self) -> None:
        # Avoid startup storm by waiting first
        await asyncio.sleep(5.0)
        while self._running:
            try:
                await self.perform_health_sweep()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Exception in HealthDaemon loop: %s", exc, exc_info=True)
            
            await asyncio.sleep(self.loop_interval)

    async def perform_health_sweep(self) -> None:
        """Runs Chunk 0 verification + 1% randomized leaky-bucket check + alerts updates."""
        logger.info("Starting health sweep cycle...")

        # 1. Update backend connection/reachability status
        for b_name, b_obj in list(self.active_backends.items()):
            try:
                if not getattr(b_obj, "_connected", False):
                    await b_obj.connect()
                    b_obj._connected = True
                res = await b_obj.health_check()
                status = "healthy" if res.reachable else "unreachable"
                with self.db.transaction():
                    self.db._conn.execute(
                        "UPDATE backends SET status = ?, last_health_check = ? WHERE id = ?",
                        (status, _now_iso(), b_obj.id)
                    )
            except Exception as exc:
                logger.error("Failed to health-check backend %s: %s", b_name, exc)
                with self.db.transaction():
                    self.db._conn.execute(
                        "UPDATE backends SET status = 'unreachable', last_health_check = ? WHERE id = ?",
                        (_now_iso(), b_obj.id)
                    )

        # Update alerts based on healthy count
        await self._evaluate_backend_alerts()

        # 2. Check Chunk 0 of all active (non-tombstoned) files
        try:
            with self.db.transaction():
                chunk0_locs = self.db._conn.execute(
                    """SELECT cl.*, c.nonce_counter, c.size, f.name as file_name, b.type as backend_type
                       FROM chunk_locations cl
                       JOIN chunks c ON cl.chunk_id = c.id
                       JOIN files f ON c.file_id = f.id
                       JOIN backends b ON cl.backend_id = b.id
                       WHERE f.tombstone = 0 AND c.chunk_index = 0 AND cl.status = 'confirmed'"""
                ).fetchall()
        except Exception as exc:
            logger.error("Failed to query Chunk 0 locations: %s", exc)
            chunk0_locs = []

        for row in chunk0_locs:
            loc = dict(row)
            res = await verify_chunk_location(self.db, loc, self.km, self.active_backends)
            await self._record_verification_result(loc, res)

        # 3. Leaky bucket 1% daily sweep
        try:
            with self.db.transaction():
                all_locs = self.db._conn.execute(
                    """SELECT cl.*, c.nonce_counter, c.size, f.name as file_name, b.type as backend_type
                       FROM chunk_locations cl
                       JOIN chunks c ON cl.chunk_id = c.id
                       JOIN files f ON c.file_id = f.id
                       JOIN backends b ON cl.backend_id = b.id
                       WHERE f.tombstone = 0 AND cl.status = 'confirmed'"""
                ).fetchall()
        except Exception as exc:
            logger.error("Failed to query all chunk locations for leaky bucket check: %s", exc)
            all_locs = []

        # Group by backend
        by_backend = {}
        for r in all_locs:
            by_backend.setdefault(r["backend_id"], []).append(dict(r))

        for b_id, locs in by_backend.items():
            # Sample 1% (at least 1, if any exist)
            sample_size = int(len(locs) * 0.01)
            if sample_size == 0 and len(locs) > 0:
                sample_size = 1
            
            sampled = random.sample(locs, sample_size)
            for loc in sampled:
                res = await verify_chunk_location(self.db, loc, self.km, self.active_backends)
                await self._record_verification_result(loc, res)

        logger.info("Health sweep cycle completed.")

    async def _record_verification_result(self, loc: dict, res: str) -> None:
        """Writes the verification check result to SQL databases and triggers UI state updates."""
        if res == "error":
            # Transient error, do not fail location immediately
            return

        with self.db.transaction():
            # Insert integrity log entry
            log_id = _new_uuid()
            self.db._conn.execute(
                """INSERT INTO integrity_log (id, chunk_id, checked_at, result, backend_id)
                   VALUES (?, ?, ?, ?, ?)""",
                (log_id, loc["chunk_id"], _now_iso(), res, loc["backend_id"])
            )
            # Prune integrity logs to keep only last 10
            self.db.prune_integrity_log(loc["chunk_id"], keep=10)

            if res in ("not_found", "auth_failed"):
                # Mark chunk location status as failed
                self.db._conn.execute(
                    """UPDATE chunk_locations
                       SET status = 'failed'
                       WHERE chunk_id = ? AND sub_block_index = ? AND backend_id = ?""",
                    (loc["chunk_id"], loc["sub_block_index"], loc["backend_id"])
                )
                logger.warning(
                    "Integrity check failed: chunk %s is %s on backend %s. Flagged for healing.",
                    loc["chunk_id"][:8], res, loc["backend_type"].upper()
                )

                # Emit Qt signal to refresh status on the main thread
                if hasattr(self.main_view, 'backends_changed'):
                    self.main_view.backends_changed.emit()
                
                self.notifications.notify(
                    "Integrity Failure",
                    f"Chunk verification failed on {loc['backend_type'].upper()}. Background healing initiated.",
                    "important"
                )
            else:
                # Mark verified date
                self.db._conn.execute(
                    """UPDATE chunk_locations
                       SET last_verified = ?
                       WHERE chunk_id = ? AND sub_block_index = ? AND backend_id = ?""",
                    (_now_iso(), loc["chunk_id"], loc["sub_block_index"], loc["backend_id"])
                )

    async def _evaluate_backend_alerts(self) -> None:
        """Counts active healthy backends and reports appropriate UI alert triggers."""
        try:
            with self.db.transaction():
                rows = self.db._conn.execute(
                    "SELECT COUNT(*) as cnt FROM backends WHERE status = 'healthy'"
                ).fetchone()
                healthy_count = rows["cnt"] if rows else 0
        except Exception:
            healthy_count = 0

        # Emit Qt signal to trigger health alert UI on the main thread
        self.signals.trigger_health_alert.emit(healthy_count)


class HealingQueue:
    """
    Background worker monitoring under-replicated chunks and executing trickle-healing.
    """
    def __init__(
        self,
        db: GhostDriveDB,
        active_backends: dict,
        km,
        main_view,
        loop_interval: float = 10.0
    ) -> None:
        self.db = db
        self.active_backends = active_backends
        self.km = km
        self.main_view = main_view
        self.loop_interval = loop_interval
        self._task = None
        self._running = False
        self._upload_active = False
        # Set of backend_ids that are currently targets of an active healing upload
        self._active_healing_backends = set()
        self.signals = DaemonSignals()

    def start(self) -> None:
        if not self._running:
            self._running = True
            self._task = asyncio.create_task(self._run_loop())
            logger.info("HealingQueue background worker started.")

    def stop(self) -> None:
        if self._running:
            self._running = False
            if self._task:
                self._task.cancel()
            logger.info("HealingQueue background worker stopped.")

    async def _run_loop(self) -> None:
        # Sleep to avoid startup congestion
        await asyncio.sleep(8.0)
        while self._running:
            try:
                # 1. Backpressure Check: Pause on active foreground uploads
                from ghostdrive.pipeline.upload import ChunkUploader
                if ChunkUploader.active_uploads > 0 or getattr(self.main_view, "active_uploads", 0) > 0 or self._upload_active:
                    logger.info("Healing trickle paused: foreground uploads active.")
                else:
                    await self.perform_healing_step()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Exception in HealingQueue loop: %s", exc, exc_info=True)
            
            await asyncio.sleep(self.loop_interval)

    async def perform_healing_step(self) -> None:
        """Finds one under-replicated chunk and heals/replicates it."""
        # 1. Query under-replicated chunks
        # Redundancy tier mapping: CRITICAL=4, IMPORTANT=3, DISPOSABLE=2
        # Select chunks where confirmed mirror count is less than the required tier replication
        # AND at least 1 confirmed source exists.
        try:
            with self.db.transaction():
                # Count healthy backends
                healthy_rows = self.db._conn.execute(
                    "SELECT id FROM backends WHERE status = 'healthy'"
                ).fetchall()
                healthy_ids = [r["id"] for r in healthy_rows]

                if not healthy_ids:
                    return

                candidates = self.db._conn.execute(
                    """SELECT c.id as chunk_id, c.size, c.nonce_counter, f.name as file_name, f.tier,
                              (SELECT COUNT(*) FROM chunk_locations cl WHERE cl.chunk_id = c.id AND cl.status = 'confirmed') as confirmed_count
                       FROM chunks c
                       JOIN files f ON c.file_id = f.id
                       WHERE f.tombstone = 0
                       ORDER BY confirmed_count ASC"""
                ).fetchall()
        except Exception as exc:
            logger.error("Failed to query healing candidates: %s", exc)
            return

        for row in candidates:
            chunk_id = row["chunk_id"]
            tier = row["tier"]
            confirmed_count = row["confirmed_count"]
            file_name = row["file_name"]

            # Map tier target replication
            target_rep = 4 if tier == "CRITICAL" else (3 if tier == "IMPORTANT" else 2)
            # Replicating up to max available healthy backends
            max_possible = min(target_rep, len(healthy_ids))

            if confirmed_count >= max_possible or confirmed_count == 0:
                continue

            # This chunk is under-replicated! Find a source and target backend
            with self.db.transaction():
                # Source confirmed locations
                sources = self.db._conn.execute(
                    """SELECT cl.*, b.type as backend_type FROM chunk_locations cl
                       JOIN backends b ON cl.backend_id = b.id
                       WHERE cl.chunk_id = ? AND cl.status = 'confirmed'""",
                    (chunk_id,)
                ).fetchall()

                # Get backends already having a confirmed or pending location
                excl_backends = self.db._conn.execute(
                    "SELECT backend_id FROM chunk_locations WHERE chunk_id = ?",
                    (chunk_id,)
                ).fetchall()
                excl_ids = [e["backend_id"] for e in excl_backends]

            if not sources:
                continue

            # Pick target backend (must be healthy and not in excl_ids and not busy healing)
            target_backend = None
            for b_id in healthy_ids:
                if b_id not in excl_ids and b_id not in self._active_healing_backends:
                    # Retrieve backend object
                    with self.db.transaction():
                        b_row = self.db._conn.execute("SELECT type FROM backends WHERE id = ?", (b_id,)).fetchone()
                    if b_row:
                        b_obj = self.active_backends.get(b_row["type"])
                        if b_obj:
                            target_backend = (b_id, b_row["type"], b_obj)
                            break

            if not target_backend:
                continue

            # We found a source location and a target backend. Perform healing!
            source_loc = dict(sources[0])
            logger.info("Healing chunk %s of '%s': copying from %s to %s.",
                        chunk_id[:8], file_name, source_loc["backend_type"], target_backend[1])
            
            self._active_healing_backends.add(target_backend[0])
            try:
                await self._heal_chunk_record(chunk_id, row["size"], row["nonce_counter"], source_loc, target_backend)
                # Success notification
                if hasattr(self.main_view, "notifications"):
                    self.main_view.notifications.notify(
                        "Healing Succeeded",
                        f"Healed chunk of '{file_name}' to {target_backend[1].upper()}.",
                        "success"
                    )
            except Exception as exc:
                logger.error("Failed to heal chunk %s: %s", chunk_id[:8], exc)
            finally:
                self._active_healing_backends.discard(target_backend[0])
            
            # Heal one chunk at a time per loop cycle (trickle)
            break

    async def _heal_chunk_record(self, chunk_id: str, size: int, nonce_counter: int, source_loc: dict, target_backend: tuple) -> None:
        target_id, target_type, target_obj = target_backend
        source_type = source_loc["backend_type"]
        source_obj = self.active_backends.get(source_type)
        if not source_obj:
            raise ValueError(f"Source backend {source_type} not available.")

        # 1. Download ciphertext blocks
        if not getattr(source_obj, "_connected", False):
            await source_obj.connect()
            source_obj._connected = True

        blocks = []
        async for block in source_obj.download(source_loc["reference_id"]):
            if block:
                blocks.append(block)

        if not blocks:
            raise ValueError("Empty ciphertext received from source backend.")

        # Extract 16-byte Poly1305 tag from end of blocks list
        tag_parts = []
        needed = 16
        for block in reversed(blocks):
            if len(block) >= needed:
                tag_parts.append(block[-needed:])
                needed = 0
                break
            else:
                tag_parts.append(block)
                needed -= len(block)
        if needed > 0:
            raise ValueError("Ciphertext too small to contain a tag.")
        tag = b"".join(reversed(tag_parts))

        # 2. Verify decryption (MAC Tag check)
        chunk_key = derive_chunk_key(self.km.master_key, self.km.hkdf_salt)
        nonce = NonceManager.counter_to_nonce(nonce_counter)

        decryptor = ChunkDecryptor(key=chunk_key, nonce=nonce, expected_tag=tag)
        total_ct_len = sum(len(b) for b in blocks) - 16
        total_fed = 0
        for block in blocks:
            if total_fed + len(block) <= total_ct_len:
                decryptor.feed(block)
                total_fed += len(block)
            else:
                take = total_ct_len - total_fed
                if take > 0:
                    decryptor.feed(block[:take])
                break

        # Consume generator to verify tag and discard decrypted plaintext
        def _run_verify(d):
            for _ in d.verify_and_decrypt_streaming():
                pass
        await asyncio.to_thread(_run_verify, decryptor)

        # 3. Reserve quota on target backend and insert pending location record within a single transaction context
        qm = QuotaManager(self.db)
        with self.db.transaction():
            ok = self.db.reserve_quota(target_id, size)
            if not ok:
                raise ValueError(f"Insufficient quota on target backend {target_id[:8]}")
            self.db._conn.execute(
                """INSERT INTO chunk_locations
                   (chunk_id, sub_block_index, backend_id, reference_id, url_type,
                    upload_date, status, quota_reserved)
                   VALUES (?, 0, ?, '', 'permanent', ?, 'pending', ?)""",
                (chunk_id, target_id, _now_iso(), size)
            )

        # 5. Upload same ciphertext blocks
        if not getattr(target_obj, "_connected", False):
            await target_obj.connect()
            target_obj._connected = True

        try:
            # We stream the exact same ciphertext blocks
            async def _stream_data(blocks_list=blocks):
                for b in blocks_list:
                    yield b

            ref_id = await target_obj.upload(
                stream=_stream_data(),
                chunk_id=chunk_id,
                sub_block_index=0
            )

            # 6. Confirm location and quota
            with self.db.transaction():
                self.db._conn.execute(
                    """UPDATE chunk_locations
                       SET status = 'confirmed', reference_id = ?, quota_reserved = 0
                       WHERE chunk_id = ? AND sub_block_index = 0 AND backend_id = ?""",
                    (ref_id, chunk_id, target_id)
                )
                qm.confirm(target_id, size)

            logger.info("Successfully healed/replicated chunk %s to target backend %s.", chunk_id[:8], target_type)
            
            # Emit Qt signals to refresh UI on main thread safely
            if hasattr(self.main_view, 'healing_completed'):
                self.main_view.healing_completed.emit()
            if hasattr(self.main_view, 'backends_changed'):
                self.main_view.backends_changed.emit()

        except Exception as exc:
            # Restore quota and fail location on error
            with self.db.transaction():
                self.db._conn.execute(
                    """UPDATE chunk_locations
                       SET status = 'failed', quota_reserved = 0
                       WHERE chunk_id = ? AND sub_block_index = 0 AND backend_id = ?""",
                    (chunk_id, target_id)
                )
                qm.restore(target_id, size)
            raise exc
