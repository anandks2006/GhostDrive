"""
healing.py -- Background health checker (leaky bucket) and trickle healing queue.
"""

import asyncio
import logging
from datetime import datetime, timezone
import uuid

from ghostdrive.database.db import GhostDriveDB
from ghostdrive.crypto.nonce import NonceManager
from ghostdrive.crypto.chunk_crypto import ChunkDecryptor
from ghostdrive.crypto.hkdf import derive_chunk_key
from ghostdrive.exceptions import AuthenticationError
from ghostdrive.pipeline.coding import erasure_parameters
from ghostdrive.pipeline.quota import QuotaManager
from ghostdrive.services import maintenance_window

logger = logging.getLogger("ghostdrive.healing")

SUB_BLOCK_BYTES = 50 * 1024 * 1024  # 50 MB standard sub-block size

class _Signal:
    """Minimal Qt-compatible signal (connect/emit) used by the web app."""

    def __init__(self) -> None:
        self._callbacks: list = []

    def connect(self, callback) -> None:
        self._callbacks.append(callback)

    def emit(self, *args) -> None:
        for callback in list(self._callbacks):
            try:
                callback(*args)
            except Exception as exc:  # pragma: no cover - defensive UI callback guard
                logger.warning("Signal callback failed: %s", exc)


class DaemonSignals:
    """Dependency-free replacement for the former PyQt6 signal container."""

    def __init__(self) -> None:
        self.refresh_backends = _Signal()
        self.refresh_files = _Signal()
        self.trigger_health_alert = _Signal()

def _now_iso() -> str:
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
    Verify that the stored object of ONE specific chunk_location record is
    intact, by reconstructing the logical chunk ciphertext (erasure) or the
    sub-block stream (replicated) and checking the Poly1305 MAC tag.

    For erasure-coded chunks the location's OWN shard must be fetched from
    its own backend and must participate in the Reed-Solomon decode, so a
    denied or corrupted shard is always attributed to the backend that holds
    it -- never masked by peers.  Returns "ok" | "not_found" | "auth_failed"
    | "error" (transient).
    """
    chunk_id = loc["chunk_id"]
    backend_id = loc["backend_id"]

    # Query all confirmed sub-block locations for this chunk_id on this backend
    with db.transaction():
        rows = db._conn.execute(
            """SELECT cl.*, b.type as backend_type FROM chunk_locations cl
               JOIN backends b ON cl.backend_id = b.id
               WHERE cl.chunk_id = ? AND cl.backend_id = ? AND cl.status = 'confirmed'
               ORDER BY cl.sub_block_index ASC""",
            (chunk_id, backend_id)
        ).fetchall()

    if not rows:
        return "not_found"

    # Get chunk metadata
    with db.transaction():
        c_row = db._conn.execute(
            "SELECT sub_block_count, erasure_k, erasure_n, erasure_padlen, nonce_counter FROM chunks WHERE id = ?",
            (chunk_id,),
        ).fetchone()
    if not c_row:
        return "not_found"
    
    sub_block_count = c_row["sub_block_count"]
    nonce_counter = c_row["nonce_counter"]
    k, n, padlen, is_erasure = erasure_parameters(c_row)

    if is_erasure:
        # ---- Erasure verification of ONE SPECIFIC location record ----------
        # The record under verification is (chunk_id, sub_block_index,
        # backend_id) on THIS backend, so the verdict must be derived from
        # THIS backend's own bytes.  The old implementation gathered "any k
        # shards in index order" and stopped, which had two blind spots:
        #   * a backend that 404s its shard was silently masked by its peers
        #     and verified 'ok', so hostility.detect_withholding never
        #     received the per-backend not_found rows it consumes, and
        #   * shards beyond the first k (parity shards) were never downloaded
        #     at all, so a byte-flipped parity shard also verified 'ok'.
        # The fix: fetch the TARGET shard from its own backend FIRST (any
        # download failure is attributed to that backend), then k-1 peer
        # shards, and force the target's bytes to participate in the zfec
        # decode -- a corrupted target then breaks the Poly1305 check of the
        # reconstructed chunk.  A healthy target still downloads exactly k
        # shards (itself + k-1 peers): no full-chunk re-download, and the
        # decode/decrypt/auth steps below are unchanged.
        target_idx = int(loc["sub_block_index"])
        target_backend_id = loc["backend_id"]
        target_backend_type = (
            loc["backend_type"] if "backend_type" in loc.keys() else None
        )

        # `rows` above is already filtered to this backend + confirmed; the
        # exact location being verified must be among them or it is gone.
        if not any(
            int(r["sub_block_index"]) == target_idx
            and r["backend_id"] == target_backend_id
            for r in rows
        ):
            return "not_found"

        # All confirmed shard rows of the chunk (peers may live on other
        # backends -- that is the point of erasure coding).
        with db.transaction():
            all_rows = db._conn.execute(
                """SELECT cl.*, b.type as backend_type FROM chunk_locations cl
                   JOIN backends b ON cl.backend_id = b.id
                   WHERE cl.chunk_id = ? AND cl.status = 'confirmed'
                   ORDER BY cl.sub_block_index ASC""",
                (chunk_id,)
            ).fetchall()

        shards_by_idx = {}
        for r in all_rows:
            if r["sub_block_index"] not in shards_by_idx:
                shards_by_idx[r["sub_block_index"]] = r

        if len(shards_by_idx) < k:
            return "not_found"

        async def _fetch_all(reference_id, b_obj):
            blocks_list = []
            async for block in b_obj.download(reference_id):
                blocks_list.append(block)
            return b"".join(blocks_list)

        try:
            downloaded = {}

            # 1) THE TARGET shard, from the backend that is being verified.
            target_obj = (
                active_backends.get(target_backend_id)
                or active_backends.get(target_backend_type)
            )
            if not target_obj:
                # The location under verification cannot be read at all.
                return "not_found"
            if not getattr(target_obj, "_connected", False):
                await target_obj.connect()
                target_obj._connected = True
            try:
                target_bytes = await _fetch_all(loc["reference_id"], target_obj)
            except Exception as exc:
                # Attribute the failure to the backend under verification
                # (peers must not mask it). Missing-object errors mean THIS
                # location is gone -> not_found; anything else is a transient
                # network error -> 'error', which does not fail the location
                # (same classification as the replicated branch below).
                exc_str = str(exc).lower()
                if "not found" in exc_str or "404" in exc_str or "does not exist" in exc_str:
                    logger.error(
                        "Chunk %s shard %d not found on backend %s: %s",
                        chunk_id[:8], target_idx, target_backend_id[:8], exc,
                    )
                    return "not_found"
                logger.warning(
                    "Transient error fetching shard %d of chunk %s from %s: %s",
                    target_idx, chunk_id[:8], target_backend_id[:8], exc,
                )
                return "error"
            if not target_bytes:
                return "not_found"
            downloaded[target_idx] = target_bytes

            # 2) k-1 peer shards from OTHER sub-block indexes (any backend).
            for sub_idx, loc_row in sorted(shards_by_idx.items()):
                if len(downloaded) >= k:
                    break
                if sub_idx == target_idx:
                    continue
                try:
                    b_obj = active_backends.get(loc_row["backend_id"]) or active_backends.get(loc_row["backend_type"])
                    if not b_obj:
                        continue
                    if not getattr(b_obj, "_connected", False):
                        await b_obj.connect()
                        b_obj._connected = True
                    peer_bytes = await _fetch_all(loc_row["reference_id"], b_obj)
                    if peer_bytes:
                        downloaded[sub_idx] = peer_bytes
                except Exception as e:
                    logger.warning("Failed to download shard index %d: %s", sub_idx, e)

            if len(downloaded) < k:
                return "not_found"

            # Reconstruct with the TARGET shard FORCED into the k-set: a
            # target whose index sorts after the first k peers must never be
            # dropped from the decode inputs, or its corruption would stay
            # invisible (that was the original parity-shard blind spot).
            blocks = [downloaded[target_idx]]
            sharenums = [target_idx]
            for sub_idx in sorted(downloaded.keys()):
                if sub_idx == target_idx:
                    continue
                blocks.append(downloaded[sub_idx])
                sharenums.append(sub_idx)
                if len(blocks) >= k:
                    break

            from zfec.easyfec import Decoder
            dec = Decoder(k, n)
            chunk_ciphertext = dec.decode(blocks, sharenums, padlen)
            
            if len(chunk_ciphertext) < 16:
                return "not_found"
                
            tag = chunk_ciphertext[-16:]
            ct_body = chunk_ciphertext[:-16]
            
            chunk_key = derive_chunk_key(km.master_key, km.hkdf_salt)
            nonce = NonceManager.counter_to_nonce(nonce_counter)
            decryptor = ChunkDecryptor(key=chunk_key, nonce=nonce, expected_tag=tag)
            decryptor.feed(ct_body)
            
            def _run_verify(d):
                for _ in d.verify_and_decrypt_streaming():
                    pass
            await asyncio.to_thread(_run_verify, decryptor)
            return "ok"
        except Exception as exc:
            logger.error("Erasure verify failed for chunk %s: %s", chunk_id[:8], exc)
            return "auth_failed"

    if len(rows) < sub_block_count:
        return "not_found"

    # Map rows by sub_block_index
    locs_by_idx = {r["sub_block_index"]: dict(r) for r in rows}

    # Check that we have all indices from 0 to sub_block_count - 1
    for i in range(sub_block_count):
        if i not in locs_by_idx:
            return "not_found"

    try:
        # Find and download the last sub-block to get the tag
        last_idx = sub_block_count - 1
        last_loc = locs_by_idx[last_idx]
        last_b_type = last_loc["backend_type"]
        last_backend_obj = active_backends.get(backend_id) or active_backends.get(last_b_type)
        if not last_backend_obj:
            return "not_found"

        if not getattr(last_backend_obj, "_connected", False):
            await last_backend_obj.connect()
            last_backend_obj._connected = True

        last_blocks = []
        async for block in last_backend_obj.download(last_loc["reference_id"]):
            if block:
                last_blocks.append(block)

        if not last_blocks:
            return "not_found"

        last_all_ct = b"".join(last_blocks)
        if len(last_all_ct) < 16:
            return "not_found"

        tag = last_all_ct[-16:]
        last_ciphertext_only = last_all_ct[:-16]

        # Initialize decryptor
        chunk_key = derive_chunk_key(km.master_key, km.hkdf_salt)
        nonce = NonceManager.counter_to_nonce(nonce_counter)
        decryptor = ChunkDecryptor(key=chunk_key, nonce=nonce, expected_tag=tag)

        # Feed sub-blocks 0 to N-2
        for i in range(last_idx):
            curr_loc = locs_by_idx[i]
            curr_b_type = curr_loc["backend_type"]
            curr_backend_obj = active_backends.get(curr_loc["backend_id"]) or active_backends.get(curr_b_type)
            if not curr_backend_obj:
                return "not_found"

            if not getattr(curr_backend_obj, "_connected", False):
                await curr_backend_obj.connect()
                curr_backend_obj._connected = True

            async for block in curr_backend_obj.download(curr_loc["reference_id"]):
                if block:
                    decryptor.feed(block)

        # Feed the last sub-block's ciphertext
        if last_ciphertext_only:
            decryptor.feed(last_ciphertext_only)

        # Verify the MAC tag
        def _run_verify(d):
            for _ in d.verify_and_decrypt_streaming():
                pass
        await asyncio.to_thread(_run_verify, decryptor)
        return "ok"

    except AuthenticationError as exc:
        logger.error("Auth verification failed for chunk %s on %s: %s", chunk_id[:8], last_b_type, exc)
        return "auth_failed"
    except Exception as exc:
        exc_str = str(exc).lower()
        if "not found" in exc_str or "404" in exc_str or "does not exist" in exc_str:
            logger.error("Chunk %s not found on backend: %s", chunk_id[:8], exc)
            return "not_found"
        else:
            logger.warning("Transient/network error verifying chunk %s: %s", chunk_id[:8], exc)
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

        # 2. Check Chunk 0 of all active (non-tombstoned) files.
        # Apply a 24-hour cooldown per location so we don't re-download every
        # chunk on every 30-second sweep cycle. A NULL last_verified means
        # this location has never been verified and must be checked immediately.
        try:
            with self.db.transaction():
                chunk0_locs = self.db._conn.execute(
                    """SELECT cl.*, c.nonce_counter, c.size, f.name as file_name, b.type as backend_type
                       FROM chunk_locations cl
                       JOIN chunks c ON cl.chunk_id = c.id
                       JOIN files f ON c.file_id = f.id
                       JOIN backends b ON cl.backend_id = b.id
                       WHERE f.tombstone = 0
                         AND c.chunk_index = 0
                         AND cl.status = 'confirmed'
                         AND (
                               cl.last_verified IS NULL
                            OR cl.last_verified < datetime('now', '-1 day')
                         )"""
                ).fetchall()
        except Exception as exc:
            logger.error("Failed to query Chunk 0 locations: %s", exc)
            chunk0_locs = []

        for row in chunk0_locs:
            loc = dict(row)
            res = await verify_chunk_location(self.db, loc, self.km, self.active_backends)
            await self._record_verification_result(loc, res)

        # 3. Leaky-bucket 1% daily sweep.
        # Sample at SQL level to avoid loading all chunk_location rows into memory
        # (a large vault can have millions of rows — fetchall() would OOM).
        # We compute 1% of total confirmed locations and pull that many random rows.
        try:
            with self.db.transaction():
                total_row = self.db._conn.execute(
                    "SELECT COUNT(*) as cnt FROM chunk_locations cl "
                    "JOIN files f ON (SELECT file_id FROM chunks WHERE id = cl.chunk_id) = f.id "
                    "WHERE f.tombstone = 0 AND cl.status = 'confirmed'"
                ).fetchone()
                total_count = total_row["cnt"] if total_row else 0
                sample_limit = max(1, int(total_count * 0.01)) if total_count > 0 else 0

                if sample_limit > 0:
                    sampled_rows = self.db._conn.execute(
                        """SELECT cl.*, c.nonce_counter, c.size, f.name as file_name, b.type as backend_type
                           FROM chunk_locations cl
                           JOIN chunks c ON cl.chunk_id = c.id
                           JOIN files f ON c.file_id = f.id
                           JOIN backends b ON cl.backend_id = b.id
                           WHERE f.tombstone = 0
                             AND cl.status = 'confirmed'
                             AND (
                                   cl.last_verified IS NULL
                                OR cl.last_verified < datetime('now', '-1 day')
                             )
                           ORDER BY RANDOM()
                           LIMIT ?""",
                        (sample_limit,)
                    ).fetchall()
                else:
                    sampled_rows = []
        except Exception as exc:
            logger.error("Failed to sample chunk locations for leaky bucket check: %s", exc)
            sampled_rows = []

        # Group sampled rows by backend for rate-limit-friendly verification
        by_backend = {}
        for r in sampled_rows:
            by_backend.setdefault(r["backend_id"], []).append(dict(r))

        for b_id, locs in by_backend.items():
            # SQL already applied 1% sampling (ORDER BY RANDOM() LIMIT) so verify
            # every row in locs directly — no further Python-side sampling needed.
            for loc in locs:
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
        """Counts active healthy backends and reports appropriate UI alert triggers.
        
        Guards against firing alerts when no backends are configured at all
        (fresh install / pre-setup state). Alerts only make sense when a
        *previously working* backend becomes unreachable.
        """
        try:
            with self.db.transaction():
                total_row = self.db._conn.execute(
                    "SELECT COUNT(*) as cnt FROM backends"
                ).fetchone()
                total_configured = total_row["cnt"] if total_row else 0

                healthy_row = self.db._conn.execute(
                    "SELECT COUNT(*) as cnt FROM backends WHERE status = 'healthy'"
                ).fetchone()
                healthy_count = healthy_row["cnt"] if healthy_row else 0
        except Exception:
            return

        # Never alert if no backends have been configured yet.
        # The blocking modal is only meaningful when a configured backend goes down.
        if total_configured == 0:
            return

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
        # Counts consecutive repair-window skips so we can throttle the debug log.
        self._window_skip_count = 0
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
                    # 2. Maintenance-window gate: only trickle repairs when the
                    # configured repair window allows it (disabled = always).
                    allowed, reason = maintenance_window.is_repair_allowed(self.db)
                    if allowed:
                        self._window_skip_count = 0
                        await self.perform_healing_step()
                    else:
                        # Throttled debug log: a closed window persists for hours
                        # and must not spam the log every loop_interval.
                        self._window_skip_count += 1
                        if self._window_skip_count == 1 or self._window_skip_count % 60 == 0:
                            logger.debug(
                                "Healing trickle skipped: %s (skip #%d)",
                                reason, self._window_skip_count,
                            )
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
                              (SELECT COUNT(DISTINCT cl.backend_id) FROM chunk_locations cl WHERE cl.chunk_id = c.id AND cl.status = 'confirmed') as confirmed_count
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
            critical_rep = int(self.db.get_setting("rep_critical", "4"))
            important_rep = int(self.db.get_setting("rep_important", "3"))
            disposable_rep = int(self.db.get_setting("rep_disposable", "2"))
            target_rep = critical_rep if tier == "CRITICAL" else (important_rep if tier == "IMPORTANT" else disposable_rep)
            
            # Map tier target routing policy
            tier_key = f"routing_{tier.lower()}_backends"
            routing_ids_str = self.db.get_setting(tier_key, "")
            routing_ids = [x.strip() for x in routing_ids_str.split(",") if x.strip()]
            
            allowed_ids = [b_id for b_id in healthy_ids if b_id in routing_ids] if routing_ids else healthy_ids

            # Replicating up to max available allowed healthy backends
            max_possible = min(target_rep, len(allowed_ids))

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

                # Get backends already having a confirmed or pending location.
                # A failed/cancelled row must NOT exclude its backend: retrying
                # that backend is exactly how healing recovers from a failure,
                # and retention prunes dead rows later.
                excl_backends = self.db._conn.execute(
                    """SELECT backend_id FROM chunk_locations
                       WHERE chunk_id = ? AND status IN ('confirmed', 'pending')""",
                    (chunk_id,)
                ).fetchall()
                excl_ids = [e["backend_id"] for e in excl_backends]

            if not sources:
                continue

            # Pick target backend (must be healthy and allowed by routing policy, not in excl_ids, and not busy healing)
            target_backend = None
            for b_id in allowed_ids:
                if b_id not in excl_ids and b_id not in self._active_healing_backends:
                    # Retrieve backend object
                    with self.db.transaction():
                        b_row = self.db._conn.execute("SELECT type FROM backends WHERE id = ?", (b_id,)).fetchone()
                    if b_row:
                        b_obj = self.active_backends.get(b_id) or self.active_backends.get(b_row["type"])
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
                # Respect the repair bandwidth cap while data actually moves.
                async with maintenance_window.background_bandwidth_scope(self.db):
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
        
        # To verify the entire chunk integrity, we must download all sub-blocks
        # Query all confirmed source locations for this chunk
        with self.db.transaction():
            rows = self.db._conn.execute(
                """SELECT cl.*, b.type as backend_type FROM chunk_locations cl
                   JOIN backends b ON cl.backend_id = b.id
                   WHERE cl.chunk_id = ? AND cl.status = 'confirmed'
                   ORDER BY cl.sub_block_index ASC""",
                (chunk_id,)
            ).fetchall()

        if not rows:
            raise ValueError(f"No confirmed source locations found for chunk {chunk_id[:8]}")

        # Get chunk metadata
        with self.db.transaction():
            c_row = self.db._conn.execute("SELECT sub_block_count FROM chunks WHERE id = ?", (chunk_id,)).fetchone()
        if not c_row:
            raise ValueError(f"Chunk {chunk_id[:8]} not found in chunks table.")
        
        sub_block_count = c_row["sub_block_count"]

        # Map rows by sub_block_index. Pick first confirmed location per index.
        locs_by_idx = {}
        for r in rows:
            idx = r["sub_block_index"]
            if idx not in locs_by_idx:
                locs_by_idx[idx] = dict(r)

        # Check we have all indices
        for i in range(sub_block_count):
            if i not in locs_by_idx:
                raise ValueError(f"Missing confirmed source location for sub-block {i} of chunk {chunk_id[:8]}")

        # Download the last sub-block first to get the tag
        last_idx = sub_block_count - 1
        last_loc = locs_by_idx[last_idx]
        last_source_type = last_loc["backend_type"]
        last_source_obj = self.active_backends.get(last_loc["backend_id"]) or self.active_backends.get(last_source_type)
        if not last_source_obj:
            raise ValueError(f"Source backend {last_source_type} not available.")

        if not getattr(last_source_obj, "_connected", False):
            await last_source_obj.connect()
            last_source_obj._connected = True

        last_blocks = []
        async for block in last_source_obj.download(last_loc["reference_id"]):
            if block:
                last_blocks.append(block)

        if not last_blocks:
            raise ValueError("Empty ciphertext received from last sub-block source backend.")

        last_all_ct = b"".join(last_blocks)
        if len(last_all_ct) < 16:
            raise ValueError("Last sub-block ciphertext too small to contain a tag.")

        tag = last_all_ct[-16:]
        last_ciphertext_only = last_all_ct[:-16]

        # Keep track of all sub-block ciphertexts for upload
        all_sub_block_ciphertexts = {}
        all_sub_block_ciphertexts[last_idx] = last_blocks
        
        # Initialize decryptor for verification
        chunk_key = derive_chunk_key(self.km.master_key, self.km.hkdf_salt)
        nonce = NonceManager.counter_to_nonce(nonce_counter)
        decryptor = ChunkDecryptor(key=chunk_key, nonce=nonce, expected_tag=tag)

        # Download and feed sub-blocks 0 to N-2
        for i in range(last_idx):
            curr_loc = locs_by_idx[i]
            curr_source_type = curr_loc["backend_type"]
            curr_source_obj = self.active_backends.get(curr_loc["backend_id"]) or self.active_backends.get(curr_source_type)
            if not curr_source_obj:
                raise ValueError(f"Source backend {curr_source_type} not available.")

            if not getattr(curr_source_obj, "_connected", False):
                await curr_source_obj.connect()
                curr_source_obj._connected = True

            curr_blocks = []
            async for block in curr_source_obj.download(curr_loc["reference_id"]):
                if block:
                    curr_blocks.append(block)
                    decryptor.feed(block)

            all_sub_block_ciphertexts[i] = curr_blocks

        # Feed the last sub-block's ciphertext
        if last_ciphertext_only:
            decryptor.feed(last_ciphertext_only)

        # Verify the tag
        def _run_verify(d):
            for _ in d.verify_and_decrypt_streaming():
                pass
        await asyncio.to_thread(_run_verify, decryptor)

        # 3. Reserve quota on target backend and insert pending location records for all sub-blocks
        qm = QuotaManager(self.db)
        with self.db.transaction():
            ok = self.db.reserve_quota(target_id, size)
            if not ok:
                raise ValueError(f"Insufficient quota on target backend {target_id[:8]}")
            
            for idx in range(sub_block_count):
                sub_quota = size if idx == 0 else 0
                # Upsert, not plain INSERT: a previously failed/cancelled row on
                # this (chunk, sub_block_index, backend) is still present — the
                # candidate query now allows healing back to that backend, so
                # we must overwrite the dead row instead of tripping the PK.
                self.db._conn.execute(
                    """INSERT INTO chunk_locations
                       (chunk_id, sub_block_index, backend_id, reference_id, url_type,
                        upload_date, status, quota_reserved)
                       VALUES (?, ?, ?, '', 'permanent', ?, 'pending', ?)
                       ON CONFLICT(chunk_id, sub_block_index, backend_id) DO UPDATE SET
                          reference_id = '', url_type = 'permanent',
                          upload_date = excluded.upload_date,
                          last_verified = NULL, status = 'pending',
                          quota_reserved = excluded.quota_reserved""",
                    (chunk_id, idx, target_id, _now_iso(), sub_quota)
                )

        # 5. Upload all sub-blocks
        if not getattr(target_obj, "_connected", False):
            await target_obj.connect()
            target_obj._connected = True

        try:
            for idx in range(sub_block_count):
                blocks_list = all_sub_block_ciphertexts[idx]
                
                async def _stream_data(bl=blocks_list):
                    for b in bl:
                        yield b

                ref_id = await target_obj.upload(
                    stream=_stream_data(),
                    chunk_id=chunk_id,
                    sub_block_index=idx
                )

                # Confirm each sub-block location
                with self.db.transaction():
                    self.db._conn.execute(
                        """UPDATE chunk_locations
                           SET status = 'confirmed', reference_id = ?, quota_reserved = 0
                           WHERE chunk_id = ? AND sub_block_index = ? AND backend_id = ?""",
                        (ref_id, chunk_id, idx, target_id)
                    )
            
            # Confirm quota after all sub-blocks are successfully uploaded
            with self.db.transaction():
                qm.confirm(target_id, size)

            logger.info("Successfully healed/replicated chunk %s (all %d sub-blocks) to target backend %s.", chunk_id[:8], sub_block_count, target_type)
            
            # Emit Qt signals to refresh UI on main thread safely
            if hasattr(self.main_view, 'healing_completed'):
                self.main_view.healing_completed.emit()
            if hasattr(self.main_view, 'backends_changed'):
                self.main_view.backends_changed.emit()

        except Exception as exc:
            # Restore quota and fail all locations on error
            with self.db.transaction():
                for idx in range(sub_block_count):
                    self.db._conn.execute(
                        """UPDATE chunk_locations
                           SET status = 'failed', quota_reserved = 0
                           WHERE chunk_id = ? AND sub_block_index = ? AND backend_id = ?""",
                        (chunk_id, idx, target_id)
                    )
                qm.restore(target_id, size)
            raise exc
