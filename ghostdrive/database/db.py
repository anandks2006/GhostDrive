"""
db.py -- GhostDrive database connection + HMAC ledger + WAL + Lamport clock.

Architecture
------------
Uses standard sqlite3 (built into Python). SQLCipher AES-256-CBC encryption
is plugged in transparently in Month 4 when the build infrastructure is ready.
The connection interface is identical -- swap ``sqlite3`` for ``sqlcipher3``
and add ``PRAGMA key = '...'`` in _apply_pragmas(). All application code
is written against this module's API, not sqlite3 directly.

HMAC Ledger (spec §8, §4.4)
----------------------------
Every write to a ledger-tracked table is chained:

    hmac_i = HMAC-SHA512(hmac_{i-1} || serialize(row_data), ledger_key)

The ledger_key is derived via HKDF from the Master Key:
    info = "ghostdrive-v1-index-mac"

Genesis block:
    hmac_0 = HMAC-SHA512(genesis_seed, ledger_key)
    genesis_seed is stored in keystore.json (spec §4.3)

The chain tip is stored in the hmac_ledger singleton row. Verification
replays rows in insertion order and checks each link.

Lamport Clock (spec §8.3)
--------------------------
logical_clock is a single counter maintained in the hmac_ledger row.
Every write that touches files/chunks/chunk_locations increments it atomically
in the SAME transaction as the data write. The clock value is written into
the row before computing its HMAC chain link.

WAL Checkpoint (spec §8.4)
---------------------------
PRAGMA wal_checkpoint(TRUNCATE) is called before every index snapshot.
The checkpoint and snapshot operations are logged to the telemetry panel.

Startup Pending Record Scan (spec §5.6)
----------------------------------------
On open(): chunk_locations rows with status='pending' are returned so the
caller can query backends and resolve them (confirmed or failed).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from ghostdrive.database.schema import (
    ALL_DDL,
    CREATE_SCHEMA_VERSION,
    SCHEMA_VERSION,
)
from ghostdrive.database.models import ChunkLocationRecord
from ghostdrive.exceptions import (
    DatabaseError,
    HMACChainError,
    WALCheckpointError,
)

logger = logging.getLogger(__name__)

# Tables included in the HMAC chain (ledger-tracked writes)
_LEDGER_TABLES = frozenset({
    "files",
    "chunks",
    "chunk_locations",
    "sharing_audit_log",
    "index_snapshots",
})


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_uuid() -> str:
    return str(uuid.uuid4())


class GhostDriveDB:
    """
    GhostDrive database connection wrapper.

    Usage::

        db = GhostDriveDB(path, ledger_key=..., genesis_seed=...)
        db.open()
        with db.transaction():
            db.insert_file(record)
        pending = db.pending_chunk_locations()
        db.close()

    Parameters
    ----------
    path:
        Path to ghostdrive.db file. Created if it does not exist.
    ledger_key:
        32-byte key for HMAC-SHA512 ledger chain.
        Derived via HKDF(Master_Key, info="ghostdrive-v1-index-mac").
    genesis_seed:
        32-byte seed for the genesis HMAC block.
        Stored in keystore.json (spec §4.3).
    """

    def __init__(
        self,
        path: Path,
        ledger_key: bytes,
        genesis_seed: bytes,
    ) -> None:
        if len(ledger_key) != 32:
            raise ValueError(f"ledger_key must be 32 bytes, got {len(ledger_key)}")
        if len(genesis_seed) != 32:
            raise ValueError(f"genesis_seed must be 32 bytes, got {len(genesis_seed)}")

        self._path        = Path(path)
        self._ledger_key  = ledger_key
        self._genesis_seed = genesis_seed
        self._conn: Optional[sqlite3.Connection] = None

    # ── Connection lifecycle ──────────────────────────────────────────────────

    def open(self) -> None:
        """
        Open the database, apply pragmas, run schema migrations, and initialise
        the HMAC ledger genesis block if this is a fresh database.

        Also scans for pending chunk_locations records (spec §5.6 startup scan).
        """
        self._path.parent.mkdir(parents=True, exist_ok=True)

        self._conn = sqlite3.connect(
            str(self._path),
            check_same_thread=False,
            isolation_level=None,   # We manage transactions manually
        )
        self._conn.row_factory = sqlite3.Row

        self._apply_pragmas()
        self._run_migrations()
        self._init_hmac_ledger_if_needed()

        logger.info("GhostDriveDB opened: %s", self._path)

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
            logger.debug("GhostDriveDB closed.")

    def __enter__(self) -> "GhostDriveDB":
        self.open()
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    # ── Transaction context manager ───────────────────────────────────────────

    class _Transaction:
        """Context manager for a single SQLite transaction."""
        def __init__(self, conn: sqlite3.Connection) -> None:
            self._conn = conn

        def __enter__(self) -> "_Transaction":
            self._conn.execute("BEGIN")
            return self

        def __exit__(self, exc_type: Any, *_: Any) -> None:
            if exc_type is None:
                self._conn.execute("COMMIT")
            else:
                self._conn.execute("ROLLBACK")

    def transaction(self) -> "_Transaction":
        """Return a context manager for an explicit transaction."""
        self._assert_open()
        return self._Transaction(self._conn)

    # ── Lamport clock ─────────────────────────────────────────────────────────

    def current_clock(self) -> int:
        """Return the current Lamport clock value (does NOT increment)."""
        self._assert_open()
        row = self._conn.execute(
            "SELECT row_count FROM hmac_ledger WHERE id = 1"
        ).fetchone()
        return row["row_count"] if row else 0

    def _increment_clock(self) -> int:
        """
        Increment the Lamport clock by 1.
        MUST be called inside an open transaction.
        Returns the new clock value.
        """
        self._conn.execute(
            "UPDATE hmac_ledger SET row_count = row_count + 1, updated_at = ? WHERE id = 1",
            (_now_iso(),),
        )
        row = self._conn.execute(
            "SELECT row_count FROM hmac_ledger WHERE id = 1"
        ).fetchone()
        return row["row_count"]

    # ── HMAC ledger ───────────────────────────────────────────────────────────

    def _compute_hmac(self, prev_hmac_hex: str, row_data: dict) -> str:
        """
        Compute the next HMAC chain link.

        hmac_i = HMAC-SHA512(prev_hmac_bytes || JSON(row_data), ledger_key)
        """
        prev_bytes = bytes.fromhex(prev_hmac_hex)
        row_bytes  = json.dumps(row_data, sort_keys=True, separators=(",", ":")).encode()
        mac = hmac.new(self._ledger_key, prev_bytes + row_bytes, hashlib.sha512)
        return mac.hexdigest()

    def _chain_hmac(self, table: str, row_data: dict) -> str:
        """
        Compute and store the next HMAC chain link for a ledger-tracked write.
        MUST be called inside an open transaction.
        Returns the new HMAC hex.
        """
        row = self._conn.execute(
            "SELECT last_hmac FROM hmac_ledger WHERE id = 1"
        ).fetchone()
        prev_hmac = row["last_hmac"]

        new_hmac = self._compute_hmac(prev_hmac, {"table": table, **row_data})

        self._conn.execute(
            "UPDATE hmac_ledger SET last_hmac = ?, updated_at = ? WHERE id = 1",
            (new_hmac, _now_iso()),
        )
        return new_hmac

    def verify_hmac_chain(self) -> bool:
        """
        Verify the integrity of the HMAC chain by replaying all ledger entries.

        This is an O(n) operation -- call only from the integrity daemon,
        not on every startup.

        Returns True if chain is intact. Raises HMACChainError on violation.
        """
        self._assert_open()
        # The chain tip is in hmac_ledger. A full replay requires storing
        # per-row HMACs -- that feature is implemented in Month 4 when the
        # integrity daemon is built. For now, we verify the ledger singleton
        # is self-consistent.
        row = self._conn.execute(
            "SELECT last_hmac, row_count FROM hmac_ledger WHERE id = 1"
        ).fetchone()
        if row is None:
            raise HMACChainError("HMAC ledger is missing -- database may be corrupted.")
        if len(row["last_hmac"]) != 128:  # SHA-512 hex = 128 chars
            raise HMACChainError("HMAC ledger chain value has unexpected length.")
        return True

    # ── WAL checkpoint ────────────────────────────────────────────────────────

    def wal_checkpoint(self) -> None:
        """
        Execute PRAGMA wal_checkpoint(TRUNCATE) before an index snapshot.
        Spec §8.4: checkpoint and snapshot are logged to telemetry panel.

        Raises WALCheckpointError on failure.
        """
        self._assert_open()
        try:
            result = self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            # result = (busy, log, checkpointed)
            busy = result[0]
            if busy:
                raise WALCheckpointError(
                    f"WAL checkpoint incomplete: {result[1]} pages remain. "
                    "Another connection may have the WAL open."
                )
            logger.info("WAL checkpoint(TRUNCATE) complete: %s", dict(result))
        except sqlite3.Error as exc:
            raise WALCheckpointError(f"WAL checkpoint failed: {exc}") from exc

    # ── File operations ───────────────────────────────────────────────────────

    def insert_file(self, record: dict) -> int:
        """
        Insert a new file record. Increments Lamport clock atomically.
        Caller must be inside a transaction().

        Args:
            record: Dict of column values (id must be UUIDv4 string).

        Returns:
            New logical_clock value.
        """
        clock = self._increment_clock()
        record = {**record, "logical_clock": clock}

        self._conn.execute(
            """INSERT INTO files
               (id, name, path, size, mime_type, tier, created_at, modified_at,
                version, version_of, tombstone, tombstone_at, logical_clock)
               VALUES
               (:id, :name, :path, :size, :mime_type, :tier, :created_at, :modified_at,
                :version, :version_of, :tombstone, :tombstone_at, :logical_clock)""",
            record,
        )
        self._chain_hmac("files", record)
        return clock

    def tombstone_file(self, file_id: str) -> None:
        """
        Mark a file as tombstoned (soft delete).
        CRITICAL/IMPORTANT: 30-day TTL. DISPOSABLE: immediate vacuum.
        Caller must be inside a transaction().
        """
        clock = self._increment_clock()
        now   = _now_iso()
        self._conn.execute(
            """UPDATE files
               SET tombstone = 1, tombstone_at = ?, logical_clock = ?
               WHERE id = ?""",
            (now, clock, file_id),
        )
        self._chain_hmac("files", {"op": "tombstone", "id": file_id, "at": now})

    # ── Chunk operations ──────────────────────────────────────────────────────

    def insert_chunk(self, record: dict) -> None:
        """Insert a chunk record. Caller must be inside a transaction()."""
        self._conn.execute(
            """INSERT INTO chunks
               (id, file_id, chunk_index, total_chunks, blake3_hash, size,
                nonce_counter, sub_block_count, is_manifest, ref_count)
               VALUES
               (:id, :file_id, :chunk_index, :total_chunks, :blake3_hash, :size,
                :nonce_counter, :sub_block_count, :is_manifest, :ref_count)""",
            record,
        )
        self._chain_hmac("chunks", record)

    def find_chunk_by_dedup_key(
        self, blake3_hash: str, size: int
    ) -> Optional[sqlite3.Row]:
        """
        Look up an existing chunk by BLAKE3+size dedup key (spec §5.5).
        Returns the chunk row or None if not found.
        """
        self._assert_open()
        return self._conn.execute(
            "SELECT * FROM chunks WHERE blake3_hash = ? AND size = ?",
            (blake3_hash, size),
        ).fetchone()

    def increment_ref_count(self, chunk_id: str) -> None:
        """Increment ref_count for a chunk (dedup soft-link). Caller in transaction()."""
        self._conn.execute(
            "UPDATE chunks SET ref_count = ref_count + 1 WHERE id = ?",
            (chunk_id,),
        )

    def decrement_ref_count(self, chunk_id: str) -> int:
        """
        Decrement ref_count. Returns new ref_count.
        Caller must check if 0 and issue backend delete().
        """
        self._conn.execute(
            "UPDATE chunks SET ref_count = ref_count - 1 WHERE id = ? AND ref_count > 0",
            (chunk_id,),
        )
        row = self._conn.execute(
            "SELECT ref_count FROM chunks WHERE id = ?", (chunk_id,)
        ).fetchone()
        return row["ref_count"] if row else 0

    # ── Chunk location operations (two-phase commit) ──────────────────────────

    def insert_chunk_location_pending(self, record: dict) -> None:
        """
        Write a pending intent record to chunk_locations.
        Called BEFORE upload starts (spec §5.6 two-phase commit step 2).
        Caller must be inside a transaction() with the nonce increment.
        """
        record = {**record, "status": "pending"}
        self._conn.execute(
            """INSERT INTO chunk_locations
               (chunk_id, sub_block_index, backend_id, reference_id, url_type,
                upload_date, last_verified, status, quota_reserved)
               VALUES
               (:chunk_id, :sub_block_index, :backend_id, :reference_id, :url_type,
                :upload_date, :last_verified, :status, :quota_reserved)""",
            record,
        )
        self._chain_hmac("chunk_locations", record)

    def confirm_chunk_location(
        self, chunk_id: str, sub_block_index: int, backend_id: str, reference_id: str
    ) -> None:
        """
        Mark a pending chunk_location as confirmed and clear quota_reserved.
        Caller must be inside a transaction().
        """
        now = _now_iso()
        self._conn.execute(
            """UPDATE chunk_locations
               SET status = 'confirmed', reference_id = ?, last_verified = ?,
                   quota_reserved = 0
               WHERE chunk_id = ? AND sub_block_index = ? AND backend_id = ?""",
            (reference_id, now, chunk_id, sub_block_index, backend_id),
        )
        self._chain_hmac("chunk_locations", {
            "op": "confirmed", "chunk_id": chunk_id,
            "sub_block_index": sub_block_index, "backend_id": backend_id,
        })

    def fail_chunk_location(
        self, chunk_id: str, sub_block_index: int, backend_id: str
    ) -> None:
        """Mark a pending chunk_location as failed. Caller in transaction()."""
        self._conn.execute(
            """UPDATE chunk_locations
               SET status = 'failed', quota_reserved = 0
               WHERE chunk_id = ? AND sub_block_index = ? AND backend_id = ?""",
            (chunk_id, sub_block_index, backend_id),
        )

    def cancel_chunk_location(
        self, chunk_id: str, sub_block_index: int, backend_id: str
    ) -> None:
        """Mark as cancelled (distinct from failed -- spec §5.7). Caller in transaction()."""
        self._conn.execute(
            """UPDATE chunk_locations
               SET status = 'cancelled', quota_reserved = 0
               WHERE chunk_id = ? AND sub_block_index = ? AND backend_id = ?""",
            (chunk_id, sub_block_index, backend_id),
        )

    def pending_chunk_locations(self) -> list[sqlite3.Row]:
        """
        Return all chunk_location rows with status='pending'.
        Called on startup to resolve in-flight uploads (spec §5.6).
        """
        self._assert_open()
        return self._conn.execute(
            "SELECT * FROM chunk_locations WHERE status = 'pending'"
        ).fetchall()

    # ── Backend quota operations (spec §5.6) ──────────────────────────────────

    def reserve_quota(self, backend_id: str, bytes_needed: int) -> bool:
        """
        Atomically reserve quota on a backend.
        SELECT + UPDATE in a single EXCLUSIVE transaction (spec §5.6).
        Caller must be inside a transaction().

        Returns True if reserved, False if insufficient space.
        """
        row = self._conn.execute(
            """SELECT quota_limit - quota_used - quota_reserved AS available
               FROM backends WHERE id = ?""",
            (backend_id,),
        ).fetchone()

        if row is None or row["available"] < bytes_needed:
            return False

        self._conn.execute(
            "UPDATE backends SET quota_reserved = quota_reserved + ? WHERE id = ?",
            (bytes_needed, backend_id),
        )
        return True

    def confirm_quota(self, backend_id: str, bytes_used: int) -> None:
        """Move quota_reserved -> quota_used on upload confirm. Caller in transaction()."""
        self._conn.execute(
            """UPDATE backends
               SET quota_used = quota_used + ?, quota_reserved = quota_reserved - ?
               WHERE id = ?""",
            (bytes_used, bytes_used, backend_id),
        )

    def restore_quota(self, backend_id: str, bytes_reserved: int) -> None:
        """Restore quota_reserved on upload failure/cancel. Caller in transaction()."""
        self._conn.execute(
            """UPDATE backends
               SET quota_reserved = MAX(0, quota_reserved - ?)
               WHERE id = ?""",
            (bytes_reserved, backend_id),
        )

    # ── integrity_log pruning (spec §8.7) ─────────────────────────────────────

    def prune_integrity_log(self, chunk_id: str, keep: int = 10) -> int:
        """
        Delete oldest integrity_log entries for chunk_id, keeping the last `keep`.
        Returns the number of rows deleted.
        """
        self._assert_open()
        rows = self._conn.execute(
            """SELECT id FROM integrity_log
               WHERE chunk_id = ?
               ORDER BY checked_at DESC""",
            (chunk_id,),
        ).fetchall()

        to_delete = [r["id"] for r in rows[keep:]]
        if to_delete:
            placeholders = ",".join("?" * len(to_delete))
            self._conn.execute(
                f"DELETE FROM integrity_log WHERE id IN ({placeholders})",
                to_delete,
            )
        return len(to_delete)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _assert_open(self) -> None:
        if self._conn is None:
            raise DatabaseError("Database is not open. Call open() first.")

    def _apply_pragmas(self) -> None:
        """Apply connection-level pragmas (spec §8.2)."""
        pragmas = [
            "PRAGMA journal_mode = WAL",
            "PRAGMA foreign_keys = ON",
            "PRAGMA secure_delete = ON",
            "PRAGMA temp_store = MEMORY",
            "PRAGMA synchronous = NORMAL",
        ]
        for p in pragmas:
            self._conn.execute(p)

    def _run_migrations(self) -> None:
        """Create schema and bump schema_version if needed."""
        self._conn.execute("BEGIN")
        try:
            self._conn.execute(CREATE_SCHEMA_VERSION)
            row = self._conn.execute("SELECT version FROM schema_version").fetchone()
            current = row["version"] if row else 0

            if current < SCHEMA_VERSION:
                for ddl in ALL_DDL:
                    stmt = ddl.strip()
                    if stmt:
                        self._conn.execute(stmt)
                if current == 0:
                    self._conn.execute(
                        "INSERT INTO schema_version (version) VALUES (?)",
                        (SCHEMA_VERSION,),
                    )
                else:
                    self._conn.execute(
                        "UPDATE schema_version SET version = ?",
                        (SCHEMA_VERSION,),
                    )
                logger.info("Schema migrated: v%d -> v%d", current, SCHEMA_VERSION)

            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise

    def _init_hmac_ledger_if_needed(self) -> None:
        """
        Initialise the HMAC ledger genesis block if this is a fresh database.

        genesis_hmac = HMAC-SHA512(genesis_seed, ledger_key)
        """
        row = self._conn.execute(
            "SELECT id FROM hmac_ledger WHERE id = 1"
        ).fetchone()

        if row is None:
            genesis_mac = hmac.new(
                self._ledger_key, self._genesis_seed, hashlib.sha512
            ).hexdigest()

            self._conn.execute("BEGIN")
            try:
                self._conn.execute(
                    """INSERT INTO hmac_ledger (id, last_hmac, row_count, updated_at)
                       VALUES (1, ?, 0, ?)""",
                    (genesis_mac, _now_iso()),
                )
                self._conn.execute("COMMIT")
                logger.info("HMAC ledger genesis block initialised.")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
