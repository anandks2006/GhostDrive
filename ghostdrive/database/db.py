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
On open(): chunk_locations rows with status='pending' are settled by the
startup scan (_settle_dangling_intents) -- their quota reservation is
restored to the backend and the intent is marked 'cancelled', because the
upload that owned it died with the previous process.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from ghostdrive.database.schema import (
    ALL_DDL,
    CREATE_SCHEMA_VERSION,
    SCHEMA_VERSION,
)
from ghostdrive.exceptions import (
    DatabaseError,
    HMACChainError,
    WALCheckpointError,
)

_USING_SQLCIPHER = True
try:
    import sqlcipher3 as sqlite3
except ImportError:
    try:
        import pysqlcipher3 as sqlite3  # type: ignore
    except ImportError:
        import sqlite3
        _USING_SQLCIPHER = False

logger = logging.getLogger(__name__)

# Tables included in the HMAC chain (ledger-tracked writes)
_LEDGER_TABLES = frozenset({
    "files",
    "chunks",
    "chunk_locations",
    "sharing_audit_log",
    "index_snapshots",
    "destructive_ops_log",
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
        master_key: bytes,
    ) -> None:
        if len(ledger_key) not in (32, 64):
            raise ValueError(f"ledger_key must be 32 or 64 bytes, got {len(ledger_key)}")
        if len(genesis_seed) != 32:
            raise ValueError(f"genesis_seed must be 32 bytes, got {len(genesis_seed)}")
        if not isinstance(master_key, bytes) or len(master_key) != 32:
            raise ValueError(f"master_key must be exactly 32 bytes, got {len(master_key) if hasattr(master_key, '__len__') else type(master_key).__name__}")

        self._path        = Path(path)
        self._ledger_key  = ledger_key
        self._genesis_seed = genesis_seed
        self._master_key   = master_key
        self._conn: Optional[sqlite3.Connection] = None
        self.is_dirty     = False
        self._lock        = threading.RLock()

    def open(self) -> None:
        """
        Open the database, apply pragmas, run schema migrations, and initialise
        the HMAC ledger genesis block if this is a fresh database.

        Also scans for pending chunk_locations records (spec §5.6 startup
        scan): dangling intents are settled by _settle_dangling_intents --
        the scan is performed on every open(), not merely documented.
        """
        # SQLCipher availability is enforced at import time; no runtime check needed.
        with self._lock:
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
            # Spec §5.6 startup scan -- REAL, not just documented: settle
            # chunk_locations rows a crash left 'pending' (see
            # _settle_dangling_intents). Runs after schema/migrations so the
            # tables exist, outside any open transaction.
            self._settle_dangling_intents()

            logger.info("GhostDriveDB opened: %s", self._path)

    def close(self) -> None:
        """Close the database connection and zero key material from memory (Spec §4.6)."""
        import ctypes
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None
                logger.debug("GhostDriveDB closed.")

            # Securely zero out key material from memory using a ctypes buffer copy.
            # We copy the bytes into a mutable ctypes buffer and zero it — this avoids
            # the CPython-specific id() + offset trick which is not portable across
            # CPython versions or alternative Python implementations (PyPy, etc.).
            for key_attr in ("_master_key", "_ledger_key", "_genesis_seed"):
                key_val = getattr(self, key_attr, None)
                if isinstance(key_val, (bytes, bytearray)) and len(key_val) > 0:
                    try:
                        buf = ctypes.create_string_buffer(key_val)
                        ctypes.memset(buf, 0, len(key_val))
                    except Exception:
                        pass
                setattr(self, key_attr, None)

    def vacuum(self) -> None:
        """Run VACUUM to reclaim database space. Cannot be run inside a transaction."""
        self._assert_open()
        with self._lock:
            self._conn.execute("VACUUM")

    def __enter__(self) -> "GhostDriveDB":
        self.open()
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    # ── Transaction context manager ───────────────────────────────────────────

    class _Transaction:
        """Context manager for a single SQLite transaction.

        Transactions are flat (one level of BEGIN..COMMIT; nesting a
        ``transaction()`` inside another raises "cannot start a transaction
        within a transaction" -- the re-entrant RLock only serialises threads,
        it does not create SAVEPOINTs).  Behaviour is unchanged for callers.
        """
        def __init__(self, db: GhostDriveDB) -> None:
            self._db = db

        def __enter__(self) -> "GhostDriveDB._Transaction":
            self._db._lock.acquire()
            import time
            import random
            max_retries = 5
            for attempt in range(max_retries + 1):
                try:
                    # BEGIN IMMEDIATE -- not the default deferred BEGIN, and
                    # deliberately not BEGIN EXCLUSIVE:
                    #  * vs DEFERRED: a deferred transaction starts as a read
                    #    snapshot and must *upgrade* to a write lock on its
                    #    first UPDATE. If another connection commits between
                    #    the snapshot and the upgrade, SQLite fails the UPDATE
                    #    with SQLITE_BUSY_SNAPSHOT ("database is locked")
                    #    IMMEDIATELY -- PRAGMA busy_timeout is deliberately
                    #    NOT consulted for snapshot conflicts -- so read-then-
                    #    write helpers such as reserve_quota lost reservations
                    #    under contention. Taking the write lock up front makes
                    #    a stale snapshot impossible (spec §5.6 EXCLUSIVE
                    #    contract, quota.py).
                    #  * vs EXCLUSIVE: EXCLUSIVE additionally blocks readers,
                    #    which in WAL mode is pointless contention -- the whole
                    #    point is only to serialise WRITERS, so IMMEDIATE is
                    #    the minimal statement that upholds the contract.
                    # Cost: read-only transaction blocks now take the write
                    # lock too (slightly more writer contention between
                    # processes); accepted, the RLock already serialised
                    # threads within a process. The locked-retry loop is kept
                    # around BEGIN because IMMEDIATE can still hit "database
                    # is locked" while another process holds the writer lock
                    # (busy_timeout applies to that wait).
                    self._db._conn.execute("BEGIN IMMEDIATE")
                    break
                except sqlite3.OperationalError as exc:
                    if "locked" in str(exc).lower() and attempt < max_retries:
                        # Exponential backoff + jitter
                        delay = 0.05 * (2 ** attempt) + random.uniform(0, 0.02)
                        time.sleep(delay)
                        continue
                    self._db._lock.release()
                    raise
                except Exception:
                    self._db._lock.release()
                    raise
            return self

        def __exit__(self, exc_type: Any, *_: Any) -> None:
            try:
                if exc_type is None:
                    self._db._conn.execute("COMMIT")
                else:
                    self._db._conn.execute("ROLLBACK")
            finally:
                self._db._lock.release()

    def transaction(self) -> "GhostDriveDB._Transaction":
        """Return a context manager for an explicit transaction."""
        self._assert_open()
        return self._Transaction(self)

    # ── Lamport clock ─────────────────────────────────────────────────────────

    def current_clock(self) -> int:
        """Return the current Lamport clock value (does NOT increment)."""
        self._assert_open()
        with self._lock:
            row = self._conn.execute(
                "SELECT logical_clock FROM hmac_ledger WHERE id = 1"
            ).fetchone()
            return row["logical_clock"] if row else 0

    def _increment_clock(self) -> int:
        """
        Increment the Lamport clock by 1.
        MUST be called inside an open transaction.
        Returns the new clock value.
        """
        self._conn.execute(
            "UPDATE hmac_ledger SET logical_clock = logical_clock + 1, updated_at = ? WHERE id = 1",
            (_now_iso(),),
        )
        row = self._conn.execute(
            "SELECT logical_clock FROM hmac_ledger WHERE id = 1"
        ).fetchone()
        return row["logical_clock"]

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
        if not self._conn.in_transaction:
            logger.warning("HMAC ledger write performed outside of an active transaction. This is non-atomic.")

        with self._lock:
            row = self._conn.execute(
                "SELECT last_hmac FROM hmac_ledger WHERE id = 1"
            ).fetchone()
            prev_hmac = row["last_hmac"]

            serialized_row = json.dumps(row_data, sort_keys=True, separators=(",", ":"))
            new_hmac = self._compute_hmac(prev_hmac, {"table": table, **row_data})

            self._conn.execute(
                "UPDATE hmac_ledger SET last_hmac = ?, updated_at = ? WHERE id = 1",
                (new_hmac, _now_iso()),
            )
            # Write to ledger_entries table
            self._conn.execute(
                """INSERT INTO ledger_entries (table_name, row_data, hmac_link)
                   VALUES (?, ?, ?)""",
                (table, serialized_row, new_hmac),
            )
            self.is_dirty = True
            return new_hmac

    def verify_hmac_chain(self, partial_check: bool = False) -> bool:
        """
        Verify the integrity of the HMAC chain by replaying all ledger entries.
        """
        with self._lock:
            self._assert_open()
            row = self._conn.execute(
                "SELECT last_hmac, logical_clock FROM hmac_ledger WHERE id = 1"
            ).fetchone()
            if row is None:
                raise HMACChainError("HMAC ledger is missing -- database may be corrupted.")
            if len(row["last_hmac"]) != 128:  # SHA-512 hex = 128 chars
                raise HMACChainError("HMAC ledger chain value has unexpected length.")
            
            if partial_check:
                return True

            # Full O(N) verification
            current_hmac = hmac.new(
                self._ledger_key, self._genesis_seed, hashlib.sha512
            ).hexdigest()

            entries = self._conn.execute(
                "SELECT table_name, row_data, hmac_link FROM ledger_entries ORDER BY seq ASC"
            ).fetchall()

            for idx, entry in enumerate(entries):
                table = entry["table_name"]
                row_data_str = entry["row_data"]
                stored_link = entry["hmac_link"]

                try:
                    row_data = json.loads(row_data_str)
                except Exception as e:
                    raise HMACChainError(f"Ledger entry {idx} row_data is not valid JSON: {e}")

                expected_link = self._compute_hmac(current_hmac, {"table": table, **row_data})

                if not hmac.compare_digest(expected_link, stored_link):
                    raise HMACChainError(f"HMAC chain broken at entry {idx} (table {table}).")

                current_hmac = expected_link

            if not hmac.compare_digest(current_hmac, row["last_hmac"]):
                raise HMACChainError("HMAC chain verification failed: tip does not match the replayed chain.")

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

    # ── Settings operations ───────────────────────────────────────────────────

    def get_setting(self, key: str, default: str) -> str:
        """Query a setting value from the settings table."""
        self._assert_open()
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM settings WHERE key = ?", (key,)
            ).fetchone()
            return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        """Insert or update a setting value in the settings table."""
        self._assert_open()
        with self._lock:
            self._conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

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
        record = {
            **record,
            "logical_clock": clock,
            "thumbnail_blob": record.get("thumbnail_blob"),
            "tags": record.get("tags", ""),
        }

        self._conn.execute(
            """INSERT INTO files
               (id, name, path, size, mime_type, tier, created_at, modified_at,
                version, version_of, tombstone, tombstone_at, logical_clock, thumbnail_blob, tags)
               VALUES
               (:id, :name, :path, :size, :mime_type, :tier, :created_at, :modified_at,
                :version, :version_of, :tombstone, :tombstone_at, :logical_clock, :thumbnail_blob, :tags)""",
            record,
        )
        # Exclude blob from HMAC verification record since JSON cannot serialize bytes
        hmac_record = {k: v for k, v in record.items() if k != "thumbnail_blob"}
        self._chain_hmac("files", hmac_record)
        return clock

    def update_file_thumbnail(self, file_id: str, blob: bytes) -> None:
        """Update the thumbnail blob of a file. Caller must be in transaction()."""
        with self._lock:
            self._assert_open()
            clock = self._increment_clock()
            self._conn.execute(
                "UPDATE files SET thumbnail_blob = ?, logical_clock = ? WHERE id = ?",
                (blob, clock, file_id),
            )
            self._chain_hmac("files", {"op": "update_thumbnail", "id": file_id})

    def update_file_tags(self, file_id: str, tags: str) -> None:
        """Update the tags string of a file. Caller must be in transaction()."""
        with self._lock:
            self._assert_open()
            clock = self._increment_clock()
            self._conn.execute(
                "UPDATE files SET tags = ?, logical_clock = ? WHERE id = ?",
                (tags, clock, file_id),
            )
            self._chain_hmac("files", {"op": "update_tags", "id": file_id, "tags": tags})

    def get_file_versions(self, file_id: str) -> list[sqlite3.Row]:
        """
        Get all versions of a file (both parent versions and children versions).
        Returns a list of file rows sorted by version descending.
        """
        with self._lock:
            self._assert_open()
            
            # Step 1: Find the root version (where version_of is NULL)
            curr_id = file_id
            visited = set()
            while curr_id and curr_id not in visited:
                visited.add(curr_id)
                row = self._conn.execute("SELECT version_of FROM files WHERE id = ?", (curr_id,)).fetchone()
                if row and row["version_of"]:
                    curr_id = row["version_of"]
                else:
                    break
            
            root_id = curr_id
            
            # Step 2: Traverse down the chain via RECURSIVE CTE
            stmt = """
            WITH RECURSIVE version_chain(id) AS (
                SELECT id FROM files WHERE id = ?
                UNION ALL
                SELECT files.id FROM files
                JOIN version_chain ON files.version_of = version_chain.id
            )
            SELECT * FROM files WHERE id IN version_chain ORDER BY version DESC
            """
            return self._conn.execute(stmt, (root_id,)).fetchall()

    def restore_file_version(self, file_id: str, version_id_to_restore: str) -> None:
        """
        Restore an old file version as a new active version.
        Creates a new files row with version = active_version + 1,
        and associates it with the chunks of version_id_to_restore.
        """
        with self._lock:
            self._assert_open()
            
            versions = self.get_file_versions(file_id)
            if not versions:
                raise ValueError("No file versions found for this file.")
            active_version = versions[0]
            
            restore_row = None
            for v in versions:
                if v["id"] == version_id_to_restore:
                    restore_row = v
                    break
            if not restore_row:
                raise ValueError("Version to restore not found in chain.")
                
            new_id = _new_uuid()
            clock = self._increment_clock()
            now = _now_iso()
            new_version = active_version["version"] + 1
            
            self._conn.execute(
                """INSERT INTO files
                   (id, name, path, size, mime_type, tier, created_at, modified_at,
                    version, version_of, tombstone, tombstone_at, logical_clock, thumbnail_blob, tags)
                   VALUES
                   (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, ?, ?, ?)""",
                (
                    new_id, restore_row["name"], restore_row["path"], restore_row["size"],
                    restore_row["mime_type"], restore_row["tier"], now, now,
                    new_version, active_version["id"], clock, restore_row["thumbnail_blob"],
                    restore_row["tags"]
                )
            )
            self._chain_hmac("files", {
                "op": "restore_version", "id": new_id, "version": new_version,
                "version_of": active_version["id"], "restored_from": version_id_to_restore
            })
            
            chunks_to_copy = self._conn.execute(
                "SELECT * FROM chunks WHERE file_id = ?", (version_id_to_restore,)
            ).fetchall()
            
            for chunk in chunks_to_copy:
                new_chunk_id = _new_uuid()
                self._conn.execute(
                    """INSERT INTO chunks
                       (id, file_id, chunk_index, total_chunks, blake3_hash, size, nonce_counter, sub_block_count,
                        erasure_k, erasure_n, erasure_padlen, is_manifest, ref_count)
                       VALUES
                       (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        new_chunk_id, new_id, chunk["chunk_index"], chunk["total_chunks"],
                        chunk["blake3_hash"], chunk["size"], chunk["nonce_counter"],
                        chunk["sub_block_count"], chunk["erasure_k"], chunk["erasure_n"],
                        chunk["erasure_padlen"], chunk["is_manifest"], chunk["ref_count"]
                    )
                )
                self._chain_hmac("chunks", {"op": "copy_restore", "id": new_chunk_id, "file_id": new_id})
                
                locs = self._conn.execute(
                    "SELECT * FROM chunk_locations WHERE chunk_id = ?", (chunk["id"],)
                ).fetchall()
                for loc in locs:
                    self._conn.execute(
                        """INSERT INTO chunk_locations
                           (chunk_id, sub_block_index, backend_id, reference_id, url_type, upload_date, last_verified, status, quota_reserved)
                           VALUES
                           (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            new_chunk_id, loc["sub_block_index"], loc["backend_id"],
                            loc["reference_id"], loc["url_type"], loc["upload_date"],
                            loc["last_verified"], loc["status"], loc["quota_reserved"]
                        )
                    )
                    self._chain_hmac("chunk_locations", {"op": "copy_restore", "chunk_id": new_chunk_id, "backend_id": loc["backend_id"]})

    # ── File version history (file_versions, v14) ─────────────────────────────
    # Version rows are immutable: nothing here ever UPDATEs an existing row
    # (history is append-only; a restore inserts a new row instead).

    def insert_file_version(self, record: dict) -> None:
        """
        Insert one immutable file_versions row. Caller must be inside a transaction().

        Args:
            record: Dict with keys: id, file_id, version, reason, size,
                    blake3_hash, manifest (JSON string), created_at.
        """
        self._conn.execute(
            """INSERT INTO file_versions
               (id, file_id, version, reason, size, blake3_hash, manifest, created_at)
               VALUES
               (:id, :file_id, :version, :reason, :size, :blake3_hash, :manifest, :created_at)""",
            record,
        )
        self._chain_hmac("file_versions", record)

    def list_file_versions(self, file_id: str, limit: int = 50) -> list[sqlite3.Row]:
        """Version history for one file, newest first. Read-only."""
        self._assert_open()
        with self._lock:
            return self._conn.execute(
                """SELECT * FROM file_versions
                   WHERE file_id = ?
                   ORDER BY version DESC
                   LIMIT ?""",
                (file_id, max(1, int(limit))),
            ).fetchall()

    def latest_file_version(self, file_id: str) -> Optional[sqlite3.Row]:
        """Newest version row for a file, or None when the file has no history."""
        self._assert_open()
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM file_versions WHERE file_id = ? ORDER BY version DESC LIMIT 1",
                (file_id,),
            ).fetchone()

    def get_file_version(self, file_id: str, version: int) -> Optional[sqlite3.Row]:
        """Fetch one specific (file_id, version) row, or None."""
        self._assert_open()
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM file_versions WHERE file_id = ? AND version = ?",
                (file_id, int(version)),
            ).fetchone()

    def rehome_file_versions(self, old_file_id: str, new_file_id: str) -> int:
        """
        Move every version row from ``old_file_id`` to ``new_file_id``.

        Sync re-uploads supersede the files row (a fresh row holds the new
        generation), but the history belongs to the *path*, not the row id --
        without this, each change would hide all previous versions behind an
        id the API no longer returns. Returns the number of moved rows.
        Caller must be inside a transaction().
        """
        if old_file_id == new_file_id:
            return 0
        self._assert_open()
        existing = self._conn.execute(
            "SELECT COUNT(*) AS n FROM file_versions WHERE file_id = ?",
            (new_file_id,),
        ).fetchone()
        if int(existing["n"] or 0) > 0:
            # UNIQUE(file_id, version) would collide; callers only re-home onto
            # a freshly uploaded row, so this indicates a logic error.
            raise ValueError(
                f"Cannot re-home versions onto {new_file_id}: it already has version history."
            )
        cur = self._conn.execute(
            "UPDATE file_versions SET file_id = ? WHERE file_id = ?",
            (new_file_id, old_file_id),
        )
        moved = cur.rowcount
        if moved:
            self._chain_hmac("file_versions", {
                "op": "rehome", "from": old_file_id, "to": new_file_id, "moved": moved,
            })
        return moved

    def prune_file_versions(self, file_id: Optional[str], keep: int) -> int:
        """
        Delete the oldest versions beyond ``keep`` (per file; every file with
        history when ``file_id`` is None). Returns the number of removed rows.

        The version the live files row currently points at -- the one whose
        manifest is exactly the file's present chunk set -- is NEVER pruned,
        even when it falls outside the keep window: pruning it would orphan
        the live file's own state from its history, and callers rely on the
        newest matching version as the "current state" anchor. Caller must be
        inside a transaction().
        """
        self._assert_open()
        keep = max(0, int(keep))
        if file_id is None:
            targets = [
                r["file_id"]
                for r in self._conn.execute(
                    "SELECT DISTINCT file_id FROM file_versions"
                ).fetchall()
            ]
        else:
            targets = [file_id]

        removed = 0
        for target in targets:
            live_ids = {
                r["id"]
                for r in self._conn.execute(
                    "SELECT id FROM chunks WHERE file_id = ?", (target,)
                ).fetchall()
            }
            rows = self._conn.execute(
                """SELECT id, version, manifest FROM file_versions
                   WHERE file_id = ?
                   ORDER BY version DESC""",
                (target,),
            ).fetchall()
            for row in rows[keep:]:
                if live_ids:
                    try:
                        manifest = json.loads(row["manifest"] or "[]")
                    except json.JSONDecodeError:
                        manifest = []
                    manifest_ids = {
                        entry.get("chunk_id")
                        for entry in manifest
                        if isinstance(entry, dict)
                    }
                    if manifest_ids and manifest_ids == live_ids:
                        # This version IS the live file state -- keep it.
                        continue
                self._conn.execute(
                    "DELETE FROM file_versions WHERE id = ?", (row["id"],)
                )
                self._chain_hmac("file_versions", {
                    "op": "delete", "id": row["id"],
                    "file_id": target, "version": row["version"],
                })
                removed += 1
        return removed

    def get_storage_analytics(self) -> dict:
        """
        Gathers storage stats for the analytics panel.
        """
        with self._lock:
            self._assert_open()
            
            backends_rows = self._conn.execute(
                "SELECT type, quota_used, quota_limit FROM backends WHERE status != 'deprecated'"
            ).fetchall()
            backend_usage = [dict(r) for r in backends_rows]
            
            tier_rows = self._conn.execute(
                "SELECT tier, COUNT(*) as count, SUM(size) as total_size FROM files WHERE tombstone = 0 GROUP BY tier"
            ).fetchall()
            tier_usage = [dict(r) for r in tier_rows]
            
            mime_rows = self._conn.execute(
                "SELECT mime_type, COUNT(*) as count, SUM(size) as total_size FROM files WHERE tombstone = 0 GROUP BY mime_type"
            ).fetchall()
            
            type_groups = {"Documents": 0, "Images": 0, "Media": 0, "Code/Data": 0, "Other": 0}
            for row in mime_rows:
                mt = (row["mime_type"] or "").lower()
                sz = row["total_size"] or 0
                if any(x in mt for x in ["pdf", "doc", "text", "txt", "rtf", "epub", "csv"]):
                    type_groups["Documents"] += sz
                elif any(x in mt for x in ["image", "png", "jpg", "jpeg", "gif", "webp", "bmp"]):
                    type_groups["Images"] += sz
                elif any(x in mt for x in ["video", "mp4", "mkv", "avi", "audio", "mp3", "wav", "ogg", "flac"]):
                    type_groups["Media"] += sz
                elif any(x in mt for x in ["json", "yaml", "xml", "py", "go", "js", "ts", "html", "css", "bin", "octet"]):
                    type_groups["Code/Data"] += sz
                else:
                    type_groups["Other"] += sz
            
            history_rows = self._conn.execute(
                """SELECT strftime('%Y-%m', timestamp) as month, SUM(bytes_transferred) as total_bytes
                   FROM upload_history
                   WHERE success = 1 AND timestamp >= date('now', '-6 month')
                   GROUP BY month
                   ORDER BY month ASC"""
            ).fetchall()
            upload_history = [dict(r) for r in history_rows]
            
            return {
                "backend_usage": backend_usage,
                "tier_usage": tier_usage,
                "type_groups": type_groups,
                "upload_history": upload_history
            }

    def rotate_ledger_key(self, new_ledger_key: bytes) -> None:
        """
        Re-calculates the HMAC chain for all ledger_entries using the new ledger_key.
        """
        import hmac
        import hashlib
        with self._lock:
            self._assert_open()
            
            rows = self._conn.execute(
                "SELECT seq, table_name, row_data FROM ledger_entries ORDER BY seq ASC"
            ).fetchall()
            
            curr_hmac = hmac.new(new_ledger_key, self._genesis_seed, hashlib.sha512).hexdigest()
            
            for row in rows:
                seq = row["seq"]
                row_bytes = row["row_data"].encode("utf-8")
                prev_bytes = bytes.fromhex(curr_hmac)
                
                mac = hmac.new(new_ledger_key, prev_bytes + row_bytes, hashlib.sha512)
                curr_hmac = mac.hexdigest()
                
                self._conn.execute(
                    "UPDATE ledger_entries SET hmac_link = ? WHERE seq = ?",
                    (curr_hmac, seq)
                )
                
            self._ledger_key = new_ledger_key
            self._conn.execute(
                "UPDATE hmac_ledger SET last_hmac = ?, updated_at = ? WHERE id = 1",
                (curr_hmac, _now_iso())
            )

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

    def restore_file(self, file_id: str) -> None:
        """
        Restore a tombstoned file (un-tombstone).
        Caller must be inside a transaction().
        """
        clock = self._increment_clock()
        self._conn.execute(
            """UPDATE files
               SET tombstone = 0, tombstone_at = NULL, logical_clock = ?
               WHERE id = ?""",
            (clock, file_id),
        )
        self._chain_hmac("files", {"op": "restore", "id": file_id})

    def purge_file_permanently(self, file_id: str) -> None:
        """
        Permanently delete a file from the index.
        Chunks are only deleted from the index (and backend) when ref_count reaches 0.
        Caller must be inside a transaction().
        """
        self._increment_clock()

        chunks = self._conn.execute(
            "SELECT id FROM chunks WHERE file_id = ?", (file_id,)
        ).fetchall()

        for c in chunks:
            cid = c["id"]
            new_ref_count = self.decrement_ref_count(cid)

            if new_ref_count == 0:
                # No other files reference this chunk — safe to delete locations and chunk
                self._conn.execute(
                    "DELETE FROM chunk_locations WHERE chunk_id = ?", (cid,)
                )
                self._chain_hmac("chunk_locations", {"op": "delete", "chunk_id": cid})

                self._conn.execute("DELETE FROM chunks WHERE id = ?", (cid,))
                self._chain_hmac("chunks", {"op": "delete", "id": cid})
            else:
                # Find another active file to re-associate the chunk with (spec §5.8)
                # Prioritise files in the same version chain, then any active (non-tombstoned) file.
                other_file = self._conn.execute(
                    """SELECT id FROM files
                       WHERE id != ? AND tombstone = 0
                       ORDER BY (version_of = ? OR id = (SELECT version_of FROM files WHERE id = ?)) DESC, created_at DESC""",
                    (file_id, file_id, file_id),
                ).fetchone()
                
                if not other_file:
                    # Fallback to any file if no active files exist
                    other_file = self._conn.execute(
                        "SELECT id FROM files WHERE id != ?", (file_id,)
                    ).fetchone()

                if other_file:
                    self._conn.execute(
                        "UPDATE chunks SET file_id = ? WHERE id = ?",
                        (other_file["id"], cid)
                    )
                    self._chain_hmac("chunks", {"op": "reassociate", "id": cid, "file_id": other_file["id"]})
            # If ref_count > 0, chunk_locations and chunk row are preserved for other files

        # Clean up any child version links to preserve version chain logic and satisfy FOREIGN KEY constraints
        row = self._conn.execute("SELECT version_of FROM files WHERE id = ?", (file_id,)).fetchone()
        parent_version_id = row["version_of"] if row else None
        self._conn.execute(
            "UPDATE files SET version_of = ? WHERE version_of = ?",
            (parent_version_id, file_id)
        )
        self._chain_hmac("files", {"op": "relink_version", "parent_version_id": parent_version_id, "version_of_deleted": file_id})

        # Delete any shares associated with this file, and their audit logs to satisfy FOREIGN KEY constraints
        shares = self._conn.execute("SELECT id FROM shares WHERE file_id = ?", (file_id,)).fetchall()
        for share in shares:
            self._conn.execute("DELETE FROM sharing_audit_log WHERE share_id = ?", (share["id"],))
            self._conn.execute("DELETE FROM shares WHERE id = ?", (share["id"],))

        self._conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
        self._chain_hmac("files", {"op": "purge", "id": file_id})

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
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM chunks WHERE blake3_hash = ? AND size = ?",
                (blake3_hash, size),
            ).fetchone()

    def find_chunk_by_file_and_index(
        self, file_id: str, chunk_index: int
    ) -> Optional[sqlite3.Row]:
        """
        Look up an existing chunk by file_id and chunk_index.
        Returns the chunk row or None if not found.
        """
        self._assert_open()
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM chunks WHERE file_id = ? AND chunk_index = ?",
                (file_id, chunk_index),
            ).fetchone()

    def increment_ref_count(self, chunk_id: str) -> None:
        """Increment ref_count for a chunk (dedup soft-link). Caller in transaction()."""
        with self._lock:
            self._assert_open()
            self._increment_clock()
            self._conn.execute(
                "UPDATE chunks SET ref_count = ref_count + 1 WHERE id = ?",
                (chunk_id,),
            )
            self._chain_hmac("chunks", {"op": "increment_ref_count", "id": chunk_id})

    def decrement_ref_count(self, chunk_id: str) -> int:
        """
        Decrement ref_count. Returns new ref_count.
        Caller must check if 0 and issue backend delete().
        """
        with self._lock:
            self._assert_open()
            self._increment_clock()
            self._conn.execute(
                "UPDATE chunks SET ref_count = ref_count - 1 WHERE id = ? AND ref_count > 0",
                (chunk_id,),
            )
            row = self._conn.execute(
                "SELECT ref_count FROM chunks WHERE id = ?", (chunk_id,)
            ).fetchone()
            ref_count = row["ref_count"] if row else 0
            self._chain_hmac("chunks", {"op": "decrement_ref_count", "id": chunk_id, "ref_count": ref_count})
            return ref_count

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

    def find_chunk_location(
        self, chunk_id: str, sub_block_index: int, backend_id: str
    ) -> Optional[sqlite3.Row]:
        """
        Look up a specific chunk location record.
        Returns the row or None if not found.
        """
        self._assert_open()
        with self._lock:
            return self._conn.execute(
                """SELECT * FROM chunk_locations
                   WHERE chunk_id = ? AND sub_block_index = ? AND backend_id = ?""",
                (chunk_id, sub_block_index, backend_id),
            ).fetchone()

    def update_chunk_location_pending(self, record: dict) -> None:
        """
        Update an existing chunk location record back to pending status.
        Caller must be inside a transaction().
        """
        record = {**record, "status": "pending"}
        self._conn.execute(
            """UPDATE chunk_locations
               SET reference_id = :reference_id, url_type = :url_type,
                   upload_date = :upload_date, last_verified = :last_verified,
                   status = :status, quota_reserved = :quota_reserved
               WHERE chunk_id = :chunk_id AND sub_block_index = :sub_block_index AND backend_id = :backend_id""",
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
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM chunk_locations WHERE status = 'pending'"
            ).fetchall()

    def _settle_dangling_intents(self) -> None:
        """
        Spec §5.6 startup scan: settle chunk_locations rows a crash left
        with status='pending' (between the intent commit and confirm).

        An intent still pending at boot can never complete -- the upload that
        owned it is gone -- so its reserved quota would leak on the backend
        forever. Every dangling intent is settled exactly like an abandoned
        upload: the reservation is restored to its backend (clamped, the same
        statement services/retention.py prune_stale_locations applies to
        stale pendings) and the row is marked 'cancelled'. The row is kept
        (not deleted) so the HMAC ledger keeps an audit trail; the dead row
        is pruned later by retention exactly like any other cancelled row.

        Everything happens in ONE transaction (quota restore + status flip +
        a single _chain_hmac ledger link, mirroring retention's pattern), so
        the scan is idempotent: a second open() finds nothing to do. A cheap
        COUNT probe first, so databases without dangling intents pay exactly
        one extra query and no transaction at all.
        """
        self._assert_open()
        row = self._conn.execute(
            "SELECT COUNT(*) AS c FROM chunk_locations WHERE status = 'pending'"
        ).fetchone()
        count = int(row["c"]) if row else 0
        if count == 0:
            return

        quota_released = 0
        with self.transaction():
            pendings = self._conn.execute(
                """SELECT chunk_id, sub_block_index, backend_id, quota_reserved
                   FROM chunk_locations WHERE status = 'pending'"""
            ).fetchall()
            for p in pendings:
                reserved = int(p["quota_reserved"] or 0)
                if reserved > 0:
                    # Same clamped restore as services/retention.py: never go
                    # negative even if the backend counter was corrected
                    # elsewhere (e.g. a concurrent restore of this intent).
                    self._conn.execute(
                        "UPDATE backends SET quota_reserved = MAX(0, quota_reserved - ?) WHERE id = ?",
                        (reserved, p["backend_id"]),
                    )
                    quota_released += reserved
                self._conn.execute(
                    """UPDATE chunk_locations
                       SET status = 'cancelled', quota_reserved = 0
                       WHERE chunk_id = ? AND sub_block_index = ? AND backend_id = ?""",
                    (p["chunk_id"], p["sub_block_index"], p["backend_id"]),
                )
            # Ledger link mirroring retention.prune_stale_locations' pattern.
            self._chain_hmac("chunk_locations", {
                "op": "startup_settle", "category": "dangling_pending",
                "count": len(pendings), "quota_released": quota_released,
            })
        logger.warning(
            "Startup scan settled %d dangling pending intent(s), releasing %d "
            "reserved bytes (spec §5.6).", len(pendings), quota_released,
        )

    # ── Backend quota operations (spec §5.6) ──────────────────────────────────

    def reserve_quota(self, backend_id: str, bytes_needed: int) -> bool:
        """
        Atomically reserve quota on a backend.
        SELECT + UPDATE in a single IMMEDIATE transaction (spec §5.6).
        Caller must be inside a transaction().

        Returns True if reserved, False if insufficient space.
        """
        # Bounded whole-transaction retry of the SELECT->UPDATE pair. With
        # _Transaction issuing BEGIN IMMEDIATE the caller already holds the
        # write lock, so the historical SQLITE_BUSY_SNAPSHOT failure of a
        # deferred read->write upgrade cannot occur any more; the retry is
        # belt-and-braces for the rare remaining "database is locked" (e.g. a
        # WAL checkpoint or another process holding the writer lock longer
        # than busy_timeout allowed at BEGIN time). Re-running BOTH statements
        # re-reads availability before deciding, so a retry can never
        # double-count a reservation -- and a reservation attempt must never
        # be silently lost (spec §5.6 EXCLUSIVE contract, quota.py).
        import time
        import random
        for attempt in range(4):
            try:
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
            except sqlite3.OperationalError as exc:
                if "database is locked" not in str(exc).lower() or attempt == 3:
                    raise
                # Exponential backoff + jitter (mirrors _Transaction's loop).
                time.sleep(0.05 * (2 ** attempt) + random.uniform(0, 0.02))
        raise AssertionError("unreachable: reserve_quota retry loop exhausted")

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

    def get_backend_available_space(self, backend_id: str) -> int:
        """
        Return available free bytes on a backend (quota_limit - quota_used - quota_reserved).
        Read-only -- no transaction required.
        """
        self._assert_open()
        with self._lock:
            row = self._conn.execute(
                """SELECT quota_limit - quota_used - quota_reserved AS available
                   FROM backends WHERE id = ?""",
                (backend_id,),
            ).fetchone()
            return row["available"] if row and row["available"] > 0 else 0

    # ── integrity_log pruning (spec §8.7) ─────────────────────────────────────

    def prune_integrity_log(self, chunk_id: str, keep: int = 10) -> int:
        """
        Delete oldest integrity_log entries for chunk_id, keeping the last `keep`.
        Returns the number of rows deleted.
        """
        self._assert_open()
        with self._lock:
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

    # ── Web-facing query helpers ──────────────────────────────────────────────

    def list_files(
        self,
        directory: str = "/",
        search: Optional[str] = None,
        include_tombstones: bool = False,
    ) -> list[sqlite3.Row]:
        """List active (or tombstoned) file rows, newest modification first."""
        self._assert_open()
        clauses = ["tombstone = ?"]
        params: list[Any] = [1 if include_tombstones else 0]
        directory = (directory or "/").strip()
        if directory not in ("", "/"):
            prefix = directory.rstrip("/") + "/"
            clauses.append("(path = ? OR path LIKE ?)")
            params.extend([prefix.rstrip("/"), prefix + "%"])
        if search:
            clauses.append("name LIKE ?")
            params.append(f"%{search}%")
        where = " AND ".join(clauses)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM files WHERE {where} ORDER BY modified_at DESC, name ASC",
                params,
            ).fetchall()
            return rows

    def get_file(self, file_id: str) -> Optional[sqlite3.Row]:
        """Fetch one file row by UUID."""
        self._assert_open()
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM files WHERE id = ?", (file_id,)
            ).fetchone()

    def get_file_chunks(self, file_id: str) -> list[sqlite3.Row]:
        """Return all chunks for a file ordered by chunk_index."""
        self._assert_open()
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM chunks WHERE file_id = ? ORDER BY chunk_index ASC",
                (file_id,),
            ).fetchall()

    def get_chunk_locations(self, chunk_id: str) -> list[sqlite3.Row]:
        """Return all chunk_locations rows for a chunk, joined with backend type."""
        self._assert_open()
        with self._lock:
            return self._conn.execute(
                """SELECT cl.*, b.type AS backend_type, b.status AS backend_status
                   FROM chunk_locations cl
                   JOIN backends b ON cl.backend_id = b.id
                   WHERE cl.chunk_id = ?
                   ORDER BY cl.sub_block_index ASC""",
                (chunk_id,),
            ).fetchall()

    def rename_file(self, file_id: str, new_name: str, new_path: str) -> None:
        """Rename/move a file. Caller must be inside a transaction()."""
        clock = self._increment_clock()
        now = _now_iso()
        self._conn.execute(
            """UPDATE files
               SET name = ?, path = ?, modified_at = ?, logical_clock = ?
               WHERE id = ?""",
            (new_name, new_path, now, clock, file_id),
        )
        self._chain_hmac("files", {
            "op": "rename", "id": file_id, "name": new_name, "path": new_path,
        })

    def list_tombstoned_files(self, older_than_days: Optional[int] = None) -> list[sqlite3.Row]:
        """List soft-deleted files (GhostDrive Trash)."""
        self._assert_open()
        with self._lock:
            if older_than_days is None:
                return self._conn.execute(
                    "SELECT * FROM files WHERE tombstone = 1 ORDER BY tombstone_at DESC"
                ).fetchall()
            return self._conn.execute(
                """SELECT * FROM files
                   WHERE tombstone = 1
                     AND tombstone_at IS NOT NULL
                     AND tombstone_at <= datetime('now', ?)
                   ORDER BY tombstone_at ASC""",
                (f"-{int(older_than_days)} days",),
            ).fetchall()

    def insert_upload_history(self, record: dict) -> None:
        """Record one backend chunk transfer for analytics. Caller in transaction()."""
        self._conn.execute(
            """INSERT INTO upload_history
               (id, backend_id, chunk_id, timestamp, bytes_transferred, duration_ms, success)
               VALUES
               (:id, :backend_id, :chunk_id, :timestamp, :bytes_transferred, :duration_ms, :success)""",
            record,
        )

    def get_backend(self, backend_id: str) -> Optional[sqlite3.Row]:
        """Fetch one backend row by id."""
        self._assert_open()
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM backends WHERE id = ?", (backend_id,)
            ).fetchone()

    def list_backends(self, include_deprecated: bool = False) -> list[sqlite3.Row]:
        """Return configured backends ordered by priority."""
        self._assert_open()
        with self._lock:
            sql = "SELECT * FROM backends"
            if not include_deprecated:
                sql += " WHERE status != 'deprecated'"
            sql += " ORDER BY priority DESC, type ASC"
            return self._conn.execute(sql).fetchall()

    def update_backend_health(
        self,
        backend_id: str,
        status: str,
        latency_ms: Optional[float] = None,
        error: Optional[str] = None,
    ) -> None:
        """Persist the result of a backend health check."""
        self._assert_open()
        with self._lock:
            self._conn.execute(
                """UPDATE backends
                   SET status = ?, last_health_check = ?, latency_ms = ?, last_error = ?
                   WHERE id = ?""",
                (status, _now_iso(), latency_ms, error, backend_id),
            )

    def update_backend_status(self, backend_id: str, status: str) -> None:
        """Change a backend's routing status without a network call."""
        self._assert_open()
        with self._lock:
            self._conn.execute(
                "UPDATE backends SET status = ? WHERE id = ?", (status, backend_id)
            )

    def update_backend_quota_used(self, backend_id: str, quota_used: int) -> None:
        """Overwrite the quota_used counter for a backend."""
        self._assert_open()
        with self._lock:
            self._conn.execute(
                "UPDATE backends SET quota_used = ? WHERE id = ?",
                (max(0, int(quota_used)), backend_id),
            )

    def delete_backend(self, backend_id: str) -> None:
        """Delete a backend row and its registry entry. Caller inside transaction()."""
        self._conn.execute(
            "DELETE FROM drive_registry WHERE backend_id = ?", (backend_id,)
        )
        self._conn.execute("DELETE FROM backends WHERE id = ?", (backend_id,))

    def insert_integrity_log(
        self, log_id: str, chunk_id: str, backend_id: str, result: str
    ) -> None:
        """Record a chunk integrity verification result."""
        self._assert_open()
        with self._lock:
            self._conn.execute(
                """INSERT INTO integrity_log (id, chunk_id, checked_at, result, backend_id)
                   VALUES (?, ?, ?, ?, ?)""",
                (log_id, chunk_id, _now_iso(), result, backend_id),
            )

    def list_integrity_events(self, limit: int = 50) -> list[sqlite3.Row]:
        """Return recent integrity verification events, newest first."""
        self._assert_open()
        with self._lock:
            return self._conn.execute(
                """SELECT il.*, f.name AS filename
                   FROM integrity_log il
                   JOIN chunks c ON il.chunk_id = c.id
                   JOIN files f ON c.file_id = f.id
                   ORDER BY il.checked_at DESC LIMIT ?""",
                (limit,),
            ).fetchall()

    def get_analytics_summary(self) -> dict:
        """Aggregate storage counters for the analytics dashboard."""
        self._assert_open()
        with self._lock:
            files = self._conn.execute(
                """SELECT COUNT(*) AS count, COALESCE(SUM(size), 0) AS bytes
                   FROM files WHERE tombstone = 0"""
            ).fetchone()
            chunks = self._conn.execute(
                """SELECT COUNT(*) AS count,
                          COALESCE(SUM(c.size), 0) AS logical_bytes,
                          COALESCE(SUM(CASE WHEN c.ref_count > 1
                                            THEN c.size * (c.ref_count - 1) ELSE 0 END), 0) AS dedup_bytes
                   FROM chunks c
                   JOIN files f ON c.file_id = f.id
                   WHERE f.tombstone = 0"""
            ).fetchone()
            physical = self._conn.execute(
                "SELECT COALESCE(SUM(quota_used), 0) AS bytes FROM backends WHERE status != 'deprecated'"
            ).fetchone()
            return {
                "file_count": int(files["count"] or 0),
                "logical_bytes": int(files["bytes"] or 0),
                "chunk_count": int(chunks["count"] or 0),
                "chunk_logical_bytes": int(chunks["logical_bytes"] or 0),
                "dedup_savings_bytes": int(chunks["dedup_bytes"] or 0),
                "physical_bytes": int(physical["bytes"] or 0),
            }

    # ── Share link operations (web sharing) ───────────────────────────────────

    def insert_share_link(self, record: dict) -> None:
        """Create a password-protected/expiring download link. Caller in transaction()."""
        self._conn.execute(
            """INSERT INTO share_links
               (token, file_id, recipient_alias, passcode_hash, passcode_salt,
                created_at, expires_at, max_downloads, download_count, last_accessed, revoked)
               VALUES
               (:token, :file_id, :recipient_alias, :passcode_hash, :passcode_salt,
                :created_at, :expires_at, :max_downloads, 0, NULL, 0)""",
            record,
        )

    def get_share_link(self, token: str) -> Optional[sqlite3.Row]:
        """Fetch one share link by token."""
        self._assert_open()
        with self._lock:
            return self._conn.execute(
                """SELECT sl.*, f.name AS filename, f.size AS file_size,
                          f.mime_type AS mime_type
                   FROM share_links sl
                   JOIN files f ON sl.file_id = f.id
                   WHERE sl.token = ?""",
                (token,),
            ).fetchone()

    def list_share_links(self) -> list[sqlite3.Row]:
        """List share links with file metadata, newest first."""
        self._assert_open()
        with self._lock:
            return self._conn.execute(
                """SELECT sl.*, f.name AS filename, f.size AS file_size,
                          f.mime_type AS mime_type
                   FROM share_links sl
                   JOIN files f ON sl.file_id = f.id
                   ORDER BY sl.created_at DESC"""
            ).fetchall()

    def revoke_share_link(self, token: str) -> bool:
        """Revoke a share link. Returns True if it existed."""
        self._assert_open()
        with self._lock:
            cur = self._conn.execute(
                "UPDATE share_links SET revoked = 1 WHERE token = ?", (token,)
            )
            return cur.rowcount > 0

    def register_share_download(self, token: str) -> None:
        """Increment download counter and record access time."""
        self._assert_open()
        with self._lock:
            self._conn.execute(
                """UPDATE share_links
                   SET download_count = download_count + 1, last_accessed = ?
                   WHERE token = ?""",
                (_now_iso(), token),
            )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _assert_open(self) -> None:
        if self._conn is None:
            raise DatabaseError("Database is not open. Call open() first.")

    def _apply_pragmas(self) -> None:
        """Apply connection-level pragmas (spec §8.2)."""
        # Strictly enforce SQLCipher encryption if available (spec §8.1)
        if _USING_SQLCIPHER:
            key_hex = self._master_key.hex()
            self._conn.execute(f"PRAGMA key = \"x'{key_hex}'\"")
        else:
            logger.warning(
                "SQLCipher is not installed. Database will be stored UNENCRYPTED. "
                "For production security, please install sqlcipher3 or pysqlcipher3."
            )

        pragmas = [
            "PRAGMA journal_mode = WAL",
            "PRAGMA foreign_keys = ON",
            "PRAGMA secure_delete = ON",
            "PRAGMA temp_store = MEMORY",
            "PRAGMA busy_timeout = 5000",
            "PRAGMA journal_size_limit = 52428800",
            "PRAGMA wal_autocheckpoint = 1000",
            # FULL not NORMAL: nonce_counter values are stored in chunks.nonce_counter.
            # A power-loss that corrupts a committed nonce counter could allow nonce
            # reuse under ChaCha20-Poly1305, which is catastrophic. FULL ensures
            # fsync() is called before every write completes (WAL safe point).
            "PRAGMA synchronous = FULL",
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
                if current == 1:
                    try:
                        self._conn.execute("ALTER TABLE files ADD COLUMN thumbnail_blob BLOB")
                        logger.info("Database migration: Added thumbnail_blob column to files table.")
                    except sqlite3.OperationalError as e:
                        if "duplicate column name" not in str(e).lower():
                            raise
                    current = 2

                if current == 2:
                    try:
                        self._conn.execute("ALTER TABLE hmac_ledger RENAME COLUMN row_count TO logical_clock")
                        logger.info("Database migration: Renamed row_count to logical_clock in hmac_ledger.")
                    except sqlite3.OperationalError as e:
                        if "no such column" not in str(e).lower():
                            raise
                    current = 3

                if current == 3:
                    # v4 adds five new tables (secrets_vault, drive_registry,
                    # smart_history, tier_patterns, destructive_ops_log).
                    # CREATE TABLE IF NOT EXISTS in ALL_DDL handles creation;
                    # no destructive changes needed.
                    logger.info(
                        "Database migration: v3 -> v4 "
                        "(secrets_vault, drive_registry, smart_history, "
                        "tier_patterns, destructive_ops_log)"
                    )
                    current = 4

                if current == 4:
                    try:
                        self._conn.execute(
                            """CREATE TABLE IF NOT EXISTS ledger_entries (
                                seq        INTEGER PRIMARY KEY AUTOINCREMENT,
                                table_name TEXT NOT NULL,
                                row_data   TEXT NOT NULL,
                                hmac_link  TEXT NOT NULL
                            ) STRICT;"""
                        )
                        self._conn.execute(
                            "ALTER TABLE hmac_ledger ADD COLUMN nonce_counter INTEGER NOT NULL DEFAULT 0"
                        )
                        logger.info("Database migration: v4 -> v5 (created ledger_entries, added nonce_counter to hmac_ledger).")
                    except sqlite3.OperationalError as e:
                        logger.warning("Database migration v4 -> v5 operational warning: %s", e)
                    current = 5

                if current == 5:
                    try:
                        logger.info("Database migration: v5 -> v6 (Unified FTS5 table and triggers in main DB).")
                    except Exception as e:
                        logger.warning("Database migration v5 -> v6 warning: %s", e)
                    current = 6

                if current == 6:
                    try:
                         logger.info("Database migration: v6 -> v7 (created settings table).")
                    except Exception as e:
                         logger.warning("Database migration v6 -> v7 warning: %s", e)
                    current = 7

                if current == 7:
                    try:
                        self._conn.execute("ALTER TABLE files ADD COLUMN tags TEXT NOT NULL DEFAULT ''")
                        logger.info("Database migration: Added tags column to files table.")
                    except sqlite3.OperationalError as e:
                        if "duplicate column name" not in str(e).lower():
                            raise
                    current = 8

                if current == 8:
                    try:
                        self._conn.execute("ALTER TABLE contacts ADD COLUMN onion_address TEXT NOT NULL DEFAULT ''")
                        self._conn.execute("ALTER TABLE contacts ADD COLUMN mlkem_public_key TEXT NOT NULL DEFAULT ''")
                        logger.info("Database migration: Added onion_address and mlkem_public_key columns to contacts table.")
                    except sqlite3.OperationalError as e:
                        if "duplicate column name" not in str(e).lower():
                            raise
                    current = 9

                if current == 9:
                    # v9 -> v10: drop the `satellite` column from backends (Storj artefact).
                    # SQLite < 3.35 does not support DROP COLUMN, so we rebuild the table.
                    try:
                        cols = [row["name"] for row in self._conn.execute("PRAGMA table_info(backends)").fetchall()]
                        if "satellite" in cols:
                            self._conn.execute("""
                                CREATE TABLE backends_new (
                                    id                TEXT PRIMARY KEY,
                                    type              TEXT NOT NULL,
                                    credentials_ref   TEXT NOT NULL,
                                    status            TEXT NOT NULL DEFAULT 'healthy'
                                                      CHECK(status IN ('healthy','degraded','unreachable','deprecated')),
                                    priority          INTEGER NOT NULL DEFAULT 100,
                                    last_health_check TEXT,
                                    quota_used        INTEGER NOT NULL DEFAULT 0,
                                    quota_limit       INTEGER NOT NULL DEFAULT 4611686018427387904,
                                    quota_reserved    INTEGER NOT NULL DEFAULT 0,
                                    ml_artifacts_only INTEGER NOT NULL DEFAULT 0,
                                    cpu_intensive     INTEGER NOT NULL DEFAULT 0,
                                    deprecated_at     TEXT
                                ) STRICT;
                            """)
                            self._conn.execute("""
                                INSERT INTO backends_new
                                    (id, type, credentials_ref, status, priority, last_health_check,
                                     quota_used, quota_limit, quota_reserved, ml_artifacts_only,
                                     cpu_intensive, deprecated_at)
                                SELECT id, type, credentials_ref, status, priority, last_health_check,
                                       quota_used, quota_limit, quota_reserved, ml_artifacts_only,
                                       cpu_intensive, deprecated_at
                                FROM backends;
                            """)
                            self._conn.execute("DROP TABLE backends")
                            self._conn.execute("ALTER TABLE backends_new RENAME TO backends")
                            logger.info("Database migration: v9 -> v10 (dropped satellite column from backends).")
                        else:
                            logger.info("Database migration: v9 -> v10 (satellite column already absent, skipping rebuild).")
                    except sqlite3.OperationalError as e:
                        logger.warning("Database migration v9 -> v10 warning: %s", e)
                    current = 10

                if current == 10:
                    # v10 -> v11: backend health telemetry columns + share_links table.
                    try:
                        cols = [r["name"] for r in self._conn.execute("PRAGMA table_info(backends)").fetchall()]
                        if "latency_ms" not in cols:
                            self._conn.execute("ALTER TABLE backends ADD COLUMN latency_ms REAL")
                        if "last_error" not in cols:
                            self._conn.execute("ALTER TABLE backends ADD COLUMN last_error TEXT")
                        logger.info("Database migration: v10 -> v11 (backend health telemetry, share links).")
                    except sqlite3.OperationalError as e:
                        logger.warning("Database migration v10 -> v11 warning: %s", e)
                    current = 11

                if current == 11:
                    # v11 -> v12: explicit erasure parameters + snapshot copies
                    # and restore-proof attestations.
                    try:
                        cols = [r["name"] for r in self._conn.execute("PRAGMA table_info(chunks)").fetchall()]
                        if "erasure_k" not in cols:
                            self._conn.execute("ALTER TABLE chunks ADD COLUMN erasure_k INTEGER NOT NULL DEFAULT 0")
                        if "erasure_n" not in cols:
                            self._conn.execute("ALTER TABLE chunks ADD COLUMN erasure_n INTEGER NOT NULL DEFAULT 0")
                        if "erasure_padlen" not in cols:
                            self._conn.execute("ALTER TABLE chunks ADD COLUMN erasure_padlen INTEGER NOT NULL DEFAULT 0")
                        snap_cols = [r["name"] for r in self._conn.execute("PRAGMA table_info(index_snapshots)").fetchall()]
                        if "slot" not in snap_cols:
                            self._conn.execute("ALTER TABLE index_snapshots ADD COLUMN slot INTEGER NOT NULL DEFAULT 0")
                        if "snapshot_size" not in snap_cols:
                            self._conn.execute("ALTER TABLE index_snapshots ADD COLUMN snapshot_size INTEGER NOT NULL DEFAULT 0")
                        logger.info("Database migration: v11 -> v12 (erasure metadata, snapshot copies, restore drills).")
                    except sqlite3.OperationalError as e:
                        logger.warning("Database migration v11 -> v12 warning: %s", e)
                    current = 12

                if current == 12:
                    # v12 -> v13: always-on protection sets. Tables are created
                    # by the shared ALL_DDL pass below.
                    logger.info("Database migration: v12 -> v13 (always-on protection sets).")
                    current = 13

                if current == 13:
                    # v13 -> v14: immutable file version history (file_versions).
                    # The table and its index are created by the shared
                    # ALL_DDL pass below, so no DDL is needed here.
                    logger.info("Database migration: v13 -> v14 (file version history).")
                    current = 14

                if current == 14:
                    # v14 -> v15: WORM / append-only backend capability flag.
                    # backends.append_only marks a backend whose bytes must
                    # never be overwritten or deleted through the app, even on
                    # request (application-level WORM, not hardware WORM).
                    # Fresh installs already have the column from
                    # CREATE_BACKENDS; this guarded ALTER upgrades v14 rows.
                    try:
                        cols = [r["name"] for r in self._conn.execute("PRAGMA table_info(backends)").fetchall()]
                        if "append_only" not in cols:
                            self._conn.execute(
                                "ALTER TABLE backends ADD COLUMN append_only INTEGER NOT NULL DEFAULT 0"
                            )
                        logger.info("Database migration: v14 -> v15 (backends.append_only WORM flag).")
                    except sqlite3.OperationalError as e:
                        logger.warning("Database migration v14 -> v15 warning: %s", e)
                    current = 15

                for ddl in ALL_DDL:
                    stmt = ddl.strip()
                    if stmt:
                        self._conn.execute(stmt)
                if row is None:
                    self._conn.execute(
                        "INSERT INTO schema_version (version) VALUES (?)",
                        (SCHEMA_VERSION,),
                    )
                else:
                    self._conn.execute(
                        "UPDATE schema_version SET version = ?",
                        (SCHEMA_VERSION,),
                    )
                logger.info("Schema migrated: v%d -> v%d", row["version"] if row else 0, SCHEMA_VERSION)

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
                    """INSERT INTO hmac_ledger (id, last_hmac, logical_clock, nonce_counter, updated_at)
                       VALUES (1, ?, 0, 0, ?)""",
                    (genesis_mac, _now_iso()),
                )
                self._conn.execute("COMMIT")
                logger.info("HMAC ledger genesis block initialised.")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def restore_hmac_ledger_from_snapshot(self, last_hmac: str, logical_clock: int) -> None:
        """
        Re-initialise or update the HMAC ledger state with a recovered tip and clock.
        Used during disaster recovery and multi-device sync.
        """
        self._assert_open()
        self._conn.execute("BEGIN")
        try:
            row = self._conn.execute("SELECT nonce_counter FROM hmac_ledger WHERE id = 1").fetchone()
            nonce_counter = row["nonce_counter"] if row else 0
            self._conn.execute(
                """INSERT OR REPLACE INTO hmac_ledger (id, last_hmac, logical_clock, nonce_counter, updated_at)
                   VALUES (1, ?, ?, ?, ?)""",
                (last_hmac, logical_clock, nonce_counter, _now_iso()),
            )
            self._conn.execute("COMMIT")
            logger.info("HMAC ledger restored/updated from snapshot: clock=%d", logical_clock)
        except Exception:
            self._conn.execute("ROLLBACK")
            raise

    # ── Secrets vault CRUD ────────────────────────────────────────────────────

    def insert_secret(self, record: dict) -> None:
        """
        Insert a new secrets_vault entry. Increments Lamport clock atomically.
        Caller must be inside a transaction().

        Args:
            record: Dict with keys: id, label, kind, encrypted_blob,
                    created_at, modified_at.
        """
        clock = self._increment_clock()
        record = {**record, "logical_clock": clock}
        self._conn.execute(
            """INSERT INTO secrets_vault
               (id, label, kind, encrypted_blob, created_at, modified_at, logical_clock)
               VALUES
               (:id, :label, :kind, :encrypted_blob, :created_at, :modified_at, :logical_clock)""",
            record,
        )
        # encrypted_blob excluded from HMAC (binary, not JSON-serialisable)
        hmac_record = {k: v for k, v in record.items() if k != "encrypted_blob"}
        self._chain_hmac("secrets_vault", hmac_record)

    def update_secret(self, secret_id: str, label: str, encrypted_blob: bytes) -> None:
        """
        Update label and encrypted_blob of an existing secret. Caller in transaction().
        """
        clock = self._increment_clock()
        now   = _now_iso()
        self._conn.execute(
            """UPDATE secrets_vault
               SET label = ?, encrypted_blob = ?, modified_at = ?, logical_clock = ?
               WHERE id = ?""",
            (label, encrypted_blob, now, clock, secret_id),
        )
        self._chain_hmac("secrets_vault", {"op": "update", "id": secret_id, "at": now})

    def delete_secret(self, secret_id: str) -> None:
        """Delete a secret entry. Caller must be inside a transaction()."""
        self._increment_clock()
        self._conn.execute("DELETE FROM secrets_vault WHERE id = ?", (secret_id,))
        self._chain_hmac("secrets_vault", {"op": "delete", "id": secret_id})

    def get_secret(self, secret_id: str) -> Optional[sqlite3.Row]:
        """Fetch one secrets_vault row by id. Read-only."""
        self._assert_open()
        return self._conn.execute(
            "SELECT * FROM secrets_vault WHERE id = ?", (secret_id,)
        ).fetchone()

    def list_secrets(self, kind: Optional[str] = None) -> list[sqlite3.Row]:
        """
        List all secrets_vault entries, optionally filtered by kind.
        Ordered by label ascending.
        """
        self._assert_open()
        if kind:
            return self._conn.execute(
                "SELECT * FROM secrets_vault WHERE kind = ? ORDER BY label", (kind,)
            ).fetchall()
        return self._conn.execute(
            "SELECT * FROM secrets_vault ORDER BY label"
        ).fetchall()

    # ── Drive registry CRUD ───────────────────────────────────────────────────

    def insert_drive_registry(self, record: dict) -> None:
        """
        Register a new local/external/NAS drive as a backend.
        Caller must be inside a transaction().

        Args:
            record: Dict with keys: backend_id, drive_uuid, drive_serial,
                    drive_label, drive_type, capacity_bytes, mount_hint,
                    registered_at. last_seen_at defaults to None.
        """
        record = {**record, "last_seen_at": record.get("last_seen_at")}
        self._conn.execute(
            """INSERT INTO drive_registry
               (backend_id, drive_uuid, drive_serial, drive_label, drive_type,
                capacity_bytes, mount_hint, registered_at, last_seen_at)
               VALUES
               (:backend_id, :drive_uuid, :drive_serial, :drive_label, :drive_type,
                :capacity_bytes, :mount_hint, :registered_at, :last_seen_at)""",
            record,
        )

    def get_drive_registry_by_backend(
        self, backend_id: str
    ) -> Optional[sqlite3.Row]:
        """Fetch drive_registry row by backend_id."""
        self._assert_open()
        return self._conn.execute(
            "SELECT * FROM drive_registry WHERE backend_id = ?", (backend_id,)
        ).fetchone()

    def get_drive_registry_by_uuid(self, drive_uuid: str) -> Optional[sqlite3.Row]:
        """Fetch drive_registry row by drive UUID. Returns first match."""
        self._assert_open()
        return self._conn.execute(
            "SELECT * FROM drive_registry WHERE drive_uuid = ?", (drive_uuid,)
        ).fetchone()

    def update_drive_last_seen(
        self, backend_id: str, mount_hint: Optional[str] = None
    ) -> None:
        """
        Update last_seen_at (and optionally mount_hint) when a registered drive
        is detected as connected. Caller must be inside a transaction().
        """
        now = _now_iso()
        if mount_hint is not None:
            self._conn.execute(
                """UPDATE drive_registry
                   SET last_seen_at = ?, mount_hint = ?
                   WHERE backend_id = ?""",
                (now, mount_hint, backend_id),
            )
        else:
            self._conn.execute(
                "UPDATE drive_registry SET last_seen_at = ? WHERE backend_id = ?",
                (now, backend_id),
            )

    def list_drive_registry(self) -> list[sqlite3.Row]:
        """List all registered local drives."""
        self._assert_open()
        return self._conn.execute(
            "SELECT * FROM drive_registry ORDER BY drive_label"
        ).fetchall()

    # ── S.M.A.R.T. history CRUD ───────────────────────────────────────────────

    def insert_smart_reading(self, record: dict) -> None:
        """
        Insert one S.M.A.R.T. reading for a drive backend.
        Caller must be inside a transaction().

        Args:
            record: Dict with keys matching smart_history columns.
                    id must be a UUIDv4 string.
        """
        self._conn.execute(
            """INSERT INTO smart_history
               (id, backend_id, checked_at, overall_health, reallocated_sectors,
                pending_sectors, uncorrectable_sectors, ssd_life_pct,
                power_on_hours, temperature_c, assessment, trend)
               VALUES
               (:id, :backend_id, :checked_at, :overall_health, :reallocated_sectors,
                :pending_sectors, :uncorrectable_sectors, :ssd_life_pct,
                :power_on_hours, :temperature_c, :assessment, :trend)""",
            record,
        )

    def get_latest_smart_reading(self, backend_id: str) -> Optional[sqlite3.Row]:
        """Return the most recent S.M.A.R.T. reading for a backend."""
        self._assert_open()
        return self._conn.execute(
            """SELECT * FROM smart_history
               WHERE backend_id = ?
               ORDER BY checked_at DESC LIMIT 1""",
            (backend_id,),
        ).fetchone()

    def get_smart_history(self, backend_id: str, limit: int = 30) -> list[sqlite3.Row]:
        """Return the last `limit` S.M.A.R.T. readings for a backend (newest first)."""
        self._assert_open()
        return self._conn.execute(
            """SELECT * FROM smart_history
               WHERE backend_id = ?
               ORDER BY checked_at DESC LIMIT ?""",
            (backend_id, limit),
        ).fetchall()

    def prune_smart_history(self, backend_id: str, keep: int = 30) -> int:
        """
        Delete oldest smart_history entries for backend_id, keeping the last `keep`.
        Returns the number of rows deleted.
        """
        self._assert_open()
        rows = self._conn.execute(
            """SELECT id FROM smart_history
               WHERE backend_id = ?
               ORDER BY checked_at DESC""",
            (backend_id,),
        ).fetchall()
        to_delete = [r["id"] for r in rows[keep:]]
        if to_delete:
            placeholders = ",".join("?" * len(to_delete))
            self._conn.execute(
                f"DELETE FROM smart_history WHERE id IN ({placeholders})",
                to_delete,
            )
        return len(to_delete)

    # ── Tier pattern CRUD ─────────────────────────────────────────────────────

    def upsert_tier_pattern(self, record: dict) -> None:
        """
        Insert or update a tier pattern.
        On conflict (path_pattern already exists), increments sample_count
        and recalculates confidence. Caller must be inside a transaction().
        """
        self._conn.execute(
            """INSERT INTO tier_patterns
               (id, path_pattern, suggested_tier, confidence, sample_count,
                created_at, last_confirmed_at)
               VALUES
               (:id, :path_pattern, :suggested_tier, :confidence, :sample_count,
                :created_at, :last_confirmed_at)
               ON CONFLICT(path_pattern) DO UPDATE SET
                   sample_count      = sample_count + 1,
                   confidence        = MIN(1.0, confidence + 0.05),
                   suggested_tier    = excluded.suggested_tier""",
            record,
        )

    def confirm_tier_pattern(self, pattern_id: str) -> None:
        """
        Mark a tier pattern as user-confirmed. Caller must be in transaction().
        """
        self._conn.execute(
            "UPDATE tier_patterns SET last_confirmed_at = ? WHERE id = ?",
            (_now_iso(), pattern_id),
        )

    def get_tier_pattern(self, path_pattern: str) -> Optional[sqlite3.Row]:
        """Fetch a tier_pattern row by glob pattern."""
        self._assert_open()
        return self._conn.execute(
            "SELECT * FROM tier_patterns WHERE path_pattern = ?", (path_pattern,)
        ).fetchone()

    def list_tier_pattern_suggestions(self) -> list[sqlite3.Row]:
        """
        List tier patterns where confidence >= 0.8 and sample_count >= 5
        that have never been confirmed (null last_confirmed_at).
        These are ready to surface to the user as automation suggestions.
        """
        self._assert_open()
        return self._conn.execute(
            """SELECT * FROM tier_patterns
               WHERE confidence >= 0.8
                 AND sample_count >= 5
                 AND last_confirmed_at IS NULL
               ORDER BY confidence DESC, sample_count DESC"""
        ).fetchall()

    # ── Destructive ops log CRUD ──────────────────────────────────────────────

    def log_destructive_op_initiated(self, record: dict) -> str:
        """
        Write the pre-execution audit log entry for a destructive operation.
        MUST be called (and fsynced via PRAGMA synchronous=FULL) BEFORE the
        operation executes. Caller must be inside a transaction().

        Args:
            record: Dict with keys: id, op_level, op_type, target_hash,
                    target_label, method, initiated_at, dry_run_hash, session_id.
                    result defaults to 'in_progress'; completed_at and
                    error_detail default to None.

        Returns:
            HMAC chain value for the log entry.
        """
        with self._lock:
            self._increment_clock()
            record = {
                **record,
                "result":       "in_progress",
                "completed_at": None,
                "error_detail": None,
            }
            # HMAC chained into integrity_log chain for tamper evidence
            hmac_value = self._chain_hmac("destructive_ops_log", {
                k: v for k, v in record.items() if k != "hmac_chain"
            })
            record["hmac_chain"] = hmac_value
            self._conn.execute(
                """INSERT INTO destructive_ops_log
                   (id, op_level, op_type, target_hash, target_label, method,
                    initiated_at, completed_at, result, error_detail,
                    dry_run_hash, session_id, hmac_chain)
                   VALUES
                   (:id, :op_level, :op_type, :target_hash, :target_label, :method,
                    :initiated_at, :completed_at, :result, :error_detail,
                    :dry_run_hash, :session_id, :hmac_chain)""",
                record,
            )
            return hmac_value

    def log_destructive_op_completed(
        self,
        op_id: str,
        result: str,
        error_detail: Optional[str] = None,
    ) -> None:
        """
        Update the destructive ops log entry after the operation completes.
        Caller must be inside a transaction().

        Args:
            op_id:        id of the log entry created by log_destructive_op_initiated.
            result:       'completed' | 'failed' | 'blocked'
            error_detail: Human-readable error message, None on success.
        """
        with self._lock:
            self._increment_clock()
            now = _now_iso()
            self._conn.execute(
                """UPDATE destructive_ops_log
                   SET result = ?, completed_at = ?, error_detail = ?
                   WHERE id = ?""",
                (result, now, error_detail, op_id),
            )
            self._chain_hmac("destructive_ops_log", {
                "op": "completed", "id": op_id, "result": result, "at": now,
            })

    def list_destructive_ops(
        self, session_id: Optional[str] = None, limit: int = 100
    ) -> list[sqlite3.Row]:
        """
        List recent destructive op log entries, newest first.
        Optionally filtered by session_id.
        """
        self._assert_open()
        with self._lock:
            if session_id:
                return self._conn.execute(
                    """SELECT * FROM destructive_ops_log
                       WHERE session_id = ?
                       ORDER BY initiated_at DESC LIMIT ?""",
                    (session_id, limit),
                ).fetchall()
            return self._conn.execute(
                "SELECT * FROM destructive_ops_log ORDER BY initiated_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
