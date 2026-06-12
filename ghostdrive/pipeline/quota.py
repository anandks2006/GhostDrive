"""
quota.py -- Atomic quota reservation for the upload pipeline (spec §5.6).

Two-phase commit quota flow
============================
1. reserve(backend_id, bytes) -- called BEFORE upload starts.
   SELECT + UPDATE in a single EXCLUSIVE transaction.
   Prevents two concurrent uploads double-spending the same quota.

2. confirm(backend_id, bytes) -- called AFTER upload succeeds.
   Moves quota_reserved -> quota_used.

3. restore(backend_id, bytes) -- called on failure or cancellation.
   Returns the reserved bytes to available pool.

The QuotaManager wraps GhostDriveDB's quota methods and adds logging and
the QuotaReservationError on insufficient space.
"""

from __future__ import annotations

import logging

from ghostdrive.exceptions import QuotaReservationError

logger = logging.getLogger(__name__)


class QuotaManager:
    """
    Atomic quota reservation, confirmation, and restoration.

    All operations require an open GhostDriveDB transaction context.

    Usage::

        qm = QuotaManager(db)
        with db.transaction():
            qm.reserve(backend_id, bytes_needed)   # raises QuotaReservationError if full
            db.insert_chunk_location_pending(...)  # write intent in same txn
        # ... upload happens ...
        with db.transaction():
            qm.confirm(backend_id, bytes_uploaded)
        # on failure:
        with db.transaction():
            qm.restore(backend_id, bytes_reserved)
    """

    def __init__(self, db) -> None:
        """
        Args:
            db: GhostDriveDB instance (open).
        """
        self._db = db

    def reserve(self, backend_id: str, bytes_needed: int) -> None:
        """
        Atomically reserve quota on a backend (spec §5.6).

        SELECT + UPDATE in the caller's exclusive transaction.
        Two concurrent calls for the same backend are serialised by SQLite.

        Args:
            backend_id:  UUIDv4 backend identifier.
            bytes_needed: Bytes to reserve.

        Raises:
            QuotaReservationError: Insufficient space on this backend.
        """
        ok = self._db.reserve_quota(backend_id, bytes_needed)
        if not ok:
            raise QuotaReservationError(
                f"Backend {backend_id[:8]}... has insufficient quota "
                f"for {bytes_needed:,} bytes. "
                "Upload will be rerouted to the next available backend."
            )
        logger.debug(
            "Quota reserved: backend=%s bytes=%d", backend_id[:8], bytes_needed
        )

    def confirm(self, backend_id: str, bytes_uploaded: int) -> None:
        """
        Move quota_reserved -> quota_used after successful upload.

        Args:
            backend_id:    UUIDv4 backend identifier.
            bytes_uploaded: Bytes actually uploaded (may differ from reserved
                            if compression resulted in fewer bytes).
        """
        self._db.confirm_quota(backend_id, bytes_uploaded)
        logger.debug(
            "Quota confirmed: backend=%s bytes=%d", backend_id[:8], bytes_uploaded
        )

    def restore(self, backend_id: str, bytes_reserved: int) -> None:
        """
        Restore quota_reserved on upload failure or cancellation.

        Idempotent: MAX(0, quota_reserved - bytes_reserved) prevents going negative
        if restore is called multiple times (e.g. on both cancel and cleanup).

        Args:
            backend_id:     UUIDv4 backend identifier.
            bytes_reserved: Bytes to return to the available pool.
        """
        self._db.restore_quota(backend_id, bytes_reserved)
        logger.debug(
            "Quota restored: backend=%s bytes=%d", backend_id[:8], bytes_reserved
        )

    def available_space(self, backend_id: str) -> int:
        """
        Return available free bytes on a backend (quota_limit - quota_used - quota_reserved).
        Read-only -- no transaction required.

        Returns:
            Available bytes. 0 if backend not found.
        """
        row = self._db._conn.execute(
            """SELECT quota_limit - quota_used - quota_reserved AS available
               FROM backends WHERE id = ?""",
            (backend_id,),
        ).fetchone()
        return row["available"] if row and row["available"] > 0 else 0
