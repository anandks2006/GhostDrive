"""Stale chunk-location retention and confirmed-duplicate rebalancing.

The repair/healing pipeline inserts new ``chunk_locations`` rows but never
removes superseded ``failed``/``cancelled`` rows, so they accumulate forever.
Worse, the healing candidate query historically excluded *every* backend with
any location row for a chunk — meaning a single ``failed`` row could block
healing back to that backend permanently.

This module prunes those leftovers (releasing reserved quota where it is
still held) and collapses duplicate ``confirmed`` copies of the same
(chunk, sub_block_index) down to one survivor.
"""

from __future__ import annotations

import logging
import math
from datetime import datetime, timedelta, timezone
from functools import cmp_to_key
from typing import Any, Optional

from ghostdrive.pipeline.coding import erasure_parameters

logger = logging.getLogger("ghostdrive.services.retention")

# Statuses that no longer carry data worth keeping: the shard is either gone
# remotely or the intent to upload it was abandoned.
_DEAD_STATUSES = ("failed", "cancelled")

# Pending rows older than this are orphaned intents the startup resolver
# (pending_chunk_locations) never settled — normally it resolves them on boot,
# so anything still pending after a day is a leftover.
_PENDING_MAX_AGE = timedelta(hours=24)


def _as_utc(now: Optional[datetime]) -> datetime:
    """Normalize an injected (or default) datetime to naive-UTC for ISO compare.

    Timestamps are stored via ``datetime.now(timezone.utc).isoformat()``; ISO
    strings with the same UTC offset compare correctly lexicographically, so
    a plain string cutoff works against ``upload_date``.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    if now.tzinfo is None:
        # Naive input is treated as UTC — consistent with the storage format.
        return now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc)


def stale_location_counts(db, older_than_days: int = 7, now: datetime | None = None) -> dict:
    """Count chunk_location rows that retention would clean up. Read-only.

    Categories:

    * ``failed_cancelled``    — dead rows older than ``older_than_days``.
    * ``stale_pending``       — pending intents older than 24h (the startup
      resolver normally settles pending rows; these are leftovers).
    * ``orphaned``            — locations whose chunk row no longer exists.
    * ``duplicate_confirmed`` — number of (chunk_id, sub_block_index) groups
      holding more than one confirmed row (extra copies of the same shard).
    """
    utc = _as_utc(now)
    cutoff = (utc - timedelta(days=older_than_days)).isoformat()
    pending_cutoff = (utc - _PENDING_MAX_AGE).isoformat()

    with db.transaction():
        failed_cancelled = db._conn.execute(
            """SELECT COUNT(*) AS cnt FROM chunk_locations
               WHERE status IN ('failed', 'cancelled') AND upload_date < ?""",
            (cutoff,),
        ).fetchone()["cnt"]
        stale_pending = db._conn.execute(
            """SELECT COUNT(*) AS cnt FROM chunk_locations
               WHERE status = 'pending' AND upload_date < ?""",
            (pending_cutoff,),
        ).fetchone()["cnt"]
        orphaned = db._conn.execute(
            """SELECT COUNT(*) AS cnt FROM chunk_locations cl
               LEFT JOIN chunks c ON c.id = cl.chunk_id
               WHERE c.id IS NULL"""
        ).fetchone()["cnt"]
        duplicate_confirmed = db._conn.execute(
            """SELECT COUNT(*) AS cnt FROM (
                   SELECT chunk_id, sub_block_index FROM chunk_locations
                   WHERE status = 'confirmed'
                   GROUP BY chunk_id, sub_block_index
                   HAVING COUNT(*) > 1
               )"""
        ).fetchone()["cnt"]

    return {
        "failed_cancelled": failed_cancelled,
        "stale_pending": stale_pending,
        "orphaned": orphaned,
        "duplicate_confirmed": duplicate_confirmed,
    }


def prune_stale_locations(db, older_than_days: int = 7, now: datetime | None = None) -> dict:
    """Delete stale chunk_location rows, returning a summary dict.

    * ``failed_cancelled`` rows: quota was already settled when they were
      failed/cancelled (``fail_chunk_location`` clears ``quota_reserved``),
      so the rows are simply dropped.
    * ``stale_pending`` rows: their reserved quota is still held on the
      backend. Quota is restored FIRST, then the row is deleted, so a crash
      between the two at worst leaves a slightly over-reserved backend that
      the next prune corrects — never an under-counted one.
    * ``orphaned`` rows: the chunk is gone, so its remote objects are handled
      by the file-delete path; here we only drop the index rows and release
      nothing (quota was settled at upload-confirm time).
    """
    utc = _as_utc(now)
    cutoff = (utc - timedelta(days=older_than_days)).isoformat()
    pending_cutoff = (utc - _PENDING_MAX_AGE).isoformat()

    quota_released = 0
    with db.transaction():
        # 1. Dead rows past the cutoff — drop them outright.
        dead_rows = db._conn.execute(
            """SELECT chunk_id, sub_block_index, backend_id FROM chunk_locations
               WHERE status IN ('failed', 'cancelled') AND upload_date < ?""",
            (cutoff,),
        ).fetchall()
        for row in dead_rows:
            db._conn.execute(
                """DELETE FROM chunk_locations
                   WHERE chunk_id = ? AND sub_block_index = ? AND backend_id = ?""",
                (row["chunk_id"], row["sub_block_index"], row["backend_id"]),
            )
        if dead_rows:
            db._chain_hmac("chunk_locations", {
                "op": "retention_prune", "category": "failed_cancelled",
                "count": len(dead_rows),
            })

        # 2. Stale pending intents: restore reserved quota, then delete.
        pending_rows = db._conn.execute(
            """SELECT chunk_id, sub_block_index, backend_id, quota_reserved
               FROM chunk_locations
               WHERE status = 'pending' AND upload_date < ?""",
            (pending_cutoff,),
        ).fetchall()
        for row in pending_rows:
            reserved = int(row["quota_reserved"] or 0)
            if reserved > 0:
                # Same clamping as db.restore_quota: never go negative even if
                # the backend counter was already corrected elsewhere.
                db._conn.execute(
                    "UPDATE backends SET quota_reserved = MAX(0, quota_reserved - ?) WHERE id = ?",
                    (reserved, row["backend_id"]),
                )
                quota_released += reserved
            db._conn.execute(
                """DELETE FROM chunk_locations
                   WHERE chunk_id = ? AND sub_block_index = ? AND backend_id = ?""",
                (row["chunk_id"], row["sub_block_index"], row["backend_id"]),
            )
        if pending_rows:
            db._chain_hmac("chunk_locations", {
                "op": "retention_prune", "category": "stale_pending",
                "count": len(pending_rows), "quota_released": quota_released,
            })

        # 3. Orphaned locations: chunk row is gone, drop the index rows.
        orphan_rows = db._conn.execute(
            """SELECT cl.chunk_id, cl.sub_block_index, cl.backend_id
               FROM chunk_locations cl
               LEFT JOIN chunks c ON c.id = cl.chunk_id
               WHERE c.id IS NULL"""
        ).fetchall()
        for row in orphan_rows:
            db._conn.execute(
                """DELETE FROM chunk_locations
                   WHERE chunk_id = ? AND sub_block_index = ? AND backend_id = ?""",
                (row["chunk_id"], row["sub_block_index"], row["backend_id"]),
            )
        if orphan_rows:
            db._chain_hmac("chunk_locations", {
                "op": "retention_prune", "category": "orphaned",
                "count": len(orphan_rows),
            })

    n_failed = len(dead_rows)
    n_pending = len(pending_rows)
    n_orphaned = len(orphan_rows)
    return {
        "failed_cancelled": n_failed,
        "stale_pending": n_pending,
        "orphaned": n_orphaned,
        "pruned": n_failed + n_pending + n_orphaned,
        "quota_released_bytes": quota_released,
    }


def _pick_winner(rows: list) -> Any:
    """Deterministically pick the confirmed row to keep.

    Preference order: (1) backends reporting healthy, (2) most recently
    COALESCE(last_verified, upload_date), (3) highest backend priority,
    (4) lexicographically smallest backend_id so repeated runs are stable.
    """
    def compare(a, b) -> int:
        a_ok = a["backend_status"] == "healthy"
        b_ok = b["backend_status"] == "healthy"
        if a_ok != b_ok:
            return -1 if a_ok else 1
        ta = a["last_verified"] or a["upload_date"] or ""
        tb = b["last_verified"] or b["upload_date"] or ""
        if ta != tb:
            return -1 if ta > tb else 1  # later ISO timestamp wins
        pa = int(a["priority"] or 0)
        pb = int(b["priority"] or 0)
        if pa != pb:
            return -1 if pa > pb else 1  # higher priority wins
        # Deterministic tiebreak so repeated runs keep the same survivor.
        return (a["backend_id"] > b["backend_id"]) - (a["backend_id"] < b["backend_id"])

    return min(rows, key=cmp_to_key(compare))


async def deduplicate_confirmed_locations(
    db,
    objects: dict | None = None,
    limit: int = 50,
) -> dict:
    """Collapse duplicate confirmed copies of the same shard to a single row.

    For each (chunk_id, sub_block_index) group with more than one confirmed
    row (up to ``limit`` groups), a winner is chosen by ``_pick_winner`` and
    every other row is deleted. When ``objects`` maps the loser's backend to a
    backend object, the remote shard is deleted best-effort; ``quota_used`` is
    released on that backend ONLY when the remote delete actually succeeded,
    estimated as ``ceil((chunk.size + 16) / k)`` — the shard size including
    the 16-byte Poly1305 tag, with ``k`` from the chunk's erasure parameters.

    Non-erasure (replicated) chunks release nothing on remote delete: a
    replicated shard is the whole chunk, but the per-backend ``quota_used``
    for full-chunk copies is settled by the file-delete path; subtracting a
    size estimate here would double-count against accounting done elsewhere.

    When ``objects`` is None this is an *index-only cleanup*: duplicate rows
    are still removed, but no remote deletes are attempted and no quota is
    released.
    """
    groups_removed = 0
    removed = 0
    quota_released = 0
    errors: list[str] = []

    # Read phase: gather duplicate groups and their rows (read-only tx).
    with db.transaction():
        groups = db._conn.execute(
            """SELECT chunk_id, sub_block_index FROM chunk_locations
               WHERE status = 'confirmed'
               GROUP BY chunk_id, sub_block_index
               HAVING COUNT(*) > 1
               LIMIT ?""",
            (limit,),
        ).fetchall()

        plans = []  # (chunk_row, winner_row, [loser_rows])
        for group in groups:
            rows = db._conn.execute(
                """SELECT cl.*, b.status AS backend_status, b.priority AS priority
                   FROM chunk_locations cl
                   JOIN backends b ON b.id = cl.backend_id
                   WHERE cl.chunk_id = ? AND cl.sub_block_index = ?
                     AND cl.status = 'confirmed'""",
                (group["chunk_id"], group["sub_block_index"]),
            ).fetchall()
            if len(rows) < 2:
                continue  # another actor may have collapsed it already
            chunk_row = db._conn.execute(
                "SELECT * FROM chunks WHERE id = ?", (group["chunk_id"],)
            ).fetchone()
            winner = _pick_winner(rows)
            losers = [r for r in rows if r is not winner]
            plans.append((chunk_row, winner, losers))

    # Remote-delete phase: deliberately OUTSIDE any transaction — holding a
    # SQLite write lock across network I/O would stall the whole app.
    decisions = []  # (row, release_bytes)
    for chunk_row, _winner, losers in plans:
        k = None
        shard_estimate = 0
        if chunk_row is not None:
            k, _n, _padlen, is_erasure = erasure_parameters(chunk_row)
            if is_erasure and k > 0:
                # Shard carries its own 16-byte tag on top of the raw size.
                shard_estimate = math.ceil((int(chunk_row["size"]) + 16) / k)
        for loser in losers:
            release = 0
            if objects is None:
                # Index-only cleanup: no remote delete, no quota release.
                decisions.append((loser, 0))
                continue
            backend_obj = objects.get(loser["backend_id"])
            if backend_obj is None:
                errors.append(
                    f"no backend object for {loser['backend_id'][:8]} "
                    f"(chunk {loser['chunk_id'][:8]}); row removed, remote copy kept"
                )
                decisions.append((loser, 0))
                continue
            try:
                await backend_obj.delete(loser["reference_id"])
                release = shard_estimate  # only after the delete succeeded
            except Exception as exc:
                errors.append(
                    f"remote delete failed on {loser['backend_id'][:8]} for "
                    f"{loser['reference_id']}: {exc}"
                )
            decisions.append((loser, release))

    # Write phase: one short transaction for row deletions, quota release and
    # the tamper-evidence ledger entries.
    if decisions:
        with db.transaction():
            for loser, release in decisions:
                if release > 0:
                    db._conn.execute(
                        "UPDATE backends SET quota_used = MAX(0, quota_used - ?) WHERE id = ?",
                        (release, loser["backend_id"]),
                    )
                    quota_released += release
                db._conn.execute(
                    """DELETE FROM chunk_locations
                       WHERE chunk_id = ? AND sub_block_index = ? AND backend_id = ?""",
                    (loser["chunk_id"], loser["sub_block_index"], loser["backend_id"]),
                )
                db._chain_hmac("chunk_locations", {
                    "op": "retention_dedup_delete",
                    "chunk_id": loser["chunk_id"],
                    "sub_block_index": loser["sub_block_index"],
                    "backend_id": loser["backend_id"],
                })
            removed = len(decisions)
            groups_removed = len(plans)

    return {
        "groups": groups_removed,
        "removed": removed,
        "quota_released_bytes": quota_released,
        "errors": errors,
    }
