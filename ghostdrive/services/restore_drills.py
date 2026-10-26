"""Scheduled restore drills and drill history for the durability badge.

``ghostdrive.services.snapshots.run_restore_drill`` already knows how to prove
that data can actually be restored: it verifies the newest index snapshot,
reassembles a file chunk from minimal shards across failure domains, checks the
BLAKE3 digest, and INSERTs the outcome into ``restore_drills``.  Historically
that proof only ever happened as a side effect of a human running a manual
snapshot restore, so a quiet system looked identical to a broken one.

This module reuses that function verbatim (never copies it) and adds the three
things a visible trust signal needs:

* ``run_drill``                     -- one automated or on-demand drill.
* ``drill_history``/``drill_summary`` -- newest-first rows and one-glance stats
  (including the staleness flag the badge and alerts are scored on).
* ``start/stop_drill_scheduler``    -- a background loop that drills on an
  interval so a restore stays *proven* without anyone remembering to check.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from ghostdrive.services import files as files_service
from ghostdrive.services import snapshots as snapshots_service

logger = logging.getLogger("ghostdrive.services.restore_drills")

# Settings keys (string values, like every other GhostDrive setting).
KEY_DRILL_ENABLED = "drill_enabled"
KEY_DRILL_INTERVAL_HOURS = "drill_interval_hours"

# Weekly cadence: one missed cycle is a problem worth surfacing well before
# data is actually lost, and it keeps drill traffic on shared offsite backends
# to roughly one restore-proof per install per week.
DEFAULT_INTERVAL_HOURS = 168.0

# A proof older than 14 days is shown as stale.  14 is deliberately half of a
# month: under the default weekly cadence it means two consecutive missed
# runs, and it sits comfortably below durability's 30-day restore-proof
# contract age so the badge warns for two weeks *before* the contract audit
# would fail.  It also guarantees that even a monthly cadence that skips one
# cycle crosses the staleness line while the miss is still recent (the gap
# since the last success passes 14 days quickly), instead of silently waiting
# out a full second cycle.
_STALE_DAYS = 14

# How many leading rows ``drill_summary`` walks to count consecutive
# failures.  Bounded so an old database with thousands of deep-drill rows
# still summarises in constant time; a streak longer than this is reported
# as its scan cap, which is plenty to decide "failing".
_MAX_CONSECUTIVE_SCAN = 100

# Module-global task pattern copied from protection.start_watcher: one loop
# per feature, double-start is a no-op, stop clears the global.
_drill_task: Optional[asyncio.Task] = None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _resolve_db(db: Any) -> Any:
    if db is None:
        from ghostdrive.services.context import require_db

        db = require_db()
    return db


def _row_to_dict(row: Any) -> dict:
    """Shape one restore_drills row exactly like snapshots.latest_drill."""
    return {
        "id": row["id"],
        "started_at": row["started_at"],
        "completed_at": row["completed_at"],
        "snapshot_id": row["snapshot_id"],
        "file_id": row["file_id"],
        "chunk_id": row["chunk_id"],
        "shards_used": int(row["shards_used"] or 0),
        "domains_used": int(row["domains_used"] or 0),
        "bytes_restored": int(row["bytes_restored"] or 0),
        "duration_ms": int(row["duration_ms"] or 0),
        "result": row["result"],
        "detail": row["detail"],
    }


def _setting_bool(db: Any, key: str, default: bool) -> bool:
    raw = str(db.get_setting(key, "true" if default else "false")).strip().lower()
    return raw in ("1", "true", "yes", "on")


def _configured_float(db: Any, key: str, fallback: float) -> float:
    """Resolve an interval: the persisted setting wins, else the fallback.

    The setting is authoritative so ``POST /api/monitoring/scheduler`` (which
    persists first) and server-startup wiring (which only calls ``start_*``)
    can never disagree about the cadence.  A locked vault or unreadable value
    falls back rather than crashing startup.
    """
    try:
        raw = str(_resolve_db(db).get_setting(key, "")).strip()
        value = float(raw) if raw else float(fallback)
        return value if value > 0 else float(fallback)
    except Exception:
        return float(fallback)


# ─── Drills ──────────────────────────────────────────────────────────────────


def _record_skipped(db: Any, detail: str, when: datetime) -> dict:
    """Record a ``skipped`` drill so the badge has an honest answer.

    Mirrors the exact column list snapshots.run_restore_drill INSERTs into so
    history/summary code never has to special-case rows it did not write.
    """
    drill_id = str(uuid.uuid4())
    stamp = when.isoformat()
    with db.transaction():
        db._conn.execute(
            """INSERT INTO restore_drills
               (id, started_at, completed_at, snapshot_id, file_id, chunk_id,
                shards_used, domains_used, bytes_restored, duration_ms, result, detail)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (drill_id, stamp, stamp, None, None, None, 0, 0, 0, 0, "skipped", detail),
        )
    return {
        "id": drill_id,
        "started_at": stamp,
        "completed_at": stamp,
        "snapshot_id": None,
        "file_id": None,
        "chunk_id": None,
        "shards_used": 0,
        "domains_used": 0,
        "bytes_restored": 0,
        "duration_ms": 0,
        "result": "skipped",
        "detail": detail,
    }


async def _drill_chunk(
    db: Any,
    chunk: Any,
    objects: dict[str, Any],
    master_key: bytes,
    salt: bytes,
    snapshot_id: str,
) -> dict:
    """Restore-verify one chunk for a deep drill and record its own row.

    The primary (default) drill is snapshots.run_restore_drill, which proves
    the snapshot AND one chunk through the minimal-shard/failure-domain path.
    A deep pass extends that proof to every remaining chunk by reusing
    snapshots' own decrypt-and-hash helper and the files service's shard
    assembly -- assemble-all-shards + decrypt + digest match is exactly the
    readability question a deep drill asks, and re-deriving it here would
    duplicate code we were told to reuse.
    """
    from ghostdrive.crypto.hkdf import derive_chunk_key

    chunk_id = str(chunk["id"])
    drill_id = str(uuid.uuid4())
    started_at = _now().isoformat()
    began = time.monotonic()
    result = "failed"
    detail = ""
    bytes_restored = 0
    shards_used = 0
    try:
        locations = [
            loc for loc in db.get_chunk_locations(chunk_id)
            if loc["status"] == "confirmed"
        ]
        if not locations:
            raise RuntimeError("No confirmed shards remain for this chunk.")
        ciphertext = await files_service._assemble_chunk(chunk, objects)
        actual, size = snapshots_service._decrypt_and_hash(
            ciphertext, chunk, derive_chunk_key(master_key, salt)
        )
        if actual != chunk["blake3_hash"]:
            raise RuntimeError("Restored chunk hash does not match the index.")
        bytes_restored = int(size)
        shards_used = len({int(loc["sub_block_index"]) for loc in locations})
        result = "passed"
        detail = f"Deep drill: chunk {chunk_id[:8]} restored from {shards_used} shard(s)."
    except Exception as exc:
        detail = f"Deep drill chunk {chunk_id[:8]} failed: {exc}"
        result = "failed"

    duration_ms = int((time.monotonic() - began) * 1000)
    completed_at = _now().isoformat()
    with db.transaction():
        db._conn.execute(
            """INSERT INTO restore_drills
               (id, started_at, completed_at, snapshot_id, file_id, chunk_id,
                shards_used, domains_used, bytes_restored, duration_ms, result, detail)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                drill_id, started_at, completed_at, snapshot_id,
                str(chunk["file_id"]), chunk_id, shards_used, 0,
                bytes_restored, duration_ms, result, detail,
            ),
        )
    return _row_to_dict(
        {
            "id": drill_id, "started_at": started_at, "completed_at": completed_at,
            "snapshot_id": snapshot_id, "file_id": str(chunk["file_id"]),
            "chunk_id": chunk_id, "shards_used": shards_used, "domains_used": 0,
            "bytes_restored": bytes_restored, "duration_ms": duration_ms,
            "result": result, "detail": detail,
        }
    )


async def run_drill(
    db: Any = None,
    deep: bool = False,
    now: datetime | None = None,
) -> dict:
    """Run one restore drill and return the recorded drill dict.

    The newest snapshot (``ORDER BY snapshot_at DESC``) and the chunk(s) it
    protects are checked first; when either is missing we record a
    ``skipped`` row instead of staying silent, so the badge can answer
    "nothing to drill" honestly rather than looking broken or green.

    ``deep=True`` drills EVERY chunk of the newest snapshot: the primary
    drill (snapshot + first chunk) still runs via snapshots.run_restore_drill,
    then each remaining chunk gets its own verification and row.
    """
    db = _resolve_db(db)
    when = now or _now()

    snapshot = db._conn.execute(
        "SELECT id FROM index_snapshots ORDER BY snapshot_at DESC LIMIT 1"
    ).fetchone()
    if snapshot is None:
        return _record_skipped(
            db, "No index snapshot exists yet; nothing to drill.", when
        )

    # Same chunk selection snapshots.run_restore_drill uses (tombstones
    # excluded, newest first) so this pre-check and the drill it guards can
    # never disagree about whether there is anything to drill.
    sql = """SELECT c.* FROM chunks c
             JOIN files f ON c.file_id = f.id
             WHERE f.tombstone = 0
             ORDER BY c.chunk_index DESC, c.id"""
    if not deep:
        sql += " LIMIT 1"
    chunks = db._conn.execute(sql).fetchall()
    if not chunks:
        return _record_skipped(
            db,
            "Index snapshot exists but no file chunks are indexed; nothing to drill.",
            when,
        )

    # REUSE: the real drill (snapshot verification, minimal-shard chunk
    # restore, and the restore_drills INSERT) lives in snapshots.py.  Import
    # it through the module object so tests can patch its seams; never
    # duplicate its body here.
    drill = await snapshots_service.run_restore_drill(db)
    if not deep:
        return drill

    from ghostdrive.services.context import active_backends, get_master_key, hkdf_salt

    master_key = get_master_key()
    salt = hkdf_salt()
    _, objects = await active_backends(connect_remote=False)
    already = {drill.get("chunk_id")}
    drilled = 1  # the primary drill already proved the first chunk
    for chunk in chunks:
        chunk_id = str(chunk["id"])
        if chunk_id in already:
            continue
        await _drill_chunk(db, chunk, objects, master_key, salt, str(snapshot["id"]))
        already.add(chunk_id)
        drilled += 1
    drill["deep"] = True
    drill["chunks_drilled"] = drilled
    return drill


def drill_history(db: Any = None, limit: int = 20) -> list[dict]:
    """Newest-first restore_drills rows (``started_at`` DESC, rowid tiebreak)."""
    db = _resolve_db(db)
    rows = db._conn.execute(
        """SELECT * FROM restore_drills
           ORDER BY started_at DESC, rowid DESC
           LIMIT ?""",
        (max(1, int(limit)),),
    ).fetchall()
    return [_row_to_dict(row) for row in rows]


def drill_summary(db: Any = None, now: datetime | None = None) -> dict:
    """One-glance drill stats for the badge and alerts.

    ``stale`` is True when a real drill (passed/failed) exists but no
    successful one happened within ``_STALE_DAYS`` -- see the constant for
    why 14.  A system that has never drilled, or whose only rows are
    ``skipped`` ("nothing to drill"), is *unproven*, not decayed: it gets no
    proof label but is not flagged stale, so a fresh install does not scream
    red before it holds any data.
    """
    db = _resolve_db(db)
    as_of = now or _now()

    last = snapshots_service.latest_drill(db)
    counts = db._conn.execute(
        """SELECT COUNT(*) AS total,
                  SUM(CASE WHEN result = 'passed' THEN 1 ELSE 0 END) AS passed,
                  SUM(CASE WHEN result = 'failed' THEN 1 ELSE 0 END) AS failed
           FROM restore_drills"""
    ).fetchone()
    total = int(counts["total"] or 0)
    passed = int(counts["passed"] or 0)
    failed = int(counts["failed"] or 0)

    row = db._conn.execute(
        """SELECT COALESCE(completed_at, started_at) AS at
           FROM restore_drills WHERE result = 'passed'
           ORDER BY started_at DESC LIMIT 1"""
    ).fetchone()
    last_success_at = row["at"] if row else None

    # Consecutive failures: walk newest-first until a non-failed row (a
    # ``skipped`` row also ends the streak -- it is not a failure).  Bounded
    # by _MAX_CONSECUTIVE_SCAN so summary stays O(1) on huge tables.
    consecutive = 0
    for row in db._conn.execute(
        """SELECT result FROM restore_drills
           ORDER BY started_at DESC, rowid DESC LIMIT ?""",
        (_MAX_CONSECUTIVE_SCAN,),
    ).fetchall():
        if row["result"] != "failed":
            break
        consecutive += 1

    # Staleness only measures decay of an existing proof (see docstring).
    stale = False
    if passed + failed > 0:
        success_dt = _parse_iso(last_success_at)
        stale = success_dt is None or (as_of - success_dt) > timedelta(days=_STALE_DAYS)

    return {
        "last": last,
        "total": total,
        "passed": passed,
        "failed": failed,
        "consecutive_failures": consecutive,
        "last_success_at": last_success_at,
        "stale": stale,
    }


# ─── Scheduler ───────────────────────────────────────────────────────────────


async def _drill_loop(db: Any, interval_hours: float) -> None:
    while True:
        # Jitter of +/-10%: many GhostDrive installs share the same offsite
        # providers (Telegram/Discord/NAS boxes).  Drilling at an exact fixed
        # cadence would make every install hit those backends in one
        # thundering herd; spreading each sleep keeps traffic smooth.
        base = max(1.0, float(interval_hours) * 3600.0)
        await asyncio.sleep(base * random.uniform(0.9, 1.1))
        try:
            target = _resolve_db(db)
            if not _setting_bool(target, KEY_DRILL_ENABLED, True):
                continue
            outcome = await run_drill(db=target)
            logger.info(
                "Scheduled restore drill %s: %s",
                outcome.get("result"),
                outcome.get("detail", ""),
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # A locked vault or an offline backend must never kill the
            # scheduler; log it and try again next cycle.
            logger.warning("Scheduled restore drill failed: %s", exc)


def start_drill_scheduler(
    interval_hours: float | None = None,
    db: Any = None,
) -> Optional[asyncio.Task]:
    """Start the background drill loop (idempotent; double-start is a no-op).

    Interval resolution: the ``drill_interval_hours`` setting wins when
    present (default ``168`` = weekly), otherwise ``interval_hours`` is used
    as the ad-hoc fallback.  Safe to call during server startup: a locked
    vault only affects the cycles, never the loop itself.
    """
    global _drill_task
    if _drill_task is not None and not _drill_task.done():
        return _drill_task
    fallback = interval_hours if interval_hours is not None else DEFAULT_INTERVAL_HOURS
    hours = _configured_float(db, KEY_DRILL_INTERVAL_HOURS, fallback)
    _drill_task = asyncio.create_task(_drill_loop(db, hours))
    return _drill_task


def stop_drill_scheduler() -> None:
    """Cancel the drill loop and clear the module global."""
    global _drill_task
    if _drill_task is not None and not _drill_task.done():
        _drill_task.cancel()
    _drill_task = None
