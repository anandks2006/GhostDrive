"""Mass-modification alarm: a rate detector for bulk rewrites in watched folders.

Ransomware's defining on-disk trait is volume -- hundreds of files rewritten
or deleted within seconds.  Sync already snapshots and Trash-preserves every
change, so the *damage* is recoverable, but recovery is an after-the-fact plan;
the user wants to be interrupted while the encryption is still running.  This module
counts how many regular files under the configured sync roots carry an mtime
inside a rolling window and raises one critical alert when that count crosses
the threshold, plus a best-effort index snapshot (an attacker's next likely
move is destroying the index/backends; a fresh snapshot widens the recovery
window -- failure to snapshot never fails the alarm).

Honest trade-offs and false-positive notes:

* mtime is the only signal.  It is cheap (one stat per file, no reads), but
  also forgeable and imprecise: an attacker who preserves mtimes shows up as
  nothing, while a legitimate bulk operation (a big copy, an archive
  extraction, an IDE rebuild) shows up as a false positive.  The default
  threshold (50 files / 5 minutes) sits above routine use and below typical
  ransomware pace; raise it if the user's workflow is bulk-write-heavy.
* The window is persisted per check, not per file event: detection
  granularity is the check cadence (scheduler default 2 minutes), not the
  instant of each write.  A burst that starts and finishes between two checks
  is still counted -- the mtimes survive -- but with less precision about
  when it happened.
* One alert per burst: the alert subject is the ISO minute of the triggering
  check, so ``record_alerts``' stable-id dedupe yields a single alert per
  burst-minute even while the loop keeps observing the same over-threshold
  rate on the next cycle.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import stat as stat_module
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

from ghostdrive.services import alerts as alerts_service
from ghostdrive.services import sync as sync_service

logger = logging.getLogger("ghostdrive.services.mass_alarm")

# ── Settings keys ─────────────────────────────────────────────────────────────
SETTING_ENABLED = "mass_alarm_enabled"          # "true" / "false"  (default true)
SETTING_THRESHOLD = "mass_alarm_threshold"      # files, default "50", clamped >= 1
SETTING_WINDOW = "mass_alarm_window_minutes"    # default "5", clamped 1..1440
SETTING_STATE = "mass_alarm_state"              # {"events": [...], "last": {...}}

DEFAULT_THRESHOLD = 50
DEFAULT_WINDOW_MINUTES = 5
MAX_WINDOW_MINUTES = 1440

MIN_INTERVAL_SECONDS = 15
DEFAULT_SCHEDULER_INTERVAL_SECONDS = 120

#: Rolling-window entries kept at 4x the configured window; the hard cap is
#: belt-and-braces so a tiny window polled forever cannot grow the row
#: unbounded (4x1-minute windows at second cadence still stays well below it).
_MAX_EVENTS = 500

_scheduler_task: Optional[asyncio.Task] = None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _setting_bool(db: Any, key: str, default: str) -> bool:
    return str(db.get_setting(key, default)).strip().lower() in ("1", "true", "yes", "on")


def _setting_int(db: Any, key: str, default: int) -> int:
    try:
        return int(str(db.get_setting(key, str(default))).strip() or default)
    except (TypeError, ValueError):
        return default


def _configured_threshold(db: Any) -> int:
    return max(1, _setting_int(db, SETTING_THRESHOLD, DEFAULT_THRESHOLD))


def _configured_window(db: Any) -> int:
    return min(
        MAX_WINDOW_MINUTES,
        max(1, _setting_int(db, SETTING_WINDOW, DEFAULT_WINDOW_MINUTES)),
    )


# ── Filesystem scan ───────────────────────────────────────────────────────────

def scan_recent_changes(
    roots: Iterable[str],
    *,
    now: Optional[datetime] = None,
    window_minutes: int = 5,
    max_files: int = 50000,
) -> int:
    """Count regular files under ``roots`` modified within the window.

    Walks each root with the same noise filters and link/junction guards as
    the sync walker (``sync._SKIP_DIRS``/``_SKIP_FILES``/``_is_link_like``):
    walking into a junction can loop or drop the scanner inside the vault's
    app-data dir, and VCS/cache directories churn constantly by nature.
    Returns early at ``max_files`` -- once the threshold is orders of
    magnitude crossed, the exact number adds nothing and the walk is the
    expensive part.
    """
    stamp = now or _now()
    cutoff = stamp.timestamp() - max(1, int(window_minutes)) * 60
    count = 0
    for root in roots:
        base = Path(root)
        try:
            if not base.is_dir() or sync_service._is_link_like(base):
                continue
        except OSError:
            continue
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False, topdown=True):
            dirnames[:] = [
                name
                for name in dirnames
                if name not in sync_service._SKIP_DIRS
                and not sync_service._is_link_like(Path(dirpath) / name)
            ]
            for name in filenames:
                if name in sync_service._SKIP_FILES or name.endswith(".gdl"):
                    continue
                path = Path(dirpath) / name
                try:
                    st = os.stat(path, follow_symlinks=False)
                except OSError:
                    continue
                if not stat_module.S_ISREG(st.st_mode):
                    continue
                if st.st_mtime >= cutoff:
                    count += 1
                    if count >= max_files:
                        return count
    return count


# ── State persistence ─────────────────────────────────────────────────────────

def _load_state(db: Any) -> dict:
    """``{"events": [{"at", "count"}], "last": check-result-dict | None}``."""
    raw = str(db.get_setting(SETTING_STATE, "") or "")
    try:
        data = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        logger.warning("Mass-alarm state unreadable; starting a fresh window.")
        data = {}
    if not isinstance(data, dict):
        data = {}
    events = data.get("events")
    if not isinstance(events, list):
        events = []
    last = data.get("last")
    return {
        "events": [e for e in events if isinstance(e, dict) and "at" in e],
        "last": last if isinstance(last, dict) else None,
    }


def _save_state(db: Any, state: dict) -> None:
    with db.transaction():
        db.set_setting(SETTING_STATE, json.dumps(state))


def _prune_events(events: list[dict], horizon: datetime) -> list[dict]:
    kept: list[dict] = []
    for event in events:
        try:
            at = datetime.fromisoformat(str(event["at"]))
        except ValueError:
            continue
        if at.tzinfo is None:
            at = at.replace(tzinfo=timezone.utc)
        if at >= horizon:
            kept.append(event)
    return kept[-_MAX_EVENTS:]


# ── Status ────────────────────────────────────────────────────────────────────

def mass_alarm_status(db: Any) -> dict:
    state = _load_state(db)
    return {
        "enabled": _setting_bool(db, SETTING_ENABLED, "true"),
        "threshold": _configured_threshold(db),
        "window_minutes": _configured_window(db),
        "window": state["events"],
        "last": state["last"],
    }


# ── Check pass ────────────────────────────────────────────────────────────────

async def check_mass_change(db: Any, *, now: Optional[datetime] = None) -> dict:
    """Scan the sync roots, update the rolling window, alert over threshold.

    When the count crosses the threshold one critical alert is emitted
    (subject = ISO minute of the check, so record_alerts dedupes a sustained
    burst into one alert per burst-minute) and an index snapshot is attempted
    best-effort -- snapshot failures (locked master key, unreachable
    backend...) are noted in the result and never raised.  When the alarm is
    disabled the filesystem is not walked at all and no alert can fire.

    Returns {"count", "threshold", "window_minutes", "triggered", "alerted",
             "enabled", "roots", "snapshot"}; the dict is also persisted as
    the "last" entry of the rolling-window state for the status route.
    """
    now = now or _now()
    stamp = now.isoformat()
    enabled = _setting_bool(db, SETTING_ENABLED, "true")
    threshold = _configured_threshold(db)
    window = _configured_window(db)
    roots = sync_service.get_sync_roots(db)
    result: dict[str, Any] = {
        "count": 0,
        "threshold": threshold,
        "window_minutes": window,
        "triggered": False,
        "alerted": False,
        "enabled": enabled,
        "roots": roots,
        "snapshot": None,
    }
    if not enabled:
        return result

    count = scan_recent_changes(roots, now=now, window_minutes=window)
    triggered = count >= threshold
    result["count"] = count
    result["triggered"] = triggered

    if triggered:
        alert = {
            "id": alerts_service.alert_id(
                "mass_modification", now.strftime("%Y-%m-%dT%H:%M")
            ),
            "kind": "mass_modification",
            "severity": "critical",
            "subject_id": now.strftime("%Y-%m-%dT%H:%M"),
            "title": "Mass file modification detected",
            "detail": (
                f"{count} files changed in the last {window} minutes across "
                f"{len(roots)} watched folders (threshold {threshold})."
            ),
            "detected_at": stamp,
        }

        # Best-effort index snapshot: the alarm fires regardless of outcome.
        try:
            from ghostdrive.services import snapshots as snapshots_service

            await snapshots_service.create_snapshot(db)
            result["snapshot"] = "ok"
        except Exception as exc:
            result["snapshot"] = f"failed: {exc}"
            logger.warning("Index snapshot after mass-change alert failed: %s", exc)

        try:
            new = alerts_service.record_alerts(db, [alert], now=now)
        except Exception as exc:
            logger.warning("Could not persist mass-modification alert: %s", exc)
            new = [alert]
        result["alerted"] = bool(new)
        if new:
            try:
                await alerts_service.dispatch(db, new)
            except Exception as exc:
                logger.warning("Could not dispatch mass-modification alert: %s", exc)

    state = _load_state(db)
    state["events"] = _prune_events(
        state["events"] + [{"at": stamp, "count": count}],
        now - timedelta(minutes=window * 4),
    )
    state["last"] = result
    _save_state(db, state)
    return result


# ── Scheduler ─────────────────────────────────────────────────────────────────

async def _mass_alarm_loop(db: Any, interval_seconds: int) -> None:
    """Sleep between checks, honoring the enable flag re-read every cycle."""
    while True:
        try:
            from ghostdrive.services.context import require_db

            target = db if db is not None else require_db()
            enabled = _setting_bool(target, SETTING_ENABLED, "true")
        except Exception as exc:
            # Locked vault / no database yet: idle instead of dying.
            logger.debug("Mass-alarm scheduler idle: %s", exc)
            enabled = False

        await asyncio.sleep(max(MIN_INTERVAL_SECONDS, interval_seconds))
        if not enabled:
            continue
        try:
            from ghostdrive.services.context import require_db

            target = db if db is not None else require_db()
            await check_mass_change(target)
        except Exception as exc:
            logger.warning("Mass-change check cycle failed: %s", exc)


def start_mass_alarm_scheduler(
    interval_seconds: Optional[int] = None,
    db: Any = None,
) -> Optional[asyncio.Task]:
    """Start the module-global mass-alarm loop (idempotent: double-start no-op).

    ``interval_seconds`` is the cadence (default 120, clamped >= 15); the
    enable flag is re-read from settings every cycle, so a start made before
    unlock still behaves once the vault opens.
    """
    global _scheduler_task
    if _scheduler_task is not None and not _scheduler_task.done():
        return _scheduler_task
    interval = max(
        MIN_INTERVAL_SECONDS, int(interval_seconds or DEFAULT_SCHEDULER_INTERVAL_SECONDS)
    )
    _scheduler_task = asyncio.create_task(_mass_alarm_loop(db, interval))
    return _scheduler_task


def stop_mass_alarm_scheduler() -> Optional[asyncio.Task]:
    """Cancel the mass-alarm loop; return the cancelled task (or None)."""
    global _scheduler_task
    task = _scheduler_task
    if task is not None and not task.done():
        task.cancel()
    _scheduler_task = None
    return task
