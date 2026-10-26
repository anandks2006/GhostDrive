"""Repair-window scheduling and repair bandwidth capping.

Trickle healing consumes upstream bandwidth, so operators may want repairs
restricted to a nightly window (e.g. 02:00–06:00) and capped to a fraction
of the link. This module owns the persisted window settings, the open/closed
decision used by the HealingQueue loop, and an async context manager that
temporarily lowers the global upload token bucket while a repair runs.

All time comparisons use *local naive* wall-clock time because a "nightly"
window is a statement about the operator's local night, not UTC.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Optional

from ghostdrive.utils.bandwidth_throttle import UPLOAD_LIMITER

logger = logging.getLogger("ghostdrive.services.maintenance_window")

# Persisted settings keys (db.set_setting / db.get_setting).
KEY_ENABLED = "repair_window_enabled"
KEY_START = "repair_window_start"
KEY_END = "repair_window_end"
KEY_BANDWIDTH = "repair_bandwidth_kbps"

# Defaults used when the settings have never been written.
DEFAULT_ENABLED = "false"
DEFAULT_START = "02:00"
DEFAULT_END = "06:00"
DEFAULT_BANDWIDTH = "0"


def parse_hhmm(value: str, default: tuple[int, int] | None = None) -> tuple[int, int]:
    """Parse an ``HH:MM`` 24-hour string into ``(hour, minute)``.

    Raises ValueError on malformed or out-of-range input. Empty/None input
    falls back to ``default``; if no default is given that is also an error,
    so callers cannot silently schedule a window from garbage.
    """
    if value is None or not str(value).strip():
        if default is None:
            raise ValueError("Empty time value and no default provided")
        return default

    raw = str(value).strip()
    parts = raw.split(":")
    if len(parts) != 2:
        raise ValueError(f"Invalid time {value!r}; expected HH:MM")

    try:
        hour = int(parts[0])
        minute = int(parts[1])
    except ValueError:
        raise ValueError(f"Invalid time {value!r}; expected HH:MM") from None

    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise ValueError(
            f"Invalid time {value!r}; hour must be 00-23 and minute 00-59"
        )
    return hour, minute


def is_within_window(now: datetime, start: tuple[int, int], end: tuple[int, int]) -> bool:
    """True when local naive ``now`` falls inside the half-open window [start, end).

    ``now`` is always injected so tests are deterministic — this function
    never reads the clock itself.

    ``start > end`` means the window spans midnight (e.g. 22:00 → 06:00 is
    open from 22:00 until midnight and again from 00:00 until 06:00).

    ``start == end`` means the window is CLOSED. It represents the empty
    interval, so operators cannot accidentally create a permanently-open
    window by setting both ends to the same value.
    """
    minutes_now = now.hour * 60 + now.minute
    start_min = start[0] * 60 + start[1]
    end_min = end[0] * 60 + end[1]

    if start_min == end_min:
        return False  # empty interval: documented as always closed
    if start_min < end_min:
        return start_min <= minutes_now < end_min
    # Overnight window: open from start until midnight, then 00:00 until end.
    return minutes_now >= start_min or minutes_now < end_min


def _load_settings(db=None) -> tuple[bool, tuple[int, int], tuple[int, int], int]:
    """Read the four persisted settings, tolerating a missing/locked db.

    Falls back to defaults so background daemons never crash on a fresh
    install or a locked vault. Corrupt stored times are reported and replaced
    with defaults rather than raising into the healing loop.
    """
    enabled_raw = DEFAULT_ENABLED
    start_raw = DEFAULT_START
    end_raw = DEFAULT_END
    bandwidth_raw = DEFAULT_BANDWIDTH

    if db is not None:
        try:
            enabled_raw = db.get_setting(KEY_ENABLED, DEFAULT_ENABLED)
            start_raw = db.get_setting(KEY_START, DEFAULT_START)
            end_raw = db.get_setting(KEY_END, DEFAULT_END)
            bandwidth_raw = db.get_setting(KEY_BANDWIDTH, DEFAULT_BANDWIDTH)
        except Exception as exc:  # locked/closed db — treat as defaults
            logger.debug("Could not read repair window settings: %s", exc)
            enabled_raw, start_raw, end_raw, bandwidth_raw = (
                DEFAULT_ENABLED, DEFAULT_START, DEFAULT_END, DEFAULT_BANDWIDTH,
            )

    try:
        start = parse_hhmm(start_raw, default=(2, 0))
    except ValueError as exc:
        logger.warning("Invalid %s setting %r (%s); using %s", KEY_START, start_raw, exc, DEFAULT_START)
        start = parse_hhmm(DEFAULT_START)
    try:
        end = parse_hhmm(end_raw, default=(6, 0))
    except ValueError as exc:
        logger.warning("Invalid %s setting %r (%s); using %s", KEY_END, end_raw, exc, DEFAULT_END)
        end = parse_hhmm(DEFAULT_END)

    try:
        bandwidth = max(0, int(str(bandwidth_raw).strip() or "0"))
    except ValueError:
        logger.warning("Invalid %s setting %r; using 0", KEY_BANDWIDTH, bandwidth_raw)
        bandwidth = 0

    enabled = str(enabled_raw).strip().lower() in ("1", "true", "yes", "on")
    return enabled, start, end, bandwidth


def _resolve_db(db=None):
    """Return the db to read settings from, or None when unavailable."""
    if db is not None:
        return db
    try:
        from ghostdrive.services.context import require_db
        return require_db()
    except Exception:
        # Locked vault / no global db — callers treat this as "use defaults".
        return None


def is_repair_allowed(db=None, now: datetime | None = None) -> tuple[bool, str]:
    """Decide whether automatic repair may run right now.

    Returns ``(allowed, reason)``:

    * ``(True, "window_disabled")``   — scheduling is off, repairs any time.
    * ``(True, "within_window")``     — scheduling is on and now is inside.
    * ``(False, "outside_window")``   — scheduling is on and now is outside.

    ``now`` defaults to the local wall clock but can be injected for tests.
    """
    if now is None:
        now = datetime.now()
    enabled, start, end, _ = _load_settings(_resolve_db(db))
    if not enabled:
        return True, "window_disabled"
    if is_within_window(now, start, end):
        return True, "within_window"
    return False, "outside_window"


def _next_open(now: datetime, start: tuple[int, int]) -> str:
    """ISO local timestamp of the next time the window will open."""
    candidate = now.replace(hour=start[0], minute=start[1], second=0, microsecond=0)
    if candidate <= now:
        # Already at/past today's opening — the next one is tomorrow.
        candidate += timedelta(days=1)
    return candidate.isoformat()


def repair_window_status(db=None, now: datetime | None = None) -> dict:
    """Snapshot of the repair window configuration and current state.

    ``next_open_at`` is the ISO local time of the next window opening, or
    None when the window is disabled (nothing to wait for).
    """
    if now is None:
        now = datetime.now()
    enabled, start, end, bandwidth = _load_settings(_resolve_db(db))
    open_now = enabled and is_within_window(now, start, end)
    return {
        "enabled": enabled,
        "start": f"{start[0]:02d}:{start[1]:02d}",
        "end": f"{end[0]:02d}:{end[1]:02d}",
        "open": open_now,
        "next_open_at": _next_open(now, start) if enabled else None,
        "repair_bandwidth_kbps": bandwidth,
    }


@asynccontextmanager
async def background_bandwidth_scope(db=None):
    """Temporarily cap the global upload token bucket for background repair.

    When ``repair_bandwidth_kbps`` > 0 the UPLOAD_LIMITER rate becomes
    ``min(current rate or unlimited, cap * 1024)`` for the duration of the
    block and is always restored on exit — including when the wrapped repair
    raises — so a failed heal cannot leave the limiter stuck at the repair
    cap. A cap of 0 is a no-op.

    The rate attribute is assigned directly rather than through
    ``set_rate_limit``: we only want to throttle throughput, not shrink the
    bucket capacity mid-flight for concurrent foreground transfers.
    """
    cap_kbps = _load_settings(_resolve_db(db))[3]
    saved = UPLOAD_LIMITER.rate_limit
    if cap_kbps > 0:
        effective_cap = cap_kbps * 1024
        # A rate of 0 means "unlimited", i.e. higher than any cap.
        current = saved if saved and saved > 0 else float("inf")
        UPLOAD_LIMITER.rate_limit = int(min(current, effective_cap))
        logger.debug(
            "Repair bandwidth capped to %d bytes/s (was %s)",
            UPLOAD_LIMITER.rate_limit, saved,
        )
    try:
        yield
    finally:
        UPLOAD_LIMITER.rate_limit = saved
