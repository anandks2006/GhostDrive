"""Weekly vault-health report: one persisted JSON rollup + optional webhook push.

Every week (default 168h) the report gathers the trust signals that already
exist -- durability audit, restore drills, active alerts, sync configuration,
storage counts, inheritance switch state -- into a single JSON document,
persists it under ``health_report_last``, and optionally POSTs it to
``health_report_webhook_url``.

Design decisions, stated honestly:

* The report is a SNAPSHOT of what the database says, not a probe.  It
  cannot tell you a backend went unreachable between reports, only what the
  last recorded status was.  Its value is the cadence: a weekly nudge that
  something is degraded, not real-time truth.
* Each source is wrapped individually: a broken subsystem degrades to
  ``{"error": ...}`` inside the report rather than failing the whole run --
  the report must still exist when something else is on fire.  The badge
  degrades to amber in that case, never green (absence of data is not data).
* The durability audit is executed ONCE per report and reused for the badge,
  so the badge and the durability section can never disagree with each
  other within one report.
* ``waste`` is imported lazily and degrades to ``{"unavailable": True}``
  when the optional service is absent, keeping this module independent of
  services owned by other waves.
* Webhook delivery is best-effort over the provider's TLS; a failed
  delivery NEVER un-persists the report -- it is stored BEFORE delivery is
  attempted, so the local record survives even when nobody is watching the
  webhook.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import urllib.request
from datetime import datetime, timezone
from typing import Any, Optional

from ghostdrive.services import alerts as alerts_service
from ghostdrive.services import durability
from ghostdrive.services import restore_drills as drills_service
from ghostdrive.services import sync as sync_service

logger = logging.getLogger("ghostdrive.services.health_report")

# ── Settings keys (exact names; the web UI and tests depend on them) ──────────
KEY_ENABLED = "health_report_enabled"            # "true" / "false" (default true)
KEY_INTERVAL_HOURS = "health_report_interval_hours"  # float, clamped >= 1
KEY_LAST_RUN = "health_report_last_run"          # ISO-8601 of last run
KEY_LAST_REPORT = "health_report_last"           # JSON report (see build_report)
KEY_WEBHOOK_URL = "health_report_webhook_url"    # optional delivery URL

DEFAULT_INTERVAL_HOURS = 168.0  # weekly, same cadence as restore drills
MIN_INTERVAL_HOURS = 1.0        # a zero/negative setting must never busy-loop

DELIVERY_TIMEOUT_SECONDS = 10

# Durability audit state -> badge color.  UNKNOWN is amber on purpose: a
# vault with no chunks has nothing proven, and "nothing proven" must not
# render green (same reasoning as the monitoring badge).
_STATE_COLORS = {
    "PROTECTED": "green",
    "DEGRADED": "amber",
    "UNPROTECTED": "red",
    "UNKNOWN": "amber",
}

# Module-global task, same pattern as restore_drills._drill_task.
_health_task: Optional[asyncio.Task] = None


# ── Small helpers ─────────────────────────────────────────────────────────────


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _resolve_db(db: Any = None) -> Any:
    if db is not None:
        return db
    from ghostdrive.services.context import require_db

    return require_db()


def _setting_bool(db: Any, key: str, default: bool) -> bool:
    raw = str(db.get_setting(key, "true" if default else "false")).strip().lower()
    return raw in ("1", "true", "yes", "on")


def _configured_hours(db: Any, fallback: float) -> float:
    """Resolve the interval: the persisted setting wins, else the fallback.

    Clamped to >= MIN_INTERVAL_HOURS so a zero setting can never busy-loop
    the scheduler.
    """
    try:
        raw = str(db.get_setting(KEY_INTERVAL_HOURS, "")).strip()
        value = float(raw) if raw else float(fallback)
        return max(MIN_INTERVAL_HOURS, value)
    except (TypeError, ValueError):
        return max(MIN_INTERVAL_HOURS, float(fallback))


# ── Report building ───────────────────────────────────────────────────────────


def _badge_from_audit(audit: dict) -> dict:
    """Minimal monitoring._badge equivalent, scored from the durability audit.

    Deliberately simpler than the full monitoring badge (which also folds in
    drill failures and alert counts): those sections already appear verbatim
    in the report, and duplicating their logic here would create a second
    source of truth that could drift from the badge the UI shows.
    """
    state_name = str(audit.get("state") or "UNKNOWN")
    color = _STATE_COLORS.get(state_name, "amber")
    return {
        "overall": color,
        "label": state_name,
        "reason": audit.get("summary") or "Durability audit returned no summary.",
    }


async def build_report(db: Any = None, *, now: datetime | None = None) -> dict:
    """Gather every health section; one failing source degrades, never crashes."""
    db = _resolve_db(db)
    when = now or _now()

    # Durability audit once, reused for the badge (see module docstring).
    try:
        audit = durability.audit_readiness(db)
        durability_section = {
            "state": audit.get("state"),
            "total_chunks": int(audit.get("total_chunks") or 0),
            "at_risk_chunks": int(audit.get("at_risk_chunks") or 0),
            "summary": audit.get("summary"),
        }
    except Exception as exc:
        logger.warning("Health report durability section unavailable: %s", exc)
        durability_section = {"error": str(exc)}

    if isinstance(durability_section.get("state"), str) and (
        durability_section["state"] in _STATE_COLORS
    ):
        badge = _badge_from_audit(durability_section)
    else:
        badge = {
            "overall": "amber",
            "label": "UNKNOWN",
            "reason": durability_section.get("error")
            or "Durability audit unavailable.",
        }

    try:
        drills = drills_service.drill_summary(db, now=when)
        drills_section = {
            "last": drills.get("last"),
            "passed": drills.get("passed"),
            "failed": drills.get("failed"),
            "stale": drills.get("stale"),
        }
    except Exception as exc:
        logger.warning("Health report drills section unavailable: %s", exc)
        drills_section = {"error": str(exc)}

    try:
        state = alerts_service.alert_state(db)
        active = [a for a in state.get("alerts", []) if not a.get("dismissed")]
        alerts_section = {
            "active_count": int(state.get("active_count") or 0),
            "critical": sum(1 for a in active if a.get("severity") == "critical"),
            "warning": sum(1 for a in active if a.get("severity") == "warning"),
        }
    except Exception as exc:
        logger.warning("Health report alerts section unavailable: %s", exc)
        alerts_section = {"error": str(exc)}

    try:
        sync = sync_service.sync_status(db)
        sync_section = {
            "enabled": bool(sync.get("enabled")),
            "roots": list(sync.get("roots") or []),
        }
    except Exception as exc:
        logger.warning("Health report sync section unavailable: %s", exc)
        sync_section = {"error": str(exc)}

    try:
        row = db._conn.execute(
            """SELECT
                   SUM(CASE WHEN tombstone = 0 THEN 1 ELSE 0 END) AS active_files,
                   SUM(CASE WHEN tombstone = 0 THEN size ELSE 0 END) AS active_bytes,
                   SUM(CASE WHEN tombstone = 1 THEN size ELSE 0 END) AS trash_bytes
               FROM files"""
        ).fetchone()
        storage_section = {
            "active_files": int(row["active_files"] or 0),
            "active_bytes": int(row["active_bytes"] or 0),
            "trash_bytes": int(row["trash_bytes"] or 0),
        }
    except Exception as exc:
        logger.warning("Health report storage section unavailable: %s", exc)
        storage_section = {"error": str(exc)}

    # Optional service from a later wave: lazy import keeps this module
    # independent; absence degrades to {"unavailable": True}, never a crash.
    try:
        from ghostdrive.services.waste import report as _waste_report

        waste_section = _waste_report(db)
    except Exception:
        waste_section = {"unavailable": True}

    try:
        from ghostdrive.services import inheritance as inheritance_service

        switch = inheritance_service.inheritance_status(db, now=when)
        inheritance_section = {
            "enabled": switch.get("enabled"),
            "overdue": switch.get("overdue"),
            "days_remaining": switch.get("days_remaining"),
        }
    except Exception as exc:
        logger.warning("Health report inheritance section unavailable: %s", exc)
        inheritance_section = {"error": str(exc)}

    return {
        "generated_at": when.isoformat(),
        "badge": badge,
        "drills": drills_section,
        "alerts": alerts_section,
        "durability": durability_section,
        "sync": sync_section,
        "storage": storage_section,
        "waste": waste_section,
        "inheritance": inheritance_section,
    }


# ── Run / persist / deliver ───────────────────────────────────────────────────


def _post_json(url: str, payload: dict) -> None:
    """Blocking stdlib POST; callers wrap it in asyncio.to_thread."""
    request = urllib.request.Request(  # noqa: S310 - user-configured URL
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=DELIVERY_TIMEOUT_SECONDS) as response:
        response.read()


async def run_health_report(
    db: Any = None, *, now: datetime | None = None, deliver: bool | None = None
) -> dict:
    """Build, persist, and (optionally) deliver one report.

    ``deliver`` tri-state: ``None`` (default) delivers iff a webhook URL is
    configured; ``True`` forces a delivery attempt (delivered=False with an
    error when no URL is set); ``False`` never delivers.
    """
    db = _resolve_db(db)
    when = now or _now()
    report = await build_report(db, now=when)

    # Persist BEFORE delivery: the local record must survive even when the
    # webhook is down or nobody is watching it.
    with db.transaction():
        db.set_setting(KEY_LAST_REPORT, json.dumps(report))
        db.set_setting(KEY_LAST_RUN, when.isoformat())

    webhook = str(db.get_setting(KEY_WEBHOOK_URL, "") or "").strip()
    if deliver is False:
        return {"report": report, "delivered": None, "delivery_error": None}
    if not webhook:
        if deliver:
            return {
                "report": report,
                "delivered": False,
                "delivery_error": "No health-report webhook URL is configured.",
            }
        return {"report": report, "delivered": None, "delivery_error": None}
    try:
        await asyncio.to_thread(_post_json, webhook, report)
    except Exception as exc:
        logger.warning("Health report webhook delivery failed: %s", exc)
        return {"report": report, "delivered": False, "delivery_error": str(exc)}
    return {"report": report, "delivered": True, "delivery_error": None}


def get_health_report(db: Any = None) -> dict:
    """Last persisted report + scheduler meta (report is None before first run)."""
    db = _resolve_db(db)
    raw = str(db.get_setting(KEY_LAST_REPORT, "") or "")
    report: Optional[dict] = None
    if raw:
        try:
            parsed = json.loads(raw)
            report = parsed if isinstance(parsed, dict) else None
        except ValueError:
            logger.warning("health_report_last setting is not valid JSON.")
    last_run = str(db.get_setting(KEY_LAST_RUN, "") or "") or None
    return {
        "enabled": _setting_bool(db, KEY_ENABLED, True),
        "interval_hours": _configured_hours(db, DEFAULT_INTERVAL_HOURS),
        "last_run": last_run,
        "report": report,
    }


def health_report_status(db: Any = None) -> dict:
    """Scheduler + settings status for the routes (hides the webhook URL)."""
    db = _resolve_db(db)
    running = _health_task is not None and not _health_task.done()
    return {
        "running": running,
        "enabled": _setting_bool(db, KEY_ENABLED, True),
        "interval_hours": _configured_hours(db, DEFAULT_INTERVAL_HOURS),
        "last_run": str(db.get_setting(KEY_LAST_RUN, "") or "") or None,
        "webhook_configured": bool(
            str(db.get_setting(KEY_WEBHOOK_URL, "") or "").strip()
        ),
    }


# ── Scheduler ─────────────────────────────────────────────────────────────────


async def _health_report_loop(db: Any, interval_hours: float) -> None:
    while True:
        # Same +/-10% jitter rationale as the drill/alert loops: many installs
        # point webhooks at the same providers; don't hit them in lockstep.
        base = max(MIN_INTERVAL_HOURS, float(interval_hours)) * 3600.0
        await asyncio.sleep(base * random.uniform(0.9, 1.1))
        try:
            target = _resolve_db(db)
            if not _setting_bool(target, KEY_ENABLED, True):
                continue  # honors the flag every cycle, like the drill loop
            outcome = await run_health_report(target)
            logger.info(
                "Scheduled health report: delivered=%s", outcome.get("delivered")
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # Locked vault, busy database, etc.: log and keep ticking so the
            # weekly cadence comes back by itself.
            logger.warning("Health report scheduler cycle failed: %s", exc)


def start_health_report_scheduler(
    interval_hours: float | None = None, db: Any = None
) -> Optional[asyncio.Task]:
    """Start the background report loop (idempotent; double-start is a no-op).

    Interval resolution: the ``health_report_interval_hours`` setting wins
    when present (default ``168`` = weekly), otherwise ``interval_hours`` is
    the ad-hoc fallback.  Both are clamped to >= 1h.
    """
    global _health_task
    if _health_task is not None and not _health_task.done():
        return _health_task
    fallback = interval_hours if interval_hours is not None else DEFAULT_INTERVAL_HOURS
    # Resolve the interval now, but tolerate a locked/absent vault: the loop
    # calls _resolve_db() every cycle, so it picks up the persisted interval
    # once the vault is unlocked. Starting must never crash the lifespan.
    try:
        hours = _configured_hours(_resolve_db(db), fallback)
    except Exception as exc:
        logger.info(
            "Health report scheduler starting without a vault (%s); "
            "using the default %sh interval.",
            exc,
            fallback,
        )
        hours = max(MIN_INTERVAL_HOURS, float(fallback))
    _health_task = asyncio.create_task(_health_report_loop(db, hours))
    return _health_task


def stop_health_report_scheduler() -> Optional[asyncio.Task]:
    """Cancel the report loop; returns the cancelled task (or None)."""
    global _health_task
    task = _health_task
    if task is not None and not task.done():
        task.cancel()
    _health_task = None
    return task
