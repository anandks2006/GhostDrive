"""
monitoring.py -- One-glance durability badge, restore drills, and resilience alerts.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from html import escape

from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel

from ghostdrive.services import alerts as alerts_service
from ghostdrive.services import durability
from ghostdrive.services import restore_drills as drills_service
from ghostdrive.services.context import require_db

logger = logging.getLogger("ghostdrive_web.monitoring")

router = APIRouter(prefix="/api/monitoring", tags=["monitoring"])

# Badge fills match the app accent (--accent: #c4f56a in styles.css) and its
# amber/red companions so an embedded badge looks native to GhostDrive.
_BADGE_FILLS = {"green": "#c4f56a", "amber": "#e8b84a", "red": "#e85d5d"}


def _http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, FileNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, ValueError):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, RuntimeError) and "locked" in str(exc).lower():
        return HTTPException(status_code=401, detail=str(exc))
    logger.exception("Monitoring operation failed: %s", exc)
    return HTTPException(status_code=500, detail=str(exc))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _age_text(past_iso: str | None) -> str:
    """Human age of an ISO timestamp: "just now" / "45m" / "3h" / "2d"."""
    if not past_iso:
        return ""
    try:
        past = datetime.fromisoformat(str(past_iso).replace("Z", "+00:00"))
    except ValueError:
        return ""
    if past.tzinfo is None:
        past = past.replace(tzinfo=timezone.utc)
    seconds = max(0, int((datetime.now(timezone.utc) - past).total_seconds()))
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h"
    return f"{seconds // 86400}d"


def _badge(db) -> dict:
    """Score the whole durability story into one glanceable verdict.

    Scoring rules (documented here because this is the trust signal):

    * RED   if the latest drill failed, the proof is stale (no success within
            14 days), or the audited guaranteed domain losses fall below the
            contract's requirement -- none of these may ever render softer.
    * AMBER if any warning/critical alert is still active (not dismissed)
            or a backend sits quarantined ("deprecated" is the quarantine
            status): degraded, but not proven at risk.
    * GREEN otherwise.
    """
    summary = drills_service.drill_summary(db)
    audit = durability.audit_readiness(db)
    contract = audit.get("contract") or durability.contract_from_settings(db)
    required = int(contract.get("required_domain_losses") or 0)
    guaranteed = audit.get("minimum_survivable_domain_losses")
    total_chunks = int(audit.get("total_chunks") or 0)
    below_contract = bool(total_chunks) and guaranteed is not None and guaranteed < required

    state = alerts_service.alert_state(db)
    active = [alert for alert in state["alerts"] if not alert["dismissed"]]
    row = db._conn.execute(
        "SELECT COUNT(*) AS n FROM backends WHERE status = 'deprecated'"
    ).fetchone()
    quarantined = int(row["n"] or 0) if row else 0

    last = summary["last"]
    if last and last.get("result") == "failed":
        overall, label = "red", "RESTORE DRILL FAILED"
    elif summary["stale"]:
        overall, label = "red", "DRILL PROOF STALE"
    elif below_contract:
        overall, label = "red", "BELOW DURABILITY CONTRACT"
    elif quarantined:
        overall, label = "amber", "BACKEND QUARANTINED"
    elif active:
        # Worst active alert names the badge; criticals sort before warnings.
        worst = sorted(
            active, key=lambda a: 0 if a["severity"] == "critical" else 1
        )[0]
        overall, label = "amber", str(worst["title"]).upper()
    else:
        overall = "green"
        if last and last.get("result") == "passed":
            age = _age_text(last.get("completed_at") or last.get("started_at"))
            label = "VERIFIED just now" if age == "just now" else f"VERIFIED {age} ago"
        elif last and last.get("result") == "skipped":
            label = "NOTHING TO DRILL"
        else:
            label = "NO RESTORE PROOF"

    return {
        "overall": overall,
        "label": label,
        "drill": summary,
        "contract": {
            "required_domain_losses": required,
            "guaranteed_domain_losses": guaranteed,
            "meets": not below_contract,
            "state": audit.get("state"),
            "summary": audit.get("summary"),
        },
        "active_alerts": len(active),
        "checked_at": _now_iso(),
    }


def _badge_svg(badge: dict) -> str:
    """Small embeddable shield SVG (the README/status badge)."""
    fill = _BADGE_FILLS.get(badge["overall"], _BADGE_FILLS["green"])
    label = escape(str(badge["label"]))
    aria = escape(f'{badge["overall"]}: {badge["label"]}')
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" width="240" height="34" '
        f'viewBox="0 0 240 34" role="img" aria-label="{aria}">'
        f'<rect x="1" y="1" width="238" height="32" rx="7" fill="#151a12" '
        f'stroke="{fill}" stroke-width="2"/>'
        f'<path d="M17 5 L27 9 v8 c0 6 -5 10 -10 12 c-5 -2 -10 -6 -10 -12 V9 Z" '
        f'fill="{fill}"/>'
        f'<text x="36" y="22" font-family="ui-monospace, SFMono-Regular, Consolas, '
        f'monospace" font-size="13" font-weight="600" fill="{fill}">{label}</text>'
        "</svg>"
    )


def _bool_setting(db, key: str, default: bool) -> bool:
    raw = str(db.get_setting(key, "true" if default else "false")).strip().lower()
    return raw in ("1", "true", "yes", "on")


def _float_setting(db, key: str, default: float) -> float:
    try:
        return float(str(db.get_setting(key, "")).strip() or default)
    except (TypeError, ValueError):
        return default


def _scheduler_status(db) -> dict:
    drill_task = getattr(drills_service, "_drill_task", None)
    alert_task = getattr(alerts_service, "_alerts_task", None)
    return {
        "drills": {
            "running": drill_task is not None and not drill_task.done(),
            "interval_hours": _float_setting(
                db, drills_service.KEY_DRILL_INTERVAL_HOURS,
                drills_service.DEFAULT_INTERVAL_HOURS,
            ),
            "enabled": _bool_setting(db, drills_service.KEY_DRILL_ENABLED, True),
        },
        "alerts": {
            "running": alert_task is not None and not alert_task.done(),
            "interval_minutes": _float_setting(
                db, alerts_service.KEY_ALERTS_INTERVAL_MINUTES,
                alerts_service.DEFAULT_INTERVAL_MINUTES,
            ),
        },
    }


# ─── Badge ───────────────────────────────────────────────────────────────────


@router.get("/badge")
def get_badge() -> dict:
    """One-glance durability verdict: overall color, label, drill + contract."""
    try:
        return _badge(require_db())
    except Exception as exc:
        raise _http_error(exc)


@router.get("/badge.svg")
def get_badge_svg() -> Response:
    """Embeddable SVG shield rendering the same badge (README/status page)."""
    try:
        svg = _badge_svg(_badge(require_db()))
    except Exception as exc:
        raise _http_error(exc)
    return Response(content=svg, media_type="image/svg+xml")


# ─── Restore drills ──────────────────────────────────────────────────────────


class DrillRunRequest(BaseModel):
    deep: bool = False


@router.get("/drills")
def list_drills(limit: int = 20) -> list[dict]:
    """Newest-first restore drill history."""
    try:
        return drills_service.drill_history(require_db(), limit=limit)
    except Exception as exc:
        raise _http_error(exc)


@router.get("/drills/summary")
def get_drill_summary() -> dict:
    """Counts, consecutive failures, last success, and the staleness flag."""
    try:
        return drills_service.drill_summary(require_db())
    except Exception as exc:
        raise _http_error(exc)


@router.post("/drills/run")
async def run_drill(req: DrillRunRequest | None = None) -> dict:
    """Run a restore drill now (deep=True drills every chunk of the newest snapshot)."""
    try:
        deep = bool(req.deep) if req else False
        return await drills_service.run_drill(require_db(), deep=deep)
    except Exception as exc:
        raise _http_error(exc)


# ─── Alerts ──────────────────────────────────────────────────────────────────


@router.get("/alerts")
def get_alerts() -> dict:
    """Active alerts merged with persisted first-seen/dismiss state."""
    try:
        return alerts_service.alert_state(require_db())
    except Exception as exc:
        raise _http_error(exc)


@router.post("/alerts/evaluate")
async def evaluate_alerts() -> dict:
    """Evaluate now, persist dedupe state, dispatch whatever is new."""
    try:
        db = require_db()
        found = alerts_service.evaluate(db)
        new = alerts_service.record_alerts(db, found)
        outcome = await alerts_service.dispatch(db, new)
        return {
            "new_alerts": new,
            "total": len(found),
            "dispatch": outcome,
        }
    except Exception as exc:
        raise _http_error(exc)


@router.delete("/alerts/{alert_id}")
def dismiss_alert(alert_id: str) -> dict:
    """Dismiss one alert; 404 for an unknown id."""
    try:
        return alerts_service.dismiss_alert(require_db(), alert_id)
    except Exception as exc:
        raise _http_error(exc)


# ─── Scheduler ───────────────────────────────────────────────────────────────


class SchedulerConfigRequest(BaseModel):
    drill_enabled: bool = True
    drill_interval_hours: float = 168
    alerts_interval_minutes: float = 15


@router.get("/scheduler")
async def get_scheduler() -> dict:
    """Running state + configured cadence, read from the module task globals."""
    try:
        return _scheduler_status(require_db())
    except Exception as exc:
        raise _http_error(exc)


@router.post("/scheduler")
async def update_scheduler(req: SchedulerConfigRequest) -> dict:
    """Persist cadence settings and (re)start the drill/alert loops.

    ``drill_enabled=false`` does not stop the drill loop -- the loop re-reads
    the flag every cycle -- so the flag stays authoritative even when a
    future caller restarts tasks underneath it.
    """
    try:
        if req.drill_interval_hours <= 0:
            raise ValueError("drill_interval_hours must be greater than 0.")
        if req.alerts_interval_minutes <= 0:
            raise ValueError("alerts_interval_minutes must be greater than 0.")
        db = require_db()
        with db.transaction():
            db.set_setting(
                drills_service.KEY_DRILL_ENABLED,
                "true" if req.drill_enabled else "false",
            )
            db.set_setting(
                drills_service.KEY_DRILL_INTERVAL_HOURS,
                str(float(req.drill_interval_hours)),
            )
            db.set_setting(
                alerts_service.KEY_ALERTS_INTERVAL_MINUTES,
                str(float(req.alerts_interval_minutes)),
            )
        # Restart both loops so the new cadence applies immediately.
        drills_service.stop_drill_scheduler()
        drills_service.start_drill_scheduler(db=db)
        alerts_service.stop_alerts_scheduler()
        alerts_service.start_alerts_scheduler(db=db)
        return _scheduler_status(db)
    except Exception as exc:
        raise _http_error(exc)
