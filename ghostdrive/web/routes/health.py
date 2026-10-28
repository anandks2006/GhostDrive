"""
health.py -- Weekly vault-health report routes.

GET  /report   last persisted report (None-safe before the first run)
POST /run      build + persist + deliver one report now
POST /settings persist clamped cadence settings (webhook URL is never echoed)
GET /status    scheduler running state + settings
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ghostdrive.services import health_report as health_service
from ghostdrive.services.context import require_db

logger = logging.getLogger("ghostdrive_web.health")

router = APIRouter(prefix="/api/health", tags=["health"])


def _http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, FileNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, ValueError):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, RuntimeError) and "locked" in str(exc).lower():
        return HTTPException(status_code=401, detail=str(exc))
    logger.exception("Health report operation failed: %s", exc)
    return HTTPException(status_code=500, detail=str(exc))


class HealthSettingsRequest(BaseModel):
    enabled: bool | None = None
    interval_hours: float | None = None
    webhook_url: str | None = None


@router.get("/report")
def get_report() -> dict:
    """Last persisted report; ``report`` is None until the first run."""
    try:
        meta = health_service.get_health_report(require_db())
        return {"last_run": meta["last_run"], "report": meta["report"]}
    except Exception as exc:
        raise _http_error(exc)


@router.post("/run")
async def run_now() -> dict:
    """Build, persist, and deliver (when a webhook is set) one report now."""
    try:
        return await health_service.run_health_report(require_db())
    except Exception as exc:
        raise _http_error(exc)


def _status(db) -> dict:
    status = health_service.health_report_status(db)
    # Same shape from POST /settings and GET /status; the webhook URL itself
    # is never echoed -- only whether one is configured.
    return {
        "running": status["running"],
        "enabled": status["enabled"],
        "interval_hours": status["interval_hours"],
        "last_run": status["last_run"],
        "webhook_configured": status["webhook_configured"],
    }


@router.post("/settings")
def update_settings(req: HealthSettingsRequest) -> dict:
    """Persist clamped settings: interval_hours < 1 becomes 1, URL trimmed.

    ``null`` fields are left untouched, so the UI can PATCH partial updates.
    """
    try:
        db = require_db()
        with db.transaction():
            if req.enabled is not None:
                db.set_setting(
                    health_service.KEY_ENABLED, "true" if req.enabled else "false"
                )
            if req.interval_hours is not None:
                hours = max(health_service.MIN_INTERVAL_HOURS, float(req.interval_hours))
                db.set_setting(health_service.KEY_INTERVAL_HOURS, str(hours))
            if req.webhook_url is not None:
                db.set_setting(
                    health_service.KEY_WEBHOOK_URL, str(req.webhook_url).strip()
                )
        return _status(db)
    except Exception as exc:
        raise _http_error(exc)


@router.get("/status")
def get_status() -> dict:
    """Scheduler running state + persisted cadence settings."""
    try:
        return _status(require_db())
    except Exception as exc:
        raise _http_error(exc)
