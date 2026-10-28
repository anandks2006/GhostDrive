"""
security.py -- Canary tripwire and mass-modification alarm routes.

One router for the two active-defense signals: the canary decoy tripwire
(register/check/settings) and the mass-change rate detector (status/settings/
on-demand check).  Every endpoint requires an unlocked vault (require_db
raises RuntimeError "locked" -> 401 via _http_error).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ghostdrive.services import canary as canary_service
from ghostdrive.services import mass_alarm as mass_alarm_service
from ghostdrive.services.context import require_db

logger = logging.getLogger("ghostdrive_web.security")

router = APIRouter(prefix="/api/security", tags=["security"])


def _http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, FileNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, ValueError):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, RuntimeError) and "locked" in str(exc).lower():
        return HTTPException(status_code=401, detail=str(exc))
    logger.exception("Security operation failed: %s", exc)
    return HTTPException(status_code=500, detail=str(exc))


class CanaryAddRequest(BaseModel):
    path: str
    plant: bool = True


class CanarySettingsRequest(BaseModel):
    enabled: bool | None = None
    interval_seconds: int | None = None


class MassAlarmSettingsRequest(BaseModel):
    enabled: bool | None = None
    threshold: int | None = None
    window_minutes: int | None = None


# ─── Canary tripwire ─────────────────────────────────────────────────────────


@router.get("/canaries")
def list_canaries() -> dict:
    """Enable flag, check interval, and every registered canary."""
    try:
        return canary_service.canary_status(require_db())
    except Exception as exc:
        raise _http_error(exc)


@router.post("/canary/add")
async def add_canary(req: CanaryAddRequest) -> dict:
    """Plant a decoy (plant=true, default) or register an existing file as-is.

    400 for an empty path or app-data overlap (and for plant=false on a
    missing file); 409 when the path is already registered or a non-canary
    file already occupies the planting spot (overwrite is never allowed --
    plant=false watches the existing file instead).
    """
    try:
        db = require_db()
        if req.plant:
            await canary_service.plant_canary(db, req.path)
        else:
            canary_service.register_existing_canary(db, req.path)
        return canary_service.canary_status(db)
    except FileExistsError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except Exception as exc:
        raise _http_error(exc)


@router.delete("/canary")
def delete_canary(path: str, delete_file: bool = False) -> dict:
    """Unregister a canary; optionally unlink the planted decoy.

    The unlink is marker-guarded in the service: files not planted by
    GhostDrive are never deleted, even with delete_file=true.
    """
    try:
        db = require_db()
        canary_service.unregister_canary(db, path, delete_file=delete_file)
        return canary_service.canary_status(db)
    except Exception as exc:
        raise _http_error(exc)


@router.post("/canary/check")
async def check_canaries() -> dict:
    """Run one canary check now (does not touch the scheduler)."""
    try:
        return await canary_service.check_canaries(require_db())
    except Exception as exc:
        raise _http_error(exc)


@router.post("/canary/settings")
def update_canary_settings(req: CanarySettingsRequest) -> dict:
    """Persist enable flag and/or check interval (clamped to >= 15s)."""
    try:
        db = require_db()
        with db.transaction():
            if req.enabled is not None:
                db.set_setting(
                    canary_service.SETTING_ENABLED, "true" if req.enabled else "false"
                )
            if req.interval_seconds is not None:
                interval = max(
                    canary_service.MIN_INTERVAL_SECONDS, int(req.interval_seconds)
                )
                db.set_setting(canary_service.SETTING_INTERVAL, str(interval))
        return canary_service.canary_status(db)
    except Exception as exc:
        raise _http_error(exc)


# ─── Mass-modification alarm ─────────────────────────────────────────────────


@router.get("/mass-change")
def get_mass_change() -> dict:
    """Config, the persisted rolling window, and the last check result."""
    try:
        return mass_alarm_service.mass_alarm_status(require_db())
    except Exception as exc:
        raise _http_error(exc)


@router.post("/mass-change/settings")
def update_mass_change_settings(req: MassAlarmSettingsRequest) -> dict:
    """Persist threshold (clamped >= 1) and window (clamped 1..1440 minutes)."""
    try:
        db = require_db()
        with db.transaction():
            if req.enabled is not None:
                db.set_setting(
                    mass_alarm_service.SETTING_ENABLED,
                    "true" if req.enabled else "false",
                )
            if req.threshold is not None:
                db.set_setting(
                    mass_alarm_service.SETTING_THRESHOLD,
                    str(max(1, int(req.threshold))),
                )
            if req.window_minutes is not None:
                db.set_setting(
                    mass_alarm_service.SETTING_WINDOW,
                    str(min(mass_alarm_service.MAX_WINDOW_MINUTES,
                            max(1, int(req.window_minutes)))),
                )
        return mass_alarm_service.mass_alarm_status(db)
    except Exception as exc:
        raise _http_error(exc)


@router.post("/mass-change/check")
async def check_mass_change() -> dict:
    """Run one mass-change scan now (does not touch the scheduler)."""
    try:
        return await mass_alarm_service.check_mass_change(require_db())
    except Exception as exc:
        raise _http_error(exc)
