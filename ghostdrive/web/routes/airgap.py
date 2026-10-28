"""airgap.py -- Air-gap export endpoints: status, export, verify, drill.

Thin HTTP shell over ``ghostdrive.services.airgap``: every handler resolves
the vault through ``require_db()`` (locked -> RuntimeError -> 401) and maps
service exceptions with the same ``_http_error`` policy as monitoring.py
(FileNotFoundError -> 404, ValueError -> 400, locked -> 401, else 500).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ghostdrive.services import airgap as airgap_service
from ghostdrive.services.context import require_db

logger = logging.getLogger("ghostdrive_web.airgap")

router = APIRouter(prefix="/api/airgap", tags=["airgap"])


def _http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, FileNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, ValueError):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, RuntimeError) and "locked" in str(exc).lower():
        return HTTPException(status_code=401, detail=str(exc))
    logger.exception("Air-gap operation failed: %s", exc)
    return HTTPException(status_code=500, detail=str(exc))


class AirgapSettingsRequest(BaseModel):
    """Partial settings update; None fields are left untouched."""

    enabled: bool | None = None
    target_dir: str | None = None
    interval_hours: float | None = None


@router.post("/settings")
def update_airgap_settings(req: AirgapSettingsRequest) -> dict:
    """Persist air-gap settings (interval clamped >= 1h) and return status.

    An empty ``target_dir`` clears the configuration; a non-empty value is
    stored as-is (existence is checked at export time -- an unplugged drive
    must not break saving the setting).
    """
    try:
        db = require_db()
        with db.transaction():
            if req.enabled is not None:
                db.set_setting(
                    airgap_service.KEY_AIRGAP_ENABLED,
                    "true" if req.enabled else "false",
                )
            if req.target_dir is not None:
                db.set_setting(
                    airgap_service.KEY_AIRGAP_TARGET_DIR, req.target_dir.strip()
                )
            if req.interval_hours is not None:
                db.set_setting(
                    airgap_service.KEY_AIRGAP_INTERVAL_HOURS,
                    str(max(1.0, float(req.interval_hours))),
                )
        return airgap_service.airgap_status(db)
    except Exception as exc:
        raise _http_error(exc)


@router.get("/status")
def get_airgap_status() -> dict:
    """Enabled flag, target dir (+ existence), cadence, last export, last drill."""
    try:
        return airgap_service.airgap_status(require_db())
    except Exception as exc:
        raise _http_error(exc)


@router.post("/export")
async def run_airgap_export(target: str | None = None) -> dict:
    """Run one export now against ``?target=`` or the configured target dir.

    400 when no target is configured (the route never guesses a drive), 404
    when the target directory does not exist (drive unplugged), 401 when the
    vault is locked.
    """
    try:
        return await airgap_service.export_airgap(require_db(), target)
    except Exception as exc:
        raise _http_error(exc)


@router.post("/verify")
async def run_airgap_verify(export_dir: str | None = None) -> dict:
    """Verify an export (default: newest under the target) with disk reads only."""
    try:
        return await airgap_service.verify_airgap(require_db(), export_dir)
    except Exception as exc:
        raise _http_error(exc)


@router.post("/drill")
async def run_airgap_drill(export_dir: str | None = None) -> dict:
    """Restore-drill an export: decrypt one file out of it and compare digests.

    Failures record the critical ``airgap_drill_failed`` alert inside the
    service -- the HTTP response carries the same ``ok``/``error`` verdict.
    """
    try:
        return await airgap_service.restore_drill_airgap(require_db(), export_dir)
    except Exception as exc:
        raise _http_error(exc)
