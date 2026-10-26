"""
hostility.py -- Hostile-backend detection, quarantine, and immutable offsite copy routes.
"""

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ghostdrive.services import hostility as hostility_service
from ghostdrive.services import snapshots
from ghostdrive.services.context import require_db

logger = logging.getLogger("ghostdrive_web.hostility")

# Shares the /api/resilience prefix with routes/resilience.py; FastAPI allows
# multiple routers on one prefix, and this keeps hostile-backend concerns in
# their own module.
router = APIRouter(prefix="/api/resilience", tags=["resilience"])


class QuarantineRequest(BaseModel):
    reason: str = ""


def _http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, FileNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, ValueError):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, RuntimeError) and "locked" in str(exc).lower():
        return HTTPException(status_code=401, detail=str(exc))
    logger.exception("Hostility operation failed: %s", exc)
    return HTTPException(status_code=500, detail=str(exc))


@router.get("/hostility/report")
def get_hostility_report(window_hours: int = 168) -> dict:
    """Correlated per-backend integrity report: withholding vs merely failing."""
    try:
        return hostility_service.detect_withholding(
            require_db(), window_hours=window_hours
        )
    except Exception as exc:
        raise _http_error(exc)


@router.post("/hostility/quarantine/{backend_id}")
def quarantine_backend(backend_id: str, req: QuarantineRequest | None = None) -> dict:
    try:
        return hostility_service.quarantine_backend(
            require_db(), backend_id, reason=req.reason if req else ""
        )
    except Exception as exc:
        raise _http_error(exc)


@router.post("/hostility/clear/{backend_id}")
def clear_quarantine(backend_id: str) -> dict:
    try:
        return hostility_service.clear_quarantine(require_db(), backend_id)
    except Exception as exc:
        raise _http_error(exc)


@router.get("/offsite/immutable")
def get_immutable_copy() -> dict:
    try:
        return snapshots.immutable_copy_status(require_db())
    except Exception as exc:
        raise _http_error(exc)


@router.post("/offsite/immutable")
async def seal_immutable_copy() -> dict:
    try:
        return await snapshots.create_immutable_copy(db=require_db())
    except Exception as exc:
        raise _http_error(exc)


@router.post("/offsite/immutable/verify")
async def verify_immutable_copy() -> dict:
    try:
        return await snapshots.verify_immutable_copy(db=require_db())
    except Exception as exc:
        raise _http_error(exc)
