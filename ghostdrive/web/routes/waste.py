"""waste.py -- Duplicate/waste report endpoints.

Thin HTTP shell over ``ghostdrive.services.waste``: ``GET /report`` runs the
report against the open vault (locked -> RuntimeError -> 401), ``GET /status``
is a symmetry stub for the UI (the report is computed on demand and is cheap,
so there is no ``last_run`` to report -- it is honestly ``None``).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException

from ghostdrive.services import waste as waste_service
from ghostdrive.services.context import require_db

logger = logging.getLogger("ghostdrive_web.waste")

router = APIRouter(prefix="/api/waste", tags=["waste"])


def _http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, FileNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, ValueError):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, RuntimeError) and "locked" in str(exc).lower():
        return HTTPException(status_code=401, detail=str(exc))
    logger.exception("Waste report failed: %s", exc)
    return HTTPException(status_code=500, detail=str(exc))


@router.get("/report")
def get_waste_report() -> dict:
    """Dedup, trash, versions, link, and top-duplicate figures for the vault."""
    try:
        return waste_service.report(require_db())
    except Exception as exc:
        raise _http_error(exc)


@router.get("/status")
def get_waste_status() -> dict:
    """Symmetry stub: nothing is persisted, so last_run is always null."""
    try:
        require_db()  # same locked -> 401 contract as every other route
        return {"last_run": None, "cheap": True}
    except Exception as exc:
        raise _http_error(exc)
