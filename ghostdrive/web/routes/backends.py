"""
backends.py -- Multi-backend provider configuration, connectivity test, and tier assignment routes.
"""

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from ghostdrive.services import backends as backend_service

logger = logging.getLogger("ghostdrive_web.backends")

router = APIRouter(prefix="/api/backends", tags=["backends"])


class TestBackendRequest(BaseModel):
    provider: str
    tier: str = "LOCAL_LOCKER"
    credentials: Dict[str, Any] = {}
    backend_id: Optional[str] = None


class SaveBackendRequest(BaseModel):
    provider: str
    name: str
    tier: str = "LOCAL_LOCKER"
    enabled: bool = True
    credentials: Dict[str, Any] = {}
    quota_cap_gb: Optional[float] = 0.0


def _http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, FileNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, ValueError):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, RuntimeError) and "locked" in str(exc).lower():
        return HTTPException(status_code=401, detail=str(exc))
    logger.exception("Backend operation failed: %s", exc)
    return HTTPException(status_code=500, detail=str(exc))


def _resolve_backend_id(provider: str) -> Optional[str]:
    from ghostdrive.services.context import require_db
    db = require_db()
    needle = provider.lower()
    key = needle.split()[0] if needle.split() else needle
    for row in db.list_backends():
        haystack = " ".join([row["type"], row["id"]]).lower()
        label = db.get_setting(f"backend_label_{row['id']}", "").lower()
        if key in haystack or needle in label:
            return row["id"]
    return None


@router.get("/list")
def list_backends() -> dict:
    try:
        return backend_service.list_backends_view()
    except Exception as exc:
        raise _http_error(exc)


@router.post("/test")
async def test_backend_connectivity(req: TestBackendRequest) -> dict:
    try:
        backend_id = req.backend_id or _resolve_backend_id(req.provider)
        return await backend_service.test_connectivity(req.provider, req.credentials, backend_id)
    except Exception as exc:
        raise _http_error(exc)


@router.post("/save")
def save_backend_config(req: SaveBackendRequest) -> dict:
    try:
        return backend_service.save_backend(
            req.provider,
            req.name,
            req.tier,
            req.enabled,
            req.credentials,
            req.quota_cap_gb or 0.0,
        )
    except Exception as exc:
        raise _http_error(exc)


@router.post("/toggle")
def toggle_backend(backend_id: str = Query(...), enabled: bool = Query(...)) -> dict:
    try:
        return backend_service.toggle_backend(backend_id, enabled)
    except Exception as exc:
        raise _http_error(exc)


@router.delete("/remove/{backend_id}")
def remove_backend(backend_id: str, force: bool = False) -> dict:
    try:
        return backend_service.remove_backend(backend_id, force=force)
    except Exception as exc:
        raise _http_error(exc)


@router.post("/health")
async def health_check_all() -> dict:
    try:
        return await backend_service.health_check_all()
    except Exception as exc:
        raise _http_error(exc)


@router.get("/drives")
def list_connected_drives() -> dict:
    try:
        return backend_service.list_connected_drives()
    except Exception as exc:
        raise _http_error(exc)


@router.get("/discover-nas")
def discover_nas() -> dict:
    try:
        return backend_service.discover_nas()
    except Exception as exc:
        raise _http_error(exc)
