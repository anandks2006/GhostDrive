"""
backends.py -- Multi-backend provider configuration, connectivity test, and tier assignment routes.
"""

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from ghostdrive.services import backends as backend_service
from ghostdrive.services.context import require_db

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
    # WORM: refuse deletes/overwrites of this backend's bytes through the app.
    append_only: bool = False


class WormToggleRequest(BaseModel):
    """Body for POST /api/backends/{backend_id}/worm.

    Toggling OFF is allowed and only relaxes FUTURE deletes: bytes already
    retained while the flag was on are not restored, and nothing retroactively
    re-deletes them (their index rows were dropped with the purge).
    """
    enabled: bool


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
        view = backend_service.list_backends_view()
        # The view predates the WORM flag; enrich each card from the DB row so
        # the UI can show which backends are append-only.
        db = require_db()
        flags = {
            row["id"]: bool(row["append_only"])
            for row in db.list_backends(include_deprecated=True)
        }
        for entry in view.get("configured_backends", []):
            entry["append_only"] = flags.get(entry["id"], False)
        return view
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
        result = backend_service.save_backend(
            req.provider,
            req.name,
            req.tier,
            req.enabled,
            req.credentials,
            req.quota_cap_gb or 0.0,
        )
        if req.append_only and result.get("backend_id"):
            # services/backends.py predates the WORM flag; apply it here on the
            # freshly created row, since this route owns the request model.
            db = require_db()
            with db.transaction():
                db._conn.execute(
                    "UPDATE backends SET append_only = 1 WHERE id = ?",
                    (result["backend_id"],),
                )
            result["append_only"] = True
        return result
    except Exception as exc:
        raise _http_error(exc)


@router.post("/{backend_id}/worm")
def set_backend_worm(backend_id: str, req: WormToggleRequest) -> dict:
    """Enable/disable WORM (append-only) mode for one backend.

    While enabled the app accepts writes but refuses to delete or overwrite
    this backend's chunk bytes (application-level enforcement -- see
    services/files.py). require_db() implies the vault is unlocked.

    Toggling OFF is allowed: future deletes become possible again, but bytes
    already retained while the flag was on are NOT restored (their index rows
    were dropped with the purge) and nothing retroactively re-deletes them.
    """
    try:
        db = require_db()
        row = db.get_backend(backend_id)
        if row is None:
            raise FileNotFoundError(f"Backend {backend_id} not found.")
        with db.transaction():
            db._conn.execute(
                "UPDATE backends SET append_only = ? WHERE id = ?",
                (1 if req.enabled else 0, backend_id),
            )
        return {
            "status": "success",
            "backend_id": backend_id,
            "append_only": bool(req.enabled),
            "message": (
                f"Backend {backend_id} is now append-only (WORM): accepts writes, "
                "refuses deletes and overwrites."
                if req.enabled
                else f"Backend {backend_id} is no longer append-only; future deletes "
                "are allowed (bytes retained while WORM was on are not restored)."
            ),
        }
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
