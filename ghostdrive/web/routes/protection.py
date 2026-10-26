"""Always-on protection set routes."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ghostdrive.services import protection
from ghostdrive.services.context import require_db

logger = logging.getLogger("ghostdrive_web.protection")

router = APIRouter(prefix="/api/protection", tags=["protection"])


class ProtectionSetCreateRequest(BaseModel):
    name: str = ""
    source_path: str
    destination_path: str = "/"
    tier: str = "IMPORTANT"
    enabled: bool = True


class ProtectionSetUpdateRequest(BaseModel):
    name: str | None = None
    source_path: str | None = None
    destination_path: str | None = None
    tier: str | None = None
    enabled: bool | None = None


class ProtectionScanRequest(BaseModel):
    max_files: int = 200


def _http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, FileNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, (ValueError, PermissionError)):
        return HTTPException(status_code=400, detail=str(exc))
    logger.exception("Protection operation failed")
    return HTTPException(status_code=500, detail=str(exc))


@router.get("/sets")
def list_sets() -> dict:
    try:
        db = require_db()
        sets = protection.list_sets(db)
        return {
            "sets": sets,
            "summary": {
                "count": len(sets),
                "enabled": sum(1 for item in sets if item["enabled"]),
                "files": sum(item["file_count"] for item in sets),
                "bytes": sum(item["total_bytes"] for item in sets),
            },
        }
    except Exception as exc:
        raise _http_error(exc)


@router.post("/sets")
def create_set(req: ProtectionSetCreateRequest) -> dict:
    try:
        return {
            "status": "success",
            "set": protection.create_set(
                require_db(),
                req.name,
                req.source_path,
                req.destination_path,
                req.tier,
                req.enabled,
            ),
        }
    except Exception as exc:
        raise _http_error(exc)


@router.put("/sets/{set_id}")
def update_set(set_id: str, req: ProtectionSetUpdateRequest) -> dict:
    try:
        return {
            "status": "success",
            "set": protection.update_set(
                require_db(),
                set_id,
                name=req.name,
                source_path=req.source_path,
                destination_path=req.destination_path,
                tier=req.tier,
                enabled=req.enabled,
            ),
        }
    except Exception as exc:
        raise _http_error(exc)


@router.delete("/sets/{set_id}")
def delete_set(set_id: str) -> dict:
    try:
        return protection.delete_set(require_db(), set_id)
    except Exception as exc:
        raise _http_error(exc)


@router.get("/sets/{set_id}/files")
def list_set_files(set_id: str, limit: int = 200) -> dict:
    try:
        db = require_db()
        return {
            "set": protection.get_set(db, set_id),
            "files": protection.list_set_files(db, set_id, limit),
        }
    except Exception as exc:
        raise _http_error(exc)


@router.post("/sets/{set_id}/scan")
async def scan_set(set_id: str, req: ProtectionScanRequest | None = None) -> dict:
    try:
        return await protection.scan_set(
            require_db(), set_id, max_files=req.max_files if req else 200
        )
    except Exception as exc:
        raise _http_error(exc)


@router.post("/scan-all")
async def scan_all(req: ProtectionScanRequest | None = None) -> dict:
    try:
        return await protection.scan_all(
            require_db(), max_files=req.max_files if req else 200
        )
    except Exception as exc:
        raise _http_error(exc)
