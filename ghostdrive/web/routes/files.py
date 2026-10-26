"""
files.py -- File management, upload/download controller, streaming preview, and tier advisor routes.
"""

import logging
from typing import Optional
from urllib.parse import quote

from fastapi import APIRouter, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from ghostdrive.services import files as files_service

logger = logging.getLogger("ghostdrive_web.files")

router = APIRouter(prefix="/api/files", tags=["files"])


class StorageTierAdvisorRequest(BaseModel):
    filename: str
    file_size: int
    mime_type: Optional[str] = None


class StorageTierAdvisorResponse(BaseModel):
    recommended_tier: str
    rationale: str


class RenameRequest(BaseModel):
    file_id: str
    new_name: str


class DeleteRequest(BaseModel):
    file_id: str
    purge: bool = False


class TagsRequest(BaseModel):
    file_id: str
    tags: str = ""


def _http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, FileNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, (ValueError, TypeError)):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, RuntimeError) and "blocked" in str(exc).lower():
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, RuntimeError) and "locked" in str(exc).lower():
        return HTTPException(status_code=401, detail=str(exc))
    logger.exception("File operation failed: %s", exc)
    return HTTPException(status_code=500, detail=str(exc))


@router.post("/tier-advisor", response_model=StorageTierAdvisorResponse)
def storage_tier_advisor(req: StorageTierAdvisorRequest) -> StorageTierAdvisorResponse:
    """Heuristic tier advisor matching file criticality to storage tier (CRITICAL, IMPORTANT, DISPOSABLE)."""
    fn_lower = req.filename.lower()

    critical_exts = [".pem", ".key", ".kdbx", ".env", ".asc", ".p12", ".pfx", ".gpg"]
    if any(fn_lower.endswith(ext) for ext in critical_exts):
        return StorageTierAdvisorResponse(
            recommended_tier="CRITICAL",
            rationale="Cryptographic key or credential container file requires 4+2 erasure protection.",
        )

    disposable_exts = [".ckpt", ".safetensors", ".pth", ".h5", ".onnx", ".pt", ".bin", ".iso", ".vhd"]
    if any(fn_lower.endswith(ext) for ext in disposable_exts) or req.file_size > 500 * 1024 * 1024:
        return StorageTierAdvisorResponse(
            recommended_tier="DISPOSABLE",
            rationale="Large ephemeral dataset or model checkpoint optimized for 2x high-capacity tier.",
        )

    return StorageTierAdvisorResponse(
        recommended_tier="IMPORTANT",
        rationale="Standard document or personal file assigned to 4+2 erasure protection.",
    )


@router.get("/list")
def list_files(
    directory: str = Query("/", alias="path"),
    category: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
) -> dict:
    try:
        return files_service.list_files(directory, category, search)
    except Exception as exc:
        raise _http_error(exc)


@router.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    tier: str = Form("IMPORTANT"),
    destination_path: str = Form("/"),
) -> dict:
    try:
        return await files_service.upload_stream(
            file,
            file.filename or "uploaded_file",
            file.content_type,
            tier,
            destination_path,
        )
    except Exception as exc:
        raise _http_error(exc)


@router.get("/download/{file_id}")
async def download_file(file_id: str):
    try:
        row = files_service.get_file_row(file_id)
        length = int(row["size"])
    except Exception as exc:
        raise _http_error(exc)

    filename = quote(row["name"])
    headers = {
        "Content-Disposition": f"attachment; filename*=UTF-8''{filename}",
        "Content-Length": str(length),
    }
    return StreamingResponse(
        files_service.iter_file(file_id),
        media_type=row["mime_type"] or "application/octet-stream",
        headers=headers,
    )


@router.get("/stream/{file_id}")
async def stream_file_preview(file_id: str, filename: Optional[str] = None):
    try:
        row = files_service.get_file_row(file_id)
    except Exception as exc:
        raise _http_error(exc)
    return StreamingResponse(
        files_service.iter_file(file_id),
        media_type=row["mime_type"] or "application/octet-stream",
        headers={"Content-Disposition": f"inline; filename*=UTF-8''{quote(row['name'])}"},
    )


@router.get("/metadata/{file_id}")
def get_file_metadata(file_id: str) -> dict:
    try:
        return files_service.metadata(file_id)
    except Exception as exc:
        raise _http_error(exc)


@router.post("/rename")
def rename_file(req: RenameRequest) -> dict:
    try:
        return files_service.rename(req.file_id, req.new_name)
    except Exception as exc:
        raise _http_error(exc)


@router.delete("/delete")
async def delete_file(req: DeleteRequest) -> dict:
    try:
        return await files_service.delete_file(req.file_id, purge=req.purge)
    except Exception as exc:
        raise _http_error(exc)


@router.get("/trash")
def list_trash(older_than_days: Optional[int] = None) -> dict:
    try:
        return files_service.trash(older_than_days)
    except Exception as exc:
        raise _http_error(exc)


@router.post("/restore")
def restore_file(req: DeleteRequest) -> dict:
    try:
        return files_service.restore(req.file_id)
    except Exception as exc:
        raise _http_error(exc)


@router.delete("/trash/empty")
async def empty_trash(older_than_days: Optional[int] = None) -> dict:
    try:
        return await files_service.empty_trash(older_than_days)
    except Exception as exc:
        raise _http_error(exc)


@router.get("/versions/{file_id}")
def list_versions(file_id: str) -> dict:
    try:
        return files_service.versions(file_id)
    except Exception as exc:
        raise _http_error(exc)


@router.post("/versions/{file_id}/restore/{version_id}")
def restore_version(file_id: str, version_id: str) -> dict:
    try:
        return files_service.restore_version(file_id, version_id)
    except Exception as exc:
        raise _http_error(exc)


@router.post("/tags")
def set_tags(req: TagsRequest) -> dict:
    try:
        return files_service.set_tags(req.file_id, req.tags)
    except Exception as exc:
        raise _http_error(exc)


@router.post("/verify/{file_id}")
async def verify_file(file_id: str) -> dict:
    try:
        return await files_service.verify_file(file_id)
    except Exception as exc:
        raise _http_error(exc)
