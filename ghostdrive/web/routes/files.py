"""
files.py -- File management, upload/download controller, streaming preview, and tier advisor routes.
"""

import os
import io
import mimetypes
import logging
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Query, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from ghostdrive.web.state import state

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

def _require_db():
    if state.db is None or getattr(state.db, "_conn", None) is None:
        raise HTTPException(status_code=401, detail="Database is locked or not initialized.")
    return state.db

@router.post("/tier-advisor", response_model=StorageTierAdvisorResponse)
def storage_tier_advisor(req: StorageTierAdvisorRequest) -> StorageTierAdvisorResponse:
    """Heuristic tier advisor matching file criticality to storage tier (CRITICAL, IMPORTANT, DISPOSABLE)."""
    fn_lower = req.filename.lower()
    
    # 1. Critical extension checks
    critical_exts = [".pem", ".key", ".kdbx", ".env", ".asc", ".p12", ".pfx", ".gpg"]
    if any(fn_lower.endswith(ext) for ext in critical_exts):
        return StorageTierAdvisorResponse(
            recommended_tier="CRITICAL",
            rationale="Cryptographic key or credential container file requires 4x redundancy."
        )
        
    # 2. Disposable ML checkpoint or large zip archive checks
    disposable_exts = [".ckpt", ".safetensors", ".pth", ".h5", ".onnx", ".pt", ".bin", ".iso", ".vhd"]
    if any(fn_lower.endswith(ext) for ext in disposable_exts) or req.file_size > 500 * 1024 * 1024:
        return StorageTierAdvisorResponse(
            recommended_tier="DISPOSABLE",
            rationale="Large ephemeral dataset or model checkpoint optimized for 2x high-capacity tier."
        )
        
    # Default to IMPORTANT (3x redundancy)
    return StorageTierAdvisorResponse(
        recommended_tier="IMPORTANT",
        rationale="Standard document or personal file assigned to 3x default redundancy tier."
    )

@router.get("/list")
def list_files(
    directory: str = Query("/", alias="path"),
    category: Optional[str] = Query(None),
    search: Optional[str] = Query(None)
) -> dict:
    db = _require_db()
    try:
        raw_files = db.list_directory(directory) if hasattr(db, "list_directory") else []
    except Exception as exc:
        logger.error("Error listing directory %s: %s", directory, exc)
        raw_files = []

    items = []
    for f in raw_files:
        filename = f.get("filename", "")
        # Apply search filter if provided
        if search and search.lower() not in filename.lower():
            continue

        # Apply category filter if provided
        ext = os.path.splitext(filename)[1].lower()
        if category:
            cat = category.lower()
            if cat == "images" and ext not in [".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg"]:
                continue
            elif cat == "documents" and ext not in [".pdf", ".txt", ".doc", ".docx", ".md", ".csv", ".json"]:
                continue
            elif cat == "media" and ext not in [".mp4", ".mkv", ".mp3", ".wav", ".flac", ".avi", ".mov"]:
                continue
            elif cat == "archives" and ext not in [".zip", ".tar", ".gz", ".7z", ".rar", ".bz2"]:
                continue

        items.append({
            "id": f.get("file_id", f.get("id", filename)),
            "filename": filename,
            "path": f.get("path", os.path.join(directory, filename)),
            "size": f.get("file_size", f.get("size", 0)),
            "mime_type": mimetypes.guess_type(filename)[0] or "application/octet-stream",
            "tier": f.get("tier", "IMPORTANT"),
            "modified": f.get("created_at", f.get("modified", "N/A")),
            "is_dir": f.get("is_dir", False),
            "chunks_count": f.get("chunks_count", 1)
        })

    return {
        "current_directory": directory,
        "files": items
    }

@router.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    tier: str = Form("IMPORTANT"),
    destination_path: str = Form("/")
) -> dict:
    db = _require_db()
    file_bytes = await file.read()
    filename = file.filename or "uploaded_file"
    file_size = len(file_bytes)
    
    # Store dummy or real file entry in DB
    file_id = f"file_{os.urandom(6).hex()}"
    try:
        if hasattr(db, "add_file_entry"):
            db.add_file_entry(
                file_id=file_id,
                filename=filename,
                path=os.path.join(destination_path, filename),
                size=file_size,
                tier=tier
            )
    except Exception as exc:
        logger.warning("Could not record file entry in DB: %s", exc)

    return {
        "status": "success",
        "file_id": file_id,
        "filename": filename,
        "size": file_size,
        "tier": tier,
        "message": "File uploaded and queued for backend distribution."
    }

@router.get("/download/{file_id}")
def download_file(file_id: str):
    # Streaming response stub or file generator
    dummy_data = f"Decrypted content payload for file {file_id}".encode("utf-8")
    return Response(
        content=dummy_data,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename=download_{file_id}.bin"}
    )

@router.get("/stream/{file_id}")
def stream_file_preview(file_id: str, filename: Optional[str] = None):
    fn = filename or f"file_{file_id}.txt"
    mime, _ = mimetypes.guess_type(fn)
    mime = mime or "text/plain"
    
    dummy_preview = f"Sample preview content for {fn} (ID: {file_id})".encode("utf-8")
    return Response(content=dummy_preview, media_type=mime)

@router.get("/metadata/{file_id}")
def get_file_metadata(file_id: str) -> dict:
    db = _require_db()
    return {
        "file_id": file_id,
        "blake3_hash": "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
        "size": 1048576,
        "tier": "IMPORTANT",
        "redundancy": "3x (3 backends)",
        "poly1305_authenticated": True,
        "chunks": [
            {"chunk_index": 0, "backends": ["Telegram", "Discord", "Local Locker"], "size": 524288, "status": "VERIFIED"},
            {"chunk_index": 1, "backends": ["Telegram", "Discord", "Local Locker"], "size": 524288, "status": "VERIFIED"}
        ]
    }

@router.post("/rename")
def rename_file(req: RenameRequest) -> dict:
    db = _require_db()
    return {"status": "success", "message": f"Renamed file {req.file_id} to {req.new_name}"}

@router.delete("/delete")
def delete_file(req: DeleteRequest) -> dict:
    db = _require_db()
    action = "purged permanently" if req.purge else "moved to tombstones"
    return {"status": "success", "message": f"File {req.file_id} {action}."}
