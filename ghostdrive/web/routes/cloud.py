"""
cloud.py -- Cloud import routes: connect with a pasted token, list, import, history.

Bring-your-own OAuth token: the user pastes an access token created in their
own Dropbox / Google Drive / OneDrive developer console. The app never sees a
cloud password; the token is validated with one cheap provider call, stored in
the OS credential store (never in the settings table), and used only against
that provider's API. Imported files travel over the provider's TLS and are
encrypted immediately on arrival through the normal upload pipeline.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ghostdrive.services import cloud_import
from ghostdrive.services.context import require_db

logger = logging.getLogger("ghostdrive_web.cloud")

router = APIRouter(prefix="/api/cloud", tags=["cloud"])


def _http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, ValueError):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, FileNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, RuntimeError) and "locked" in str(exc).lower():
        return HTTPException(status_code=401, detail=str(exc))
    logger.exception("Cloud import operation failed: %s", exc)
    return HTTPException(status_code=500, detail=str(exc))


class ConnectRequest(BaseModel):
    provider: str
    token: str


class DisconnectRequest(BaseModel):
    provider: str


class ImportRequest(BaseModel):
    # Paths-list shape (not opaque file dicts): the server re-resolves every
    # path against a fresh provider listing before importing, so the request
    # cannot smuggle in arbitrary remote ids.
    provider: str
    paths: list[str]
    dest_dir: str | None = None


# ─── Connection management ───────────────────────────────────────────────────


@router.get("/status")
def get_status() -> dict:
    """Per-provider connection state with a masked token hint (never the token)."""
    try:
        return cloud_import.connection_status(require_db())
    except Exception as exc:
        raise _http_error(exc)


@router.post("/connect")
def post_connect(req: ConnectRequest) -> dict:
    """Validate a pasted token (400 with the provider's error when rejected),
    store it in the OS credential store, and return the fresh status."""
    try:
        db = require_db()
        cloud_import.connect(db, req.provider, req.token)
        return cloud_import.connection_status(db)
    except Exception as exc:
        raise _http_error(exc)


@router.post("/disconnect")
def post_disconnect(req: DisconnectRequest) -> dict:
    """Forget the stored token for one provider (idempotent)."""
    try:
        return cloud_import.disconnect(require_db(), req.provider)
    except Exception as exc:
        raise _http_error(exc)


# ─── Browsing and importing ──────────────────────────────────────────────────


@router.get("/list")
async def get_list(provider: str, folder: str | None = None) -> dict:
    """First page of a provider folder listing (400 when not connected)."""
    try:
        return await cloud_import.list_remote(require_db(), provider, folder=folder)
    except Exception as exc:
        raise _http_error(exc)


@router.post("/import")
async def post_import(req: ImportRequest) -> dict:
    """Import the given remote paths, sequentially, through the encrypting pipeline.

    Each path is re-resolved against a fresh provider listing; unknown paths
    and per-file download/upload failures come back in ``results`` without
    aborting the batch. A batch summary is appended to the import history.
    """
    try:
        db = require_db()
        if not [p for p in req.paths if str(p or "").strip()]:
            raise ValueError("No remote paths were provided.")
        if len(req.paths) > cloud_import.MAX_IMPORT_PATHS:
            raise ValueError(
                f"Too many paths in one request (max {cloud_import.MAX_IMPORT_PATHS})."
            )
        resolved = cloud_import.resolve_remote_paths(db, req.provider, req.paths)
        summary = await cloud_import.import_many(db, req.provider, resolved, dest_dir=req.dest_dir)
        summary["at"] = cloud_import._now_iso()
        cloud_import.append_import_history(db, {
            "provider": summary["provider"],
            "imported": summary["imported"],
            "failed": summary["failed"],
            "bytes": summary["bytes"],
            "at": summary["at"],
        })
        return summary
    except Exception as exc:
        raise _http_error(exc)


@router.get("/history")
def get_history() -> dict:
    """Newest-first import summaries (settings-backed, capped at 20)."""
    try:
        return {"history": cloud_import.import_history(require_db())}
    except Exception as exc:
        raise _http_error(exc)
