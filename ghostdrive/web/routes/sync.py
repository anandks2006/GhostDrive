"""
sync.py -- Real-time folder sync and file version history routes.

Covers the sync scheduler (status/start/stop/one-shot pass/settings) and the
file_versions API (list / restore / prune) on one router.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ghostdrive.services import sync as sync_service
from ghostdrive.services import versions as versions_service
from ghostdrive.services.context import require_db

logger = logging.getLogger("ghostdrive_web.sync")

router = APIRouter(prefix="/api/sync", tags=["sync"])

# Setting key mirroring the version_keep service default (see services/versions).
VERSION_KEEP_SETTING = "version_keep"


class SyncSettingsRequest(BaseModel):
    enabled: bool | None = None
    # Legacy single-root field: replaces the whole list with one folder.
    root: str | None = None
    # Multi-folder field: replaces the whole list (empty list clears it).
    roots: list[str] | None = None
    interval_seconds: int | None = None
    on_change: bool | None = None


class VersionRestoreRequest(BaseModel):
    version: int


class VersionPruneRequest(BaseModel):
    keep: int | None = None


def _http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, FileNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, ValueError):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, RuntimeError) and "locked" in str(exc).lower():
        return HTTPException(status_code=401, detail=str(exc))
    logger.exception("Sync operation failed: %s", exc)
    return HTTPException(status_code=500, detail=str(exc))


def _validated_root(raw: str) -> str:
    """Validate one candidate sync root; return its resolved path string.

    Raises 400 for an empty/nonexistent/non-directory path and for the
    feedback-loop guard (app-data overlap), so a bad folder never enters the
    configured list -- even though the guard also re-runs on every pass.
    """
    if not str(raw).strip():
        raise HTTPException(
            status_code=400, detail="Sync root folder must not be empty."
        )
    root = Path(raw).expanduser()
    if not root.exists() or not root.is_dir():
        raise HTTPException(
            status_code=400,
            detail=f"Sync root does not exist or is not a directory: {raw}",
        )
    guard = sync_service.feedback_guard(root)
    if guard:
        raise HTTPException(status_code=400, detail=guard)
    return str(root.resolve())


@router.get("/status")
def get_sync_status() -> dict:
    """Sync configuration, scheduler state, and the last pass result."""
    try:
        return sync_service.sync_status(require_db())
    except Exception as exc:
        raise _http_error(exc)


@router.post("/start")
async def start_sync() -> dict:
    """Start the background sync scheduler (idempotent)."""
    # async so asyncio.create_task() runs on the app's event loop rather than
    # a threadpool thread (which has no running loop).
    try:
        db = require_db()
        sync_service.start_sync_scheduler(db)
        return {"status": "success", "sync": sync_service.sync_status(db)}
    except Exception as exc:
        raise _http_error(exc)


@router.post("/stop")
async def stop_sync() -> dict:
    """Stop the background sync scheduler if it is running."""
    try:
        db = require_db()
        task = sync_service.stop_sync_scheduler()
        if task is not None:
            # Reap the cancelled loop so no pending-task warning leaks from
            # the event loop when it shuts down.
            with contextlib.suppress(asyncio.CancelledError):
                await task
        return {"status": "success", "sync": sync_service.sync_status(db)}
    except Exception as exc:
        raise _http_error(exc)


@router.post("/run")
async def run_sync() -> dict:
    """Run exactly one sync pass now and return its counters."""
    try:
        return await sync_service.run_sync_pass(require_db())
    except Exception as exc:
        raise _http_error(exc)


@router.post("/settings")
def update_sync_settings(req: SyncSettingsRequest) -> dict:
    """Persist sync settings.

    ``roots`` replaces the full auto-vault folder list (each entry must
    exist, be a directory, and pass the feedback-loop guard; ``[]`` clears
    the list). The legacy ``root`` field replaces the list with that single
    folder. Both are optional alongside the scheduler settings.
    """
    try:
        db = require_db()
        if req.roots is not None:
            sync_service.set_sync_roots(
                db, [_validated_root(entry) for entry in req.roots]
            )
        elif req.root is not None:
            sync_service.set_sync_roots(db, [_validated_root(req.root)])
        if req.enabled is not None:
            db.set_setting(
                sync_service.SETTING_ENABLED, "true" if req.enabled else "false"
            )
        if req.on_change is not None:
            db.set_setting(
                sync_service.SETTING_ON_CHANGE, "true" if req.on_change else "false"
            )
        if req.interval_seconds is not None:
            # The scheduler floors at 15 s; persist the clamped value so
            # status reports what actually runs.
            clamped = max(sync_service.MIN_INTERVAL_SECONDS, int(req.interval_seconds))
            db.set_setting(sync_service.SETTING_INTERVAL, str(clamped))
        return sync_service.sync_status(db)
    except HTTPException:
        raise
    except Exception as exc:
        raise _http_error(exc)


# ── File version history ──────────────────────────────────────────────────────

@router.get("/versions/{file_id}")
def list_versions(file_id: str, limit: int = 50) -> dict:
    """Version history for one file, newest first."""
    try:
        db = require_db()
        if db.get_file(file_id) is None:
            raise FileNotFoundError(f"File {file_id} not found.")
        rows = db.list_file_versions(file_id, limit=limit)
        return {
            "file_id": file_id,
            "versions": [versions_service.version_dict(row) for row in rows],
        }
    except Exception as exc:
        raise _http_error(exc)


@router.post("/versions/{file_id}/restore")
async def restore_version(file_id: str, req: VersionRestoreRequest) -> dict:
    """Point the file back at version req.version (appends a restore version)."""
    try:
        db = require_db()
        result = await versions_service.restore_version(db, file_id, req.version)
        return {"status": "success", **result}
    except Exception as exc:
        raise _http_error(exc)


@router.post("/versions/{file_id}/prune")
def prune_versions(file_id: str, req: VersionPruneRequest | None = None) -> dict:
    """Drop old versions beyond ``keep`` (default: version_keep setting, 10)."""
    try:
        db = require_db()
        keep = req.keep if req and req.keep is not None else None
        if keep is None:
            raw = str(db.get_setting(VERSION_KEEP_SETTING, "10") or "10")
            try:
                keep = int(raw)
            except ValueError:
                keep = 10
        result = versions_service.prune_versions(db, file_id=file_id, keep=keep)
        return {"status": "success", **result}
    except Exception as exc:
        raise _http_error(exc)
