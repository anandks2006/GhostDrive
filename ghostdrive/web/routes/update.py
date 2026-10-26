"""
update.py -- Opt-in update check / download / install routes.

Wired to ghostdrive/platform/updater.py: checking is disabled unless the
user (or a vendor/operator packaging GhostDrive) has configured a feed,
downloads are only staged when the feed provided a sha256, and nothing is
ever installed without an explicit confirmation from the UI.
"""

import asyncio
import logging
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ghostdrive.platform import updater
from ghostdrive.services.context import require_db
from ghostdrive.web.state import state

logger = logging.getLogger("ghostdrive_web.update")

router = APIRouter(prefix="/api/update", tags=["update"])


class UpdateSettingsRequest(BaseModel):
    enabled: bool = False
    feed_url: str = ""


class InstallRequest(BaseModel):
    path: str
    confirm: bool = False


def _http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, FileNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, ValueError):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, RuntimeError) and "confirmation required" in str(exc).lower():
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, RuntimeError) and "locked" in str(exc).lower():
        return HTTPException(status_code=401, detail=str(exc))
    logger.exception("Update operation failed: %s", exc)
    return HTTPException(status_code=500, detail=str(exc))


@router.get("/check")
async def check_for_update() -> dict:
    """Probe the configured feed for a newer release.

    Errors come back as ``{"status": "error"}`` (200), not as HTTP failures:
    an unreachable feed is information for the UI, not a broken endpoint.
    The default configuration returns ``{"status": "disabled"}`` without
    touching the network.
    """
    try:
        return await updater.check_for_update(require_db())
    except Exception as exc:
        raise _http_error(exc)


@router.get("/status")
def update_status() -> dict:
    """Persisted checker settings plus the cached last-check result."""
    try:
        return updater.status(require_db())
    except Exception as exc:
        raise _http_error(exc)


@router.post("/settings")
def update_settings(req: UpdateSettingsRequest) -> dict:
    """Persist ``update_check_enabled`` + ``update_feed_url`` atomically.

    Saving also clears the last-check cache: a cached result belongs to the
    feed it came from, and must never be shown after the feed changed.
    """
    try:
        db = require_db()
        with db.transaction():
            db.set_setting(
                updater.UPDATE_CHECK_ENABLED, "true" if req.enabled else "false"
            )
            db.set_setting(updater.UPDATE_FEED_URL, req.feed_url.strip())
            db.set_setting(updater.UPDATE_LAST_CHECK, "")
        return {"status": "success", **updater.status(db)}
    except Exception as exc:
        raise _http_error(exc)


@router.post("/download")
async def download_update() -> dict:
    """Stage the verified installer under ``state.app_data_dir/updates``.

    Refuses (400) unless the last check reports ``update_available`` *with*
    a sha256 — an ``unverified`` update is never downloaded, because we
    cannot prove what the bytes are.
    """
    try:
        db = require_db()
        result = await updater.check_for_update(db)
        state_name = str(result.get("status") or "")
        if state_name == "unverified":
            raise HTTPException(status_code=400, detail="no checksum available")
        if state_name != "update_available":
            raise HTTPException(
                status_code=400, detail=f"no update available (status: {state_name})"
            )
        url = str(result.get("url") or "")
        sha256 = str(result.get("sha256") or "")
        dest_dir = Path(state.app_data_dir) / "updates"
        # stage_download is synchronous (blocking I/O) → worker thread.
        return await asyncio.to_thread(
            updater.stage_download, url, sha256, dest_dir
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise _http_error(exc)


@router.post("/install")
def install_update(req: InstallRequest) -> dict:
    """Spawn the staged installer after the user confirmed the prompt.

    Two independent gates, both required:

    1. path-traversal guard — only files inside our own updates directory
       may ever be spawned; a crafted ``path`` like ``../../evil.exe``
       (or a relative path resolved against the server's cwd) is rejected
       before anything else happens;
    2. ``confirm=True`` — never spawn a process without the user clicking
       through first (the updater itself re-checks this too).
    """
    try:
        updates_dir = (Path(state.app_data_dir) / "updates").resolve()
        candidate = Path(req.path).expanduser()
        if not candidate.is_absolute():
            # Relative paths would resolve against the server's cwd —
            # reject outright rather than guess where they land.
            raise HTTPException(status_code=400, detail="path outside updates directory")
        resolved = candidate.resolve()
        if not resolved.is_relative_to(updates_dir):
            raise HTTPException(status_code=400, detail="path outside updates directory")
        if not req.confirm:
            raise HTTPException(status_code=400, detail="confirmation required")
        return updater.run_installer(resolved, confirm=True)
    except HTTPException:
        raise
    except Exception as exc:
        raise _http_error(exc)
