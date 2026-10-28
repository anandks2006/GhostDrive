"""
extension.py -- Browser extension support: lock-tolerant status probe, zip
download of the packaged extension, and a CORS-free raw-body upload route.

The "Encrypt to GhostDrive" browser extension (packaging/extension/) is a thin
loopback client.  Its only write path is ``POST /api/extension/upload`` with
the raw bytes as the body -- not multipart -- because a Manifest V3 service
worker composing multipart bodies by hand buys nothing over one POST with a
query parameter.  ``server.py`` configures no CORS middleware; the extension
works anyway because Chromium exempts fetches covered by the manifest's
``host_permissions`` (loopback only) from CORS.  See
docs/BROWSER_EXTENSION.md §3 for the full story.
"""

from __future__ import annotations

import io
import logging
import zipfile
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query, Request, Response

from ghostdrive.services import files as files_service

logger = logging.getLogger("ghostdrive_web.extension")

router = APIRouter(prefix="/api/extension", tags=["extension"])

# packaging/extension lives at <repo root>/packaging/extension, three levels
# above this file (ghostdrive/web/routes/extension.py).
EXTENSION_DIR = Path(__file__).resolve().parents[3] / "packaging" / "extension"
DOWNLOAD_NAME = "ghostdrive-extension.zip"

try:
    # Port discovery for the status payload; a locked vault still answers from
    # the environment/default, matching the ops model in services/remote_access.
    from ghostdrive.services.remote_access import resolve_port as _resolve_port
except Exception:  # pragma: no cover - defensive; remote_access is stdlib-only
    _resolve_port = None


def _http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, FileNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, ValueError):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, RuntimeError) and "locked" in str(exc).lower():
        return HTTPException(status_code=401, detail=str(exc))
    logger.exception("Extension operation failed: %s", exc)
    return HTTPException(status_code=500, detail=str(exc))


def _app_port() -> int:
    if _resolve_port is None:
        return 8000
    try:
        return int(_resolve_port(None))
    except Exception as exc:
        logger.debug("resolve_port failed, defaulting to 8000: %s", exc)
        return 8000


# ─── Status (lock-tolerant) ──────────────────────────────────────────────────


@router.get("/status")
def extension_status() -> dict:
    """Cheap probe for the extension popup: reachable while the vault is locked.

    No ``require_db()`` -- the popup's "is the app running?" check must not
    demand an unlocked vault.  ``installed_hint`` only reports that the
    packaged extension exists on disk (a download button should be shown);
    it cannot detect an actually-installed browser extension.
    """
    return {
        "installed_hint": (EXTENSION_DIR / "manifest.json").is_file(),
        "app_url": f"http://127.0.0.1:{_app_port()}",
        "docs": "/static/",
    }


# ─── Download (zip of packaging/extension/) ──────────────────────────────────


@router.get("/download")
def download_extension() -> Response:
    """Zip packaging/extension/ in memory and serve it as ghostdrive-extension.zip.

    The source of truth is the directory on disk; nothing is cached, so the
    next download always reflects the current files.  This is the "get the
    extension" button for the web UI (load it via chrome://extensions ->
    Load unpacked, or unzip anywhere).
    """
    if not EXTENSION_DIR.is_dir():
        raise HTTPException(
            status_code=404,
            detail=f"Extension pack not found at {EXTENSION_DIR}.",
        )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as bundle:
        for file in sorted(EXTENSION_DIR.rglob("*")):
            if not file.is_file():
                continue
            if "__pycache__" in file.parts or file.name.startswith("."):
                continue
            bundle.write(file, arcname=str(file.relative_to(EXTENSION_DIR)).replace("\\", "/"))
    if not buffer.getvalue():
        raise HTTPException(
            status_code=404,
            detail=f"Extension pack at {EXTENSION_DIR} is empty.",
        )
    return Response(
        content=buffer.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{DOWNLOAD_NAME}"'},
    )


# ─── Upload (raw bytes, used by the extension) ───────────────────────────────


@router.options("/upload")
def extension_upload_preflight() -> Response:
    """Belt-and-braces OPTIONS answer for the upload route.

    Chromium does not run CORS preflight for extension fetches covered by the
    manifest's host_permissions, so this is not on the critical path; it exists
    so a misbehaving client gets a truthful 204 instead of FastAPI's 405.
    """
    return Response(
        status_code=204,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
        },
    )


@router.post("/upload")
async def extension_upload(
    request: Request,
    path: str = Query(
        ...,
        description="Vault path including the filename, e.g. browser/selection-2026-10-28.txt",
    ),
    mime_type: str = Query("text/plain", description="MIME type recorded for the file."),
    tier: str = Query("IMPORTANT", description="Storage tier (CRITICAL/IMPORTANT/DISPOSABLE)."),
) -> dict:
    """Store raw request bytes as one encrypted vault file.

    Contract (what the extension sends): POST with the file bytes as the body
    and no Content-Type gymnastics; ``path`` is the full destination including
    the filename -- the last component becomes the file name, everything before
    it the directory.  An empty body is a 400; a locked vault is a 401 with a
    JSON ``detail`` the extension surfaces in its notification.
    """
    body = await request.body()
    if not body:
        raise HTTPException(status_code=400, detail="Empty request body; nothing to upload.")

    # Check the trailing slash on the *raw* value; stripping first would make
    # a directory-only path like "browser/" silently become a file named "browser".
    raw = str(path).strip().replace("\\", "/")
    if not raw or raw.endswith("/"):
        raise HTTPException(
            status_code=400,
            detail="path must end with a filename, e.g. browser/selection.txt",
        )
    normalised = raw.strip("/")
    filename = normalised.rsplit("/", 1)[-1]
    directory = "/" + normalised.rsplit("/", 1)[0] if "/" in normalised else "/"
    if not filename:
        raise HTTPException(status_code=400, detail="path must include a filename.")

    try:
        return await files_service.upload_stream(
            io.BytesIO(body),
            filename,
            mime_type or "application/octet-stream",
            tier or "IMPORTANT",
            directory,
        )
    except Exception as exc:
        raise _http_error(exc)
