"""
sharing.py -- Shared media, public links generator, access expiration, and link revocation API.

Also serves the zero-knowledge envelope flow: ``POST /api/sharing/envelope``
creates an envelope link, ``GET /e/{token}`` renders the recipient page, and
``/api/public/envelope/{token}[/blob]`` hand the browser the ciphertext it
decrypts locally with WebCrypto (see services/sharing.py for the layout).
"""

import html
import logging
from typing import Optional
from urllib.parse import quote

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel

from ghostdrive.services import sharing as sharing_service
from ghostdrive.services import files as files_service

logger = logging.getLogger("ghostdrive_web.sharing")

router = APIRouter(prefix="/api/sharing", tags=["sharing"])
public_router = APIRouter(tags=["public"])


class CreateShareLinkRequest(BaseModel):
    file_id: str
    recipient_alias: Optional[str] = "public"
    ttl_hours: int = 72
    require_passcode: bool = False
    passcode: Optional[str] = None
    max_downloads: Optional[int] = None


class CreateEnvelopeLinkRequest(BaseModel):
    file_id: str
    ttl_hours: int = 72
    max_downloads: Optional[int] = None
    passphrase: Optional[str] = None


def _http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, FileNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, ValueError):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, RuntimeError) and "locked" in str(exc).lower():
        return HTTPException(status_code=401, detail=str(exc))
    logger.exception("Sharing operation failed: %s", exc)
    return HTTPException(status_code=500, detail=str(exc))


def _envelope_error(exc: Exception) -> HTTPException:
    """Envelope endpoints map the shared link errors to 404/403/401.

    ``_http_error`` would turn PermissionError (expired/revoked/limit) into a
    500, which is wrong for a public recipient-facing endpoint, so the
    envelope flow gets its own mapping.
    """
    if isinstance(exc, FileNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, PermissionError):
        # Same messages the classic /s/ page shows: expired / revoked / limit.
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, RuntimeError) and "locked" in str(exc).lower():
        return HTTPException(status_code=401, detail=str(exc))
    logger.exception("Envelope share operation failed: %s", exc)
    return HTTPException(status_code=500, detail=str(exc))


@router.get("/links")
def list_shared_links(request: Request) -> dict:
    try:
        result = sharing_service.list_links()
        base = str(request.base_url).rstrip("/")
        for link in result["shared_links"]:
            link["url"] = f"{base}/s/{link['token']}"
        return result
    except Exception as exc:
        raise _http_error(exc)


@router.post("/create")
def create_share_link(req: CreateShareLinkRequest, request: Request) -> dict:
    try:
        link = sharing_service.create_link(
            req.file_id,
            req.recipient_alias or "public",
            req.ttl_hours,
            req.require_passcode,
            req.passcode,
            req.max_downloads,
        )
        link["url"] = f"{str(request.base_url).rstrip('/')}/s/{link['token']}"
        link["message"] = "Share link created successfully."
        return link
    except Exception as exc:
        raise _http_error(exc)


@router.post("/envelope")
async def create_envelope_share(req: CreateEnvelopeLinkRequest, request: Request) -> dict:
    """Create a zero-knowledge envelope link (decryption happens in the browser)."""
    try:
        link = await sharing_service.create_envelope_link(
            req.file_id,
            ttl_hours=req.ttl_hours,
            max_downloads=req.max_downloads,
            passphrase=req.passphrase,
        )
        base = str(request.base_url).rstrip("/")
        link["url"] = f"{base}/e/{link['token']}"
        link["message"] = (
            "Envelope link created. The passphrase was shown only in this "
            "response — relay it out-of-band; it is never stored."
        )
        return link
    except Exception as exc:
        raise _http_error(exc)


@router.delete("/revoke/{link_id}")
def revoke_share_link(link_id: str) -> dict:
    try:
        return sharing_service.revoke_link(link_id)
    except Exception as exc:
        raise _http_error(exc)


def _page(message: str, form_token: Optional[str] = None) -> HTMLResponse:
    form = ""
    if form_token:
        token = html.escape(form_token, quote=True)
        form = f"""
        <form method="post" action="/s/{token}">
          <input name="passcode" type="password" placeholder="Share passcode" autofocus/>
          <button type="submit">Download</button>
        </form>"""
    body = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>GhostDrive Share</title>
<style>
 body {{ background:#0b0f19; color:#e5e7eb; font-family:system-ui,sans-serif;
        display:flex; align-items:center; justify-content:center; height:100vh; margin:0; }}
 .card {{ background:#111827; border:1px solid #1f2937; border-radius:14px; padding:32px 40px;
          max-width:440px; text-align:center; }}
 input {{ padding:10px 12px; border-radius:8px; border:1px solid #374151; background:#0b0f19;
          color:#e5e7eb; margin-right:8px; }}
 button {{ padding:10px 16px; border-radius:8px; border:0; background:#8b5cf6; color:white;
           cursor:pointer; }}
 code {{ color:#a78bfa; }}
</style></head>
<body><div class="card"><h2>GhostDrive</h2><p>{message}</p>{form}</div></body></html>"""
    return HTMLResponse(body)


@public_router.get("/s/{token}", response_class=HTMLResponse)
async def public_share_page(token: str, passcode: Optional[str] = None):
    try:
        row = sharing_service.open_link(token, passcode)
    except FileNotFoundError:
        return _page("This share link does not exist.")
    except PermissionError as exc:
        message = html.escape(str(exc))
        need_passcode = "passcode" in message.lower() and "required" in message.lower()
        return _page(message, token if need_passcode else None)

    sharing_service.register_download(token)
    return StreamingResponse(
        files_service.iter_file(row["file_id"]),
        media_type=row["mime_type"] or "application/octet-stream",
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{quote(row['filename'])}"
        },
    )


@public_router.post("/s/{token}", response_class=HTMLResponse)
async def public_share_download(token: str, passcode: str = Form("")):
    try:
        row = sharing_service.open_link(token, passcode)
    except FileNotFoundError:
        return _page("This share link does not exist.")
    except PermissionError as exc:
        message = html.escape(str(exc))
        need_passcode = "passcode" in message.lower() and "required" in message.lower()
        return _page(message, token if need_passcode else None)

    sharing_service.register_download(token)
    return StreamingResponse(
        files_service.iter_file(row["file_id"]),
        media_type=row["mime_type"] or "application/octet-stream",
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{quote(row['filename'])}"
        },
    )


# ─── Zero-knowledge envelope links (/e/{token}) ──────────────────────────────

def _envelope_page(token: str, info: dict) -> HTMLResponse:
    """Recipient page: passphrase field + receive.js decrypt/download flow.

    Deliberately contains NO secrets — only the token (already in the URL)
    and public file metadata.  The passphrase is typed by the recipient and
    never leaves the browser.
    """
    filename = html.escape(info["filename"], quote=True)
    token_esc = html.escape(token, quote=True)
    size = info["file_size"]
    body = f"""<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>GhostDrive Secure Share</title>
<style>
 body {{ background:#0b0e0b; color:#eef3ea; font-family:system-ui,sans-serif; margin:0;
        display:flex; align-items:center; justify-content:center; min-height:100vh; }}
 .card {{ background:#101410; border:1px solid #242b23; border-radius:16px; padding:36px 40px;
          max-width:460px; width:92%; text-align:center; box-shadow:0 24px 80px rgba(0,0,0,.35); }}
 h1 {{ font-size:20px; margin:0 0 6px; letter-spacing:.02em; }}
 .muted {{ color:#98a294; font-size:13px; margin:0 0 20px; word-break:break-all; }}
 form {{ display:flex; gap:8px; }}
 input {{ flex:1; min-width:0; padding:11px 13px; border-radius:10px; border:1px solid #242b23;
          background:#080a08; color:#eef3ea; font-size:14px; }}
 input:focus {{ outline:none; border-color:#c4f56a; }}
 button {{ padding:11px 18px; border-radius:10px; border:0; background:#c4f56a; color:#101504;
           font-weight:600; cursor:pointer; }}
 button:disabled {{ opacity:.6; cursor:wait; }}
 #gd-status {{ min-height:34px; font-size:13px; color:#98a294; margin-top:16px; line-height:1.45; }}
 #gd-status.error {{ color:#ff7d7d; }}
 #gd-status.ok {{ color:#7ce3b1; }}
 code {{ color:#c4f56a; }}
</style></head>
<body data-token="{token_esc}">
 <div class="card">
  <h1>GhostDrive</h1>
  <p class="muted"><code>{filename}</code> &middot; {size} bytes &middot; end-to-end encrypted</p>
  <form id="gd-unlock" autocomplete="off">
    <input id="gd-passphrase" type="password" placeholder="Share passphrase" autofocus autocomplete="off"/>
    <button id="gd-decrypt" type="submit">Decrypt</button>
  </form>
  <p id="gd-status" role="status">Decryption happens in this browser; the server never sees your passphrase.</p>
 </div>
 <script src="/static/js/receive.js" defer></script>
</body></html>"""
    return HTMLResponse(body)


@public_router.get("/e/{token}", response_class=HTMLResponse)
def envelope_share_page(token: str):
    """Zero-knowledge share page: passphrase field + client-side decryption."""
    try:
        info = sharing_service.verify_envelope_access(token)
    except FileNotFoundError:
        return _page("This share link does not exist.")
    except PermissionError as exc:
        return _page(html.escape(str(exc)))
    return _envelope_page(token, info)


@public_router.get("/api/public/envelope/{token}")
def public_envelope_header(token: str) -> dict:
    """Canonical envelope header for the browser (wrapped key only — no plaintext)."""
    try:
        info = sharing_service.verify_envelope_access(token)
    except Exception as exc:
        raise _envelope_error(exc)
    header = dict(info["header"])
    header["envelope_url"] = f"/api/public/envelope/{token}/blob"
    return header


@public_router.get("/api/public/envelope/{token}/blob")
async def public_envelope_blob(token: str):
    """Stream the stored envelope ciphertext — still fully encrypted."""
    try:
        info = sharing_service.verify_envelope_access(token)
        envelope = await sharing_service.load_envelope_blob(info)
    except Exception as exc:
        raise _envelope_error(exc)
    # Count the download only after the ciphertext was actually produced, so
    # max_downloads behaves exactly like the classic /s/{token} flow.  The
    # existing download routes do not throttle, so neither does this one.
    sharing_service.register_download(token)
    return StreamingResponse(
        iter([envelope]),
        media_type="application/octet-stream",
        headers={
            "Content-Length": str(len(envelope)),
            "Content-Disposition": (
                f"attachment; filename*=UTF-8''{quote(info['filename'])}"
            ),
            "Cache-Control": "no-store",
        },
    )
