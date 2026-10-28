"""Cloud import: pull files from Dropbox / Google Drive / OneDrive into the vault.

The point is removing switching cost: a file sitting in someone else's cloud is
one paste away from being a GhostDrive file -- chunked, encrypted, erasure
coded and committed through the exact same ``files_service.upload_stream``
pipeline a local upload uses. Once imported, the cloud copy is irrelevant:
the vault copy is the real one.

OAuth is deliberately NOT automated. Desktop OAuth flows require a client id
and a browser redirect URI we cannot secure in a local app, so this module is
"bring your own token": the user creates an access token in their provider's
developer console (or pastes one from an existing session) and pastes it here.
The app never sees your cloud password. Tokens are stored in the OS credential
store (``ghostdrive.crypto.credential_store`` -- AES-256-GCM blob inside the
OS Keyring, keyed as ``cloud_<provider>_token``), NOT in the SQL settings
table, so they never sit in plaintext next to the index. Tokens are used only
against the provider's own API.

Transport honesty: imported bytes travel from the provider to us over the
provider's TLS (we do not -- and cannot -- add a second layer in transit); the
moment they land here they go through the encrypting pipeline and the
plaintext exists only in a short-lived temp spool file. All provider HTTP
goes through the module-level ``_http`` helper (stdlib ``urllib.request``)
so tests can monkeypatch a single seam and never touch the network.

Provider API shapes (the real endpoints; exercised in tests only via a mocked
transport):

* Dropbox:    ``POST https://api.dropboxapi.com/2/files/list_folder`` (or
              ``/2/files/list_folder_continue`` with a cursor) and
              ``POST https://content.dropboxapi.com/2/files/download``,
              ``Authorization: Bearer <token>``.
* Google Drive: ``GET https://www.googleapis.com/drive/v3/files`` (folder
              filter via ``q='<folder_id>' in parents``; cursor = pageToken)
              and ``GET https://www.googleapis.com/drive/v3/files/{id}?alt=media``,
              ``Authorization: Bearer <token>``. "folder" means a Drive folder
              ID, not a path.
* OneDrive:   ``GET https://graph.microsoft.com/v1.0/me/drive/root/children``
              (or ``/me/drive/root:/{folder}:/children``; cursor = the absolute
              ``@odata.nextLink``) and ``GET https://graph.microsoft.com/v1.0/me/drive/items/{id}/content``,
              ``Authorization: Bearer <token>``.

Size limit: downloads are buffered in memory, capped at MAX_IMPORT_BYTES
(100 MiB) per file -- an honest bound for a paste-a-token importer; larger
files should be moved with a direct backend (S3/NAS) instead.
"""

from __future__ import annotations

import asyncio
import io
import json
import logging
import mimetypes
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Optional

from ghostdrive.services import files as files_service

logger = logging.getLogger("ghostdrive.services.cloud_import")

# ── Settings keys ─────────────────────────────────────────────────────────────
SETTING_HISTORY = "cloud_import_history"   # JSON list of import summaries, newest first

#: Tokens are NOT stored in settings -- see the credential_store note above.
_TOKEN_KEY_TEMPLATE = "cloud_{provider}_token"

HISTORY_CAP = 20            # import summaries kept in settings
MAX_IMPORT_BYTES = 100 * 1024 * 1024   # per-file download cap (buffered in memory)
MAX_IMPORT_PATHS = 500      # route-level cap on one import request
MAX_LIST_PAGES = 40         # path resolution walks at most this many list pages
LIST_PAGE_LIMIT = 100       # provider page size (small keeps validate_token cheap)
DEFAULT_TIER = "IMPORTANT"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── HTTP seam ─────────────────────────────────────────────────────────────────

def _http(
    method: str,
    url: str,
    headers: Optional[dict] = None,
    body: Optional[bytes] = None,
    timeout: int = 30,
) -> tuple[int, bytes]:
    """The single HTTP entry point for this module (stdlib urllib only).

    Returns ``(status_code, response_body_bytes)``; HTTP error statuses are
    returned, not raised, so callers can surface the provider's own error
    body. Network-level failures raise ``urllib.error.URLError``.

    This is the test seam: tests monkeypatch ``cloud_import._http`` with a
    fake transport, so no test ever opens a real socket.
    """
    request = urllib.request.Request(url, data=body, headers=dict(headers or {}), method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - URLs are provider-built constants
            return int(response.getcode()), response.read()
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read()


def _error_message(body: bytes) -> str:
    """Best-effort extraction of a provider error string from a response body."""
    try:
        data = json.loads(body.decode("utf-8", "replace"))
    except (ValueError, AttributeError):
        return (body or b"").decode("utf-8", "replace")[:300] or "no response body"
    if isinstance(data, dict):
        # Dropbox: {"error_summary": "..."}; Graph: {"error": {"message": ...}};
        # Drive: {"error": {"message": ...}}.
        summary = data.get("error_summary")
        if summary:
            return str(summary)[:300]
        err = data.get("error")
        if isinstance(err, dict) and err.get("message"):
            return str(err["message"])[:300]
        if isinstance(err, str):
            return err[:300]
    return json.dumps(data)[:300]


def _expect_json(name: str, status: int, body: bytes) -> dict:
    if not 200 <= status < 300:
        raise ValueError(f"{name} API error {status}: {_error_message(body)}")
    try:
        data = json.loads(body.decode("utf-8"))
    except ValueError:
        raise RuntimeError(f"{name} API returned a malformed (non-JSON) response.")
    if not isinstance(data, dict):
        raise RuntimeError(f"{name} API returned an unexpected JSON payload.")
    return data


def _expect_bytes(name: str, status: int, body: bytes) -> bytes:
    if not 200 <= status < 300:
        raise ValueError(f"{name} download failed {status}: {_error_message(body)}")
    return body


def _cleanse_text(value: Optional[str], what: str) -> str:
    """Normalise a provider path/folder string; reject control chars and '..'."""
    text = str(value or "").strip().replace("\\", "/")
    if any(ord(c) < 32 for c in text):
        raise ValueError(f"{what} contains control characters.")
    segments = [seg for seg in text.split("/") if seg not in ("", ".")]
    if any(seg == ".." for seg in segments):
        raise ValueError(f"{what} cannot contain '..' traversal.")
    return "/".join(segments)


def _safe_vault_dir(dest: Optional[str]) -> str:
    """Normalise a user-supplied vault destination directory string.

    ``dest`` is joined as a *vault* path string (never a filesystem path), but
    empties and control characters are still rejected and '..' traversal is
    refused outright. ``None`` means the vault root.
    """
    if dest is None:
        return "/"
    text = _cleanse_text(dest, "Destination directory")
    if not str(dest).strip():
        raise ValueError("Destination directory cannot be empty.")
    return "/" + text if text else "/"


def _basename(path: Optional[str]) -> str:
    return str(path or "").replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]


# ── Provider abstraction ──────────────────────────────────────────────────────

class _ProviderBase:
    """Common interface every cloud provider implementation satisfies."""

    name: str = ""

    def list_files(self, token: str, *, folder: Optional[str] = None, cursor: Optional[str] = None) -> dict:
        """First page (or cursor page) of a folder listing.

        Returns ``{"files": [{"path", "name", "size", "modified_at", "id"}],
        "next_cursor": str | None}``. Directories are never included -- this
        importer moves files, not folder trees.
        """
        raise NotImplementedError

    def download(self, token: str, file_id_or_path: str) -> bytes:
        """Download one remote file's full content (buffered; see size cap)."""
        raise NotImplementedError


class DropboxProvider(_ProviderBase):
    """Dropbox HTTP API v2 (list_folder + download)."""

    name = "dropbox"
    API = "https://api.dropboxapi.com"
    CONTENT = "https://content.dropboxapi.com"

    def list_files(self, token, *, folder=None, cursor=None):
        headers = {"Authorization": f"Bearer {token}"}
        if cursor:
            url = f"{self.API}/2/files/list_folder_continue"
            payload = {"cursor": cursor}
        else:
            url = f"{self.API}/2/files/list_folder"
            # folder "" is the Dropbox root; a leading slash is optional.
            payload = {"path": _cleanse_text(folder, "Folder path") if folder else "", "limit": LIST_PAGE_LIMIT}
        status, body = _http(
            "POST", url,
            headers={**headers, "Content-Type": "application/json"},
            body=json.dumps(payload).encode("utf-8"),
        )
        data = _expect_json(self.name, status, body)
        files = []
        for entry in data.get("entries", []):
            if entry.get(".tag") != "file":
                continue  # folders are not importable
            path = entry.get("path_display") or entry.get("path_lower") or ""
            files.append({
                "path": path,
                "name": entry.get("name") or _basename(path),
                "size": int(entry.get("size") or 0),
                "modified_at": entry.get("server_modified"),
                "id": entry.get("id") or path,
            })
        return {"files": files, "next_cursor": data.get("cursor") if data.get("has_more") else None}

    def download(self, token, file_id_or_path):
        # Dropbox accepts either a path or an "id:..." handle in the Arg header.
        status, body = _http(
            "POST", f"{self.CONTENT}/2/files/download",
            headers={
                "Authorization": f"Bearer {token}",
                "Dropbox-API-Arg": json.dumps({"path": str(file_id_or_path)}),
            },
        )
        return _expect_bytes(self.name, status, body)


class GoogleDriveProvider(_ProviderBase):
    """Google Drive v3 REST API (files.list + files.get?alt=media).

    The ``folder`` argument is a Drive *folder ID* (not a path); entries are
    reported with a synthetic ``/<name>`` path built from the listing.
    """

    name = "gdrive"
    API = "https://www.googleapis.com/drive/v3"
    FOLDER_MIME = "application/vnd.google-apps.folder"

    def _folder(self, folder: Optional[str]) -> str:
        text = str(folder or "").strip()
        if text and any(ord(c) < 32 for c in text):
            raise ValueError("Folder id contains control characters.")
        return text

    def list_files(self, token, *, folder=None, cursor=None):
        params: dict[str, str] = {
            "pageSize": str(LIST_PAGE_LIMIT),
            "fields": "nextPageToken,files(id,name,size,mimeType,modifiedTime)",
        }
        parent = self._folder(folder)
        if parent:
            params["q"] = f"'{parent}' in parents"
        if cursor:
            params["pageToken"] = cursor
        url = f"{self.API}/files?{urllib.parse.urlencode(params)}"
        status, body = _http("GET", url, headers={"Authorization": f"Bearer {token}"})
        data = _expect_json(self.name, status, body)
        prefix = f"/{parent.strip('/')}" if parent else ""
        files = []
        for entry in data.get("files", []):
            if entry.get("mimeType") == self.FOLDER_MIME:
                continue  # folders are not importable
            name = entry.get("name") or ""
            files.append({
                "path": f"{prefix}/{name}",
                "name": name,
                "size": int(entry.get("size") or 0),
                "modified_at": entry.get("modifiedTime"),
                "id": entry.get("id") or name,
            })
        return {"files": files, "next_cursor": data.get("nextPageToken") or None}

    def download(self, token, file_id_or_path):
        quoted = urllib.parse.quote(str(file_id_or_path), safe="")
        status, body = _http(
            "GET", f"{self.API}/files/{quoted}?alt=media",
            headers={"Authorization": f"Bearer {token}"},
        )
        return _expect_bytes(self.name, status, body)


class OneDriveProvider(_ProviderBase):
    """Microsoft Graph drive API (children listing + /content download).

    The ``folder`` argument is a drive-relative path such as ``/Documents``.
    The pagination cursor is Graph's absolute ``@odata.nextLink`` URL, stored
    verbatim and passed back as-is.
    """

    name = "onedrive"
    API = "https://graph.microsoft.com/v1.0"

    def list_files(self, token, *, folder=None, cursor=None):
        if cursor:
            url = str(cursor)
        elif folder:
            rel = _cleanse_text(folder, "Folder path")
            url = f"{self.API}/me/drive/root:/{rel}:/children?$top={LIST_PAGE_LIMIT}"
        else:
            url = f"{self.API}/me/drive/root/children?$top={LIST_PAGE_LIMIT}"
        status, body = _http("GET", url, headers={"Authorization": f"Bearer {token}"})
        data = _expect_json(self.name, status, body)
        files = []
        for entry in data.get("value", []):
            if "folder" in entry:
                continue  # folders are not importable
            name = entry.get("name") or ""
            files.append({
                "path": f"/{name}",
                "name": name,
                "size": int(entry.get("size") or 0),
                "modified_at": entry.get("lastModifiedDateTime"),
                "id": entry.get("id") or name,
            })
        return {"files": files, "next_cursor": data.get("@odata.nextLink") or None}

    def download(self, token, file_id_or_path):
        quoted = urllib.parse.quote(str(file_id_or_path), safe="")
        status, body = _http(
            "GET", f"{self.API}/me/drive/items/{quoted}/content",
            headers={"Authorization": f"Bearer {token}"},
        )
        return _expect_bytes(self.name, status, body)


#: The provider registry every entry point resolves names against.
PROVIDERS: dict[str, _ProviderBase] = {
    "dropbox": DropboxProvider(),
    "gdrive": GoogleDriveProvider(),
    "onedrive": OneDriveProvider(),
}


def _provider(name: str) -> _ProviderBase:
    prov = PROVIDERS.get(str(name or "").strip().lower())
    if prov is None:
        raise ValueError(f"Unknown provider {name!r}; expected one of {sorted(PROVIDERS)}.")
    return prov


# ── Token storage (OS credential store) ───────────────────────────────────────

def _token_key(provider: str) -> str:
    return _TOKEN_KEY_TEMPLATE.format(provider=provider)


def _store_token(provider: str, token: str) -> None:
    from ghostdrive.crypto.credential_store import credential_store

    credential_store.store(_token_key(provider), token)


def _load_token(provider: str) -> Optional[str]:
    from ghostdrive.crypto.credential_store import credential_store

    try:
        return credential_store.load(_token_key(provider))
    except Exception as exc:  # keyring backend missing/broken: report "not connected"
        logger.warning("Could not read cloud token for %s: %s", provider, exc)
        return None


def _delete_token(provider: str) -> None:
    from ghostdrive.crypto.credential_store import credential_store

    credential_store.delete(_token_key(provider))


def _mask(token: str) -> str:
    """Display hint for a stored token: first 4 + … + last 4, never the token."""
    if len(token) >= 8:
        return f"{token[:4]}…{token[-4:]}"
    return "…"


def _require_token(provider: str) -> str:
    token = _load_token(provider)
    if not token:
        raise ValueError(f"{provider} is not connected (no stored token).")
    return token


# ── Public operations ─────────────────────────────────────────────────────────

def validate_token(provider: str, token: str) -> dict:
    """Cheap authenticated probe: list the first (small) page with the token.

    Raises ValueError carrying the provider's own error message when the
    token is rejected (401/403 etc.) so the route can surface it verbatim.
    """
    prov = _provider(provider)
    token = (token or "").strip()
    if not token:
        raise ValueError("Token cannot be empty.")
    try:
        prov.list_files(token)
    except ValueError:
        raise  # the provider already surfaced a faithful error
    except Exception as exc:
        raise ValueError(f"{prov.name} token validation failed: {exc}")
    return {"provider": prov.name, "validated": True}


def connect(db, provider: str, token: str) -> dict:
    """Validate the pasted token, then persist it in the OS credential store.

    ``db`` is accepted for interface symmetry with the other entry points;
    tokens live in the keyring, not the database.
    """
    prov = _provider(provider)
    validate_token(prov.name, token)
    _store_token(prov.name, (token or "").strip())
    logger.info("Cloud provider %s connected (token stored in OS credential store).", prov.name)
    return {"provider": prov.name, "connected": True, "validated": True, "token_hint": _mask((token or "").strip())}


def disconnect(db, provider: str) -> dict:
    """Forget the stored token for one provider. Idempotent."""
    prov = _provider(provider)
    _delete_token(prov.name)
    return {"provider": prov.name, "connected": False}


def connection_status(db) -> dict:
    """Per-provider connection state. ``validated`` stays None: validation is
    only ever proven live (on connect / list / import) and is not persisted."""
    status: dict[str, dict] = {}
    for name in PROVIDERS:
        token = _load_token(name)
        status[name] = {
            "connected": bool(token),
            "token_hint": _mask(token) if token else None,
            "validated": None,
        }
    return status


async def list_remote(db, provider: str, *, folder: Optional[str] = None) -> dict:
    """First page of a provider folder listing using the stored token."""
    prov = _provider(provider)
    token = _require_token(prov.name)
    return await asyncio.to_thread(prov.list_files, token, folder=folder)


def resolve_remote_paths(db, provider: str, paths: list[str], *, max_pages: int = MAX_LIST_PAGES) -> list[dict]:
    """Re-resolve requested remote paths against a fresh provider listing.

    The import route takes a plain list of paths (not opaque file dicts from
    the UI) and re-lists the provider here, so what gets imported is whatever
    the provider currently says lives at that path -- the UI cannot smuggle
    in arbitrary ids. Unknown paths come back carrying an ``error`` marker so
    ``import_many`` counts them as failed without aborting the batch.
    """
    prov = _provider(provider)
    token = _require_token(prov.name)

    def _key(p: str) -> str:
        return str(p).replace("\\", "/").rstrip("/")

    wanted = {_key(p) for p in paths if str(p or "").strip()}
    found: dict[str, dict] = {}
    cursor: Optional[str] = None
    pages = 0
    while (wanted - found.keys()) and pages < max_pages:
        page = prov.list_files(token, cursor=cursor)
        pages += 1
        for entry in page.get("files", []):
            key = _key(entry.get("path", ""))
            if key in wanted:
                found[key] = entry
        cursor = page.get("next_cursor")
        if not cursor:
            break

    resolved: list[dict] = []
    for raw in paths:
        entry = found.get(_key(raw))
        if entry is not None:
            resolved.append(dict(entry))
        else:
            resolved.append({
                "path": raw,
                "name": _basename(raw),
                "size": 0,
                "id": None,
                "modified_at": None,
                "error": "path not found in remote listing",
            })
    return resolved


async def import_file(
    db,
    provider: str,
    remote: dict,
    *,
    dest_path: Optional[str] = None,
    now: Optional[str] = None,
) -> dict:
    """Download one remote entry and push it through the encrypting pipeline.

    ``remote`` is a ``list_files`` entry (``path``/``name``/``size``/``id``).
    The download is fed to ``files_service.upload_stream`` -- the very same
    service path a local web/CLI upload uses -- so the file lands chunked,
    encrypted and erasure coded exactly like any other vault file.

    Provenance: ``upload_stream`` accepts a MIME type (passed through when the
    provider supplies one) but exposes no free-form metadata field, so the
    provider/origin of an import is recorded in the ``cloud_import_history``
    setting rather than on the file row itself.

    ``now`` is an optional caller-supplied timestamp for history correlation;
    the vault row's own created/modified times are set by the upload pipeline.
    """
    prov = _provider(provider)
    token = _require_token(prov.name)
    if remote.get("error"):
        raise ValueError(str(remote["error"]))

    name = str(remote.get("name") or "").strip() or _basename(remote.get("path"))
    if not name:
        raise ValueError("Remote entry has no usable file name.")
    reference = str(remote.get("id") or remote.get("path") or "").strip()
    if not reference:
        raise ValueError("Remote entry has no id or path to download by.")

    data = await asyncio.to_thread(prov.download, token, reference)
    if len(data) > MAX_IMPORT_BYTES:
        raise ValueError(
            f"Remote file {name!r} is {len(data)} bytes; per-file import cap is "
            f"{MAX_IMPORT_BYTES // (1024 * 1024)} MiB."
        )

    dest_dir = _safe_vault_dir(dest_path)
    mime = remote.get("mime") or mimetypes.guess_type(name)[0]  # None -> pipeline guesses
    result = await files_service.upload_stream(io.BytesIO(data), name, mime, DEFAULT_TIER, dest_dir)
    file_row = result.get("file") or {}
    logger.info("Imported %s from %s as file %s", name, prov.name, result.get("file_id"))
    return {
        "file_id": result["file_id"],
        "name": name,
        "size": len(data),
        "provider": prov.name,
        "path": file_row.get("path") or f"{dest_dir.rstrip('/')}/{name}",
    }


async def import_many(
    db,
    provider: str,
    files: list[dict],
    *,
    dest_dir: Optional[str] = None,
    now: Optional[str] = None,
) -> dict:
    """Import a batch of remote entries sequentially (concurrency = 1).

    Simple and honest: one file at a time, in order. A failing download or
    upload is collected into its per-file result and never aborts the rest of
    the batch. Entries carrying an ``error`` marker (from
    ``resolve_remote_paths``) are counted failed without a download attempt.
    """
    prov = _provider(provider)
    _require_token(prov.name)  # fail the whole batch fast when not connected
    dest = _safe_vault_dir(dest_dir)  # fail the whole batch fast on a bad destination

    results: list[dict] = []
    imported = failed = total_bytes = 0
    for entry in files or []:
        label = str(entry.get("path") or entry.get("name") or "")
        if entry.get("error"):
            failed += 1
            results.append({
                "path": label,
                "name": entry.get("name"),
                "provider": prov.name,
                "status": "failed",
                "error": str(entry["error"]),
            })
            continue
        try:
            outcome = await import_file(db, prov.name, entry, dest_path=dest, now=now)
        except Exception as exc:
            logger.warning("Cloud import failed for %s (%s): %s", label, prov.name, exc)
            failed += 1
            results.append({
                "path": label,
                "name": entry.get("name"),
                "provider": prov.name,
                "status": "failed",
                "error": str(exc),
            })
            continue
        imported += 1
        total_bytes += outcome["size"]
        results.append({**outcome, "status": "imported"})

    return {
        "provider": prov.name,
        "imported": imported,
        "failed": failed,
        "results": results,
        "bytes": total_bytes,
    }


# ── Import history ────────────────────────────────────────────────────────────

def import_history(db, limit: int = HISTORY_CAP) -> list[dict]:
    """Newest-first import summaries (settings-backed, capped)."""
    raw = db.get_setting(SETTING_HISTORY, "[]") or "[]"
    try:
        entries = json.loads(raw)
    except ValueError:
        return []
    if not isinstance(entries, list):
        return []
    return [entry for entry in entries if isinstance(entry, dict)][:limit]


def append_import_history(db, summary: dict) -> list[dict]:
    """Prepend one import summary, trimming the settings list to HISTORY_CAP."""
    entries = [summary, *import_history(db)][:HISTORY_CAP]
    with db.transaction():
        db.set_setting(SETTING_HISTORY, json.dumps(entries))
    return entries
