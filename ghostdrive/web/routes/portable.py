"""
portable.py -- Portable vault (.gdvault) export/import HTTP routes.

Export streams a single passphrase-encrypted file to the browser; import
accepts an uploaded file, unpacks the keystore (and optionally replaces the
index) and reopens the vault.
"""

import logging
import tempfile
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field

from ghostdrive.services import portable
from ghostdrive.web.state import state

logger = logging.getLogger("ghostdrive_web.portable")

router = APIRouter(prefix="/api/portable", tags=["portable"])


class PortableExportRequest(BaseModel):
    passphrase: str
    include_index: bool = True
    label: str = ""


def _require_km():
    if state.km is None or not state.km.is_unlocked:
        raise HTTPException(status_code=401, detail="Keystore is locked.")
    return state.km


@router.get("/status")
def portable_status() -> dict:
    return {
        "available": True,
        "unlocked": state.km is not None and state.km.is_unlocked,
        "format": portable.FORMAT,
        "extension": ".gdvault",
    }


@router.post("/export")
def export_portable(req: PortableExportRequest) -> Response:
    """
    Build a ``.gdvault`` archive and stream it as a download.

    The outer envelope is sealed with the supplied passphrase (the vault
    passphrase in normal use) so the file is useless without it.
    """
    _require_km()
    if not req.passphrase:
        raise HTTPException(status_code=400, detail="Passphrase is required.")

    with tempfile.TemporaryDirectory(prefix="gdportable-") as tmp:
        out = Path(tmp) / "ghostdrive-vault.gdvault"
        try:
            result = portable.export_portable_vault(
                out,
                req.passphrase.encode("utf-8"),
                state.keystore_path,
                db=state.db,
                settings=_nonsecret_settings(),
                include_index=req.include_index,
                label=req.label,
            )
        except portable.PortableVaultError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except Exception as exc:
            logger.error("Portable export failed: %s", exc)
            raise HTTPException(status_code=500, detail=f"Export failed: {exc}")
        data = out.read_bytes()

    filename = "ghostdrive-vault.gdvault"
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(data)),
            "X-GhostDrive-Blake3": result["blake3"],
            "X-GhostDrive-Has-Index": "1" if result["has_index"] else "0",
        },
    )


@router.post("/inspect")
async def inspect_portable(file: UploadFile = File(...), passphrase: str = "") -> dict:
    """Validate an uploaded vault and return non-secret metadata."""
    if not passphrase:
        raise HTTPException(status_code=400, detail="Passphrase is required.")
    blob = await file.read()
    with tempfile.TemporaryDirectory(prefix="gdportable-") as tmp:
        path = Path(tmp) / (file.filename or "upload.gdvault")
        path.write_bytes(blob)
        try:
            return portable.inspect_portable_vault(path, passphrase.encode("utf-8"))
        except portable.PortableVaultError as exc:
            raise HTTPException(status_code=400, detail=str(exc))


@router.post("/import")
async def import_portable_endpoint(
    file: UploadFile = File(...),
    passphrase: str = "",
    restore_index: bool = False,
    overwrite: bool = False,
) -> dict:
    """
    Import a ``.gdvault``.

    Always writes the keystore to the app data dir (``overwrite`` required if
    one exists). ``restore_index=True`` additionally replaces the local index
    with the archived snapshot.

    Two phases so a *fresh machine* (no keystore yet) works: unpack the
    keystore first, unlock it to obtain the Master Key, then decrypt the
    snapshot and reopen the database from the imported index.
    """
    if not passphrase:
        raise HTTPException(status_code=400, detail="Passphrase is required.")
    # NOTE: allocate a FRESH bytes object per use — unlock() deliberately
    # zeroes passphrase buffers in place, which would corrupt a reused one.
    blob = await file.read()

    with tempfile.TemporaryDirectory(prefix="gdportable-") as tmp:
        path = Path(tmp) / (file.filename or "upload.gdvault")
        path.write_bytes(blob)

        # Phase 1: unpack the keystore (no key material needed yet).
        try:
            result = portable.import_portable_vault(
                path,
                passphrase.encode("utf-8"),
                state.keystore_path,
                overwrite=True if overwrite else False,
            )
        except portable.PortableVaultError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

        # Phase 2: unlock the imported keystore so snapshot decryption has a key.
        from ghostdrive.crypto.keystore import KeystoreManager
        from ghostdrive.exceptions import AuthenticationError

        km = KeystoreManager(state.keystore_path)
        try:
            km.unlock(passphrase.encode("utf-8"))
        except AuthenticationError:
            raise HTTPException(status_code=401, detail="Incorrect passphrase for the imported keystore.")
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Unlock failed: {exc}")

        if restore_index:
            # Close any live DB before replacing its file on disk.
            if state.db is not None and getattr(state.db, "_conn", None) is not None:
                try:
                    state.db.close()
                except Exception:
                    pass
                state.db = None
            try:
                result = portable.import_portable_vault(
                    path,
                    passphrase.encode("utf-8"),
                    state.keystore_path,
                    index_destination=state.db_path,
                    overwrite=True,
                    master_key=bytes(km.master_key),
                    hkdf_salt=bytes(km.hkdf_salt),
                )
            except portable.PortableVaultError as exc:
                raise HTTPException(status_code=400, detail=str(exc))

    # Reopen from the freshly imported keystore/index.
    from ghostdrive.web.routes.auth import _open_db

    try:
        _open_db(km)
        state.km = km
    except Exception as exc:
        logger.error("Import unpacked but database open failed: %s", exc)
        return {
            "status": "partial",
            "written": result["written"],
            "message": f"Files written but database failed to open: {exc}",
        }

    return {
        "status": "success",
        "written": result["written"],
        "index_restored": bool(restore_index),
        "created_at": result.get("created_at"),
        "message": "Portable vault imported and unlocked.",
    }


def _nonsecret_settings() -> dict:
    """Settings safe to embed: excludes anything credential-like."""
    allowed = (
        "theme", "autostart", "bandwidth_limit_kbps", "scrub_interval_hours",
        "tier_CRITICAL_backends", "tier_IMPORTANT_backends", "tier_DISPOSABLE_backends",
        "pwa_installed",
    )
    return {k: v for k, v in (state.settings or {}).items() if k in allowed}
