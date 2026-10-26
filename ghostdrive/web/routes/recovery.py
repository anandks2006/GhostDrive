"""
recovery.py -- Threshold recovery (Shamir 3-of-5 key shares): export, status,
and combine/restore endpoints.

The export endpoint returns the share *texts* once for browser download (the
server never persists shares); the combine endpoint restores a keystore from
pasted shares exactly like seed-phrase restore, then opens the database.
"""

import logging
from typing import List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ghostdrive.crypto.keystore import KeystoreManager
from ghostdrive.crypto.shamir import DEFAULT_THRESHOLD, DEFAULT_TOTAL_SHARES, text_to_share
from ghostdrive.exceptions import CryptoError
from ghostdrive.services import recovery_kit
from ghostdrive.web.state import state

logger = logging.getLogger("ghostdrive_web.recovery")

router = APIRouter(prefix="/api/recovery", tags=["recovery"])


class KitExportRequest(BaseModel):
    threshold: int = Field(DEFAULT_THRESHOLD, ge=2, le=255)
    total: int = Field(DEFAULT_TOTAL_SHARES, ge=2, le=255)
    label: str = ""


class KitCombineRequest(BaseModel):
    shares: List[str] = Field(..., min_length=1)
    passphrase: str


def _require_km() -> KeystoreManager:
    if state.km is None or not state.km.is_unlocked:
        raise HTTPException(status_code=401, detail="Keystore is locked.")
    return state.km


@router.get("/status")
def recovery_status() -> dict:
    """Threshold-recovery status (non-secret)."""
    km = state.km
    unlocked = km is not None and km.is_unlocked
    return {
        "available": True,
        "unlocked": unlocked,
        "threshold": DEFAULT_THRESHOLD,
        "total": DEFAULT_TOTAL_SHARES,
        "seed_backup_confirmed": bool(state.settings.get("seed_backup_confirmed")),
        "offline_tool": "python -m ghostdrive.cli.recovery_tool",
    }


@router.post("/kit/export")
def export_kit(req: KitExportRequest) -> dict:
    """
    Split the unlocked Master Key into ``total`` shares and return them as
    transcribed texts for one-time download. Nothing is written server-side.
    """
    km = _require_km()
    if req.total > 255 or req.threshold > req.total:
        raise HTTPException(status_code=400, detail="Require 2 <= threshold <= total <= 255.")
    if req.threshold < 2:
        raise HTTPException(status_code=400, detail="Threshold must be at least 2.")

    from ghostdrive.crypto.shamir import secret_commitment, share_to_text, split_secret

    try:
        shares = split_secret(bytes(km.master_key), threshold=req.threshold, total=req.total)
    except CryptoError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    import time
    import uuid

    manifest = {
        "format": recovery_kit.KIT_FORMAT,
        "version": recovery_kit.KIT_VERSION,
        "kit_id": uuid.uuid4().hex,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "label": req.label.strip(),
        "threshold": req.threshold,
        "total": req.total,
        "commitment": secret_commitment(bytes(km.master_key)),
    }
    return {
        "status": "success",
        "manifest": manifest,
        "shares": [share_to_text(s) for s in shares],
        "filenames": [
            f"ghostdrive-share-{i}-of-{req.total}.gdshare"
            for i in range(1, req.total + 1)
        ],
        "download_hint": (
            f"Store each share in a different secure location. "
            f"Any {req.threshold} of {req.total} restore your vault."
        ),
    }


@router.post("/kit/preview")
def preview_shares(req: dict) -> dict:
    """Validate pasted shares and report threshold progress (no secret computed)."""
    raw = req.get("shares") or []
    if not isinstance(raw, list) or not raw:
        raise HTTPException(status_code=400, detail="At least one share is required.")
    shares = []
    errors = []
    for i, text in enumerate(raw, start=1):
        try:
            shares.append(text_to_share(text))
        except CryptoError as exc:
            errors.append(f"Share #{i}: {exc}")
    summary = recovery_kit.share_summary(shares) if shares else None
    ready = bool(shares) and summary["provided"] >= summary["threshold"]
    return {
        "status": "success",
        "valid": len(errors) == 0,
        "errors": errors,
        "summary": summary,
        "ready": ready and not errors,
        "missing": max(0, (summary["threshold"] or 0) - (summary["provided"] or 0))
        if summary
        else None,
    }


@router.post("/kit/combine")
def combine_kit(req: KitCombineRequest) -> dict:
    """
    Reconstruct the Master Key from >= threshold pasted shares and rebuild
    ``keystore.json`` with a new passphrase (same flow as seed restore).
    """
    if not req.passphrase:
        raise HTTPException(status_code=400, detail="New passphrase is required.")
    if state.keystore_path.exists() and state.km is not None and state.km.is_unlocked:
        raise HTTPException(
            status_code=409,
            detail="Vault is already unlocked. Lock it before restoring from shares.",
        )

    shares = []
    for i, text in enumerate(req.shares, start=1):
        try:
            shares.append(text_to_share(text))
        except CryptoError as exc:
            raise HTTPException(status_code=400, detail=f"Share #{i}: {exc}")

    try:
        secret = recovery_kit.combine_recovery_kit(shares)
    except recovery_kit.RecoveryKitError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    try:
        # restore_keystore_from_key returns the unlocked manager — use it.
        km = recovery_kit.restore_keystore_from_key(
            secret,
            state.keystore_path,
            req.passphrase.encode("utf-8"),
        )
    except recovery_kit.RecoveryKitError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    finally:
        # Never leave a raw Master Key reference hanging around on failure.
        del secret

    from ghostdrive.web.routes.auth import _open_db

    try:
        _open_db(km)
    except Exception as exc:
        logger.error("DB open after share restore failed: %s", exc)
        raise HTTPException(
            status_code=500,
            detail=f"Keystore restored but database failed to open: {exc}",
        )
    state.km = km

    return {
        "status": "success",
        "message": "Vault restored from key shares and unlocked.",
    }
