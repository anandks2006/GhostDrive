"""
inheritance.py -- Inheritance / dead-man's switch routes.

Status / enable / check-in / disable / manual release / immediate check.
The web server binds to 127.0.0.1 only (see web/server.py), so the status
payload may include the contact list (the UI must show it) without that
leaving the machine via GhostDrive.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ghostdrive.services import inheritance as inheritance_service
from ghostdrive.services.context import require_db

logger = logging.getLogger("ghostdrive_web.inheritance")

router = APIRouter(prefix="/api/inheritance", tags=["inheritance"])


def _http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, FileNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, ValueError):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, RuntimeError) and "locked" in str(exc).lower():
        return HTTPException(status_code=401, detail=str(exc))
    logger.exception("Inheritance operation failed: %s", exc)
    return HTTPException(status_code=500, detail=str(exc))


class ContactInput(BaseModel):
    name: str
    webhook_url: str


class EnableRequest(BaseModel):
    interval_days: int = inheritance_service.DEFAULT_INTERVAL_DAYS
    release_passphrase: str
    contacts: list[ContactInput]


class DisableRequest(BaseModel):
    wipe_package: bool = True


class ReleaseRequest(BaseModel):
    confirm: bool = False


@router.get("/status")
def get_status() -> dict:
    """Switch status: timer, contacts, sealed-package flag, release record."""
    try:
        return inheritance_service.inheritance_status(require_db())
    except Exception as exc:
        raise _http_error(exc)


@router.post("/enable")
async def enable(req: EnableRequest) -> dict:
    """Seal the master-key shares and start the timer.

    Returns the status dict only -- the release passphrase is NEVER echoed
    back (it is not stored anywhere on this machine).
    """
    try:
        return await inheritance_service.enable_inheritance(
            require_db(),
            req.interval_days,
            req.release_passphrase,
            [contact.model_dump() for contact in req.contacts],
        )
    except Exception as exc:
        raise _http_error(exc)


@router.post("/check-in")
def check_in() -> dict:
    """Reset the dead-man's timer (the owner is alive and present)."""
    try:
        return inheritance_service.check_in(require_db())
    except Exception as exc:
        raise _http_error(exc)


@router.post("/disable")
def disable(req: DisableRequest | None = None) -> dict:
    """Turn the switch off; wipe the sealed package by default (contacts kept)."""
    try:
        db = require_db()
        wipe = True if req is None else bool(req.wipe_package)
        inheritance_service.disable_inheritance(db, wipe_package=wipe)
        return inheritance_service.inheritance_status(db)
    except Exception as exc:
        raise _http_error(exc)


@router.post("/release")
async def release(req: ReleaseRequest) -> dict:
    """Manual escape hatch: deliver the package regardless of overdue.

    400 unless ``confirm`` is true -- delivery is irreversible.
    """
    if not req.confirm:
        raise HTTPException(
            status_code=400,
            detail=(
                "release requires confirm=true; delivery of the sealed "
                "package to your contacts is irreversible."
            ),
        )
    try:
        return await inheritance_service.release_now(require_db(), confirm=True)
    except Exception as exc:
        raise _http_error(exc)


@router.post("/check")
async def check_now() -> dict:
    """Run one inheritance evaluation immediately (alert + delivery if overdue)."""
    try:
        return await inheritance_service.check_inheritance(require_db(), deliver=True)
    except Exception as exc:
        raise _http_error(exc)
