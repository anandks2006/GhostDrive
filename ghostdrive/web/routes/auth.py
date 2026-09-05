"""
auth.py -- Authentication, Keystore unlock/setup, and database initialization routes.
"""

import logging
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from typing import Optional

from ghostdrive.web.state import state
from ghostdrive.crypto.keystore import KeystoreManager
from ghostdrive.database.db import GhostDriveDB
from ghostdrive.crypto.hkdf import derive_index_mac_key

logger = logging.getLogger("ghostdrive_web.auth")

router = APIRouter(prefix="/api/auth", tags=["auth"])

class AuthStatusResponse(BaseModel):
    keystore_exists: bool
    is_unlocked: bool
    db_opened: bool

class SetupRequest(BaseModel):
    passphrase: str

class SetupResponse(BaseModel):
    seed_phrase: str
    message: str

class RestoreRequest(BaseModel):
    seed_phrase: str
    passphrase: str

class UnlockRequest(BaseModel):
    passphrase: str

class ResetDBRequest(BaseModel):
    confirm: bool

def _init_km() -> KeystoreManager:
    if state.km is None:
        state.km = KeystoreManager(state.keystore_path)
    return state.km

def _open_db(unlocked_km: KeystoreManager) -> None:
    master_key = unlocked_km._master_key_buf.key
    hkdf_salt = unlocked_km._hkdf_salt
    genesis_seed = unlocked_km._genesis_seed

    ledger_key = derive_index_mac_key(master_key, hkdf_salt)
    db = GhostDriveDB(state.db_path, ledger_key, genesis_seed, master_key)
    db.open()
    state.db = db

@router.get("/status", response_model=AuthStatusResponse)
def get_auth_status() -> AuthStatusResponse:
    km_exists = state.keystore_path.exists()
    is_unlocked = (state.km is not None and state.km.is_unlocked)
    db_opened = (state.db is not None and getattr(state.db, "_conn", None) is not None)
    return AuthStatusResponse(
        keystore_exists=km_exists,
        is_unlocked=is_unlocked,
        db_opened=db_opened
    )

@router.post("/setup", response_model=SetupResponse)
def setup_keystore(req: SetupRequest) -> SetupResponse:
    if not req.passphrase:
        raise HTTPException(status_code=400, detail="Passphrase cannot be empty.")
    
    km = _init_km()
    seed_phrase = km.create_new(req.passphrase.encode("utf-8"), calibrate=False)
    km.verify_and_save(seed_phrase)
    
    # Open database
    try:
        _open_db(km)
    except Exception as exc:
        logger.error("Failed to open database during setup: %s", exc)
        raise HTTPException(status_code=500, detail=f"Database initialization failed: {exc}")

    return SetupResponse(
        seed_phrase=seed_phrase,
        message="Keystore initialized successfully. Save your seed phrase securely!"
    )

@router.post("/restore")
def restore_keystore(req: RestoreRequest) -> dict:
    if not req.seed_phrase or not req.passphrase:
        raise HTTPException(status_code=400, detail="Seed phrase and passphrase are required.")
    
    km = _init_km()
    try:
        km.recover_from_seed(req.seed_phrase, req.passphrase.encode("utf-8"))
        _open_db(km)
    except Exception as exc:
        logger.error("Restore failed: %s", exc)
        raise HTTPException(status_code=400, detail=f"Restore failed: {exc}")

    return {"status": "success", "message": "Keystore restored and database opened."}

@router.post("/unlock")
def unlock_keystore(req: UnlockRequest) -> dict:
    if not req.passphrase:
        raise HTTPException(status_code=400, detail="Passphrase is required.")
    
    if not state.keystore_path.exists():
        raise HTTPException(status_code=404, detail="Keystore file not found. Run setup first.")

    km = _init_km()
    try:
        km.unlock(req.passphrase.encode("utf-8"))
    except Exception:
        raise HTTPException(status_code=401, detail="Incorrect password.")

    try:
        _open_db(km)
    except Exception as exc:
        logger.error("Database open failed after unlock: %s", exc)
        return {
            "status": "db_error",
            "error": f"Database decryption failed: {exc}",
            "can_reset": True
        }

    return {"status": "success", "message": "Unlocked successfully."}

@router.post("/reset-db")
def reset_database(req: ResetDBRequest) -> dict:
    if not req.confirm:
        raise HTTPException(status_code=400, detail="Confirmation required.")
    
    if state.km is None or not state.km.is_unlocked:
        raise HTTPException(status_code=401, detail="Keystore must be unlocked to reset DB.")

    # Close DB connection if open
    if state.db:
        try:
            state.db.close()
        except Exception:
            pass
        state.db = None

    # Delete database files
    for suffix in ["", "-wal", "-journal", "-shm"]:
        p = state.db_path.with_suffix(state.db_path.suffix + suffix)
        if p.exists():
            try:
                p.unlink()
            except Exception as exc:
                logger.error("Error removing DB file %s: %s", p, exc)

    # Re-open fresh database
    try:
        _open_db(state.km)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to recreate database: {exc}")

    return {"status": "success", "message": "Fresh database created successfully."}

@router.post("/lock")
def lock_keystore() -> dict:
    state.clean_shutdown()
    return {"status": "success", "message": "Keystore locked and session ended."}
