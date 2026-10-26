"""
secrets.py -- Keystore master secrets manager, BIP39 seed reveal, backup, and passphrase change.
"""

import importlib.util
import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ghostdrive.web.state import state
from ghostdrive.crypto.keystore import KeystoreManager
from ghostdrive.crypto.secrets_vault import SecretsVault

logger = logging.getLogger("ghostdrive_web.secrets")

router = APIRouter(prefix="/api/secrets", tags=["secrets"])

class RevealSeedRequest(BaseModel):
    passphrase: str

class ChangePassphraseRequest(BaseModel):
    current_passphrase: str
    new_passphrase: str

class SecretCreateRequest(BaseModel):
    label: str
    kind: str = "password"
    payload: Dict[str, Any] = {}

class SecretUpdateRequest(BaseModel):
    label: Optional[str] = None
    payload: Dict[str, Any] = {}

def _require_km() -> KeystoreManager:
    if state.km is None or not state.km.is_unlocked:
        raise HTTPException(status_code=401, detail="Keystore is locked.")
    return state.km


def _vault() -> SecretsVault:
    km = _require_km()
    if state.db is None or getattr(state.db, "_conn", None) is None:
        raise HTTPException(status_code=401, detail="Database is locked.")
    return SecretsVault(state.db, km.master_key, km.hkdf_salt)

@router.post("/reveal-seed")
def reveal_seed_phrase(req: RevealSeedRequest) -> dict:
    km = _require_km()
    try:
        # Verify current passphrase by unlocking or validating against master key
        if state.keystore_path and state.keystore_path.exists():
            km.unlock(req.passphrase.encode("utf-8"))
        phrase = km.export_seed_phrase()
        return {"status": "success", "seed_phrase": phrase}
    except Exception:
        raise HTTPException(status_code=401, detail="Authentication failed. Incorrect passphrase.")

@router.post("/export-backup")
def export_encrypted_backup(req: RevealSeedRequest) -> dict:
    km = _require_km()
    try:
        if state.keystore_path and state.keystore_path.exists():
            km.unlock(req.passphrase.encode("utf-8"))
        with open(state.keystore_path, "r", encoding="utf-8") as f:
            raw_json = f.read()
        return {
            "status": "success",
            "keystore_json": raw_json,
            "filename": "ghostdrive_keystore_backup.json"
        }
    except Exception:
        raise HTTPException(status_code=401, detail="Authentication failed.")

@router.post("/change-passphrase")
def change_master_passphrase(req: ChangePassphraseRequest) -> dict:
    km = _require_km()
    try:
        # Verify current passphrase first
        if state.keystore_path and state.keystore_path.exists():
            km.unlock(req.current_passphrase.encode("utf-8"))
        km.change_passphrase(req.new_passphrase.encode("utf-8"))
        return {"status": "success", "message": "Master passphrase updated successfully."}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Passphrase change failed: {exc}")

@router.get("/vault")
def list_vault_secrets(kind: Optional[str] = None) -> dict:
    try:
        return {"secrets": _vault().list_secrets(kind)}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/vault")
def create_vault_secret(req: SecretCreateRequest) -> dict:
    if not req.label.strip():
        raise HTTPException(status_code=400, detail="Secret label cannot be empty.")
    try:
        secret_id = _vault().add_secret(req.label.strip(), req.kind, req.payload)
        return {"status": "success", "secret_id": secret_id, "message": "Secret stored in encrypted vault."}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/vault/{secret_id}")
def get_vault_secret(secret_id: str) -> dict:
    try:
        secret = _vault().get_secret(secret_id)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    if secret is None:
        raise HTTPException(status_code=404, detail="Secret not found.")
    return secret


@router.put("/vault/{secret_id}")
def update_vault_secret(secret_id: str, req: SecretUpdateRequest) -> dict:
    try:
        vault = _vault()
        existing = vault.get_secret(secret_id)
        if existing is None:
            raise HTTPException(status_code=404, detail="Secret not found.")
        payload = req.payload or existing["payload"]
        label = (req.label or existing["label"]).strip()
        vault.update_secret(secret_id, label, payload)
        return {"status": "success", "message": "Secret updated."}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.delete("/vault/{secret_id}")
def delete_vault_secret(secret_id: str) -> dict:
    try:
        _vault().delete_secret(secret_id)
        return {"status": "success", "message": "Secret deleted."}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/post-quantum-status")
def get_post_quantum_status() -> dict:
    supported = importlib.util.find_spec("mlkem") is not None
    return {
        "ml_kem_768_supported": supported,
        "mode": "ML-KEM-768 + X25519" if supported else "Classical (ML-KEM package not installed)",
        "post_quantum_shield_active": supported,
    }
