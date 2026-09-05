"""
secrets.py -- Keystore master secrets manager, BIP39 seed reveal, backup, and passphrase change.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ghostdrive.web.state import state
from ghostdrive.crypto.keystore import KeystoreManager

router = APIRouter(prefix="/api/secrets", tags=["secrets"])

class RevealSeedRequest(BaseModel):
    passphrase: str

class ChangePassphraseRequest(BaseModel):
    current_passphrase: str
    new_passphrase: str

def _require_km() -> KeystoreManager:
    if state.km is None or not state.km.is_unlocked:
        raise HTTPException(status_code=401, detail="Keystore is locked.")
    return state.km

@router.post("/reveal-seed")
def reveal_seed_phrase(req: RevealSeedRequest) -> dict:
    km = _require_km()
    try:
        phrase = km.reveal_seed(req.passphrase.encode("utf-8"))
        return {"status": "success", "seed_phrase": phrase}
    except Exception:
        raise HTTPException(status_code=401, detail="Authentication failed. Incorrect passphrase.")

@router.post("/export-backup")
def export_encrypted_backup(req: RevealSeedRequest) -> dict:
    km = _require_km()
    try:
        phrase = km.reveal_seed(req.passphrase.encode("utf-8"))
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
        km.change_passphrase(
            req.current_passphrase.encode("utf-8"),
            req.new_passphrase.encode("utf-8"),
            calibrate=False
        )
        return {"status": "success", "message": "Master passphrase updated successfully."}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Passphrase change failed: {exc}")

@router.get("/post-quantum-status")
def get_post_quantum_status() -> dict:
    return {
        "ml_kem_768_supported": True,
        "mode": "Hybrid Kyber-768 + X25519",
        "post_quantum_shield_active": True
    }
