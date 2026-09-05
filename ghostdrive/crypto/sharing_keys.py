"""
sharing_keys.py -- Cryptographic wrappers for ML-KEM-768 key pairs.
"""

import os
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from mlkem.ml_kem import ML_KEM, ML_KEM_768
from ghostdrive.crypto.hkdf import derive_subkey, INFO_MLKEM_PRIVKEY

logger = logging.getLogger(__name__)

def generate_sharing_keypair() -> tuple[bytes, bytes]:
    """
    Generates a new ML-KEM-768 encapsulation and decapsulation keypair.
    
    Returns:
        ek: Encapsulation (public) key bytes.
        dk: Decapsulation (private) key bytes.
    """
    kem = ML_KEM(ML_KEM_768)
    ek, dk = kem.key_gen()
    return ek, dk

def encrypt_sharing_privkey(privkey_bytes: bytes, master_key: bytes, salt: bytes) -> bytes:
    """Encrypts ML-KEM private key bytes with AESGCM using a key derived from master_key."""
    key = derive_subkey(master_key, salt, INFO_MLKEM_PRIVKEY)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, privkey_bytes, None)
    return nonce + ciphertext

def decrypt_sharing_privkey(encrypted_bytes: bytes, master_key: bytes, salt: bytes) -> bytes:
    """Decrypts ML-KEM private key bytes using a key derived from master_key."""
    key = derive_subkey(master_key, salt, INFO_MLKEM_PRIVKEY)
    if len(encrypted_bytes) < 28:
        raise ValueError("Invalid encrypted key format (too short).")
    nonce = encrypted_bytes[:12]
    ciphertext = encrypted_bytes[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

def get_or_create_sharing_keypair(db, master_key: bytes, salt: bytes) -> tuple[bytes, bytes]:
    """Retrieves current user's ML-KEM keypair from settings, generating it if missing."""
    ek_hex = db.get_setting("mlkem_pubkey_hex", "")
    dk_enc_hex = db.get_setting("mlkem_privkey_enc", "")
    
    if ek_hex and dk_enc_hex:
        try:
            ek = bytes.fromhex(ek_hex)
            dk_enc = bytes.fromhex(dk_enc_hex)
            dk = decrypt_sharing_privkey(dk_enc, master_key, salt)
            return ek, dk
        except Exception as exc:
            logger.warning("Failed to decrypt existing ML-KEM keypair, regenerating: %s", exc)
            
    # Generate new one
    ek, dk = generate_sharing_keypair()
    dk_enc = encrypt_sharing_privkey(dk, master_key, salt)
    
    db.set_setting("mlkem_pubkey_hex", ek.hex())
    db.set_setting("mlkem_privkey_enc", dk_enc.hex())
    
    logger.info("New ML-KEM-768 sharing keypair generated and saved to settings.")
    return ek, dk
