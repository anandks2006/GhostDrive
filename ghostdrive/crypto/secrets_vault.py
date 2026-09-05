"""
secrets_vault.py -- Cryptographically isolated secrets vault engine for GhostDrive.
"""

from __future__ import annotations

import os
import json
import time
import hmac
import struct
import base64
import hashlib
import logging
from datetime import datetime, timezone
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ghostdrive.crypto.hkdf import derive_secrets_key
from ghostdrive.database.db import GhostDriveDB
from ghostdrive.exceptions import CryptoError, DatabaseError

logger = logging.getLogger(__name__)

AES_GCM_NONCE_BYTES = 12


def generate_totp(seed: str) -> str:
    """
    Generate standard 6-digit TOTP code (RFC 6238) from a base32 seed.
    Self-contained implementation using only standard Python libraries.
    """
    try:
        # Normalize and pad base32 seed
        seed_clean = seed.replace(" ", "").upper()
        padding_needed = len(seed_clean) % 8
        if padding_needed:
            seed_clean += "=" * (8 - padding_needed)
        
        key = base64.b32decode(seed_clean)
        
        # 30-second step interval
        time_step = 30
        counter = int(time.time() / time_step)
        
        # Pack counter as 8-byte big-endian integer
        msg = struct.pack(">Q", counter)
        
        # Compute HMAC-SHA1
        hmac_hash = hmac.new(key, msg, hashlib.sha1).digest()
        
        # Dynamic truncation
        offset = hmac_hash[-1] & 0x0F
        binary_code = struct.unpack(">I", hmac_hash[offset:offset+4])[0] & 0x7FFFFFFF
        
        # Generate 6-digit code
        totp = binary_code % 1_000_000
        return f"{totp:06d}"
    except Exception as exc:
        logger.warning("Failed to generate TOTP: %s", exc)
        return "------"


class SecretsVault:
    """
    Secrets Vault Engine.
    Handles cryptographically isolated CRUD operations on the secrets_vault database table.
    """

    def __init__(self, db: GhostDriveDB, master_key: bytes, keystore_salt: bytes) -> None:
        """
        Derive secrets vault key. Stores the key as a mutable bytearray in memory
        so it can be securely zeroed out on lock.
        """
        if not isinstance(master_key, bytes) or len(master_key) != 32:
            raise CryptoError("Master key must be exactly 32 bytes.")
        if not isinstance(keystore_salt, bytes) or len(keystore_salt) != 32:
            raise CryptoError("Keystore salt must be exactly 32 bytes.")

        self.db = db
        # Derive secrets key
        derived_key = derive_secrets_key(master_key, keystore_salt)
        self._key: Optional[bytearray] = bytearray(derived_key)
        
        logger.info("Secrets vault engine initialized.")

    def _assert_unlocked(self) -> None:
        if self._key is None:
            raise CryptoError("Secrets vault is locked. Key has been zeroed out.")

    def _encrypt(self, payload: dict) -> bytes:
        """Encrypt JSON payload with AES-256-GCM. Returns nonce + ciphertext."""
        self._assert_unlocked()
        
        plaintext = json.dumps(payload).encode("utf-8")
        nonce = os.urandom(AES_GCM_NONCE_BYTES)
        
        # Convert bytearray key to bytes for AESGCM
        key_bytes = bytes(self._key)
        ciphertext = AESGCM(key_bytes).encrypt(nonce, plaintext, None)
        
        # Prepend 12-byte nonce to ciphertext
        return nonce + ciphertext

    def _decrypt(self, encrypted_blob: bytes) -> dict:
        """Decrypt AES-256-GCM blob (nonce + ciphertext) and return JSON dict."""
        self._assert_unlocked()
        
        if len(encrypted_blob) < AES_GCM_NONCE_BYTES + 16:
            raise CryptoError("Malformed encrypted blob: too short.")
            
        nonce = encrypted_blob[:AES_GCM_NONCE_BYTES]
        ciphertext = encrypted_blob[AES_GCM_NONCE_BYTES:]
        
        try:
            key_bytes = bytes(self._key)
            plaintext = AESGCM(key_bytes).decrypt(nonce, ciphertext, None)
            return json.loads(plaintext.decode("utf-8"))
        except Exception as exc:
            raise CryptoError(f"Secrets vault decryption failed: {exc}")

    def lock(self) -> None:
        """Securely zero out the secrets key in memory and lock the vault."""
        if self._key is not None:
            # Overwrite key buffer with zeros before discarding
            for i in range(len(self._key)):
                self._key[i] = 0
            self._key = None
            logger.info("Secrets vault locked. Key zeroed in memory.")

    def add_secret(self, label: str, kind: str, payload: dict) -> str:
        """
        Encrypt payload, generate UUID, and insert into the database.
        
        kind: 'password' | 'note' | 'api_key' | 'ssh_key' | 'seed_phrase'
        """
        self._assert_unlocked()
        
        secret_id = str(uuid_generator())
        encrypted_blob = self._encrypt(payload)
        now = datetime_now_iso()

        record = {
            "id": secret_id,
            "label": label,
            "kind": kind,
            "encrypted_blob": encrypted_blob,
            "created_at": now,
            "modified_at": now,
        }

        try:
            with self.db.transaction():
                self.db.insert_secret(record)
            logger.info("Secret added successfully: %s (%s)", label, kind)
            return secret_id
        except Exception as exc:
            raise DatabaseError(f"Failed to insert secret: {exc}")

    def get_secret(self, secret_id: str) -> Optional[dict]:
        """Fetch, decrypt, and return a secret record including decrypted payload."""
        self._assert_unlocked()
        
        row = self.db.get_secret(secret_id)
        if not row:
            return None

        try:
            payload = self._decrypt(row["encrypted_blob"])
            
            # If kind is 'password' and a TOTP seed is present, append the current code
            if row["kind"] == "password" and payload.get("totp_seed"):
                payload["totp_code"] = generate_totp(payload["totp_seed"])

            return {
                "id": row["id"],
                "label": row["label"],
                "kind": row["kind"],
                "created_at": row["created_at"],
                "modified_at": row["modified_at"],
                "logical_clock": row["logical_clock"],
                "payload": payload,
            }
        except Exception as exc:
            raise CryptoError(f"Failed to decrypt secret: {exc}")

    def update_secret(self, secret_id: str, label: str, payload: dict) -> None:
        """Encrypt payload and update an existing secret."""
        self._assert_unlocked()
        
        encrypted_blob = self._encrypt(payload)
        
        try:
            with self.db.transaction():
                self.db.update_secret(secret_id, label, encrypted_blob)
            logger.info("Secret updated successfully: %s", label)
        except Exception as exc:
            raise DatabaseError(f"Failed to update secret: {exc}")

    def delete_secret(self, secret_id: str) -> None:
        """Delete a secret from the vault."""
        self._assert_unlocked()
        
        try:
            with self.db.transaction():
                self.db.delete_secret(secret_id)
            logger.info("Secret deleted: %s", secret_id)
        except Exception as exc:
            raise DatabaseError(f"Failed to delete secret: {exc}")

    def list_secrets(self, kind: Optional[str] = None) -> list[dict]:
        """List and decrypt all secrets, optionally filtered by kind."""
        self._assert_unlocked()
        
        rows = self.db.list_secrets(kind)
        results = []
        
        for row in rows:
            try:
                payload = self._decrypt(row["encrypted_blob"])
                if row["kind"] == "password" and payload.get("totp_seed"):
                    payload["totp_code"] = generate_totp(payload["totp_seed"])
                
                results.append({
                    "id": row["id"],
                    "label": row["label"],
                    "kind": row["kind"],
                    "created_at": row["created_at"],
                    "modified_at": row["modified_at"],
                    "logical_clock": row["logical_clock"],
                    "payload": payload,
                })
            except Exception as exc:
                logger.error("Failed to decrypt secret %s during listing: %s", row["id"], exc)
                # Continue listing other secrets rather than crashing
                continue
                
        return results


def uuid_generator() -> str:
    import uuid
    return str(uuid.uuid4())


def datetime_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
