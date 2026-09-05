"""
credential_store.py -- Process-global AES-256-GCM credential store for GhostDrive.

All credentials persisted in the OS Keyring are encrypted with a key derived
from the master key via HKDF-SHA512 with the fixed info string
    b"ghostdrive-v1-backend-credentials"
This module provides a singleton that:
  1. Is initialised once at keystore unlock (set_active_key).
  2. Is zeroed at keystore lock (clear_active_key).
  3. Offers encrypt() / decrypt() / store() / load() / delete() helpers that
     all backend and pipeline code can call without holding the master key.

Security properties:
  - Two-layer protection: OS Keyring (DPAPI/libsecret/Keychain) + AES-256-GCM.
  - The 32-byte cred_key lives in a bytearray so it can be zeroed on lock.
  - Each encrypt() call uses a fresh 12-byte os.urandom nonce (semantic security).
  - Blob format stored in the keyring: base64(nonce[12] || ciphertext_with_tag).
  - If the keyring value cannot be decrypted (wrong key / corruption) the call
    returns None -- callers must treat that as "credential not available".
"""

from __future__ import annotations

import os
import base64
import logging
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

_KEYRING_SERVICE = "ghostdrive"
_AES_NONCE_BYTES = 12


class _CredentialStore:
    """
    Singleton holding the active AES-256-GCM credential encryption key.
    Thread-safety: this is written once (at unlock) and zeroed once (at lock).
    All reads are from the calling thread only. Not designed for concurrent writers.
    """

    def __init__(self) -> None:
        self._key: Optional[bytearray] = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def set_active_key(self, master_key: bytes, hkdf_salt: bytes) -> None:
        """
        Derive and cache the credential encryption key.
        Called once when the keystore is unlocked.
        """
        from ghostdrive.crypto.hkdf import derive_backend_credentials_key
        derived = derive_backend_credentials_key(master_key, hkdf_salt)
        if self._key is not None:
            self._zero_key()
        self._key = bytearray(derived)
        logger.debug("CredentialStore: key loaded.")

    def clear_active_key(self) -> None:
        """
        Zero the key from memory. Called when the keystore locks.
        After this call all encrypt/decrypt operations will fail gracefully.
        """
        self._zero_key()
        logger.debug("CredentialStore: key zeroed.")

    @property
    def is_unlocked(self) -> bool:
        return self._key is not None

    # ── Crypto primitives ─────────────────────────────────────────────────────

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt a plaintext credential string.

        Returns:
            base64(nonce[12] || ciphertext_with_tag) -- safe for keyring storage.

        Raises:
            RuntimeError: If the store is locked (key not set).
        """
        if self._key is None:
            raise RuntimeError(
                "CredentialStore is locked. Unlock the GhostDrive keystore first."
            )
        key_bytes = bytes(self._key)
        nonce = os.urandom(_AES_NONCE_BYTES)
        ciphertext = AESGCM(key_bytes).encrypt(nonce, plaintext.encode("utf-8"), None)
        return base64.b64encode(nonce + ciphertext).decode("ascii")

    def decrypt(self, encrypted_b64: str) -> Optional[str]:
        """
        Decrypt a keyring blob produced by encrypt().

        Returns:
            Plaintext string, or None if the key is not set or decryption fails.
        """
        if self._key is None or not encrypted_b64:
            return None
        try:
            key_bytes = bytes(self._key)
            raw = base64.b64decode(encrypted_b64)
            if len(raw) < _AES_NONCE_BYTES + 16:  # nonce + min GCM tag
                return None
            nonce, ciphertext = raw[:_AES_NONCE_BYTES], raw[_AES_NONCE_BYTES:]
            plaintext = AESGCM(key_bytes).decrypt(nonce, ciphertext, None)
            return plaintext.decode("utf-8")
        except Exception as exc:
            logger.error("CredentialStore.decrypt failed: %s", exc)
            return None

    # ── High-level keyring helpers ────────────────────────────────────────────

    def store(self, keyring_key: str, plaintext: str) -> None:
        """
        Encrypt plaintext and write the blob to the OS Keyring.

        Raises:
            RuntimeError:  Store is locked.
            Exception:     Keyring backend errors (propagated to caller).
        """
        import keyring
        blob = self.encrypt(plaintext)
        keyring.set_password(_KEYRING_SERVICE, keyring_key, blob)
        logger.debug("CredentialStore: stored encrypted credential '%s'.", keyring_key)

    def load(self, keyring_key: str) -> Optional[str]:
        """
        Read a blob from the OS Keyring and decrypt it.

        Returns:
            Plaintext string, or None if not found or decryption fails.
        """
        import keyring
        blob = keyring.get_password(_KEYRING_SERVICE, keyring_key)
        if not blob:
            return None
        return self.decrypt(blob)

    def delete(self, keyring_key: str) -> None:
        """
        Delete a credential blob from the OS Keyring. Silently ignores errors.
        """
        try:
            import keyring
            keyring.delete_password(_KEYRING_SERVICE, keyring_key)
            logger.debug("CredentialStore: deleted credential '%s'.", keyring_key)
        except Exception:
            pass  # Key may not exist; safe to ignore

    # ── Private ───────────────────────────────────────────────────────────────

    def _zero_key(self) -> None:
        if self._key is not None:
            for i in range(len(self._key)):
                self._key[i] = 0
            self._key = None


# ── Module-level singleton ────────────────────────────────────────────────────

#: The single process-global credential store instance.
#: Initialise with set_active_key() at unlock; zero with clear_active_key() at lock.
credential_store = _CredentialStore()
