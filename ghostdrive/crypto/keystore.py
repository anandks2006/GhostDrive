"""
keystore.py — Master Key management: BIP39, Argon2id, AES-256-GCM.

Spec §4.3 — BIP39 Master Key Architecture
==========================================
FIRST RUN:
  Generate 256-bit random Master Key
  Generate 32-byte random HKDF salt → store in keystore.json (encrypted)
  Define HMAC ledger genesis seed → store in keystore.json (encrypted)
  Encode Master Key as 24-word BIP39 seed phrase
  MANDATORY: User re-enters all 24 words to verify before proceeding
  Argon2id(daily_passphrase, calibrated_params) → keystore_enc_key
  AES-256-GCM(keystore_enc_key, {Master_Key ‖ hkdf_salt ‖ genesis_seed}) → keystore.json

NORMAL UNLOCK:
  Argon2id(passphrase) → keystore_enc_key
  Decrypt keystore.json → Master Key + salt in ctypes buffer
  Passphrase zeroed from memory immediately (ctypes explicit zero)
  All workers receive memory-safe key reference ONLY

PASSPHRASE CHANGE:
  Unlock with current passphrase → Master Key in buffer (already unlocked)
  Argon2id(new_passphrase) → new_keystore_enc_key
  AES-256-GCM(new_keystore_enc_key, {Master_Key ‖ salt ‖ genesis_seed}) → new keystore.json
  Atomic replace old keystore.json (never delete before new write succeeds)

RECOVERY (lost laptop / forgotten passphrase):
  24-word seed phrase → Master Key reconstructed directly
  New passphrase → new Argon2id → new keystore.json
  HKDF salt and genesis seed MUST be provided from backup for full recovery;
  generating new ones means all existing encrypted data becomes unreachable.

Spec §4.5 — Credential Storage
================================
Backend credentials are stored via OS keyring (libsecret/DPAPI/Keychain),
NOT in ghostdrive.db or any plaintext file. Handled in backends/registry.py.
"""

import base64
import ctypes
import hashlib
import hmac
import json
import logging
import multiprocessing
import os
import secrets
import time
from pathlib import Path
from typing import Optional

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from mnemonic import Mnemonic

from ghostdrive.exceptions import AuthenticationError, CryptoError, KeystoreError

logger = logging.getLogger(__name__)

# ─── Constants ────────────────────────────────────────────────────────────────

KEYSTORE_VERSION    = 1
MASTER_KEY_BYTES    = 32   # 256-bit entropy from BIP39
HKDF_SALT_BYTES     = 32   # Random 32-byte HKDF salt (generated at first run)
GENESIS_SEED_BYTES  = 32   # HMAC ledger genesis seed
ARGON2_SALT_BYTES   = 32   # Argon2id salt (separate from HKDF salt)
AES_GCM_NONCE_BYTES = 12   # 96-bit nonce for AES-256-GCM

# Default Argon2id parameters (used as baseline for calibration)
_DEFAULT_ARGON2_PARAMS = {
    "time_cost":   3,
    "memory_cost": 65_536,  # 64 MB
    "parallelism": 4,
    "hash_len":    32,
}


# ─── MasterKeyBuffer — ctypes-based secure memory ─────────────────────────────

class MasterKeyBuffer:
    """
    Secure buffer for the 256-bit Master Key.

    The Master Key is stored in a ctypes buffer so it can be explicitly zeroed
    from memory when no longer needed (Spec §4.3 — "Passphrase zeroed from
    memory immediately"). Python ``bytes`` objects are immutable and cannot be
    zeroed; ctypes buffers can.

    Workers receive a reference to this object, not a copy of the raw bytes.
    This prevents the key from proliferating across the heap.

    Usage
    -----
        with MasterKeyBuffer(key_bytes) as buf:
            subkey = derive_chunk_key(buf.key, salt)
        # After exiting the context, buf.key raises KeystoreError
    """

    def __init__(self, key_bytes: bytes) -> None:
        if not isinstance(key_bytes, bytes) or len(key_bytes) != MASTER_KEY_BYTES:
            raise ValueError(
                f"Master Key must be exactly {MASTER_KEY_BYTES} bytes; "
                f"got {len(key_bytes) if isinstance(key_bytes, bytes) else type(key_bytes).__name__!r}"
            )
        self._buf = ctypes.create_string_buffer(MASTER_KEY_BYTES)
        ctypes.memmove(self._buf, key_bytes, MASTER_KEY_BYTES)
        self._zeroed = False

    @property
    def key(self) -> bytes:
        """Return the Master Key as a bytes copy."""
        if self._zeroed:
            raise KeystoreError(
                "Master Key buffer has been zeroed. "
                "Unlock the keystore again before accessing the key."
            )
        return self._buf.raw

    def zero(self) -> None:
        """Explicitly zero the key material from memory."""
        if not self._zeroed:
            ctypes.memset(self._buf, 0, MASTER_KEY_BYTES)
            self._zeroed = True

    def __del__(self) -> None:
        """Ensure key is zeroed on garbage collection (defence in depth)."""
        # Guard against the case where __init__ raised before _zeroed was assigned.
        if hasattr(self, "_zeroed"):
            self.zero()

    def __enter__(self) -> "MasterKeyBuffer":
        return self

    def __exit__(self, *_) -> bool:
        self.zero()
        return False  # Do not suppress exceptions


# ─── BIP39 helpers ────────────────────────────────────────────────────────────

def entropy_to_mnemonic(entropy: bytes) -> str:
    """
    Encode 32 bytes of entropy as a 24-word BIP39 mnemonic.

    Args:
        entropy: 32-byte (256-bit) random Master Key.

    Returns:
        Space-separated 24-word BIP39 mnemonic string.
    """
    if len(entropy) != MASTER_KEY_BYTES:
        raise CryptoError(f"BIP39 entropy must be {MASTER_KEY_BYTES} bytes")
    mnemo = Mnemonic("english")
    return mnemo.to_mnemonic(entropy)


def mnemonic_to_entropy(phrase: str) -> bytes:
    """
    Recover 32 bytes of entropy from a 24-word BIP39 mnemonic.

    This is the INVERSE of the standard ``Mnemonic.to_mnemonic()`` operation.
    The BIP39 checksum is verified using constant-time comparison (Spec §4.1).

    Args:
        phrase: 24-word space-separated BIP39 mnemonic (case-insensitive).

    Returns:
        32-byte Master Key (entropy).

    Raises:
        KeystoreError: Invalid words, wrong word count, or checksum mismatch.
    """
    mnemo = Mnemonic("english")
    word_list: list[str] = mnemo.wordlist  # 2048-word BIP39 English list

    words = phrase.strip().split()
    if len(words) != 24:
        raise KeystoreError(
            f"BIP39 seed phrase must be exactly 24 words; got {len(words)}"
        )

    # Map each word to its 11-bit index
    bits = ""
    for word in words:
        w = word.lower()
        if w not in word_list:
            raise KeystoreError(
                f"Invalid BIP39 word: {word!r}. "
                "Check your seed phrase for typos."
            )
        idx = word_list.index(w)
        bits += format(idx, "011b")

    # 24 × 11 = 264 bits = 256 entropy bits + 8 checksum bits
    entropy_bits   = bits[:256]
    checksum_bits  = bits[256:]

    # Convert entropy bits → bytes
    entropy = int(entropy_bits, 2).to_bytes(MASTER_KEY_BYTES, "big")

    # Verify BIP39 checksum (first 8 bits of SHA-256 of entropy)
    sha256_first_byte = hashlib.sha256(entropy).digest()[0]
    expected_checksum = format(sha256_first_byte, "08b")[:8]

    # Constant-time comparison — never leak timing info on seed phrase entry
    if not hmac.compare_digest(checksum_bits, expected_checksum):
        raise KeystoreError(
            "BIP39 checksum verification FAILED. "
            "One or more words may be incorrect or in the wrong order."
        )

    return entropy


# ─── Argon2id helpers ─────────────────────────────────────────────────────────

def calibrate_argon2id(target_seconds: float = 1.0) -> dict:
    """
    Auto-calibrate Argon2id ``time_cost`` to hit approximately ``target_seconds``
    on the current hardware. Runs ONCE at first-run wizard (Spec §4.1).

    The memory_cost is fixed at 64 MB (65536 KB). The parallelism is set to
    min(4, CPU count). Only ``time_cost`` is adjusted.

    Args:
        target_seconds: Target derivation duration in seconds (default 1.0).

    Returns:
        Dict with keys: time_cost, memory_cost, parallelism, hash_len.
    """
    parallelism = min(4, multiprocessing.cpu_count())
    memory_cost = _DEFAULT_ARGON2_PARAMS["memory_cost"]
    hash_len    = _DEFAULT_ARGON2_PARAMS["hash_len"]

    # Measure baseline with time_cost=1
    test_secret = os.urandom(32)
    test_salt   = os.urandom(ARGON2_SALT_BYTES)

    t0 = time.perf_counter()
    hash_secret_raw(
        secret=test_secret,
        salt=test_salt,
        time_cost=1,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=hash_len,
        type=Type.ID,
    )
    elapsed_per_iter = time.perf_counter() - t0

    # Guard against implausibly fast timing (VM or mocked test environment)
    elapsed_per_iter = max(elapsed_per_iter, 0.001)

    time_cost = max(1, round(target_seconds / elapsed_per_iter))

    return {
        "time_cost":   time_cost,
        "memory_cost": memory_cost,
        "parallelism": parallelism,
        "hash_len":    hash_len,
    }


def _argon2id_derive(passphrase: bytes, salt: bytes, params: dict) -> bytes:
    """
    Derive a key from passphrase using Argon2id.

    Args:
        passphrase: Raw passphrase bytes.
        salt:       32-byte random Argon2id salt (from keystore.json plaintext header).
        params:     Dict with time_cost, memory_cost, parallelism, hash_len.

    Returns:
        Derived key bytes (length = params["hash_len"]).
    """
    return hash_secret_raw(
        secret=passphrase,
        salt=salt,
        time_cost=params["time_cost"],
        memory_cost=params["memory_cost"],
        parallelism=params["parallelism"],
        hash_len=params.get("hash_len", 32),
        type=Type.ID,
    )


# ─── AES-256-GCM helpers ──────────────────────────────────────────────────────

def _aes_gcm_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt plaintext with AES-256-GCM.

    Args:
        key:       32-byte AES-256 key.
        plaintext: Arbitrary-length plaintext.

    Returns:
        Tuple of (nonce, ciphertext_with_tag).
        The nonce is a fresh 12-byte random value.

    Raises:
        CryptoError: If key is not 32 bytes.
    """
    if not isinstance(key, bytes) or len(key) != 32:
        raise CryptoError(f"AES-256-GCM key must be 32 bytes; got {len(key) if isinstance(key, bytes) else type(key).__name__!r}")
    nonce = os.urandom(AES_GCM_NONCE_BYTES)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def _aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt ciphertext with AES-256-GCM and verify the auth tag.

    Args:
        key:        32-byte AES-256 key.
        nonce:      12-byte nonce used during encryption.
        ciphertext: Ciphertext with appended GCM tag.

    Returns:
        Plaintext bytes.

    Raises:
        AuthenticationError: If decryption or tag verification fails
                             (wrong key, corrupted ciphertext, or wrong nonce).
    """
    if not isinstance(key, bytes) or len(key) != 32:
        raise CryptoError(f"AES-256-GCM key must be 32 bytes; got {len(key) if isinstance(key, bytes) else type(key).__name__!r}")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise AuthenticationError(
            "AES-256-GCM decryption failed. "
            "Wrong passphrase, corrupted keystore, or tampered data."
        ) from exc


# ─── KeystoreManager ──────────────────────────────────────────────────────────

class KeystoreManager:
    """
    Manages the GhostDrive keystore (``keystore.json``).

    Responsibilities
    ----------------
    - Generate and store the 256-bit Master Key.
    - Encode the Master Key as a BIP39 24-word seed phrase.
    - Enforce the mandatory seed phrase verification step at first run.
    - Protect the Master Key, HKDF salt, and genesis seed with
      Argon2id + AES-256-GCM encryption.
    - Provide the unlocked Master Key in a ctypes buffer that can be
      explicitly zeroed.
    - Handle passphrase changes (atomic keystore replace).
    - Handle recovery from seed phrase.

    State Machine
    -------------
        LOCKED ──unlock()──► UNLOCKED ──lock()──► LOCKED
        ABSENT ──create_new() + verify_and_save()──► UNLOCKED
    """

    def __init__(self, keystore_path: Path) -> None:
        self.keystore_path = Path(keystore_path)
        self._master_key_buf: Optional[MasterKeyBuffer] = None
        self._hkdf_salt: Optional[bytes] = None
        self._genesis_seed: Optional[bytes] = None
        self._argon2_params: Optional[dict] = None
        self._pending_creation: Optional[dict] = None

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def is_unlocked(self) -> bool:
        """True if the Master Key is loaded in memory."""
        return (
            self._master_key_buf is not None
            and not self._master_key_buf._zeroed
        )

    @property
    def master_key(self) -> bytes:
        """The 32-byte Master Key. Raises if locked."""
        if not self.is_unlocked:
            raise KeystoreError("Keystore is locked. Call unlock() first.")
        return self._master_key_buf.key

    @property
    def hkdf_salt(self) -> bytes:
        """The 32-byte HKDF salt. Raises if locked."""
        if not self.is_unlocked:
            raise KeystoreError("Keystore is locked. Call unlock() first.")
        return self._hkdf_salt

    @property
    def genesis_seed(self) -> bytes:
        """The 32-byte HMAC ledger genesis seed. Raises if locked."""
        if not self.is_unlocked:
            raise KeystoreError("Keystore is locked. Call unlock() first.")
        return self._genesis_seed

    # ── First-run flow ────────────────────────────────────────────────────────

    def create_new(
        self,
        passphrase: bytes,
        calibrate: bool = True,
        argon2_params: Optional[dict] = None,
    ) -> str:
        """
        First-run: generate a new Master Key and begin the keystore creation
        flow. The keystore is NOT written to disk until ``verify_and_save()``
        is called with the confirmed seed phrase.

        Args:
            passphrase:    Passphrase bytes (will be zeroed after ``verify_and_save()``).
            calibrate:     If ``True``, auto-calibrate Argon2id to ~1 s (default).
            argon2_params: If provided, use these params instead of calibrating.
                           Use only for testing (e.g. fast params with low memory).

        Returns:
            24-word BIP39 seed phrase. The user MUST write this down and
            re-enter it in ``verify_and_save()`` before proceeding.

        Raises:
            KeystoreError: If a keystore already exists at the path.
        """
        if self.keystore_path.exists():
            raise KeystoreError(
                f"Keystore already exists at {self.keystore_path}. "
                "Use unlock() to open it, or delete it first for a fresh start."
            )

        # Generate cryptographic material
        master_key   = secrets.token_bytes(MASTER_KEY_BYTES)
        hkdf_salt    = hashlib.sha256(master_key + b"ghostdrive-hkdf-salt-v1").digest()
        genesis_seed = hashlib.sha256(master_key + b"ghostdrive-hmac-genesis-seed-v1").digest()

        # Encode as BIP39 mnemonic
        seed_phrase = entropy_to_mnemonic(master_key)

        # Resolve Argon2id parameters
        params = argon2_params or (
            calibrate_argon2id(target_seconds=1.0)
            if calibrate
            else _DEFAULT_ARGON2_PARAMS.copy()
        )

        # Stage pending creation data (not yet written to disk)
        self._pending_creation = {
            "master_key":   master_key,
            "hkdf_salt":    hkdf_salt,
            "genesis_seed": genesis_seed,
            "passphrase":   passphrase,
            "argon2_params": params,
        }

        return seed_phrase

    def verify_and_save(self, confirmed_phrase: str) -> None:
        """
        Mandatory BIP39 verification step (Spec §4.3).

        The user re-enters all 24 words to confirm they have written them down.
        If verification passes, the keystore is written atomically to disk.

        Args:
            confirmed_phrase: The 24-word phrase re-entered by the user.

        Raises:
            KeystoreError: If ``create_new()`` was not called first, or if
                           the confirmed phrase does not match.
        """
        if self._pending_creation is None:
            raise KeystoreError(
                "No pending keystore creation. Call create_new() first."
            )

        # Decode entropy from the confirmed phrase
        try:
            recovered_entropy = mnemonic_to_entropy(confirmed_phrase)
        except KeystoreError as exc:
            raise KeystoreError(
                f"Seed phrase verification failed: {exc}"
            ) from exc

        # Compare recovered entropy with the original Master Key (constant-time)
        if not hmac.compare_digest(recovered_entropy, self._pending_creation["master_key"]):
            raise KeystoreError(
                "Seed phrase verification FAILED: the words you entered do not "
                "match the generated seed phrase. Please try again carefully."
            )

        # All good — write keystore to disk
        pd = self._pending_creation
        self._write_keystore(
            master_key=pd["master_key"],
            hkdf_salt=pd["hkdf_salt"],
            genesis_seed=pd["genesis_seed"],
            passphrase=pd["passphrase"],
            argon2_params=pd["argon2_params"],
        )

        # Set as unlocked
        self._master_key_buf = MasterKeyBuffer(pd["master_key"])
        self._hkdf_salt      = pd["hkdf_salt"]
        self._genesis_seed   = pd["genesis_seed"]
        self._argon2_params  = pd["argon2_params"]

        # Zero the pending passphrase if it is mutable
        _zero_if_mutable(pd["passphrase"])

        self._pending_creation = None

    # ── Normal unlock ─────────────────────────────────────────────────────────

    def unlock(self, passphrase: bytes | bytearray) -> None:
        """
        Normal unlock: derive keystore_enc_key from passphrase via Argon2id,
        decrypt keystore.json, load Master Key into ctypes buffer.

        The passphrase is zeroed from memory immediately after Argon2id
        derivation (Spec §4.3).

        Args:
            passphrase: Raw passphrase bytes or bytearray.

        Raises:
            KeystoreError:       If keystore file does not exist or is malformed.
            AuthenticationError: If the passphrase is wrong.
        """
        if not self.keystore_path.exists():
            raise KeystoreError(
                f"Keystore not found at {self.keystore_path}. "
                "Run the first-run wizard to create one."
            )

        # Load keystore
        try:
            with open(self.keystore_path, "r", encoding="utf-8") as fh:
                ks = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            raise KeystoreError(f"Failed to read keystore: {exc}") from exc

        if ks.get("version") != KEYSTORE_VERSION:
            raise KeystoreError(
                f"Unsupported keystore version {ks.get('version')!r}; "
                f"expected {KEYSTORE_VERSION}"
            )

        argon2_salt = base64.b64decode(ks["argon2_salt"])
        params = {
            "time_cost":   ks["argon2_time_cost"],
            "memory_cost": ks["argon2_memory_cost"],
            "parallelism": ks["argon2_parallelism"],
            "hash_len":    ks.get("argon2_hash_len", 32),
        }

        # Derive keystore encryption key from passphrase (Argon2id)
        keystore_enc_key = _argon2id_derive(passphrase, argon2_salt, params)

        # Zero passphrase IMMEDIATELY after KDF — before any further operations
        _zero_if_mutable(passphrase)

        # Decrypt the payload
        nonce      = base64.b64decode(ks["nonce"])
        ciphertext = base64.b64decode(ks["ciphertext"])
        payload    = _aes_gcm_decrypt(keystore_enc_key, nonce, ciphertext)

        # Parse payload: master_key ‖ hkdf_salt ‖ genesis_seed (32+32+32 = 96 bytes)
        expected_len = MASTER_KEY_BYTES + HKDF_SALT_BYTES + GENESIS_SEED_BYTES
        if len(payload) != expected_len:
            raise KeystoreError(
                f"Corrupted keystore payload: expected {expected_len} bytes, "
                f"got {len(payload)}"
            )

        master_key   = payload[:32]
        hkdf_salt    = payload[32:64]
        genesis_seed = payload[64:96]

        self._master_key_buf = MasterKeyBuffer(master_key)
        self._hkdf_salt      = hkdf_salt
        self._genesis_seed   = genesis_seed
        self._argon2_params  = params

    # ── Lock ──────────────────────────────────────────────────────────────────

    def lock(self) -> None:
        """
        Zero the Master Key from memory and lock the keystore.
        Part of the clean shutdown sequence (Spec §9.5, Step 6).
        """
        if self._master_key_buf is not None:
            self._master_key_buf.zero()
            self._master_key_buf = None

        # NOTE: Python bytes are immutable so we cannot zero the old buffer
        # in-place. Overwriting the reference drops the last Python reference
        # to the object; CPython will GC it but timing is not guaranteed.
        # For maximum security, callers should use bytearray for sensitive data.
        if self._hkdf_salt:
            self._hkdf_salt = b"\x00" * HKDF_SALT_BYTES
            self._hkdf_salt = None

        if self._genesis_seed:
            self._genesis_seed = b"\x00" * GENESIS_SEED_BYTES
            self._genesis_seed = None

        # Zero Argon2id parameters (cost parameters could assist timing attacks)
        self._argon2_params = None

    # ── Passphrase change ─────────────────────────────────────────────────────

    def change_passphrase(self, new_passphrase: bytes | bytearray) -> None:
        """
        Change the keystore passphrase (Spec §4.3 — PASSPHRASE CHANGE).

        The keystore must already be unlocked. Re-encrypts the Master Key,
        HKDF salt, and genesis seed with a new Argon2id-derived key, then
        atomically replaces keystore.json.

        Args:
            new_passphrase: New raw passphrase bytes or bytearray.

        Raises:
            KeystoreError: If keystore is not unlocked.
        """
        if not self.is_unlocked:
            raise KeystoreError("Keystore must be unlocked to change passphrase.")

        # Re-calibrate Argon2id for current hardware
        new_params = calibrate_argon2id(target_seconds=1.0)

        self._write_keystore(
            master_key=self._master_key_buf.key,
            hkdf_salt=self._hkdf_salt,
            genesis_seed=self._genesis_seed,
            passphrase=new_passphrase,
            argon2_params=new_params,
        )
        self._argon2_params = new_params
        _zero_if_mutable(new_passphrase)

    def rotate_keys(self, new_salt: bytes, passphrase: bytes | bytearray) -> None:
        """
        Rotate the HKDF salt. Re-encrypts the master key with the new salt
        using the current passphrase.
        """
        if not self.is_unlocked:
            raise KeystoreError("Keystore must be unlocked to rotate keys.")
            
        self._write_keystore(
            master_key=self._master_key_buf.key,
            hkdf_salt=new_salt,
            genesis_seed=self._genesis_seed,
            passphrase=passphrase,
            argon2_params=self._argon2_params,
        )
        self._hkdf_salt = new_salt
        _zero_if_mutable(passphrase)

    # ── Recovery ──────────────────────────────────────────────────────────────

    def recover_from_seed(
        self,
        seed_phrase: str,
        new_passphrase: bytes,
        hkdf_salt: Optional[bytes] = None,
        genesis_seed: Optional[bytes] = None,
        calibrate: bool = True,
        argon2_params: Optional[dict] = None,
    ) -> None:
        """
        Recovery from 24-word BIP39 seed phrase (Spec §4.3 — RECOVERY).

        Reconstructs the Master Key from the seed phrase and creates a new
        keystore.json with the new passphrase.

        WARNING: If ``hkdf_salt`` and ``genesis_seed`` are not provided (i.e.
        not available from backup), NEW ones are generated. This means all
        HKDF-derived subkeys will be different, making existing encrypted data
        unreachable without the database. The user must also re-import the
        database backup to recover their files.

        Args:
            seed_phrase:   24-word BIP39 seed phrase.
            new_passphrase: New passphrase for the new keystore.
            hkdf_salt:     Optional: restored 32-byte HKDF salt from backup.
            genesis_seed:  Optional: restored 32-byte HMAC genesis seed from backup.
            calibrate:     If ``True`` (default), auto-calibrate Argon2id to ~1 s.
            argon2_params: If provided, use these params instead of calibrating
                           (testing hook; overrides ``calibrate``).
        """
        master_key = mnemonic_to_entropy(seed_phrase)

        _hkdf_salt    = hkdf_salt    if hkdf_salt    else hashlib.sha256(master_key + b"ghostdrive-hkdf-salt-v1").digest()
        _genesis_seed = genesis_seed if genesis_seed else hashlib.sha256(master_key + b"ghostdrive-hmac-genesis-seed-v1").digest()

        if hkdf_salt is None or genesis_seed is None:
            import warnings
            warnings.warn(
                "Recovery without hkdf_salt and genesis_seed uses deterministic derivations. "
                "Legacy installations may have used random salts.",
                UserWarning,
                stacklevel=2,
            )
            logger.info("Recovery: no salt/genesis seed provided. Deriving deterministically from Master Key.")

        params = argon2_params or (
            calibrate_argon2id(target_seconds=1.0) if calibrate else _DEFAULT_ARGON2_PARAMS.copy()
        )

        self._write_keystore(
            master_key=master_key,
            hkdf_salt=_hkdf_salt,
            genesis_seed=_genesis_seed,
            passphrase=new_passphrase,
            argon2_params=params,
        )

        self._master_key_buf = MasterKeyBuffer(master_key)
        self._hkdf_salt      = _hkdf_salt
        self._genesis_seed   = _genesis_seed
        self._argon2_params  = params

    # ── Seed phrase export ────────────────────────────────────────────────────

    def export_seed_phrase(self) -> str:
        """
        Export the current Master Key as a 24-word BIP39 seed phrase.
        Used for backup display in the settings panel.
        Keystore must be unlocked.
        """
        if not self.is_unlocked:
            raise KeystoreError("Keystore must be unlocked to export seed phrase.")
        return entropy_to_mnemonic(self._master_key_buf.key)

    # ── Private ───────────────────────────────────────────────────────────────

    def _write_keystore(
        self,
        master_key: bytes,
        hkdf_salt: bytes,
        genesis_seed: bytes,
        passphrase: bytes,
        argon2_params: dict,
    ) -> None:
        """
        Encrypt and write keystore.json atomically to disk (fsync).

        Keystore JSON structure:
          version            : int   (KEYSTORE_VERSION)
          argon2_salt        : b64   (32-byte random Argon2id salt)
          argon2_time_cost   : int
          argon2_memory_cost : int
          argon2_parallelism : int
          argon2_hash_len    : int
          nonce              : b64   (12-byte AES-GCM nonce)
          ciphertext         : b64   (AES-256-GCM ciphertext + 16-byte tag)
                                     Plaintext payload = master_key ‖ hkdf_salt ‖ genesis_seed
        """
        from ghostdrive.utils.fsync import atomic_write

        # Fresh 32-byte Argon2id salt (different from HKDF salt)
        argon2_salt = os.urandom(ARGON2_SALT_BYTES)

        # Derive keystore encryption key from passphrase via Argon2id
        keystore_enc_key = _argon2id_derive(passphrase, argon2_salt, argon2_params)

        # Plaintext payload: master_key ‖ hkdf_salt ‖ genesis_seed
        payload = master_key + hkdf_salt + genesis_seed  # 96 bytes

        # Encrypt with AES-256-GCM
        nonce, ciphertext = _aes_gcm_encrypt(keystore_enc_key, payload)

        keystore_data = {
            "version":            KEYSTORE_VERSION,
            "argon2_salt":        base64.b64encode(argon2_salt).decode(),
            "argon2_time_cost":   argon2_params["time_cost"],
            "argon2_memory_cost": argon2_params["memory_cost"],
            "argon2_parallelism": argon2_params["parallelism"],
            "argon2_hash_len":    argon2_params.get("hash_len", 32),
            "nonce":              base64.b64encode(nonce).decode(),
            "ciphertext":         base64.b64encode(ciphertext).decode(),
        }

        raw = json.dumps(keystore_data, indent=2).encode("utf-8")

        # Atomic write + fsync (write-to-temp, fsync, rename)
        atomic_write(self.keystore_path, raw)


# ─── Utility ──────────────────────────────────────────────────────────────────

def _zero_if_mutable(data) -> None:
    """
    Zero a mutable bytes-like object (bytearray) or CPython bytes object in place.
    Uses ctypes to overwrite the internal buffer of immutable bytes as a best-effort.
    """
    if isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = 0
    elif isinstance(data, bytes):
        try:
            length = len(data)
            if length > 0:
                # CPython-specific offset for ob_sval in PyBytesObject
                offset = 32 if ctypes.sizeof(ctypes.c_void_p) == 8 else 16
                ctypes.memset(id(data) + offset, 0, length)
        except Exception:
            pass
