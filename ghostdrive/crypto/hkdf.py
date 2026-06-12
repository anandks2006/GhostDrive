"""
hkdf.py — HKDF-SHA512 subkey derivation with fixed info strings.

Spec §4.2 — HKDF Info Strings (Key Purpose Binding)
=====================================================
Without distinct info strings, subkeys derived from the same Master Key are
indistinguishable. The info strings below are FIXED CONSTANTS in the codebase.

DO NOT change them without a full migration plan — changing any info string
silently produces a different subkey for every installation, making all
existing encrypted data unreadable.

Key derivation path:
    Master Key (32 bytes, from BIP39 entropy)
    + HKDF salt (32 bytes, random, generated at first run, stored in keystore.json)
    + info string (purpose-binding constant)
    ──────────────────────────────────────────
    → derived subkey (length as required per consumer)
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ghostdrive.exceptions import CryptoError

# ─── Fixed info string constants ──────────────────────────────────────────────
# These are the ONLY valid info strings for GhostDrive subkey derivation.
# Defined in Spec §4.2.

INFO_CHUNK_ENCRYPTION  = b"ghostdrive-v1-chunk-encryption"    # ChaCha20-Poly1305 chunk key
INFO_INDEX_MAC         = b"ghostdrive-v1-index-mac"           # HMAC-SHA512 SQLite ledger chain key
INFO_KEYSTORE_ENC      = b"ghostdrive-v1-keystore-enc"        # AES-256-GCM keystore.json encryption
INFO_SHARE_KEY         = b"ghostdrive-v1-share-key"           # Share package encryption (Phase 2)
INFO_INDEX_BACKUP_NAME = b"ghostdrive-v1-index-backup-name"   # Deterministic index backup filename
INFO_CLI_SESSION       = b"ghostdrive-v1-cli-session"         # CLI companion session-derived key


def derive_subkey(
    master_key: bytes,
    salt: bytes,
    info: bytes,
    length: int = 32,
) -> bytes:
    """
    Derive a subkey from the Master Key using HKDF-SHA512.

    Args:
        master_key: 256-bit (32-byte) Master Key from BIP39 entropy.
        salt:       Fixed 32-byte random HKDF salt from keystore.json.
                    Generated once at first run; MUST be shared with the
                    Kaggle CLI for consistent subkey derivation across devices.
        info:       Purpose-binding info string. Use one of the INFO_* constants
                    defined in this module. Never pass an ad-hoc string here.
        length:     Output key length in bytes (default 32).

    Returns:
        ``length``-byte derived subkey.

    Raises:
        CryptoError: If inputs fail validation.
    """
    if not isinstance(master_key, bytes) or len(master_key) != 32:
        raise CryptoError(
            f"master_key must be exactly 32 bytes (256-bit); got {len(master_key) if isinstance(master_key, bytes) else type(master_key).__name__}"
        )
    if not isinstance(salt, bytes) or len(salt) != 32:
        raise CryptoError(
            f"HKDF salt must be exactly 32 bytes; got {len(salt) if isinstance(salt, bytes) else type(salt).__name__}"
        )
    if not isinstance(info, bytes) or len(info) == 0:
        raise CryptoError("HKDF info must be non-empty bytes; use an INFO_* constant from this module")
    if not isinstance(length, int) or length < 1:
        raise CryptoError(f"Output length must be a positive integer; got {length!r}")

    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(master_key)


# ─── Convenience wrappers for each defined subkey ─────────────────────────────

def derive_chunk_key(master_key: bytes, salt: bytes) -> bytes:
    """
    Derive the ChaCha20-Poly1305 chunk encryption key (32 bytes).
    Used for ALL chunk encryption and decryption operations.
    """
    return derive_subkey(master_key, salt, INFO_CHUNK_ENCRYPTION, length=32)


def derive_index_mac_key(master_key: bytes, salt: bytes) -> bytes:
    """
    Derive the HMAC-SHA512 SQLite ledger chain key (64 bytes).
    Used to chain every write in ghostdrive.db for tamper detection.
    """
    return derive_subkey(master_key, salt, INFO_INDEX_MAC, length=64)


def derive_keystore_enc_key(master_key: bytes, salt: bytes) -> bytes:
    """
    Derive the AES-256-GCM keystore.json encryption key (32 bytes).

    NOTE: This is NOT used to derive the primary keystore_enc_key at unlock time
    (that comes directly from Argon2id over the passphrase). This subkey is
    used for secondary encryption layers that need a key derived from the
    Master Key itself (e.g., re-encrypting exported key material).
    """
    return derive_subkey(master_key, salt, INFO_KEYSTORE_ENC, length=32)


def derive_share_key(master_key: bytes, salt: bytes) -> bytes:
    """
    Derive the share package encryption key (32 bytes).
    Used for Phase 2 ML-KEM-768 sharing.
    """
    return derive_subkey(master_key, salt, INFO_SHARE_KEY, length=32)


def derive_index_backup_name(master_key: bytes, salt: bytes) -> bytes:
    """
    Derive the deterministic index backup filename seed (32 bytes).
    The backup is stored at a path derived from this value so it is
    discoverable from the Master Key alone during cold-start recovery.
    """
    return derive_subkey(master_key, salt, INFO_INDEX_BACKUP_NAME, length=32)


def derive_cli_session_key(
    master_key: bytes,
    hkdf_salt: bytes,
    session_salt: bytes,
) -> bytes:
    """
    Derive a scoped, time-limited CLI session key (32 bytes).

    The session key is derived with a combined salt:
        combined_salt = HKDF_salt XOR session_salt

    This ensures the session key is unique per session while remaining
    reproducible from the Master Key + both salts. If the session key is
    compromised, only data uploaded during that session window is at risk.

    Args:
        master_key:   32-byte Master Key.
        hkdf_salt:    Fixed 32-byte HKDF salt from keystore.json.
        session_salt: Fresh 32-byte random salt generated at session setup.
                      Stored in the Colab/Kaggle environment secret store.

    Returns:
        32-byte CLI session key.
    """
    if not isinstance(session_salt, bytes) or len(session_salt) != 32:
        raise CryptoError(f"session_salt must be exactly 32 bytes; got {len(session_salt) if isinstance(session_salt, bytes) else type(session_salt).__name__}")

    combined_salt = bytes(a ^ b for a, b in zip(hkdf_salt, session_salt))
    return derive_subkey(master_key, combined_salt, INFO_CLI_SESSION, length=32)
