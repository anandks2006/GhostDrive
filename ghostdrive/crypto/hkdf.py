"""
hkdf.py — HKDF-SHA512 subkey derivation with fixed info strings.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ghostdrive.exceptions import CryptoError

# ─── Fixed info string constants ──────────────────────────────────────────────
# These are the ONLY valid info strings for GhostDrive subkey derivation.
# Defined in Spec §4.2.

INFO_CHUNK_ENCRYPTION  = b"sloth-chunk-enc-v1"    # ChaCha20-Poly1305 chunk key
INFO_INDEX_MAC         = b"sloth-hmac-v1"           # HMAC-SHA512 SQLite ledger chain key
INFO_KEYSTORE_ENC      = b"sloth-keystore-enc-v1"        # AES-256-GCM keystore.json encryption
INFO_SHARE_KEY         = b"sloth-share-key-v1"           # Share package encryption (Phase 2)
INFO_INDEX_BACKUP_NAME = b"sloth-index-backup-name-v1"   # Deterministic index backup filename
INFO_SECRETS_KEY            = b"sloth-secrets-v1"                    # Secrets vault encryption key
INFO_BACKEND_CREDENTIALS   = b"ghostdrive-v1-backend-credentials"  # 3rd-party backend credential encryption
INFO_INDEX_BACKUP_ENC      = b"sloth-db-snapshot-v1"     # AES-256-GCM database backup encryption
INFO_CREDENTIALS_BACKUP_NAME = b"ghostdrive-v1-credentials-backup-name" # Deterministic credentials backup filename
INFO_P2P_IDENTITY           = b"ghostdrive-v1-p2p-identity"  # Ed25519 P2P / Tor sharing identity key
INFO_MLKEM_PRIVKEY          = b"ghostdrive-v1-mlkem-privkey"  # ML-KEM-768 private key encryption key



def derive_subkey(
    master_key: bytes,
    salt: bytes,
    info: bytes,
    length: int = 32,
) -> bytes:
    """
    Derive a subkey from the Master Key using HKDF-SHA512.

    Args:
        master_key: 256-bit (32-byte) Master Key.
        salt:       Fixed 32-byte random HKDF salt from keystore.json.
                    Generated once at first run.
        info:       Purpose-binding info string. Use one of the INFO_* constants
                    defined in this module. Never pass an ad-hoc string here.
        length:     Output key length in bytes (default 32).

    Returns:
        ``length``-byte derived subkey.

    Raises:
        CryptoError: If inputs fail validation.
    """
    if not isinstance(master_key, (bytes, bytearray, memoryview)) or len(master_key) != 32:
        raise CryptoError(
            f"master_key must be exactly 32 bytes (256-bit); got {len(master_key) if isinstance(master_key, (bytes, bytearray, memoryview)) else type(master_key).__name__}"
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


def derive_secrets_key(master_key: bytes, salt: bytes) -> bytes:
    """
    Derive the AES-256-GCM secrets vault encryption key (32 bytes).
    Used to encrypt password and note blobs in secrets_vault.
    """
    return derive_subkey(master_key, salt, INFO_SECRETS_KEY, length=32)


def derive_backend_credentials_key(master_key: bytes, salt: bytes) -> bytes:
    """
    Derive the AES-256-GCM backend credentials encryption key (32 bytes).
    Used to encrypt 3rd-party backend credentials (Discord, Telegram) before
    they are stored in the OS Keyring. This provides a second layer of
    protection: OS Keyring access control + AES-256-GCM tied to the master key.
    Cryptographically isolated from all other subkeys via a unique info string.
    """
    return derive_subkey(master_key, salt, INFO_BACKEND_CREDENTIALS, length=32)


def derive_index_backup_enc_key(master_key: bytes, salt: bytes) -> bytes:
    """
    Derive the AES-256-GCM database index backup encryption key (32 bytes).
    Cryptographically isolated from all other subkeys via a unique info string.
    """
    return derive_subkey(master_key, salt, INFO_INDEX_BACKUP_ENC, length=32)


def derive_credentials_backup_name(master_key: bytes, salt: bytes) -> bytes:
    """
    Derive the deterministic credentials bundle backup filename seed (32 bytes).
    """
    return derive_subkey(master_key, salt, INFO_CREDENTIALS_BACKUP_NAME, length=32)


def derive_p2p_identity_key(master_key: bytes, salt: bytes) -> bytes:
    """
    Derive the Ed25519 P2P identity key seed (32 bytes).

    Used in sharing.py to generate the per-device Ed25519 signing key that
    authenticates outbound P2P/Tor connections.  Cryptographically isolated
    from all other subkeys via a dedicated info string so a compromise of this
    key reveals nothing about the chunk encryption key or HMAC ledger key.
    """
    return derive_subkey(master_key, salt, INFO_P2P_IDENTITY, length=32)

