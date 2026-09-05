"""
models.py -- Python dataclasses for every ghostdrive.db table row.

Used throughout the pipeline to avoid raw tuple/dict indexing. Every field
maps 1:1 to a column in schema.py. UUIDs are stored as text strings.

Spec §8.2 -- Schema Overview
"""

from __future__ import annotations

import dataclasses
from typing import Optional


# ── files ─────────────────────────────────────────────────────────────────────

@dataclasses.dataclass
class FileRecord:
    """
    One row in the `files` table.

    version_of: UUIDv4 of the parent version (None for first version).
    tombstone:  True after user deletion. Row is NOT immediately deleted.
                CRITICAL/IMPORTANT: 30-day TTL. DISPOSABLE: immediate vacuum.
    logical_clock: Lamport clock value at time of write. Incremented atomically
                   in the same transaction as the write it timestamps.
    """
    id:           str                   # UUIDv4
    name:         str
    path:         str
    size:         int                   # bytes, original file
    mime_type:    str
    tier:         str                   # "CRITICAL" | "IMPORTANT" | "DISPOSABLE"
    created_at:   str                   # ISO-8601
    modified_at:  str                   # ISO-8601
    version:      int                   # 1-based, incremented on re-upload
    version_of:   Optional[str]         # UUIDv4 of parent version
    tombstone:    bool
    tombstone_at: Optional[str]         # ISO-8601, None if not tombstoned
    logical_clock: int


# ── chunks ────────────────────────────────────────────────────────────────────

@dataclasses.dataclass
class ChunkRecord:
    """
    One row in the `chunks` table.

    blake3_hash:   BLAKE3 hash of the ORIGINAL file bytes BEFORE compression.
                   Used as the dedup key together with size.
    nonce_counter: The monotonic counter value used as the ChaCha20-Poly1305
                   nonce for this chunk. Written in the same SQLite transaction
                   as the chunk_locations pending intent record (spec §4.4).
    is_manifest:   True for the index manifest chunk -- replicated to ALL
                   backends regardless of tier redundancy level.
    ref_count:     Number of FileRecords referencing this chunk. Backend delete
                   issued only when ref_count reaches 0 (spec §5.8).
    """
    id:             str                 # UUIDv4
    file_id:        str                 # UUIDv4 -> files.id
    chunk_index:    int                 # 0-based
    total_chunks:   int
    blake3_hash:    str                 # hex string
    size:           int                 # bytes, original chunk (pre-compression)
    nonce_counter:  int                 # monotonic counter -> 96-bit nonce
    sub_block_count: int
    is_manifest:    bool
    ref_count:      int                 # >= 1 while any file references this chunk


# ── chunk_locations ───────────────────────────────────────────────────────────

@dataclasses.dataclass
class ChunkLocationRecord:
    """
    One row in the `chunk_locations` table.

    One row per (chunk, sub_block, backend) triple.
    status lifecycle: pending -> confirmed | failed | cancelled

    quota_reserved: Bytes reserved on the backend for this sub-block.
                    Set before upload, cleared (moved to quota_used) on confirm,
                    restored on failure/cancel.
    """
    chunk_id:       str                 # UUIDv4 -> chunks.id
    sub_block_index: int                # 0-based
    backend_id:     str                 # UUIDv4 -> backends.id
    reference_id:   str                 # backend-specific: message_id, asset URL, CIDv1, etc.
    url_type:       str                 # "permanent" | "ephemeral" (Discord)
    upload_date:    str                 # ISO-8601
    last_verified:  Optional[str]       # ISO-8601, None if never verified
    status:         str                 # "pending" | "confirmed" | "failed" | "cancelled"
    quota_reserved: int                 # bytes


# ── backends ──────────────────────────────────────────────────────────────────

@dataclasses.dataclass
class BackendRecord:
    """
    One row in the `backends` table.

    credentials_ref: Keyring service+account key string -- never the credential
                     itself (spec §4.5). ghostdrive.db stores ONLY this ref.
    deprecated_at:   Set when backend is being phased out. New uploads skip it.
    """
    id:               str               # UUIDv4
    type:             str               # "telegram" | "discord" | "nas" | "local_fs" | "external_drive"
    credentials_ref:  str               # keyring ref, never the credential
    status:           str               # "healthy" | "degraded" | "unreachable" | "deprecated"
    priority:         int               # lower = preferred for upload routing
    last_health_check: Optional[str]    # ISO-8601
    quota_used:       int               # bytes
    quota_limit:      int               # bytes (2**62 for unlimited backends)
    quota_reserved:   int               # bytes currently in-flight
    ml_artifacts_only: bool
    cpu_intensive:    bool
    deprecated_at:    Optional[str]     # ISO-8601


# ── upload_history ────────────────────────────────────────────────────────────

@dataclasses.dataclass
class UploadHistoryRecord:
    """One row in the `upload_history` table. Append-only performance log."""
    id:               str               # UUIDv4
    backend_id:       str               # UUIDv4 -> backends.id
    chunk_id:         str               # UUIDv4 -> chunks.id
    timestamp:        str               # ISO-8601
    bytes_transferred: int
    duration_ms:      int
    success:          bool


# ── contacts ──────────────────────────────────────────────────────────────────

@dataclasses.dataclass
class ContactRecord:
    """One row in the `contacts` table (Phase 2 sharing)."""
    id:           str                   # UUIDv4
    nickname:     str
    public_key:   str                   # hex-encoded ML-KEM-768 public key
    fingerprint:  str                   # SHA-256 of public key, hex
    added_date:   str                   # ISO-8601
    trust_level:  str                   # "trusted" | "untrusted"


# ── shares ────────────────────────────────────────────────────────────────────

@dataclasses.dataclass
class ShareRecord:
    """One row in the `shares` table (Phase 2 sharing)."""
    id:             str                 # UUIDv4
    contact_id:     str                 # UUIDv4 -> contacts.id
    file_id:        str                 # UUIDv4 -> files.id
    reference_id:   str                 # backend reference for the share package
    status:         str                 # "active" | "revoked" | "expired"
    expiry:         Optional[str]       # ISO-8601, None = no expiry
    created_date:   str                 # ISO-8601
    downloaded_at:  Optional[str]       # ISO-8601, None if not yet downloaded
    download_limit: Optional[int]       # None = unlimited
    download_count: int


# ── sharing_audit_log ─────────────────────────────────────────────────────────

@dataclasses.dataclass
class SharingAuditLogRecord:
    """
    One row in the `sharing_audit_log` table.

    Append-only, HMAC-chained (same ledger pattern as main index).
    event_type: "share_created" | "share_downloaded" | "share_revoked" | "share_expired"
    hmac_chain: HMAC-SHA512(prev_hmac || row_data, ledger_key)
    """
    id:         str                     # UUIDv4
    share_id:   str                     # UUIDv4 -> shares.id
    event_type: str
    timestamp:  str                     # ISO-8601
    hmac_chain: str                     # hex-encoded HMAC-SHA512


# ── index_snapshots ───────────────────────────────────────────────────────────

@dataclasses.dataclass
class IndexSnapshotRecord:
    """
    One row in the `index_snapshots` table.

    hash_backend_id: The backend where the BLAKE3 hash is stored -- DIFFERENT
                     from the backend where the snapshot file lives (cross-backend
                     hash verification, spec §8.6).
    """
    id:              str                # UUIDv4
    snapshot_at:     str                # ISO-8601
    blake3_hash:     str                # hex-encoded BLAKE3 hash of snapshot file
    hash_backend_id: str                # UUIDv4 -> backends.id (NOT the snapshot backend)
    wal_checkpointed: bool


# ── integrity_log ─────────────────────────────────────────────────────────────

@dataclasses.dataclass
class IntegrityLogRecord:
    """
    One row in the `integrity_log` table.

    Pruned to last 10 results per chunk_id (spec §8.7).
    result: "ok" | "hash_mismatch" | "not_found" | "auth_failed"
    """
    id:         str                     # UUIDv4
    chunk_id:   str                     # UUIDv4 -> chunks.id
    checked_at: str                     # ISO-8601
    result:     str
    backend_id: str                     # UUIDv4 -> backends.id


# ── secrets_vault ─────────────────────────────────────────────────────────────

@dataclasses.dataclass
class SecretsVaultRecord:
    """
    One row in the `secrets_vault` table.

    encrypted_blob: AES-256-GCM encrypted JSON payload.
        Encryption key: HKDF(master_key, info="sloth-secrets-v1", salt=keystore_salt).
        The plaintext JSON schema varies by kind:
          password:    {url, username, password, totp_seed?}
          note:        {markdown_content}
          api_key:     {service, key_value, expiry?}
          ssh_key:     {private_key_pem, public_key_pem, fingerprint}
          seed_phrase: {words}  -- BIP39 or similar
    """
    id:             str               # UUIDv4
    label:          str               # user-visible name
    kind:           str               # "password"|"note"|"api_key"|"ssh_key"|"seed_phrase"
    encrypted_blob: bytes             # AES-256-GCM ciphertext
    created_at:     str               # ISO-8601
    modified_at:    str               # ISO-8601
    logical_clock:  int


# ── drive_registry ────────────────────────────────────────────────────────────

@dataclasses.dataclass
class DriveRegistryRecord:
    """
    One row in the `drive_registry` table.

    Identity is drive_uuid (filesystem UUID), NOT mountpoint or drive letter.
    drive_serial is opportunistic -- may be None if elevation was not available.
    mount_hint is stored only as a UI convenience ("last seen at E:\\") --
    it is NEVER used as the identity key for reconnection.
    """
    backend_id:     str               # UUIDv4 -> backends.id (PRIMARY KEY)
    drive_uuid:     str               # filesystem-level UUID
    drive_serial:   Optional[str]     # hardware serial, None if unavailable
    drive_label:    str               # user-visible label set at registration
    drive_type:     str               # "ssd"|"hdd"|"nas"|"unknown"
    capacity_bytes: int
    mount_hint:     Optional[str]     # last known mountpoint (hint only)
    registered_at:  str               # ISO-8601
    last_seen_at:   Optional[str]     # ISO-8601, None until first reconnect


# ── smart_history ─────────────────────────────────────────────────────────────

@dataclasses.dataclass
class SmartHistoryRecord:
    """
    One row in the `smart_history` table.

    Pruned to last 30 entries per backend_id via prune_smart_history().
    ssd_life_pct is None for HDDs (S.M.A.R.T. Attr 231 not applicable).
    trend is computed by the SmartMonitor trend engine, not stored as raw data.
    """
    id:                    str           # UUIDv4
    backend_id:            str           # UUIDv4 -> backends.id
    checked_at:            str           # ISO-8601
    overall_health:        str           # "PASSED"|"FAILED"|"UNKNOWN"
    reallocated_sectors:   int           # Attr 5
    pending_sectors:       int           # Attr 197
    uncorrectable_sectors: int           # Attr 198
    ssd_life_pct:          Optional[int] # Attr 231, None for HDDs
    power_on_hours:        Optional[int] # Attr 9
    temperature_c:         Optional[int] # current temperature
    assessment:            str           # "healthy"|"degrading"|"critical"|"unknown"
    trend:                 str           # "stable"|"worsening"|"accelerating"


# ── tier_patterns ─────────────────────────────────────────────────────────────

@dataclasses.dataclass
class TierPatternRecord:
    """
    One row in the `tier_patterns` table.

    GhostDrive observes that files in a path always receive the same tier,
    then records the pattern here. When confidence >= 0.8 and sample_count >= 5,
    the UI offers to automate the tier assignment (user must confirm -- never
    auto-applied without explicit user approval).
    """
    id:                str           # UUIDv4
    path_pattern:      str           # glob, e.g. "/home/user/models/*"
    suggested_tier:    str           # "CRITICAL"|"IMPORTANT"|"DISPOSABLE"
    confidence:        float         # 0.0 - 1.0
    sample_count:      int           # files observed matching this pattern
    created_at:        str           # ISO-8601
    last_confirmed_at: Optional[str] # ISO-8601, None if user never confirmed


# ── destructive_ops_log ───────────────────────────────────────────────────────

@dataclasses.dataclass
class DestructiveOpsLogRecord:
    """
    One row in the `destructive_ops_log` table.

    Append-only, HMAC-chained (same chain pattern as integrity_log).
    Written in TWO steps:
      1. Before execution: result='in_progress', completed_at=None
      2. After execution:  result='completed'|'failed', completed_at=ISO-8601

    target_hash: BLAKE3 of the absolute path string -- raw path is NEVER stored.
    dry_run_hash: BLAKE3 of the exact dry-run text displayed to the user
                  before they confirmed. Provides audit proof that the user
                  saw accurate information before confirming.

    L3 (whole-drive) operations are NOT implemented -- users are directed to
    manufacturer tools. Only L1 (file overwrite) and L2 (backend removal)
    are logged here.
    """
    id:            str           # UUIDv4
    op_level:      str           # "L1"|"L2"
    op_type:       str           # "file_overwrite"|"backend_removal"
    target_hash:   str           # BLAKE3 hex of target path (privacy)
    target_label:  str           # human-readable: filename or drive label
    method:        str           # "software_1pass"|"software_3pass"|"backend_deprecated"
    initiated_at:  str           # ISO-8601
    completed_at:  Optional[str] # ISO-8601, None while in_progress
    result:        str           # "completed"|"failed"|"blocked"|"in_progress"
    error_detail:  Optional[str] # None on success
    dry_run_hash:  str           # BLAKE3 hex of dry-run output
    session_id:    str           # session UUIDv4
    hmac_chain:    str           # hex HMAC-SHA512
