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
    satellite:       Storj-specific: "US1" | "EU1" | "AP1". Locked at first
                     upload -- never changed after that.
    deprecated_at:   Set when backend is being phased out. New uploads skip it.
    """
    id:               str               # UUIDv4
    type:             str               # "telegram" | "github" | "discord" | etc.
    credentials_ref:  str               # keyring ref, never the credential
    status:           str               # "healthy" | "degraded" | "unreachable" | "deprecated"
    priority:         int               # lower = preferred for upload routing
    last_health_check: Optional[str]    # ISO-8601
    quota_used:       int               # bytes
    quota_limit:      int               # bytes (2**62 for unlimited backends)
    quota_reserved:   int               # bytes currently in-flight
    ml_artifacts_only: bool
    cpu_intensive:    bool
    satellite:        Optional[str]     # Storj only
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
