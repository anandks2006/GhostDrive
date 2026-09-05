"""
schema.py -- SQL DDL for all ghostdrive.db tables.

Pure constants -- no database connection here.
All PKs are UUIDv4 text. No sequential integers (spec §8.2).

Connection pragmas applied by db.py on every open:
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;
    PRAGMA secure_delete = ON;
    PRAGMA temp_store = MEMORY;
    PRAGMA synchronous = NORMAL;    -- WAL mode: NORMAL is safe and faster than FULL
"""

# ─── Table DDL ────────────────────────────────────────────────────────────────

CREATE_FILES = """
CREATE TABLE IF NOT EXISTS files (
    id            TEXT PRIMARY KEY,         -- UUIDv4
    name          TEXT NOT NULL,
    path          TEXT NOT NULL,
    size          INTEGER NOT NULL,         -- original file bytes
    mime_type     TEXT NOT NULL DEFAULT '',
    tier          TEXT NOT NULL             -- 'CRITICAL'|'IMPORTANT'|'DISPOSABLE'
                  CHECK(tier IN ('CRITICAL','IMPORTANT','DISPOSABLE')),
    created_at    TEXT NOT NULL,            -- ISO-8601
    modified_at   TEXT NOT NULL,            -- ISO-8601
    version       INTEGER NOT NULL DEFAULT 1,
    version_of    TEXT REFERENCES files(id),-- NULL for first version
    tombstone     INTEGER NOT NULL DEFAULT 0,  -- 0|1 bool
    tombstone_at  TEXT,                     -- ISO-8601, NULL if not tombstoned
    logical_clock INTEGER NOT NULL DEFAULT 0,
    thumbnail_blob BLOB,
    tags          TEXT NOT NULL DEFAULT ''
) STRICT;
"""

CREATE_CHUNKS = """
CREATE TABLE IF NOT EXISTS chunks (
    id              TEXT PRIMARY KEY,       -- UUIDv4
    file_id         TEXT NOT NULL REFERENCES files(id),
    chunk_index     INTEGER NOT NULL,       -- 0-based
    total_chunks    INTEGER NOT NULL,
    blake3_hash     TEXT NOT NULL,          -- hex, on ORIGINAL bytes pre-compression
    size            INTEGER NOT NULL,       -- original chunk bytes pre-compression
    nonce_counter   INTEGER NOT NULL,       -- monotonic counter -> 96-bit nonce
    sub_block_count INTEGER NOT NULL DEFAULT 1,
    is_manifest     INTEGER NOT NULL DEFAULT 0,  -- 0|1 bool
    ref_count       INTEGER NOT NULL DEFAULT 1,  -- >= 1 while referenced
    UNIQUE(file_id, chunk_index)
) STRICT;
"""

CREATE_CHUNK_LOCATIONS = """
CREATE TABLE IF NOT EXISTS chunk_locations (
    chunk_id        TEXT NOT NULL REFERENCES chunks(id),
    sub_block_index INTEGER NOT NULL,       -- 0-based
    backend_id      TEXT NOT NULL REFERENCES backends(id),
    reference_id    TEXT NOT NULL,          -- backend-specific: msg_id, URL, CIDv1 ...
    url_type        TEXT NOT NULL DEFAULT 'permanent'
                    CHECK(url_type IN ('permanent','ephemeral')),
    upload_date     TEXT NOT NULL,          -- ISO-8601
    last_verified   TEXT,                   -- ISO-8601, NULL if never verified
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK(status IN ('pending','confirmed','failed','cancelled')),
    quota_reserved  INTEGER NOT NULL DEFAULT 0,  -- bytes reserved, cleared on confirm
    PRIMARY KEY (chunk_id, sub_block_index, backend_id)
) STRICT;
"""

CREATE_BACKENDS = """
CREATE TABLE IF NOT EXISTS backends (
    id                TEXT PRIMARY KEY,     -- UUIDv4
    type              TEXT NOT NULL,        -- 'telegram'|'discord'|'nas'|'local_fs'|'external_drive'
    credentials_ref   TEXT NOT NULL,        -- keyring ref ONLY, never the credential
    status            TEXT NOT NULL DEFAULT 'healthy'
                      CHECK(status IN ('healthy','degraded','unreachable','deprecated')),
    priority          INTEGER NOT NULL DEFAULT 100,
    last_health_check TEXT,                 -- ISO-8601
    quota_used        INTEGER NOT NULL DEFAULT 0,
    quota_limit       INTEGER NOT NULL DEFAULT 4611686018427387904,  -- 2^62, unlimited
    quota_reserved    INTEGER NOT NULL DEFAULT 0,
    ml_artifacts_only INTEGER NOT NULL DEFAULT 0,  -- 0|1 bool
    cpu_intensive     INTEGER NOT NULL DEFAULT 0,  -- 0|1 bool
    deprecated_at     TEXT                  -- ISO-8601, NULL if not deprecated
) STRICT;
"""

CREATE_UPLOAD_HISTORY = """
CREATE TABLE IF NOT EXISTS upload_history (
    id                TEXT PRIMARY KEY,     -- UUIDv4
    backend_id        TEXT NOT NULL REFERENCES backends(id),
    chunk_id          TEXT NOT NULL REFERENCES chunks(id),
    timestamp         TEXT NOT NULL,        -- ISO-8601
    bytes_transferred INTEGER NOT NULL,
    duration_ms       INTEGER NOT NULL,
    success           INTEGER NOT NULL      -- 0|1 bool
) STRICT;
"""

CREATE_CONTACTS = """
CREATE TABLE IF NOT EXISTS contacts (
    id               TEXT PRIMARY KEY,           -- UUIDv4
    nickname         TEXT NOT NULL,
    public_key       TEXT NOT NULL,              -- hex Ed25519 identity key
    fingerprint      TEXT NOT NULL UNIQUE,       -- SHA-256 of public key, hex
    added_date       TEXT NOT NULL,              -- ISO-8601
    trust_level      TEXT NOT NULL DEFAULT 'untrusted'
                     CHECK(trust_level IN ('trusted','untrusted')),
    onion_address    TEXT NOT NULL DEFAULT '',   -- Tor onion address or host
    mlkem_public_key TEXT NOT NULL DEFAULT ''    -- hex ML-KEM-768 public key
) STRICT;
"""

CREATE_SHARES = """
CREATE TABLE IF NOT EXISTS shares (
    id             TEXT PRIMARY KEY,        -- UUIDv4
    contact_id     TEXT NOT NULL REFERENCES contacts(id),
    file_id        TEXT NOT NULL REFERENCES files(id),
    reference_id   TEXT NOT NULL,           -- backend reference for share package
    status         TEXT NOT NULL DEFAULT 'active'
                   CHECK(status IN ('active','revoked','expired')),
    expiry         TEXT,                    -- ISO-8601, NULL = no expiry
    created_date   TEXT NOT NULL,           -- ISO-8601
    downloaded_at  TEXT,                    -- ISO-8601, NULL if not downloaded
    download_limit INTEGER,                 -- NULL = unlimited
    download_count INTEGER NOT NULL DEFAULT 0
) STRICT;
"""

CREATE_SHARING_AUDIT_LOG = """
CREATE TABLE IF NOT EXISTS sharing_audit_log (
    id         TEXT PRIMARY KEY,            -- UUIDv4
    share_id   TEXT NOT NULL REFERENCES shares(id),
    event_type TEXT NOT NULL
               CHECK(event_type IN ('share_created','share_downloaded',
                                    'share_revoked','share_expired')),
    timestamp  TEXT NOT NULL,               -- ISO-8601
    hmac_chain TEXT NOT NULL                -- hex HMAC-SHA512 of prev_hmac || row_data
) STRICT;
"""

CREATE_INDEX_SNAPSHOTS = """
CREATE TABLE IF NOT EXISTS index_snapshots (
    id               TEXT PRIMARY KEY,      -- UUIDv4
    snapshot_at      TEXT NOT NULL,         -- ISO-8601
    blake3_hash      TEXT NOT NULL,         -- hex BLAKE3 of snapshot file
    hash_backend_id  TEXT NOT NULL REFERENCES backends(id),  -- DIFFERENT backend from snapshot file
    wal_checkpointed INTEGER NOT NULL DEFAULT 0  -- 0|1 bool
) STRICT;
"""

CREATE_INTEGRITY_LOG = """
CREATE TABLE IF NOT EXISTS integrity_log (
    id         TEXT PRIMARY KEY,            -- UUIDv4
    chunk_id   TEXT NOT NULL REFERENCES chunks(id),
    checked_at TEXT NOT NULL,              -- ISO-8601
    result     TEXT NOT NULL
               CHECK(result IN ('ok','hash_mismatch','not_found','auth_failed')),
    backend_id TEXT NOT NULL REFERENCES backends(id)
) STRICT;
"""

# ─── New tables: Secrets Vault ───────────────────────────────────────────────

CREATE_SECRETS_VAULT = """
CREATE TABLE IF NOT EXISTS secrets_vault (
    id             TEXT PRIMARY KEY,         -- UUIDv4
    label          TEXT NOT NULL,            -- user-visible name
    kind           TEXT NOT NULL             -- entry type
                   CHECK(kind IN ('password','note','api_key','ssh_key','seed_phrase')),
    encrypted_blob BLOB NOT NULL,            -- AES-256-GCM encrypted JSON payload
                                             -- key: HKDF(master, info="sloth-secrets-v1")
    created_at     TEXT NOT NULL,            -- ISO-8601
    modified_at    TEXT NOT NULL,            -- ISO-8601
    logical_clock  INTEGER NOT NULL DEFAULT 0
) STRICT;
"""

# ─── New tables: Drive Registry ───────────────────────────────────────────────

CREATE_DRIVE_REGISTRY = """
CREATE TABLE IF NOT EXISTS drive_registry (
    backend_id     TEXT PRIMARY KEY REFERENCES backends(id),
    drive_uuid     TEXT NOT NULL,            -- filesystem-level UUID (identity key)
    drive_serial   TEXT,                     -- hardware serial (may require elevation)
    drive_label    TEXT NOT NULL,            -- user-visible label from registration
    drive_type     TEXT NOT NULL DEFAULT 'unknown'
                   CHECK(drive_type IN ('ssd','hdd','nas','unknown')),
    capacity_bytes INTEGER NOT NULL DEFAULT 0,
    mount_hint     TEXT,                     -- last known mountpoint (HINT ONLY, not identity)
    registered_at  TEXT NOT NULL,            -- ISO-8601
    last_seen_at   TEXT                      -- ISO-8601, NULL until first reconnect
) STRICT;
"""

# ─── New tables: S.M.A.R.T. History ──────────────────────────────────────────
# Rolling window: prune_smart_history() keeps last 30 entries per backend_id.

CREATE_SMART_HISTORY = """
CREATE TABLE IF NOT EXISTS smart_history (
    id                    TEXT PRIMARY KEY,  -- UUIDv4
    backend_id            TEXT NOT NULL REFERENCES backends(id),
    checked_at            TEXT NOT NULL,     -- ISO-8601
    overall_health        TEXT NOT NULL      -- smartctl overall-health assessment
                          CHECK(overall_health IN ('PASSED','FAILED','UNKNOWN')),
    reallocated_sectors   INTEGER NOT NULL DEFAULT 0,  -- Attr 5
    pending_sectors       INTEGER NOT NULL DEFAULT 0,  -- Attr 197
    uncorrectable_sectors INTEGER NOT NULL DEFAULT 0,  -- Attr 198
    ssd_life_pct          INTEGER,           -- Attr 231, NULL for HDDs
    power_on_hours        INTEGER,           -- Attr 9
    temperature_c         INTEGER,           -- current temperature
    assessment            TEXT NOT NULL DEFAULT 'unknown'
                          CHECK(assessment IN ('healthy','degrading','critical','unknown')),
    trend                 TEXT NOT NULL DEFAULT 'stable'
                          CHECK(trend IN ('stable','worsening','accelerating'))
) STRICT;
"""

# ─── New tables: Tier Patterns ────────────────────────────────────────────────
# Auto-tier learning: GhostDrive observes which paths always get the same tier
# and suggests (never auto-applies) automating it.

CREATE_TIER_PATTERNS = """
CREATE TABLE IF NOT EXISTS tier_patterns (
    id                TEXT PRIMARY KEY,      -- UUIDv4
    path_pattern      TEXT NOT NULL UNIQUE,  -- glob, e.g. '/home/user/models/*'
    suggested_tier    TEXT NOT NULL
                      CHECK(suggested_tier IN ('CRITICAL','IMPORTANT','DISPOSABLE')),
    confidence        REAL NOT NULL DEFAULT 0.0,  -- 0.0-1.0; shown as suggestion at >= 0.8
    sample_count      INTEGER NOT NULL DEFAULT 0, -- files observed matching this pattern
    created_at        TEXT NOT NULL,         -- ISO-8601
    last_confirmed_at TEXT                   -- ISO-8601, NULL if user has never confirmed
) STRICT;
"""

# ─── New tables: Destructive Operations Audit Log ─────────────────────────────
# Append-only HMAC-chained log of all L1/L2 destructive operations.
# L3 (whole-drive) is NOT implemented -- users are referred to manufacturer tools.
#
# target_hash: BLAKE3 of the absolute target path (never the raw path -- privacy).
# dry_run_hash: BLAKE3 of the exact dry-run output shown to the user before confirm.

CREATE_DESTRUCTIVE_OPS_LOG = """
CREATE TABLE IF NOT EXISTS destructive_ops_log (
    id            TEXT PRIMARY KEY,          -- UUIDv4
    op_level      TEXT NOT NULL              -- L1=file overwrite, L2=backend removal
                  CHECK(op_level IN ('L1','L2')),
    op_type       TEXT NOT NULL,             -- 'file_overwrite' | 'backend_removal'
    target_hash   TEXT NOT NULL,             -- BLAKE3 of target path (no raw path stored)
    target_label  TEXT NOT NULL,             -- human-readable: filename or drive label
    method        TEXT NOT NULL,             -- 'software_1pass'|'software_3pass'|'backend_deprecated'
    initiated_at  TEXT NOT NULL,             -- ISO-8601 (written BEFORE execution)
    completed_at  TEXT,                      -- ISO-8601, NULL while in_progress
    result        TEXT NOT NULL DEFAULT 'in_progress'
                  CHECK(result IN ('completed','failed','blocked','in_progress')),
    error_detail  TEXT,                      -- NULL on success
    dry_run_hash  TEXT NOT NULL,             -- BLAKE3 of dry-run output shown to user
    session_id    TEXT NOT NULL,             -- session UUIDv4
    hmac_chain    TEXT NOT NULL              -- hex HMAC-SHA512, chained to integrity_log
) STRICT;
"""

# ─── Indexes ──────────────────────────────────────────────────────────────────

CREATE_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_files_path         ON files(path);
CREATE INDEX IF NOT EXISTS idx_files_tombstone    ON files(tombstone, tombstone_at);
CREATE INDEX IF NOT EXISTS idx_files_version_of   ON files(version_of);
CREATE INDEX IF NOT EXISTS idx_chunks_file_id     ON chunks(file_id);
CREATE INDEX IF NOT EXISTS idx_chunks_blake3      ON chunks(blake3_hash, size);
CREATE INDEX IF NOT EXISTS idx_chunk_loc_status   ON chunk_locations(status);
CREATE INDEX IF NOT EXISTS idx_chunk_loc_chunk    ON chunk_locations(chunk_id);
CREATE INDEX IF NOT EXISTS idx_integrity_chunk    ON integrity_log(chunk_id, checked_at);
CREATE INDEX IF NOT EXISTS idx_upload_hist_chunk  ON upload_history(chunk_id);
CREATE INDEX IF NOT EXISTS idx_upload_hist_ts     ON upload_history(timestamp);
CREATE INDEX IF NOT EXISTS idx_secrets_kind       ON secrets_vault(kind);
CREATE INDEX IF NOT EXISTS idx_drive_registry_uuid ON drive_registry(drive_uuid);
CREATE INDEX IF NOT EXISTS idx_smart_history_be   ON smart_history(backend_id, checked_at);
CREATE INDEX IF NOT EXISTS idx_tier_patterns_path ON tier_patterns(path_pattern);
CREATE INDEX IF NOT EXISTS idx_destops_session    ON destructive_ops_log(session_id, initiated_at);
"""

# ─── New tables: Ledger Entries (v5) ──────────────────────────────────────────

CREATE_LEDGER_ENTRIES = """
CREATE TABLE IF NOT EXISTS ledger_entries (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    table_name TEXT NOT NULL,
    row_data   TEXT NOT NULL,
    hmac_link  TEXT NOT NULL
) STRICT;
"""

# ─── HMAC ledger metadata table ───────────────────────────────────────────────
# Stores the running HMAC chain tip so verification can start from the last
# known-good state without replaying every row.

CREATE_HMAC_LEDGER = """
CREATE TABLE IF NOT EXISTS hmac_ledger (
    id            INTEGER PRIMARY KEY CHECK(id = 1),  -- singleton row
    last_hmac     TEXT NOT NULL,          -- hex HMAC-SHA512 of last committed row
    logical_clock INTEGER NOT NULL DEFAULT 0,
    nonce_counter INTEGER NOT NULL DEFAULT 0,
    updated_at    TEXT NOT NULL           -- ISO-8601
) STRICT;
"""

# ─── FTS5 schema (Unified inside main SQLCipher DB) ───────────────────────────

CREATE_FTS5 = """
CREATE VIRTUAL TABLE IF NOT EXISTS files_fts USING fts5(
    file_id,            -- UUIDv4. Indexed so SELECT can return it.
    name,
    path,
    mime_type,
    tags
);
"""

CREATE_FTS_TRIGGER_INSERT = """
CREATE TRIGGER IF NOT EXISTS fts_after_insert AFTER INSERT ON files
BEGIN
    INSERT INTO files_fts(file_id, name, path, mime_type, tags)
    VALUES(new.id, new.name, new.path, new.mime_type, '');
END;
"""

CREATE_FTS_TRIGGER_DELETE = """
CREATE TRIGGER IF NOT EXISTS fts_after_delete AFTER DELETE ON files
BEGIN
    DELETE FROM files_fts WHERE file_id = old.id;
END;
"""

CREATE_FTS_TRIGGER_UPDATE = """
CREATE TRIGGER IF NOT EXISTS fts_after_update AFTER UPDATE ON files
BEGIN
    UPDATE files_fts
    SET name = new.name, path = new.path, mime_type = new.mime_type
    WHERE file_id = new.id;
END;
"""

CREATE_SETTINGS = """
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;
"""

# ─── Convenience list of all DDL statements (applied in order) ────────────────

ALL_DDL: list[str] = [
    CREATE_BACKENDS,        # backends first -- referenced by drive_registry, smart_history, etc.
    CREATE_FILES,
    CREATE_CHUNKS,
    CREATE_CHUNK_LOCATIONS,
    CREATE_UPLOAD_HISTORY,
    CREATE_CONTACTS,
    CREATE_SHARES,
    CREATE_SHARING_AUDIT_LOG,
    CREATE_INDEX_SNAPSHOTS,
    CREATE_INTEGRITY_LOG,
    CREATE_HMAC_LEDGER,
    CREATE_LEDGER_ENTRIES,
    # v4 tables ---
    CREATE_SECRETS_VAULT,
    CREATE_DRIVE_REGISTRY,   # references backends(id)
    CREATE_SMART_HISTORY,    # references backends(id)
    CREATE_TIER_PATTERNS,
    CREATE_DESTRUCTIVE_OPS_LOG,
    CREATE_FTS5,
    CREATE_FTS_TRIGGER_INSERT,
    CREATE_FTS_TRIGGER_DELETE,
    CREATE_FTS_TRIGGER_UPDATE,
    CREATE_SETTINGS,
    *CREATE_INDEXES.strip().split(";\n"),   # one statement per index
]

# ─── Schema version (for future migrations) ───────────────────────────────────

SCHEMA_VERSION = 10

CREATE_SCHEMA_VERSION = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
) STRICT;
"""


