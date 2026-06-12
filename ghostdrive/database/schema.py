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
    logical_clock INTEGER NOT NULL DEFAULT 0
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
    type              TEXT NOT NULL,        -- 'telegram'|'github'|'discord'|...
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
    satellite         TEXT,                 -- Storj: 'US1'|'EU1'|'AP1', NULL for others
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
    id          TEXT PRIMARY KEY,           -- UUIDv4
    nickname    TEXT NOT NULL,
    public_key  TEXT NOT NULL,              -- hex ML-KEM-768 public key
    fingerprint TEXT NOT NULL UNIQUE,       -- SHA-256 of public key, hex
    added_date  TEXT NOT NULL,              -- ISO-8601
    trust_level TEXT NOT NULL DEFAULT 'untrusted'
                CHECK(trust_level IN ('trusted','untrusted'))
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
"""

# ─── HMAC ledger metadata table ───────────────────────────────────────────────
# Stores the running HMAC chain tip so verification can start from the last
# known-good state without replaying every row.

CREATE_HMAC_LEDGER = """
CREATE TABLE IF NOT EXISTS hmac_ledger (
    id          INTEGER PRIMARY KEY CHECK(id = 1),  -- singleton row
    last_hmac   TEXT NOT NULL,          -- hex HMAC-SHA512 of last committed row
    row_count   INTEGER NOT NULL DEFAULT 0,
    updated_at  TEXT NOT NULL           -- ISO-8601
) STRICT;
"""

# ─── Convenience list of all DDL statements (applied in order) ────────────────

ALL_DDL: list[str] = [
    CREATE_BACKENDS,        # backends first -- referenced by chunk_locations, etc.
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
    *CREATE_INDEXES.strip().split(";\n"),   # one statement per index
]

# ─── FTS5 schema (ghostdrive_search.fts -- separate unencrypted DB) ───────────

CREATE_FTS5 = """
CREATE VIRTUAL TABLE IF NOT EXISTS files_fts USING fts5(
    file_id,            -- UUIDv4. Indexed so SELECT can return it.
    name,
    path,
    mime_type,
    tags
    -- No content='' : we store content in the FTS index for full retrieval.
    -- The index is local-only and rebuildable from ghostdrive.db (spec §8.1).
);
"""

# ─── Schema version (for future migrations) ───────────────────────────────────

SCHEMA_VERSION = 1

CREATE_SCHEMA_VERSION = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
) STRICT;
"""
