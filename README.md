# GhostDrive

> **Encrypted, redundant, multi-backend personal cloud drive.**
> BCA Final Year Project 2026–27 — Anand K S

GhostDrive turns free-tier accounts on existing internet services into a unified,
encrypted, redundant personal cloud drive. No dedicated server required. Storage
backends only ever receive client-side-encrypted ciphertext under random object
names. Note that classic `/s/{token}` share links are streamed server-decrypted
by the local app (see [Security Model](#security-model)).

## Supported Backends

| Backend | Type | Description |
|---|---|---|
| Telegram | Cloud | MTProto channel storage via Telethon |
| Discord | Cloud | Bot-channel storage via discord.py |
| Local Folder Locker | Local | Encrypted offline vault (no network required) |
| NAS (Network Attached) | Local / LAN | SFTP or SMB/CIFS storage |
| External Drive | Hardware | Removable USB/external drive registration |

## Features

- Real end-to-end encrypted upload/download (ChaCha20-Poly1305, one tag per chunk)
- Reed-Solomon erasure coding (zfec 4+2) for CRITICAL/IMPORTANT tiers
- Tier-aware routing: CRITICAL (4x), IMPORTANT (3x), DISPOSABLE (2x)
- Trash with restore, file versions, tags, and permanent purge
- BLAKE3 integrity verification and background scrub/repair
- Worst-case durability contract with failure-domain placement, what-if loss simulation, and domain-aware repair/evacuation
- AES-256-GCM encrypted index snapshots replicated across failure domains, with one-click restore and periodic restore drills
- Always-on protection sets that mirror local folders into the vault and re-upload changed files
- Passcode-protected, expiring public share links — zero-knowledge `/e/{token}`
  envelope links (recommended) or classic `/s/{token}` (server-decrypted)
- Encrypted secrets vault (passwords, notes, API keys, TOTP)
- SQLite-backed analytics, backend health, telemetry, and smart throttling
- Headless CLI companion for scripts, CI, and notebooks

## Cryptographic Stack

- **Argon2id** — Passphrase → keystore key (auto-calibrated at vault creation and
  passphrase change; unlocks reuse the stored parameters)
- **BIP39 256-bit** — Master Key encoded as a 24-word seed phrase
- **HKDF-SHA512** — Master Key → isolated subkeys
- **ChaCha20-Poly1305** — Chunk streaming (single Poly1305 tag per chunk)
- **AES-256-GCM** — Key wrapping, keystore and credential encryption
- **BLAKE3** — Chunk integrity hash / dedup key
- **HMAC-SHA512** — SQLite ledger chain integrity

## Requirements

- Python 3.11+ (3.12 recommended)
- SQLCipher for an encrypted index (see
  [`docs/setup_sqlcipher_windows.md`](docs/setup_sqlcipher_windows.md))
- Optional ML-KEM-768 for post-quantum sharing
  (see [`docs/setup_liboqs.md`](docs/setup_liboqs.md))

## Setup

```bash
# Install Poetry, then project + backend/web extras
pip install poetry
poetry install --with backends,web

# Run the test suite
poetry run pytest tests/ -v
```

## Run

```bash
# Web interface (opens http://127.0.0.1:8000)
poetry run ghostdrive

# Headless CLI
poetry run ghostdrive-cli init                 # create vault, print seed phrase
poetry run ghostdrive-cli status
poetry run ghostdrive-cli upload ./file.bin --tier IMPORTANT
poetry run ghostdrive-cli ls /docs
poetry run ghostdrive-cli download <id-or-name> -o ./restored.bin
poetry run ghostdrive-cli share <id-or-name> --ttl-hours 24 --passcode secret
poetry run ghostdrive-cli backends --test
poetry run ghostdrive-cli verify <id-or-name>
poetry run ghostdrive-cli doctor
```

Set `GHOSTDRIVE_DATA_DIR` to use a custom vault/data directory and
`GHOSTDRIVE_PASSPHRASE` to unlock non-interactively.

## Notes on Platform-Specific Dependencies

- **SQLCipher (`sqlcipher3`)**: required for database encryption. Without it the
  app runs with an unencrypted index and logs a warning. See
  [`docs/setup_sqlcipher_windows.md`](docs/setup_sqlcipher_windows.md).
- **FTS search index**: the full-text search index is an FTS5 virtual table
  (`files_fts`) living **inside the main database**, kept in sync by triggers
  (`schema.py::CREATE_FTS5`). It is therefore encrypted whenever SQLCipher is
  active and plaintext only in the same no-SQLCipher fallback as the rest of
  the index. It is local-only and never synced to backends. See
  [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) (Threat 1.3).
- **`mlkem` / liboqs**: optional, only for PQ sharing helpers. See
  [`docs/setup_liboqs.md`](docs/setup_liboqs.md).
- **blake3**: pre-built wheels are available for Windows/Linux/macOS.

## Security Model

- Storage backends see only client-side-encrypted ciphertext under random object
  names — never file plaintext or real filenames. Share links, by contrast:
  zero-knowledge `/e/{token}` links are decrypted only in the recipient's
  browser (server sees ciphertext only), while classic `/s/{token}` links
  stream server-decrypted content to the token holder and require the
  unlocked vault
- Master Key is a lifetime credential — loss of the passphrase and every copy of
  the key (seed phrase, recovery shares) is unrecoverable by design
- Key and crypto-material comparisons use `hmac.compare_digest` (constant-time);
  share-token lookup is an indexed DB equality match — timing surface bounded by
  the token's 192-bit entropy (`secrets.token_urlsafe(24)`)
- Streaming crypto in 64 KB blocks; web uploads spool to a temporary file that is
  deleted after the encrypted pipeline commits
- Residual risks (memory disclosure, metadata leakage, no transport pinning,
  classic-link plaintext) are documented in
  [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)

## What's new (unreleased)

Features that landed after the phase plan below. Security claims are verified in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md); test coverage notes in
[`docs/TESTING.md`](docs/TESTING.md).

- **Recovery**: Shamir 3-of-5 recovery kit (`.gdshare` files); offline
  `ghostdrive-restore` tool
- **Portability**: single-file `.gdvault` export/import to move a vault between
  machines
- **Sharing**: zero-knowledge `/e/{token}` links — PBKDF2-600k passphrase wrap,
  browser-side AES-256-GCM
- **Reliability**: adaptive erasure coding (4+2/4+4), repair/retention windows,
  immutable offsite snapshot copies, withholding-backend detection
- **Restore drills**: periodic snapshot restore checks with status badge and
  alerting
- **Sync & history**: real-time folder sync with version snapshots
- **Backends**: S3-compatible object storage
- **App & ops**: system tray, PWA offline shell, opt-in update checker,
  GitHub Actions CI (new — not yet battle-tested)

## Development Phases

| Month | Phase | Status |
|---|---|---|
| 1 | Crypto Core | Complete |
| 2 | Chunking + Database | Complete |
| 3 | Backend Layer + Telemetry | Complete |
| 4 | Storage Backends & Refinements | Complete |
| 5 | Reliability Systems | Complete |
| 6 | Web Core | Complete |
| 7 | Polish + Operations | Complete |
| 8 | Sharing + Erasure Coding | Complete |
| 9 | Testing + Hardening | Complete |
| 10 | Submission | In progress |
