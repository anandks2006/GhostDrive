# GhostDrive

> **Encrypted, redundant, multi-backend personal cloud drive.**
> BCA Final Year Project 2026–27 — Anand K S

GhostDrive turns free-tier accounts on existing internet services into a unified, encrypted, redundant personal cloud drive. No dedicated server required. No backend ever sees plaintext data.

## Supported Backends (Phase 1)
| Backend | Free Tier | Tier |
|---|---|---|
| Telegram | Unlimited | CRITICAL |
| GitHub Releases | ~5 GB/repo | IMPORTANT |
| Discord | Unlimited | IMPORTANT |
| Mega.nz | 20 GB | CRITICAL |
| Hugging Face | Unlimited | IMPORTANT |
| Backblaze B2 | 10 GB | IMPORTANT |
| Cloudflare R2 | 10 GB | IMPORTANT |
| Storj | 25 GB | IMPORTANT |
| Archive.org | Unlimited | DISPOSABLE |
| IPFS | Unlimited | IMPORTANT |

## Cryptographic Stack
- **Argon2id** — Passphrase → keystore key (auto-calibrated to ~1s, once per session)
- **BIP39 256-bit** — Master Key encoded as 24-word seed phrase
- **HKDF-SHA512** — Master Key → subkeys (fixed info strings, cryptographically isolated)
- **ChaCha20-Poly1305** — Chunk streaming (single Poly1305 tag per chunk, NOT per 64 KB block)
- **AES-256-GCM** — Key wrapping, keystore encryption
- **BLAKE3 + file_size** — Dedup key (pre-compression hash, fixed zstd level 3)
- **HMAC-SHA512** — SQLite ledger chain integrity

## Development Phases
| Month | Phase | Status |
|---|---|---|
| 1 | Crypto Core | ✅ Complete |
| 2 | Chunking + Database | ✅ Complete |
| 3 | Backend Layer + Telemetry | ✅ Complete |
| 4 | Remaining Backends + CLI | ✅ Complete |
| 5 | Reliability Systems | ✅ Complete |
| 6 | GUI Core | ✅ Complete |
| 7 | Polish + Operations | 🔜 |
| 8 | Sharing + Erasure Coding | 🔜 |
| 9 | Testing + Hardening | 🔜 |
| 10 | Submission | 🔜 |

## Setup

```bash
# Install Poetry
pip install poetry

# Install dependencies
poetry install

# Run tests
poetry run pytest tests/ -v
```

## Notes on Platform-Specific Dependencies

- **SQLCipher (`sqlcipher3`)**: Required for database encryption. On Windows, use the pre-built wheel from `sqlcipher3-binary` or install via `pip install sqlcipher3-binary`. See `docs/setup_sqlcipher_windows.md`.
- **`liboqs` (ML-KEM-768)**: Required for Phase 2 sharing. Requires the liboqs C library compiled from source. See `docs/setup_liboqs.md`.
- **blake3**: Pre-built wheels available for Windows/Linux/macOS. Rust toolchain required for source builds.

## Security Model
- Backend providers never see plaintext data
- Master Key is a lifetime credential — loss of both passphrase AND seed phrase is unrecoverable by design
- All secret comparisons use `hmac.compare_digest` (constant-time)
- 64 KB generator streaming — no BytesIO buffers, no intermediate disk writes on upload
