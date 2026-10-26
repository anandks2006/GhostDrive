# GhostDrive Threat Model

This document describes what GhostDrive **actually defends against**, as
implemented in this repository. Every mitigation cites a real file path and
symbol; every claim of protection is followed by an honest statement of
residual risk. Claims that could not be verified from the code are not made.

Terminology used below:

- **Master Key** — the 32-byte random root secret (`MASTER_KEY_BYTES` in
  `ghostdrive/crypto/keystore.py`).
- **Backend** — a storage provider the ciphertext is written to (Telegram,
  Discord, SFTP/SMB NAS, local folder, external drive, S3).
- **Vault data directory** — the local GhostDrive app-data directory holding
  `keystore.json`, `ghostdrive.db`, `nonce_counter.json`, and optionally local
  backend ciphertext.

---

## 1. Assets

| # | Asset | Where it lives | Protected by |
|---|-------|----------------|--------------|
| A1 | **File plaintext** | Only on the source machine during read, and in memory of the intended recipient | ChaCha20-Poly1305 per logical chunk with a fresh monotonic nonce (`ghostdrive/crypto/chunk_crypto.py::ChunkEncryptor`, `ghostdrive/crypto/nonce.py::NonceManager`); key = HKDF-SHA512 subkey `INFO_CHUNK_ENCRYPTION` (`ghostdrive/crypto/hkdf.py::derive_chunk_key`) |
| A2 | **Master Key** | `keystore.json` at rest; `MasterKeyBuffer` (ctypes) while unlocked | Argon2id(passphrase) → AES-256-GCM (`keystore.py::_argon2id_derive`, `_aes_gcm_encrypt`, `KeystoreManager.unlock`); BIP39 24-word seed phrase as offline backup (`entropy_to_mnemonic` / `mnemonic_to_entropy`) |
| A3 | **Keystore payload** (`master_key ‖ hkdf_salt ‖ genesis_seed`, 96 bytes) | `keystore.json` | AES-256-GCM with a fresh random 12-byte nonce per write; Argon2id cost parameters stored in the **cleartext header** of `keystore.json` (`KeystoreManager._write_keystore`); atomic replace via `ghostdrive/utils/fsync.py::atomic_write` |
| A4 | **Share passphrases** | Envelope share links: wrap key only; classic links: server-side passcode hash | Envelope: PBKDF2-HMAC-SHA256 / **600 000** iterations (`ENVELOPE_PBKDF2_ITERATIONS` in `ghostdrive/services/sharing.py`); classic link passcode: PBKDF2-HMAC-SHA256 / **200 000** iterations stored as a hex digest (`_PBKDF2_ITERATIONS`, `_hash_passcode`) |
| A5 | **Backend credentials** (Telegram/Discord tokens, SSH keys, S3 keys) | OS keyring (DPAPI/libsecret/Keychain), never in `ghostdrive.db` | Two layers: OS keyring ACL **and** AES-256-GCM with subkey `INFO_BACKEND_CREDENTIALS` (`ghostdrive/crypto/credential_store.py::_CredentialStore.store`, `ghostdrive/crypto/hkdf.py::derive_backend_credentials_key`); key zeroed on lock (`clear_active_key`) |
| A6 | **Recovery shares** | Up to 5 `.gdshare` files + `ghostdrive-recovery-kit.json` manifest | Shamir's Secret Sharing over GF(2^8), 3-of-5 default (`ghostdrive/crypto/shamir.py::split_secret`; `ghostdrive/services/recovery_kit.py::export_recovery_kit`); manifest carries only a SHA-256 **commitment**, never the secret (`shamir.py::secret_commitment`) |
| A7 | **Local index metadata** (file names, paths, tags, chunk map, nonce counters) | `ghostdrive.db` (SQLite, WAL) | SQLCipher `PRAGMA key` when available (`ghostdrive/database/db.py::_apply_pragmas`); HMAC-SHA512 ledger chain over ledger-tracked tables (`db.py::_LEDGER_TABLES`, `verify_hmac_chain`) — tamper-evident, not tamper-proof |
| A8 | **Nonce counter state** | `nonce_counter.json` or `hmac_ledger.nonce_counter` in SQLite | Persist-before-return ordering with atomic write + fsync (`nonce.py::next_nonce`, steps documented in its docstring); SQLite path runs inside the upload transaction under `db._lock` |
| A9 | **Encrypted index snapshots** | One copy per failure domain on backends (`snapshots.py`) | AES-256-GCM with subkey `INFO_INDEX_BACKUP_ENC`; header (id, timestamp, plaintext BLAKE3) authenticated as AAD (`ghostdrive/services/snapshots.py` module docstring); deterministic chunk name only derivable from the Master Key (`derive_index_backup_name`) |

> **Verified code-vs-spec drift (A3):** the `keystore.py` module header
> describes the HKDF salt and genesis seed as *random 32-byte* values, but
> `KeystoreManager.create_new()` actually derives **both deterministically** as
> `SHA-256(master_key ‖ fixed label)` (lines 435–436). Consequences, stated
> precisely: (a) the 24-word seed phrase alone regenerates salt + genesis on
> recovery for current installs (`recover_from_seed()` re-derives them and
> only warns for *legacy* installs that may have had random ones); (b) the
> "salt" contributes no entropy beyond the Master Key. HKDF salts need not be
> secret, so (b) is not a vulnerability — but comments saying "random" should
> not be read as an extra entropy source.

---

## 2. Adversaries

| Adversary | Summary |
|-----------|---------|
| **AD-1** Local attacker with disk access | Reads the vault data directory on a stolen/lost (powered-off or locked) machine |
| **AD-2** Malicious or withholding storage backend | A cloud/LAN provider that confirms uploads, then corrupts, withholds, or fabricates reads |
| **AD-3** Network attacker | On-path observer between the client and backends, or between the client and share recipients |
| **AD-4** Cloud provider subpoena / provider data request | Legal or insider demand served on a backend provider |
| **AD-5** Ransomware on the live machine | Encrypts/deletes everything it can reach while the user is running GhostDrive |
| **AD-6** Supply-chain attacker | Compromises a PyPI dependency, the lockfile pipeline, or a distributed build artifact |

---

## 3. Threat → Mitigation → Residual risk

### AD-1 — Local attacker with disk access

**Threat 1.1: Offline brute force of `keystore.json` to recover the Master Key.**
- *Mitigation:* Argon2id key derivation with parameters calibrated once at
  first run (`keystore.py::calibrate_argon2id`: memory 64 MB, parallelism
  `min(4, cpu_count)`, `time_cost` tuned toward a ~1 s target) and
  AES-256-GCM authentication of the payload
  (`keystore.py::_aes_gcm_decrypt` raises `AuthenticationError` on any tag
  failure).
- *Residual risk (honest):* The KDF cost is bounded by a ~1 s *software*
  target — deliberately modest against GPU/ASIC crackers. A weak passphrase is
  the weakest link; a well-resourced attacker with the file can attempt
  billions of guesses scaled only by Argon2id's 64 MB / ~1 s cost. The
  cleartext header also tells the attacker exactly what cost to expect.

**Threat 1.2: Reading vault ciphertext directly from disk.**
- *Mitigation:* All chunk bytes are encrypted client-side before upload or
  before being written to a local/external-folder backend
  (`ghostdrive/pipeline/upload.py` pipeline order, steps 6–7; single Poly1305
  tag per chunk verified before any plaintext is released
  (`chunk_crypto.py::ChunkDecryptor.verify_and_decrypt`)).
- *Residual risk:* File **sizes, chunk boundaries, timestamps, and access
  patterns** are visible on disk — chunks are stored content-store style
  under UUID names, not hidden names (e.g. `local_fs_backend.py`:
  `f".{chunk_id}_{sub_block_index:04d}.gdc"`), so an observer sees structure but not
  filenames. An active local attacker can also **delete** data —
  confidentiality only, availability is not guaranteed
  locally (see AD-5).

**Threat 1.3: Recovering file inventory / names from the local index.**
- *Mitigation:* SQLCipher encrypts `ghostdrive.db` with the Master Key
  (`db.py::_apply_pragmas` → `PRAGMA key`).
- *Residual risk (honest, important):*
  1. If `sqlcipher3` / `pysqlcipher3` is not installed, `db.py` silently falls
     back to stock `sqlite3` and stores the index **unencrypted**, logging only
     a warning (`db.py` lines 69–77, 1457–1461). `docs/setup_sqlcipher_windows.md`
     states this plainly ("do not use that mode for real data") and that there
     is **no automatic plaintext→encrypted migration** — an already-created
     vault stays plaintext until you rotate data directories.
  2. Even **with** SQLCipher, the FTS5 search index
     (`ghostdrive/database/fts.py`) is a *separate, unencrypted, local-only*
     SQLite database by design (Spec §8.1): file names, paths, and tags sit in
     plaintext `ghostdrive_search.fts`. It is never synced to backends, but a
     disk-reading attacker gets the file inventory for free.

**Threat 1.4: Recovering key material from RAM / swap / pagefile while unlocked.**
- *Mitigation:* The Master Key lives in a ctypes buffer with explicit
  zeroing (`keystore.py::MasterKeyBuffer.zero`, context-manager exit,
  `__del__`); the passphrase is zeroed immediately after KDF
  (`keystore.py::_zero_if_mutable` called right after `_argon2id_derive`);
  subkeys are derived per-purpose and credential keys are zeroed on lock
  (`credential_store.py::clear_active_key`); workers hold a *reference* to the
  buffer rather than copies where possible.
- *Residual risk (honest):*
  1. **The key is in process memory whenever the keystore is unlocked.** The
     `.key` property returns a fresh `bytes` *copy* on every access, and
     `KeystoreManager.lock()` itself documents that immutable Python `bytes`
     (salt, genesis seed) cannot be reliably zeroed — CPython GC timing is not
     guaranteed (comment at `keystore.py` lines 597–600).
  2. The repository contains **no `mlock`/`VirtualLock`/`GlobalLock` calls**
     (verified by grep), so nothing prevents the OS from paging key material
     to the **pagefile** or writing it to a **hibernation file or crash dump**.
     On Windows, a disk attacker who finds the pagefile/hiberfil after an
     unlocked session may recover key bytes.
  3. `_zero_if_mutable`'s CPython-`bytes` overwrite relies on a hard-coded
     `ob_sval` offset (32/16) and swallows all exceptions — best effort only.

**Threat 1.5: Seed phrase / recovery-share theft.**
- *Mitigation:* First-run forces re-entry of all 24 words with constant-time
  comparison (`keystore.py::verify_and_save`, `hmac.compare_digest`);
  recovery kits carry only shares + a non-reversible commitment; 3-of-5
  threshold means stealing the whole kit directory still yields no key
  (`recovery_kit.py` docstring).
- *Residual risk:* `export_seed_phrase()` displays the seed on screen while
  unlocked (settings panel) — shoulder-surfing or screen-scraping wins.
  Anyone holding **3 of 5 shares, or the seed phrase**, holds the Master Key
  forever; there is no rotation-without-re-encryption story for old data
  (rotating the HKDF salt via `KeystoreManager.rotate_keys` re-encrypts the
  keystore but does not re-encrypt existing chunks).

### AD-2 — Malicious / withholding storage backend

**Threat 2.1: Backend returns corrupted or fabricated chunk bytes.**
- *Mitigation:* Authenticated encryption — `ChunkDecryptor.verify_and_decrypt`
  verifies the Poly1305 tag **first** and raises `AuthenticationError`
  without returning a single plaintext byte; comparison is constant-time
  (`ghostdrive/crypto/compare.py::verify_auth_tag` →
  `hmac.compare_digest`). Background scrubbing re-verifies chunks
  (`ghostdrive/services/resilience.py`, module docstring: "Integrity scrubbing
  and Reed-Solomon shard repair"), recording per-backend results in
  `integrity_log`.
- *Residual risk:* Corruption is **detected**, not prevented: recovery then
  depends on erasure-coded parity or redundant copies actually existing (see
  2.3). A backend serving garbage until scrub day consumes redundancy silently
  in between.

**Threat 2.2: Backend confirms uploads, then withholds data (hostile provider).**
- *Mitigation:* `ghostdrive/services/hostility.py::detect_withholding()`
  correlates `integrity_log` rows **across** backends: a failure is charged to
  a backend only if *another* backend served the same chunk `ok` in the same
  window (the "peer control"; minimum 6 checks / 168 h window by default).
  Confirmed hosts are quarantined by flipping them to the existing
  `deprecated` status, which immediately removes them from upload routing
  (`WHERE status = 'healthy'`).
- *Residual risk (honest):* Detection requires at least one honest peer with a
  recent `ok` on the same chunk. If a chunk's copies all live only on hostile
  backends, or colluding backends fail in unison, the verdict is
  `insufficient_data` — no accusation is made. Quarantine happens **after**
  observed failures, not before; availability damage in the window is real.

**Threat 2.3: Enough backends fail that data is unrecoverable.**
- *Mitigation:* Reed-Solomon erasure coding via zfec (floor 4+2, adaptive
  4+4 — `ghostdrive/pipeline/coding.py`, re-exported through
  `ghostdrive/services/durability.py`); failure domains are *physical*
  (same-disk folders share one domain; NAS grouped by host; Telegram/Discord by
  provider — `durability.py::backend_failure_domain`), and
  `durability.py::audit_readiness()` reports the strongest worst-case
  guarantee: how many independent domains can be lost before a chunk drops
  below the recovery threshold (`MAX_DOMAIN_LOSSES = TOTAL_SHARDS - DATA_SHARDS`).
- *Residual risk:* The module docstring states the deliberate stance: the
  audit "**never estimates a probability**" — it counts domains, it does not
  predict MTBF. If the user places everything on domains that *look* distinct
  but share fate (e.g. two providers behind the same upstream account), the
  audit cannot know. Guarantees stop at `basic` (1 domain) unless the user
  opts into `safe`/`paranoid` contracts requiring offsite copies and restore
  proofs (`CONTRACT_PRESETS`).

**Threat 2.4: Backend learns what the user stores.**
- *Mitigation:* Uploads are addressed by **random UUID chunk ids**
  (`upload.py::chunk_id = _new_uuid()`), never by filename; backend object
  names are derived from those ids
  (`telegram_backend.py`: `f"gd_{chunk_id}_{sub_block_index:04d}.enc"`;
  `discord_backend.py`: `f"gd_{chunk_id[:8]}_{sub_block_index:04d}.enc"`). Payload bytes are
  ChaCha20-Poly1305 ciphertext (erasure shards of it, where coded).
- *Residual risk (honest):* The backend still sees **sizes, counts, timing,
  upload/download frequency, total volume, and the account identity**. The
  Telegram caption embeds `chunk_id[:8]` (`_CAPTION_PREFIX`), which lets a
  provider link API-side Telegram messages to a client's chunk map if it also
  observes metadata. Dedup is computed client-side only
  (`pipeline/dedup.py`, BLAKE3 on original bytes) — the backend never sees the
  dedup key — but identical stored sub-block sizes across accounts can still
  correlate by traffic analysis.

### AD-3 — Network attacker

**Threat 3.1: On-path interception of uploads/downloads.**
- *Mitigation:* Content is encrypted **before it reaches any transport**
  (A1). Transport confidentiality/integrity is delegated to each backend's
  protocol — Telegram MTProto (Telethon), Discord/S3 over HTTPS (httpx),
  SFTP (paramiko/SSH), SMB (smbprotocol), local disk.
- *Residual risk (honest):* GhostDrive performs **no certificate pinning or
  backend identity verification of its own** (grep finds no
  `ssl_context`/`fingerprint` pinning for backend transports; the only
  fingerprint verification in the codebase is the P2P handshake below). TLS
  to HTTPS backends is whatever `httpx`'s defaults provide; SMB without
  signing/encryption is plaintext at the transport layer — but the payload is
  already ciphertext. Precisely stated: **the backend sees chunk ciphertext,
  sizes, UUID object names and timing; it does not see file plaintext or
  real filenames.** Transport attacks can still drop, reorder, or replay
  traffic (integrity of *delivery* — detected at read time by Poly1305, not
  prevented) and observe all metadata.

**Threat 3.2: Attacker on the local UI.**
- *Mitigation:* The web server binds **loopback only**
  (`ghostdrive/web/server.py`: `host = "127.0.0.1"`).
- *Residual risk (honest):* It serves plain HTTP (no `ssl_keyfile` anywhere),
  so the vault passphrase, share links, and — for classic `/s/{token}` links —
  decrypted file bytes cross loopback unencrypted. Any local process or
  browser extension with access to the user's session can observe them.

**Threat 3.3: Attacker against share links.**
- *Mitigation (envelope links):* `/e/{token}` stores one contiguous
  `GDSHARE1` ciphertext blob; the passphrase only wraps a random 32-byte key
  (PBKDF2-600k) and the recipient's browser decrypts via WebCrypto — "the
  server only ever sees ciphertext" (`services/sharing.py` module docstring).
  Segment AAD binds the segment index, so reordering/dropping fails
  authentication in the browser.
- *Residual risk (honest):*
  1. **Classic `/s/{token}` links are zero-knowledge in name only**: they
     stream *server-decrypted* plaintext (`sharing.py` module docstring line 5
     and `create_envelope_link`'s docstring reference to the "same path
     /s/{token} uses" for assembly+decryption). The token is a bearer
     capability: anyone who obtains it receives plaintext over HTTP.
  2. The envelope **passphrase is shown once at creation** and must travel
     out-of-band; if the attacker gets token + passphrase, all bets are off.
  3. The wrap key protects only 32 bytes; PBKDF2-600k is not memory-hard —
     a GPU attacker with the stored envelope blob can grind passphrases at
     PBKDF2 speed (the module docstring acknowledges PBKDF2 "not memory-hard
     anyway").
  4. P2P/Tor transfers authenticate contacts by Ed25519 fingerprint verified
     against the local contacts table (trust-on-first-use)
     (`ghostdrive/pipeline/sharing.py` handshake, lines ~123–141); a poisoned
     contacts table defeats it. If no Tor binary is installed the code falls
     back to a **mock** onion identity (`ghostdrive/utils/tor_manager.py`) —
     dev convenience, not a security mode.

### AD-4 — Cloud provider subpoena

- *Mitigation:* What a provider can hand over is ciphertext only (A1): no
  file plaintext, no real filenames, no dedup keys. Snapshots on backends are
  AES-256-GCM with keys derived from the Master Key and names derived via
  `derive_index_backup_name` — useless without the key (`snapshots.py`).
  `keystore.json`, if seized from the *user*, resists offline attack only as
  far as Argon2id + passphrase strength (AD-1.1). Backend credentials stored
  *at the provider* are the provider's own tokens, not GhostDrive secrets.
- *Residual risk (honest):*
  1. **Metadata is fully disclosed**: volumes, timing graph, file sizes
     (via chunk sizes), account linkage, and — if the same file appears in
     multiple accounts — correlatable sub-block size sequences. Traffic
     analysis is explicitly out of scope (§5).
  2. A subpoena can be extended to the *user's own* provider account backups
     or to compel the provider to serve modified client binaries (see AD-6).
  3. If the user's local machine is also seized, recovery-share files (3 of 5
     enough) or the seed phrase defeat everything by design.

### AD-5 — Ransomware on the live machine

- *Mitigation (confidentiality):* Ransomware that encrypts backend ciphertext
  gains nothing it can read; local/external folder backends hold only
  ciphertext. Nothing readable is stored outside the vault except what the
  user keeps there (see AD-1.3 — the plaintext FTS index and, without
  SQLCipher, the plaintext DB are the exceptions on the metadata plane).
- *Mitigation (recoverability):*
  - Erasure-coded + domain-spread shards (`durability.py`, `upload.py`)
  - Encrypted, immutable index snapshots written to one backend per failure
    domain with restore proofs (`snapshots.py::create_immutable_copy`,
    `SNAPSHOT_TARGET_DOMAINS = 4`)
  - Periodic restore drills (`ghostdrive/services/restore_drills.py`;
    age thresholds in `durability.py::RESTORE_PROOF_MAX_AGE_DAYS`)
  - Tamper-evident HMAC ledger + `PRAGMA synchronous = FULL` specifically to
    prevent a power-loss (or malicious) nonce-counter corruption — the comment
    at `db.py::_apply_pragmas` calls nonce reuse "catastrophic" and mandates
    FULL over NORMAL for that reason
  - Ransomware cannot usefully modify a share that is being uploaded: the
    OS file lock (below) detects contention — though only *advisory*.
- *Residual risk (honest):*
  1. **Single-machine trust:** the nonce counter, keystore, DB, and credential
     keys all live on one machine. An attacker with write access to the vault
     data directory can **roll back `nonce_counter.json` or the SQLite row** —
     the fsync ordering protects against crashes, **not against a deliberate
     rollback by an active attacker**. A rewound counter means nonce reuse
     under the same chunk key (see `nonce.py` contract and
     `chunk_crypto.py` "catastrophic" note). The counter is persisted, not
     signed.
  2. Ransomware that deletes local data first removes the local copies of
     snapshots; recovery then depends entirely on offsite backends having been
     provisioned (the `basic` contract does *not* require offsite —
     `CONTRACT_PRESETS`).
  3. `FileLock` is best-effort by spec: if acquisition fails it
     **proceeds without a lock** and flags the record
     `uploaded-without-integrity-lock` (`ghostdrive/pipeline/file_lock.py::
     _warn_and_skip`, module docstring). On Windows the lock is taken on a
     1-byte **sidecar file** (`{name}.gdl`) via `LockFileEx`, not on the data
     file (`_acquire_windows`), because Windows byte-range locks are
     mandatory and would deny GhostDrive's own readers. A concurrent modifier
     can therefore still change a file mid-upload; the pre-upload BLAKE3 pass
     (`_compute_blake3_chunk`) and the encryption read are two separate reads
     (TOCTOU window) — mitigated, not eliminated.

### AD-6 — Supply chain

- *Mitigation:* All Python dependencies are declared in `pyproject.toml` and
  pinned by `poetry.lock` (including `content-hash` validation); the crypto
  stack is small and standard (cryptography, argon2-cffi, mnemonic, blake3,
  zstandard, zfec, Telethon, discord.py, paramiko, smbprotocol). Tests run on
  every push (`.github/workflows/ci.yml`) so upstream behavioral changes tend
  to surface early. liboqs (ML-KEM) is deliberately *outside* the lockfile and
  installed manually (`pyproject.toml` comment; `docs/setup_liboqs.md`).
- *Residual risk (honest):*
  1. **No signature verification or attestation** of `poetry.lock`, package
     artifacts, or releases. A PyPI compromise of any installed package runs
  code with access to the unlocked key material.
  2. Distributed binaries (PyInstaller spec and Inno Setup installer, both
     asserted by `tests/test_packaging.py`) shift trust to the build machine;
     there is no reproducible-build or signing workflow in this repo.
  3. `poetry install` resolves from PyPI at install time — an attacker who
     compromises the lockfile *in-repo* (e.g. via a malicious PR) also wins;
     that is what CI review is for.

---

## 4. Trust boundaries

```
                         TRUST BOUNDARY 1            TRUST BOUNDARY 2
                        (your machine: keys)         (network: ciphertext)
  +-----------------------------------------+     +--------------------------+
  |  USER                                 |     |                          |
  |   |  passphrase / 24-word seed        |     |   BACKEND PROVIDERS      |
  |   v                                   |     |   - Telegram / Discord   |
  |  +-------------------+                |     |   - NAS (SFTP / SMB)     |
  |  | keystore.json     |  Argon2id      |     |   - Local folder / USB   |
  |  | (AES-256-GCM)     |<----passphrase |     |   - S3                    |
  |  +---------+---------+                |     |   sees:                  |
  |            | unlock                   |     |     * chunk CIPHERTEXT   |
  |            v                          |     |     * UUID object names  |
  |  +-------------------+  HKDF-SHA512   |     |     * sizes / timing     |
  |  | MasterKeyBuffer   |--------------+ |     |     * account identity   |
  |  | (ctypes, zeroed)  |              | |     |   never:                 |
  |  +---------+---------+              | |     |     * file plaintext     |
  |            |                        | |     |     * real filenames     |
  |            v                        | |     |     * Master Key / salt  |
  |  +-----------------------------+    | |     |     * share passphrases  |
  |  | pipeline/upload.py          |    | |     +------------+-------------+
  |  | BLAKE3 dedup -> zstd ->     |    | |                  |
  |  | ChaCha20-Poly1305 stream    |----|-|------------------+  TB2: payload is
  |  | (nonce = fsync'd counter)   |    | |                         already
  |  +--------------+--------------+    | |                         ciphertext
  |                 |                   | |                  +----v-----------+
  |  +--------------v--------------+    | |  HTTPS/MTProto/   | TRANSPORT     |
  |  | ghostdrive.db (SQLCipher or |    | |  SSH/SMB -------> | (TLS/MTProto/ |
  |  | plaintext fallback!)        |    | |                   |  SSH per      |
  |  | + ghostdrive_search.fts     |    | |                   |  backend; NO  |
  |  | | (ALWAYS plaintext, local) |    | |                   |  pinning here)|
  |  +------------------------------+   | |                   +--------------+
  |  | OS keyring: backend creds   |    | | TB1: keys, passphrase and
  |  | (AES-GCM under Master Key)  |    | |      plaintext never cross it
  |  +------------------------------+   | |
  |  | web UI: 127.0.0.1 plain HTTP|<---+ |  TB3: classic /s/ links stream
  |  +------------------------------+    | |      server-decrypted plaintext;
  |  | recovery shares (.gdshare)  |     | |      envelope /e/ links do not
  |  | 3-of-5 Shamir, offline      |     | +-----------------------------+
  |  +-----------------------------+     |
  +-----------------------------------------+
         single-machine trust domain
```

- **TB1** — Key material, passphrase, and decrypted plaintext stay inside this
  boundary. Everything that crosses it is ciphertext (except the classic
  `/s/` share stream, TB3, which is a *deliberate* plaintext disclosure to a
  bearer-token holder).
- **TB2** — Backend API. Payload already encrypted client-side; only metadata
  and ciphertext cross.
- **TB3** — Recipient-facing share channel: envelope links are zero-knowledge
  end-to-end; classic links are decrypted by the local server and are not.

---

## 5. What GhostDrive explicitly does NOT defend against

1. **A malicious or tampered client binary.** The client holds the keys and
   does all the encryption; a modified GhostDrive can exfiltrate the Master
   Key, passphrase, or plaintext. Nothing in the repo signs or verifies the
   client (see AD-6 for the binary-distribution gap).
2. **OS compromise while unlocked.** Any process that can read the
   GhostDrive process's memory (debugger, DLL injection, credential dump)
   or read keystrokes obtains the passphrase or Master Key. Memory is
   zeroed *best-effort*, never locked (no `mlock`/`VirtualLock`).
3. **Pagefile / hibernation / crash-dump leakage** of unlocked key material —
   not scrubbed, not prevented (documented residual risk, AD-1.4).
4. **Traffic analysis of backend API calls.** Sizes, timing, volumes, and
   account linkage are inherently visible to providers and on-path observers;
   chunk UUIDs are random, but *sequence-of-sizes* correlation across accounts
   is not addressed.
5. **Availability / deletion by providers or attackers.** Redundancy raises
   the cost of destruction; it does not prevent it (AD-2.3, AD-5).
6. **Colluding backends.** Withholding attribution needs an honest peer
   control (`hostility.py`); unanimous hostility yields `insufficient_data`.
7. **Weak passphrases.** Argon2id/PBKDF2 raise the guess cost; they do not
   save "password123".
8. **Cold-boot / DMA / physical attacks on a running machine**, beyond the
   best-effort ctypes zeroing.
9. **Losing both the passphrase and the seed/recovery shares** — unrecoverable
   by design (README "Security Model").
10. **Side channels** (cache-timing in shared tenancy). Secret *comparisons*
    are constant-time (`hmac.compare_digest` throughout `crypto/compare.py`,
    `shamir.py::_ct_eq`), but GF(2^8) table lookups in `shamir.py::_gf_mul`
    are not, and no constant-time discipline is claimed for field arithmetic.
11. **Secrets outside the vault.** The artifact cleaner exists precisely
    because OS metadata leaks: see below.

**Windows artifact leakage — what `platform/artifact_cleaner` does and does
not cover** (abstract base: `ghostdrive/platform/artifact_cleaner.py`;
implementations under `ghostdrive/platform/windows|linux|macos/`):

- *Does:* at setup, excludes the data directory from indexing and writes
  `.nomedia` / `.metadata_never_index` markers; on demand, audits and removes
  thumbnail-cache entries, recent-file/MRU entries (Windows `RecentDocs`
  registry keys pruned), and search-index hits for explicitly marked plaintext
  files outside the vault. On Windows it deletes whole `thumbcache_*.db`
  files (Windows rebuilds them for other files).
- *Does NOT cover:* pagefile/hibernation/crash dumps, shellbags, USN journal /
  `$MFT`, browser download history or browser caches, application-specific
  recent lists it does not know about, memory contents, or any file the user
  did not explicitly mark. Search-index auditing is best-effort and reports
  `skipped_components` when the indexer is inaccessible. **Coverage gap for
  maintainers:** no file under `tests/` references `artifact_cleaner`
  (grep returns zero matches) — this subsystem is currently untested.

---

## 6. Verification — which tests prove which claims

All paths relative to `tests/`. Only files that exist are listed; mapping was
produced by grepping the suite for the symbols cited above.

| Claim (§) | Proof |
|-----------|-------|
| Argon2id derivation, AES-256-GCM keystore round-trip, BIP39 checksum, `MasterKeyBuffer` zeroing, constant-time compares (A2/A3, AD-1.1) | `test_crypto.py` (header enumerates these coverage targets) |
| ChaCha20-Poly1305 single-tag-per-chunk; no plaintext before auth (A1, AD-2.1) | `test_crypto.py` |
| Nonce counter monotonicity, fsync persistence, restart-resume (A8) | `test_crypto.py::TestNonceManager`, `test_pipeline.py`, `test_month9.py`, `test_adaptive_coding.py` |
| Shamir split/combine, threshold secrecy, tamper/typo detection, commitment (A6) | `test_shamir.py` |
| Recovery-kit export/combine and restore (A6, AD-1.5) | `test_recovery_kit.py`, `test_recovery_api.py` |
| Seed-phrase migration/recovery path | `test_migration_recovery.py` |
| Offline `ghostdrive-restore` tool exists and imports without the web stack | `test_packaging.py::test_recovery_tool_entry_point`, `::test_recovery_tool_imports_without_web_stack` |
| File lock behaviour incl. Windows paths, skipped-lock flag, concurrency (AD-5) | `test_file_lock.py`, `test_month9.py` |
| Upload two-phase commit: pending intent before upload, cancellation cleanup, fail+restore (A8) | `test_pipeline.py` (header) |
| BLAKE3 dedup on original bytes; ref-count semantics | `test_pipeline.py`, `test_database.py` |
| Quota reserve/confirm/restore atomicity | `test_pipeline.py`, `test_database.py` |
| Failure-domain model, worst-case durability audit (AD-2.3) | `test_durability.py` (`audit_readiness`) |
| Withholding detection with peer control (AD-2.2) | `test_offsite_hostility.py::test_detect_withholding_peer_control` (+ `test_alerts.py` wiring) |
| Immutable offsite snapshot copies (AD-5) | `test_offsite_hostility.py` (`snapshots.create_immutable_copy`) |
| Restore drills and staleness/badge reporting (`services/restore_drills.py`, AD-5) | `test_restore_drills.py` |
| Envelope `GDSHARE1` layout; browser-equivalent decryption; wrong passphrase and tampered blob fail (A4, AD-3.3) | `test_share_links.py` (contains a Python mirror of `receive.js`) |
| Share expiry / download caps / revocation; P2P engine over mocked sockets | `test_share_links.py`, `test_sharing_engine.py` |
| HMAC ledger chain, WAL, FTS, tombstones (A7) | `test_database.py` |
| Secrets vault AES-256-GCM + lock zeroes key | `test_secrets_vault.py` |
| Secure-erase overwrite and guard rails | `test_secure_erase.py` |
| NAS/S3 backends are hermetic (no network) — CI safety | `test_nas_backend.py`, `test_s3_backend.py`, `test_local_backends.py` |
| Tray lifecycle without sockets | `test_tray.py` |
| Portable vault `.gdvault` export/import | `test_portable_vault.py`, `test_portable_api.py` |
| Folder sync reconcile + version snapshots | `test_sync.py`, `test_versions.py` |
| Repair/retention windows, healing-queue gating | `test_retention_window.py` |
| Opt-in update checker (off by default) | `test_updater.py` |
| Entry-point scripts / packaging artifacts | `test_packaging.py` |
| Web app routes | `test_web_app.py`, `test_pwa.py` |
| `platform/artifact_cleaner` (all three platforms) | **No test coverage** (gap, AD-5/§5) |
| SQLCipher plaintext fallback path (AD-1.3) | Not exercised by a dedicated test; `test_database.py` imports `sqlcipher3` directly, so CI implicitly requires it installed |

Not collected by default (no `test_*.py` name, or gated):
`integration_backends.py`, `integration_telegram.py`,
`smoke_telegram_backend.py`, `smoke_discord_backend.py` (the two smoke files
are additionally `@pytest.mark.integration` + credential-gated).

**Test-vs-production Argon2 parameters:** `tests/conftest.py` defines
`FAST_ARGON2_PARAMS` (`time_cost=1`, `memory_cost=8192` KB, `parallelism=1`)
and the keystore tests pass it via `create_new(..., argon2_params=...)`. The
suite therefore exercises keystore *logic* at roughly **1/8,000th** of the
production memory cost and never waits for the calibrated ~1 s derivation —
production strength is a runtime property of `calibrate_argon2id()` +
`keystore.json` parameters, not something the test suite proves.

---

**Last verified against commit:** _«TODO: maintainers — this file was written
against an uncommitted working tree; there is deliberately no hash here. After
you verify each claim above against the code, replace this line with
`Last verified against commit: <sha> (YYYY-MM-DD)»` and re-run
`py -m pytest -q --no-header -p no:cacheprovider` (see `docs/TESTING.md`)._
