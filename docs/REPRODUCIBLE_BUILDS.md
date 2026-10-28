# Reproducible Builds & Signed Releases

This document explains how GhostDrive releases are built, signed, and
verified — and, just as importantly, what is *not* yet reproducible. It
pairs with the honest-adversary framing of [THREAT_MODEL.md](THREAT_MODEL.md)
(section AD-6, supply chain) and with the updater's behaviour described in
[REMOTE_ACCESS.md](REMOTE_ACCESS.md).

## 1. Why signed releases matter for an E2EE product

For an end-to-end-encrypted drive, the client *is* the security boundary:
it holds the Master Key and performs every encryption. The threat model
states it plainly (§5.1): a modified GhostDrive client can exfiltrate the
passphrase, the Master Key, or plaintext — encryption protects nothing if
the attacker controls the encryptor. A PyPI compromise, a tampered build
machine, or a hostile mirror serving a "GhostDrive installer" all win by
swapping the client, and until now nothing in the repo could detect that
(THREAT_MODEL.md AD-6, residual risk 2).

Signing closes the *provenance* half of that gap: every release artifact
is accompanied by a detached Ed25519 signature made with an offline key,
and verifiers — humans rebuilding from source, and the updater at runtime
— refuse anything that does not verify. It does not close the safety half;
see the trust model in §7.

## 2. Quickstart (three commands, run from the repo root)

```powershell
# 1. ON AN OFFLINE MACHINE — generate the signing keypair once.
py -3.12 scripts/keygen_release_key.py --out-dir release_keys
#    → prints a fingerprint; compare it OUT-OF-BAND before publishing
#      release_public.pem (see §5).

# 2. ON THE SIGNING MACHINE (has git + the private key) — build + sign.
py -3.12 scripts/release.py --private-key release_keys/release_private.pem
#    → dist/ghostdrive-<version>-src.zip + .sha256 + .sig + SHA256SUMS.txt(.sig)
#    The version comes from --version, else the exact v* tag at HEAD,
#    else ghostdrive/__init__.py::__version__ (the single source of truth).

# 3. ANYWHERE ELSE — verify what you downloaded.
py -3.12 scripts/verify_release.py --public-key release_keys/release_public.pem --dist dist/
#    → per-file PASS/FAIL table; exit code 0 = all pass.
```

`verify_release.py` is also a library: `verify_artifact(artifact, public_key_pem)`
returns `{"ok", "sha256", "sha256_ok", "signature_ok", "error"}`.

## 3. What IS reproducible today

The source archive `ghostdrive-<version>-src.zip` is byte-deterministic:

- **Content comes from the git index**, not the working tree
  (`git ls-files -s` + one `git cat-file --batch` round-trip). CRLF
  checkout translation on Windows, uncommitted local edits, and untracked
  files cannot change a single byte of the artifact.
- **Every zip field that zipfile would derive from the host is pinned**:
  paths sorted, fixed 1980-01-01 timestamp, `create_system` forced to
  Unix regardless of build host, permissions taken from the git mode,
  ZIP_DEFLATED at a fixed compression level 9.
- **The build runs twice** into scratch directories and compares the two
  sha256s; any nondeterminism fails the release loudly
  (`release.py`, "double-build check"). A second run on another machine
  with the same commit and the same zlib should produce the identical
  sha256 — that is the property to actually test before trusting it.
- A mid-merge (unmerged index) checkout refuses to build rather than
  archiving a conflicted tree.

Caveats, stated honestly: deflate output can differ between zlib builds,
so byte-identity across *toolchain versions* is not guaranteed — pin your
zlib/Python if you intend to compare hashes across machines. Submodule
gitlinks are excluded (only this repo's tracked files are archived).

## 4. What is NOT reproducible yet — the shipped binary

The PyInstaller bundle (`ghostdrive.spec`, `scripts/build_windows.ps1`)
and the Inno Setup installer are **not** byte-identical across builds:
the packer embeds timestamps, host paths, and toolchain-dependent bytes.
Mitigations, in decreasing order of strength:

1. **Pin the toolchain**: Python version + PyInstaller + Inno versions,
   installed from `poetry.lock` on a clean build machine or container.
2. **Set `SOURCE_DATE_EPOCH`** to the release commit's timestamp before
   packaging; tools that honour it clamp embedded timestamps, shrinking
   (not eliminating) the variance.
3. **Sign whatever binary you ship anyway.** A signature is not
   reproducibility and reproducibility is not a signature: publishing
   `GhostDrive-<version>-setup.exe` + `.sig` + sha256 lets every user
   verify provenance of the exact bytes you shipped, even while a
   third-party rebuild can only *approximate* them.

The source archive is the reproducible unit; the binary is the signed
unit. Both properties belong in a real release, at different strengths.

## 5. Key handling

- The private key is written **without a passphrase** (automation needs
  unattended signing on the offline box; the file gets a best-effort
  chmod 0o600 and a printed `icacls` hint instead). Anyone holding
  `release_private.pem` can sign releases every verifier will trust.
- **Keep it offline.** Never on the build host, never on the web host,
  never in git. The build machine only needs the *public* key.
- `keygen_release_key.py` refuses to overwrite existing keys without
  `--force` — an accidental second run must not silently rotate the key.
- **Fingerprints travel out-of-band**: the fingerprint is sha256 over the
  raw 32-byte public key, printed colon-grouped. Confirm it via a second
  independent channel (signed commit, release notes, a phone call) before
  anyone trusts a downloaded `release_public.pem`.
- **Rotation**: generate a new key, publish the new fingerprint through
  the same out-of-band channel, and update the distributed/trusted
  public key. The `.sig` format carries `pubkey_sha256`, so a signature
  made by a *stale or foreign* key fails closed before any crypto runs
  (`updater.verify_release_signature`, the key-rotation guard).

## 6. The `.sig` format

One small JSON document per artifact, next to it (`<artifact>.sig`):

```json
{"algo": "ed25519",
 "sig": "<base64 of the raw 64-byte Ed25519 signature over the exact artifact bytes>",
 "pubkey_sha256": "<hex sha256 of the raw 32-byte public key>",
 "artifact": "<filename — informational only>",
 "sha256": "<hex — informational only>"}
```

Verifiers must hash the bytes they actually received and never trust the
informational fields; only `algo`, `sig` and `pubkey_sha256` are checked
(`ghostdrive/platform/updater.py::verify_release_signature`).

## 7. How the updater checks signatures at runtime (and the trust model)

Set the env var `GHOSTDRIVE_RELEASE_PUBKEY` to the path of the trusted PEM
public key (env var rather than a settings key so verification works
before — and without — an unlocked vault, and so an operator can set it
system-wide). With it set, `stage_download` performs the sha256 check as
before and then fetches `<download-url>.sig` and verifies it; on any
failure the partial file is deleted and the update aborts with
`SignatureError`. With the env var unset — the default — behaviour is
byte-for-byte the legacy sha256-only path. If the env var is set but no
`.sig` accompanies the download, the updater logs a loud warning and
accepts on sha256 alone; that fallback exists today and disappears when
signature checking becomes the default — it is opt-in now and will be
enforced by default once key distribution is established.

**Trust model, stated precisely**: a valid signature proves the artifact
was produced by whoever holds the release private key — it does **not**
prove the code is safe, audited, or free of backdoors. A compromised
signing key means an attacker signs malware that every verifier trusts;
the offline key, out-of-band fingerprint, and auditable source archive
exist to make that attack expensive, not impossible. Pair this document
with THREAT_MODEL.md: signatures address AD-6 (supply chain) at the
distribution layer, while the crypto stack defends the data itself.
