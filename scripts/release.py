"""release.py -- Build and sign a reproducible GhostDrive source release.

Produces, into ``--out`` (default ``dist/``):

* ``ghostdrive-<version>-src.zip`` — a byte-deterministic archive of every
  git-tracked source file, plus a ``.sha256`` sidecar and a detached
  ``.sig`` Ed25519 signature document;
* ``SHA256SUMS.txt`` (+ ``.sig``) covering every other file in the output
  directory.

Why the archive is reproducible (see docs/REPRODUCIBLE_BUILDS.md for the
full operator story):

* the content of each entry comes from the git INDEX (``git ls-files -s``
  + ``git cat-file --batch``), not from the working tree — so CRLF/autocrlf
  checkout translation and uncommitted local edits cannot change a single
  byte of the artifact;
* paths are sorted, every ``ZipInfo`` gets the fixed DOS timestamp
  (1980-01-01), ``create_system`` is pinned to Unix, permissions are taken
  from the git mode, and compression is ZIP_DEFLATED at a fixed level 9;
* the build is performed TWICE into scratch directories and the two
  sha256s must be identical — nondeterminism (dict ordering, stray
  timestamps, locale effects) fails the release loudly instead of
  shipping a subtly different artifact.

What is NOT reproducible yet: the PyInstaller/Inno Setup *binary*. This
script only signs the source archive; pin the binary toolchain, set
``SOURCE_DATE_EPOCH``, and sign whatever binary you ship anyway (a
signature is not reproducibility, and reproducibility is not a signature —
you want both; the doc explains the trade-off honestly).

Signature document format (``<artifact>.sig``, JSON, one line per key)::

    {"algo": "ed25519",                 # only algorithm accepted
     "sig": "<base64 of 64 raw bytes>", # Ed25519 over the exact artifact bytes
     "pubkey_sha256": "<hex>",          # sha256 of the raw 32-byte public key
     "artifact": "<filename>",          # informational — verifiers hash bytes
     "sha256": "<hex>"}                 # informational — verifiers recompute

Usage (from the repo root, on the signing machine):

    py -3.12 scripts/release.py --private-key release_keys/release_private.pem
    py -3.12 scripts/release.py --private-key ... --version 1.2.3 --out dist/
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ghostdrive.platform.updater import (  # noqa: E402
    SIG_ALGO,
    SignatureError,
    release_pubkey_fingerprint,
    release_pubkey_sha256_hex,
)

# ── Determinism knobs ───────────────────────────────────────────────────────
# Every value below is fixed on purpose; a varying one would break the
# byte-identity the double-build check enforces.
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)  # earliest timestamp the zip format allows
_ZIP_SYSTEM_UNIX = 3  # ZipInfo defaults create_system per-host — pin it, or
                      # Windows-built and Linux-built archives would differ
_ZIP_MODE_FILE = 0o644
_ZIP_MODE_EXEC = 0o755
_COMPRESS_LEVEL = 9
_GITLINK_MODE = "160000"  # submodule entry — not part of the source tree

_ARTIFACT_TPL = "ghostdrive-{version}-src.zip"
_SUMS_NAME = "SHA256SUMS.txt"
_SIG_SUFFIX = ".sig"
_SHA256_SUFFIX = ".sha256"


# ── Version (single source of truth: ghostdrive/__init__.py) ────────────────

def read_source_version(repo_root: Path = REPO_ROOT) -> str:
    """``__version__`` from ``ghostdrive/__init__.py`` — no import needed.

    Read (and regexed) rather than imported so the script works on a bare
    machine with no dependencies installed beyond ``cryptography``, and so
    the value cannot be shadowed by an installed distribution metadata.
    """
    text = (repo_root / "ghostdrive" / "__init__.py").read_text(encoding="utf-8")
    m = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', text, re.MULTILINE)
    if not m:
        raise RuntimeError(f"__version__ not found in {repo_root / 'ghostdrive' / '__init__.py'}")
    return m.group(1)


def git_exact_tag(repo_root: Path = REPO_ROOT) -> Optional[str]:
    """The ``v*`` tag pointing exactly at HEAD, or None.

    None when git is unavailable, the repo has no matching tags, or HEAD
    is not exactly tagged — a ``v1.2.3-4-gabc1234`` describe result is NOT
    a release version and is deliberately not used.
    """
    try:
        proc = subprocess.run(
            ["git", "describe", "--tags", "--match", "v*", "--exact-match"],
            cwd=repo_root, capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def determine_version(explicit: Optional[str], repo_root: Path = REPO_ROOT) -> str:
    """``--version`` argument > exact ``v*`` tag at HEAD > ``__version__``."""
    if explicit and explicit.strip():
        return explicit.strip()
    tag = git_exact_tag(repo_root)
    if tag:
        return tag[1:] if tag.startswith("v") else tag
    return read_source_version(repo_root)


# ── Source tree from the git index ──────────────────────────────────────────

def _git_index_entries(repo_root: Path) -> list[tuple[str, str, str]]:
    """``(path, git-mode, blob-sha)`` for every tracked file, sorted by path.

    Content-addressed by design: reading the index (not the working tree)
    makes the archive a function of the *committed* tree — checkout line-
    ending translation, local edits and untracked files are all invisible.
    """
    proc = subprocess.run(
        ["git", "ls-files", "-s", "-z"],
        cwd=repo_root, capture_output=True, check=True,
    )
    entries: list[tuple[str, str, str]] = []
    unmerged: list[str] = []
    for record in proc.stdout.split(b"\0"):
        if not record:
            continue
        meta, tab, path_b = record.partition(b"\t")
        parts = meta.split()  # "<mode> <sha> <stage>"
        if not tab or len(parts) != 3:
            raise RuntimeError(f"unexpected git ls-files output: {record!r}")
        mode, sha, stage = (p.decode("ascii") for p in parts)
        path = path_b.decode("utf-8", "surrogateescape")
        if stage != "0":
            # Unmerged (mid-merge) index: releasing a conflicted tree is
            # never what the operator meant — refuse rather than guess.
            unmerged.append(path)
            continue
        if mode == _GITLINK_MODE:
            continue  # submodule pointer — not part of this source tree
        entries.append((path, mode, sha))
    if unmerged:
        raise RuntimeError(
            f"unmerged index entries — resolve the merge before releasing: {unmerged}"
        )
    if not entries:
        raise RuntimeError("git ls-files returned nothing — not a GhostDrive checkout?")
    entries.sort(key=lambda e: e[0])
    return entries


def git_tracked_blobs(repo_root: Path = REPO_ROOT) -> list[tuple[str, str, bytes]]:
    """``(path, git-mode, blob bytes)`` for every tracked file, sorted.

    Blobs are read in one ``git cat-file --batch`` round-trip (index
    content, byte-for-byte what a fresh clone would check out).
    """
    entries = _git_index_entries(repo_root)
    request = "".join(f"{sha}\n" for _, _, sha in entries).encode("ascii")
    proc = subprocess.run(
        ["git", "cat-file", "--batch"],
        cwd=repo_root, input=request, capture_output=True, check=True,
    )
    out = proc.stdout
    blobs: list[tuple[str, str, bytes]] = []
    pos = 0
    for path, mode, _sha in entries:
        header_end = out.find(b"\n", pos)
        if header_end == -1:
            raise RuntimeError(f"git cat-file --batch: truncated header for {path}")
        header = out[pos:header_end].split()  # "<sha> blob <size>"
        if len(header) != 3 or header[1] != b"blob":
            raise RuntimeError(
                f"unexpected cat-file header for {path}: {out[pos:header_end]!r}"
            )
        size = int(header[2])
        body = out[header_end + 1: header_end + 1 + size]
        if len(body) != size:
            raise RuntimeError(f"git cat-file --batch: truncated body for {path}")
        pos = header_end + 1 + size + 1  # skip body + its trailing newline
        # Note: a symlink (mode 120000) stores its *target path* as blob
        # content; we archive that as a regular entry — the reproducible
        # unit is the git content, not a recreated filesystem object.
        blobs.append((path, mode, body))
    return blobs


def build_source_zip(zip_path: Path, blobs: list[tuple[str, str, bytes]],
                     version: str) -> str:
    """Write the deterministic source zip; return its sha256 (hex).

    Every field that zipfile would otherwise derive from the host (wall
    clock, create_system, working-tree bytes) is pinned explicitly — see
    the determinism knobs at the top of this module.
    """
    prefix = f"ghostdrive-{version}/"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path, mode, data in blobs:
            info = zipfile.ZipInfo(filename=prefix + path, date_time=ZIP_TIMESTAMP)
            info.create_system = _ZIP_SYSTEM_UNIX
            mode_bits = _ZIP_MODE_EXEC if mode == "100755" else _ZIP_MODE_FILE
            info.external_attr = mode_bits << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(
                info, data,
                compress_type=zipfile.ZIP_DEFLATED, compresslevel=_COMPRESS_LEVEL,
            )
    return hashlib.sha256(zip_path.read_bytes()).hexdigest()


# ── Signing ─────────────────────────────────────────────────────────────────

def _load_private_key(private_key_pem: bytes) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(private_key_pem, password=None)
    except (ValueError, TypeError) as exc:
        raise SignatureError(f"unusable release private key: {exc}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise SignatureError("release private key is not Ed25519")
    return key


def sign_payload(payload: bytes, private_key_pem: bytes,
                 artifact_name: str = "") -> dict:
    """Detached Ed25519 signature document — the ``.sig`` JSON format.

    ``artifact_name`` / sha256 are embedded as informational fields only;
    verifiers must hash the bytes they received, never trust the document
    about what it signed.
    """
    key = _load_private_key(private_key_pem)
    doc: dict = {
        "algo": SIG_ALGO,
        "sig": base64.b64encode(key.sign(payload)).decode("ascii"),
        "pubkey_sha256": release_pubkey_sha256_hex(
            key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ),
    }
    if artifact_name:
        doc["artifact"] = artifact_name
        doc["sha256"] = hashlib.sha256(payload).hexdigest()
    return doc


def _write_sig(artifact_path: Path, sig_doc: dict) -> Path:
    sig_path = artifact_path.with_name(artifact_path.name + _SIG_SUFFIX)
    sig_path.write_text(json.dumps(sig_doc, indent=2) + "\n",
                        encoding="utf-8", newline="\n")
    return sig_path


def write_sums(dist_dir: Path) -> Path:
    """``SHA256SUMS.txt`` over every other regular file in ``dist_dir``.

    GNU coreutils style lines (``<sha256>  <name>``), sorted by filename;
    the sums files themselves are excluded (a file cannot meaningfully
    list its own hash — that is what its ``.sig`` is for).
    """
    lines = []
    for path in sorted(dist_dir.iterdir(), key=lambda p: p.name):
        if not path.is_file():
            continue
        if path.name in (_SUMS_NAME, _SUMS_NAME + _SIG_SUFFIX):
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.name}\n")
    sums = dist_dir / _SUMS_NAME
    sums.write_text("".join(lines), encoding="utf-8", newline="\n")
    return sums


# ── CLI ─────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build and sign a reproducible GhostDrive source release."
    )
    parser.add_argument("--private-key", type=Path, required=True,
                        help="PEM Ed25519 private key (release_private.pem)")
    parser.add_argument("--version", default=None,
                        help="release version (default: exact v* tag at HEAD, "
                             "else ghostdrive/__init__.__version__)")
    parser.add_argument("--out", type=Path, default=Path("dist"),
                        help="output directory (default: dist/)")
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT,
                        help=argparse.SUPPRESS)  # test seam; defaults to checkout
    args = parser.parse_args(argv)

    try:
        private_key_pem = args.private_key.read_bytes()
        key = _load_private_key(private_key_pem)  # fail fast, before any build
    except (OSError, SignatureError) as exc:
        print(f"error: cannot use private key {args.private_key}: {exc}",
              file=sys.stderr)
        return 1

    try:
        version = determine_version(args.version, args.repo_root)
        blobs = git_tracked_blobs(args.repo_root)
    except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
        print(f"error: cannot determine release source: {exc}", file=sys.stderr)
        return 1

    out_dir = args.out
    out_dir.mkdir(parents=True, exist_ok=True)
    artifact = out_dir / _ARTIFACT_TPL.format(version=version)

    # Reproducibility guard: build twice into scratch dirs; a single
    # differing byte means the pipeline is nondeterministic somewhere and
    # the release must not ship.
    with tempfile.TemporaryDirectory(prefix="ghostdrive-release-") as tmp:
        tmp_dir = Path(tmp)
        first = build_source_zip(tmp_dir / "first.zip", blobs, version)
        second = build_source_zip(tmp_dir / "second.zip", blobs, version)
        if first != second:
            print(
                "FATAL: release build is not reproducible — two builds of the "
                f"same tree produced different sha256 ({first} vs {second}). "
                "Do not ship this artifact.",
                file=sys.stderr,
            )
            return 1
        shutil.copyfile(tmp_dir / "first.zip", artifact)

    payload = artifact.read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    artifact.with_name(artifact.name + _SHA256_SUFFIX).write_text(
        f"{digest}  {artifact.name}\n", encoding="utf-8", newline="\n"
    )
    sig_path = _write_sig(artifact, sign_payload(payload, private_key_pem,
                                                 artifact_name=artifact.name))

    sums = write_sums(out_dir)
    sums_sig_path = _write_sig(
        sums, sign_payload(sums.read_bytes(), private_key_pem,
                           artifact_name=sums.name)
    )

    pubkey_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print("GhostDrive release build")
    print(f"  version:          {version} ({len(blobs)} tracked source files)")
    print(f"  artifact:         {artifact} ({len(payload)} bytes)")
    print(f"  sha256:           {digest}")
    print(f"  signature:        {sig_path} ({SIG_ALGO}, key fingerprint "
          f"{release_pubkey_fingerprint(pubkey_pem)})")
    print(f"  checksums:        {sums} (+ {sums_sig_path.name})")
    print("  reproducibility:  double-build check passed (two builds, identical sha256)")
    print()
    print("NOTE: this signs the SOURCE archive. PyInstaller/Inno binaries are not")
    print("byte-reproducible yet -- pin the toolchain, set SOURCE_DATE_EPOCH, and")
    print("sign whatever binary you ship. See docs/REPRODUCIBLE_BUILDS.md.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
