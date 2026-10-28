"""verify_release.py -- Verify GhostDrive release artifacts and signatures.

Checks, per artifact:

* the ``.sha256`` sidecar (when present) against the recomputed hash of
  the bytes actually on disk;
* the detached ``.sig`` Ed25519 document against the artifact bytes and
  the trusted public key (the same check the updater performs at runtime,
  ghostdrive/platform/updater.py::verify_release_signature);
* with ``--dist``: additionally cross-checks every file listed in
  ``SHA256SUMS.txt`` (whose own authenticity is established by
  ``SHA256SUMS.txt.sig``).

Usable as a library: :func:`verify_artifact` returns a plain dict so
tests and other tooling can consume the result without parsing stdout.

Usage (from the repo root):

    py -3.12 scripts/verify_release.py --public-key release_keys/release_public.pem --dist dist/
    py -3.12 scripts/verify_release.py --public-key release_keys/release_public.pem --artifact dist/ghostdrive-0.1.0-alpha-src.zip

Exit code 0 when everything passes, 1 on any failure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ghostdrive.platform.updater import (  # noqa: E402
    SignatureError,
    release_pubkey_fingerprint,
    verify_release_signature,
)

_SIG_SUFFIX = ".sig"
_SHA256_SUFFIX = ".sha256"
_SUMS_NAME = "SHA256SUMS.txt"


def verify_artifact(artifact: Path, public_key_pem: bytes) -> dict:
    """Verify one artifact: sha256 sidecar (when present) + Ed25519 ``.sig``.

    Returns::

        {"ok": bool,           # signature verified AND no sha256 discrepancy
         "sha256": str|None,   # recomputed hash of the bytes on disk
         "sha256_ok": bool|None,  # sidecar match; None = no sidecar to check
         "signature_ok": bool, # Ed25519 .sig verified against the key
         "error": str|None}    # human-readable failure reasons, "; "-joined

    A missing ``.sha256`` sidecar is NOT an error (the signature already
    covers the bytes — ``SHA256SUMS.txt`` carries no sidecar of its own),
    but a missing ``.sig`` is: an artifact nobody signed is exactly what
    this tool exists to reject.
    """
    artifact = Path(artifact)
    result: dict = {
        "ok": False,
        "sha256": None,
        "sha256_ok": None,
        "signature_ok": False,
        "error": None,
    }
    if not artifact.is_file():
        result["error"] = f"artifact not found: {artifact}"
        return result

    payload = artifact.read_bytes()
    result["sha256"] = hashlib.sha256(payload).hexdigest()
    errors: list[str] = []

    sidecar = artifact.with_name(artifact.name + _SHA256_SUFFIX)
    if sidecar.is_file():
        parts = sidecar.read_text(encoding="utf-8", errors="replace").split()
        expected = parts[0].lower() if parts else ""
        result["sha256_ok"] = bool(expected) and expected == result["sha256"]
        if not result["sha256_ok"]:
            errors.append(
                f"sha256 mismatch (sidecar says {expected or '<empty>'}, "
                f"file is {result['sha256']})"
            )

    sig_path = artifact.with_name(artifact.name + _SIG_SUFFIX)
    if sig_path.is_file():
        try:
            meta = json.loads(sig_path.read_bytes())
            verify_release_signature(payload, meta, public_key_pem)
            result["signature_ok"] = True
        except (SignatureError, json.JSONDecodeError) as exc:
            errors.append(f"signature: {exc}")
    else:
        errors.append(f"no {artifact.name}{_SIG_SUFFIX} alongside artifact")

    result["error"] = "; ".join(errors) or None
    result["ok"] = result["signature_ok"] and result["sha256_ok"] is not False
    return result


def _parse_sums(sums_path: Path) -> dict[str, str]:
    """``{filename: sha256}`` from a GNU-style SHA256SUMS.txt (best effort)."""
    listed: dict[str, str] = {}
    for line in sums_path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split()
        if len(parts) >= 2:
            listed[parts[1].lstrip("*").lower()] = parts[0].lower()
    return listed


def verify_dist(dist_dir: Path, public_key_pem: bytes) -> list[tuple[str, dict]]:
    """Verify every artifact in ``dist_dir`` (sidecars and sigs skipped).

    When ``SHA256SUMS.txt`` is present, each file it lists is additionally
    cross-checked against it — a mismatch is reported per row and flips
    that row to FAIL even if the file's own ``.sig`` verifies.
    """
    dist_dir = Path(dist_dir)
    if not dist_dir.is_dir():
        return [("<dist>", {"ok": False, "sha256": None, "sha256_ok": None,
                            "signature_ok": False,
                            "error": f"not a directory: {dist_dir}"})]
    sums_path = dist_dir / _SUMS_NAME
    listed = _parse_sums(sums_path) if sums_path.is_file() else None

    rows: list[tuple[str, dict]] = []
    for path in sorted((p for p in dist_dir.iterdir() if p.is_file()),
                       key=lambda p: p.name):
        if path.name.endswith((_SIG_SUFFIX, _SHA256_SUFFIX)):
            continue  # verified as part of their artifact, not standalone
        res = verify_artifact(path, public_key_pem)
        if listed is not None and path.name.lower() in listed:
            expected = listed[path.name.lower()]
            if expected != res["sha256"]:
                res["sha256_ok"] = False
                res["ok"] = False
                note = (f"SHA256SUMS.txt lists {expected}, file is {res['sha256']}")
                res["error"] = "; ".join(filter(None, [res["error"], note])) or note
        rows.append((path.name, res))
    return rows


def _print_table(rows: list[tuple[str, dict]]) -> None:
    header = f"{'FILE':<40} {'SHA256':<7} {'SIG':<5} {'RESULT':<6}"
    print(header)
    print("-" * len(header))
    for name, res in rows:
        sha_col = {True: "PASS", False: "FAIL", None: "-"}[res["sha256_ok"]]
        sig_col = "PASS" if res["signature_ok"] else "FAIL"
        verdict = "PASS" if res["ok"] else "FAIL"
        print(f"{name:<40} {sha_col:<7} {sig_col:<5} {verdict:<6}")
        if res["error"]:
            print(f"{'':<4} ! {res['error']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify GhostDrive release artifacts (sha256 + Ed25519 sig)."
    )
    parser.add_argument("--public-key", type=Path, required=True,
                        help="trusted PEM Ed25519 public key (release_public.pem)")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--artifact", type=Path,
                        help="single artifact to verify (its .sig/.sha256 "
                             "must sit alongside it)")
    target.add_argument("--dist", type=Path,
                        help="directory of release files to verify in full "
                             "(incl. SHA256SUMS.txt)")
    args = parser.parse_args(argv)

    try:
        public_key_pem = args.public_key.read_bytes()
        fingerprint = release_pubkey_fingerprint(public_key_pem)
    except OSError as exc:
        print(f"error: cannot read public key {args.public_key}: {exc}",
              file=sys.stderr)
        return 1
    except SignatureError as exc:
        print(f"error: {args.public_key} is not a usable release key: {exc}",
              file=sys.stderr)
        return 1
    print(f"trusted key fingerprint: {fingerprint}")

    if args.artifact is not None:
        rows = [(args.artifact.name,
                 verify_artifact(args.artifact, public_key_pem))]
    else:
        rows = verify_dist(args.dist, public_key_pem)

    if not rows:
        print(f"nothing to verify in {args.dist}")
        return 1

    _print_table(rows)
    ok = all(res["ok"] for _, res in rows)
    print()
    print("ALL PASS" if ok else "FAILURES PRESENT -- do not trust these files")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
