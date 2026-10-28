"""keygen_release_key.py -- Generate the Ed25519 release-signing keypair.

The private key signs release artifacts (scripts/release.py) and must live
on an OFFLINE machine; the public key is what verifiers trust —
scripts/verify_release.py on any rebuild machine, and the running updater
via the ``GHOSTDRIVE_RELEASE_PUBKEY`` env var
(ghostdrive/platform/updater.py). Operator doc: docs/REPRODUCIBLE_BUILDS.md.

The private key is written WITHOUT a passphrase, deliberately: release
signing is meant to run unattended from a build script on an air-gapped
signing box, and a key that needs a human typing a passphrase never gets
used for weekly releases. That trade-off is exactly why the output prints
a loud warning and why the file must never be within reach of a network.

Usage (from the repo root):

    py -3.12 scripts/keygen_release_key.py --out-dir release_keys [--force]

Outputs ``release_private.pem`` (PKCS#8, PEM, unencrypted) and
``release_public.pem`` (SubjectPublicKeyInfo PEM), and prints the public
key fingerprint — sha256 over the raw 32-byte public key, colon-grouped.
Compare that fingerprint out-of-band (phone call, signed commit, release
notes on a second channel) before trusting a key you downloaded.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ghostdrive.platform.updater import release_pubkey_fingerprint  # noqa: E402

PRIVATE_KEY_NAME = "release_private.pem"
PUBLIC_KEY_NAME = "release_public.pem"

_WARNING = """\
!! ------------------------------------------------------------------------
!!  WARNING: {name} is written WITHOUT a passphrase.
!!  Anyone who obtains this file can sign GhostDrive releases that every
!!  verifier -- and every updater with GHOSTDRIVE_RELEASE_PUBKEY set --
!!  will trust. Handle it accordingly:
!!    * Keep it on an OFFLINE machine; never on the build or web host.
!!    * Never commit it to git; never copy it to a networked box.
!!    * Restrict file permissions (best-effort chmod 0o600 was attempted;
!!      on Windows run: icacls release_private.pem /inheritance:r
!!      /grant:r <your-user>:F).
!! ------------------------------------------------------------------------"""


def generate_private_key() -> Ed25519PrivateKey:
    """A fresh Ed25519 private key (cryptography's OpenSSL-backed CSPRNG)."""
    return Ed25519PrivateKey.generate()


def private_key_pem(key: Ed25519PrivateKey) -> bytes:
    """PKCS#8 PEM, unencrypted — loadable with ``password=None``."""
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_pem(key: Ed25519PrivateKey) -> bytes:
    """SubjectPublicKeyInfo PEM — what verifiers and the updater trust."""
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def write_keypair(out_dir: Path, force: bool = False) -> dict:
    """Write ``release_private.pem`` + ``release_public.pem`` into ``out_dir``.

    Refuses to overwrite existing key files unless ``force=True`` — a
    second accidental run must never silently replace the signing key
    (every published fingerprint would instantly go stale).

    Returns:
        ``{"private_key": Path, "public_key": Path, "fingerprint": str}``
        with the colon-grouped sha256 fingerprint of the raw public key.

    Raises:
        FileExistsError: a target file exists and ``force`` is False.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    priv_path = out_dir / PRIVATE_KEY_NAME
    pub_path = out_dir / PUBLIC_KEY_NAME
    if not force:
        existing = [p for p in (priv_path, pub_path) if p.exists()]
        if existing:
            raise FileExistsError(
                "refusing to overwrite existing release key file(s): "
                + ", ".join(str(p) for p in existing)
                + " (pass --force to rotate)"
            )

    key = generate_private_key()
    priv_pem = private_key_pem(key)
    pub_pem = public_key_pem(key)
    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)

    # Best-effort owner-only permissions; a no-op-ish best effort on
    # Windows (see the printed icacls hint), meaningful on POSIX.
    for path in (priv_path, pub_path):
        try:
            os.chmod(path, 0o600)
        except OSError:  # pragma: no cover - platform/filesystem dependent
            pass

    return {
        "private_key": priv_path,
        "public_key": pub_path,
        "fingerprint": release_pubkey_fingerprint(pub_pem),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate the Ed25519 release-signing keypair (offline machine!)"
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("release_keys"),
        help="directory for release_private.pem / release_public.pem "
             "(default: release_keys)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite existing key files (rotates the signing key — "
             "every published fingerprint goes stale)",
    )
    args = parser.parse_args(argv)

    try:
        result = write_keypair(args.out_dir, force=args.force)
    except FileExistsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(_WARNING.format(name=PRIVATE_KEY_NAME))
    print()
    print(f"  private key:  {result['private_key']}")
    print(f"  public key:   {result['public_key']}")
    print(f"  fingerprint:  {result['fingerprint']}")
    print()
    print("Compare the fingerprint OUT-OF-BAND (a second, independent channel)")
    print("before anyone trusts this public key -- see docs/REPRODUCIBLE_BUILDS.md.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
