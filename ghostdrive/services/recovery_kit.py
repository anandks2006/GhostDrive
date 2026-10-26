"""
recovery_kit.py — Shamir 3-of-5 key-share recovery kit: export, verify, combine.

A *recovery kit* is the on-disk artifact produced when the user exports
threshold recovery shares:

    <destination>/
      ghostdrive-recovery-kit.json     manifest (threshold, commitment, no secret)
      ghostdrive-share-1.gdshare       one transcribed share per file
      ...
      ghostdrive-share-N.gdshare

The manifest deliberately contains only non-secret data: the kit identifier,
threshold/total, creation timestamp, word count and a SHA-256 *commitment* to
the Master Key. An attacker who steals the whole kit directory still needs
any 3 of the 5 share files to reconstruct the key, and the commitment lets
:func:`combine_recovery_kit` prove the reconstruction is correct (guards
against mixed kits and transcription errors that survive per-share checksums).

Combining shares reconstructs the Master Key directly — equivalent to the
24-word seed phrase — so the result can drive either:
  * ``KeystoreManager.recover_from_seed()`` (same code path as seed restore), or
  * the offline standalone restore tool (``ghostdrive.cli.recovery_tool``),
    which needs no server, database, or network.
"""

from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Iterable, Optional, Sequence

from ghostdrive.crypto.shamir import (
    DEFAULT_THRESHOLD,
    DEFAULT_TOTAL_SHARES,
    ShamirError,
    combine_shares,
    secret_commitment,
    share_metadata,
    share_to_text,
    split_secret,
    text_to_share,
    verify_commitment,
)
from ghostdrive.exceptions import CryptoError

KIT_FORMAT = "ghostdrive-recovery-kit"
KIT_VERSION = 1
KIT_FILENAME = "ghostdrive-recovery-kit.json"
SHARE_SUFFIX = ".gdshare"


class RecoveryKitError(CryptoError):
    """Raised for invalid recovery-kit export/combine operations."""


def export_recovery_kit(
    master_key: bytes,
    destination: Path | str,
    threshold: int = DEFAULT_THRESHOLD,
    total: int = DEFAULT_TOTAL_SHARES,
    label: str = "",
) -> dict:
    """
    Split ``master_key`` into ``total`` shares and write a complete kit to
    ``destination``.

    Args:
        master_key:  32-byte Master Key (unlocked keystore).
        destination: Directory to write the manifest + share files into.
        threshold:   Shares required to reconstruct (default 3).
        total:       Shares to produce (default 5).
        label:       Optional user label recorded in the manifest.

    Returns:
        The manifest dict (also written to ``ghostdrive-recovery-kit.json``).

    Raises:
        RecoveryKitError: Invalid parameters or write failure.
    """
    dest = Path(destination)
    try:
        dest.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise RecoveryKitError(f"Cannot create kit directory {dest}: {exc}") from exc

    # Refuse to clobber an existing kit silently — the shares would be lost.
    manifest_path = dest / KIT_FILENAME
    if manifest_path.exists():
        raise RecoveryKitError(
            f"A recovery kit already exists at {manifest_path}. "
            "Export to a different directory or remove the old kit first."
        )

    try:
        shares = split_secret(master_key, threshold=threshold, total=total)
    except ShamirError as exc:
        raise RecoveryKitError(str(exc)) from exc

    kit_id = uuid.uuid4().hex
    created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    share_files = []
    for i, share in enumerate(shares, start=1):
        fname = f"ghostdrive-share-{i}-of-{total}{SHARE_SUFFIX}"
        path = dest / fname
        try:
            path.write_text(share_to_text(share) + "\n", encoding="utf-8")
        except OSError as exc:
            raise RecoveryKitError(f"Failed to write {path}: {exc}") from exc
        share_files.append(fname)

    manifest = {
        "format": KIT_FORMAT,
        "version": KIT_VERSION,
        "kit_id": kit_id,
        "created_at": created,
        "label": (label or "").strip(),
        "threshold": threshold,
        "total": total,
        "master_key_bytes": len(master_key),
        "commitment": secret_commitment(master_key),
        "share_files": share_files,
        "instructions": (
            "Store each share file in a different secure location. "
            f"Any {threshold} of {total} files restore your vault; "
            "fewer than {0} reveal nothing.".format(threshold)
        ),
    }
    try:
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    except OSError as exc:
        raise RecoveryKitError(f"Failed to write manifest: {exc}") from exc

    return manifest


def load_manifest(kit_dir: Path | str) -> dict:
    """Read and validate the kit manifest from a kit directory."""
    path = Path(kit_dir) / KIT_FILENAME
    if not path.exists():
        raise RecoveryKitError(f"No {KIT_FILENAME} found in {kit_dir}.")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RecoveryKitError(f"Unreadable kit manifest: {exc}") from exc
    if manifest.get("format") != KIT_FORMAT:
        raise RecoveryKitError("Not a GhostDrive recovery kit manifest.")
    if manifest.get("version") != KIT_VERSION:
        raise RecoveryKitError(f"Unsupported kit version {manifest.get('version')}.")
    for key in ("threshold", "total", "commitment"):
        if key not in manifest:
            raise RecoveryKitError(f"Kit manifest missing {key!r}.")
    return manifest


def collect_shares(
    sources: Iterable[Path | str],
    kit_dir: Optional[Path | str] = None,
) -> list[bytes]:
    """
    Resolve a mixed list of inputs into validated binary shares.

    Each source may be:
      * a path to a ``.gdshare`` file (read + decode),
      * a raw share *text* string (``GDSHARE1:...``), or
      * ``None`` (ignored).

    If ``kit_dir`` is given and a source path doesn't exist, the filename is
    resolved inside the kit directory too, so callers can pass bare filenames.
    """
    shares: list[bytes] = []
    for src in sources:
        if src is None:
            continue
        text: Optional[str] = None
        as_path = Path(str(src))
        if as_path.exists() and as_path.is_file():
            text = as_path.read_text(encoding="utf-8")
        elif kit_dir is not None:
            candidate = Path(kit_dir) / as_path.name
            if candidate.exists():
                text = candidate.read_text(encoding="utf-8")
            elif as_path.suffix == SHARE_SUFFIX:
                raise RecoveryKitError(f"Share not found: {src}")
            else:
                text = str(src)  # not a filename — treat as pasted share text
        elif as_path.suffix == SHARE_SUFFIX or len(as_path.parts) > 1:
            # Looks like a file path but doesn't exist → clearer than a
            # "missing prefix" decode error.
            raise RecoveryKitError(f"Share not found: {src}")
        else:
            text = str(src)  # treat as pasted share text
        try:
            shares.append(text_to_share(text))
        except ShamirError as exc:
            raise RecoveryKitError(f"Invalid share {src}: {exc}") from exc
    return shares


def combine_recovery_kit(
    shares: Sequence[bytes],
    commitment: Optional[str] = None,
    threshold: Optional[int] = None,
) -> bytes:
    """
    Reconstruct the Master Key from binary shares, optionally verifying
    against the manifest commitment.

    Args:
        shares:     Binary shares (from :func:`collect_shares` / ``text_to_share``).
        commitment: Manifest ``commitment`` hex digest, if available.
        threshold:  Manifest threshold (informational; combine enforces the
            threshold embedded in the share headers either way).

    Returns:
        The 32-byte Master Key.

    Raises:
        RecoveryKitError: Too few/corrupted shares or commitment mismatch.
    """
    if threshold is not None and len(shares) < threshold:
        raise RecoveryKitError(
            f"Kit requires {threshold} shares; only {len(shares)} provided."
        )
    try:
        secret = combine_shares(list(shares))
    except ShamirError as exc:
        raise RecoveryKitError(str(exc)) from exc

    if commitment and not verify_commitment(secret, commitment):
        raise RecoveryKitError(
            "Reconstructed key does NOT match the kit commitment. "
            "The shares belong to a different recovery kit or are corrupted."
        )
    return secret


def share_summary(shares: Sequence[bytes]) -> dict:
    """Non-secret summary of provided shares (threshold/total/index list)."""
    metas = [share_metadata(s) for s in shares]
    return {
        "provided": len(metas),
        "threshold": metas[0]["threshold"] if metas else None,
        "total": metas[0]["total"] if metas else None,
        "indexes": [m["index"] for m in metas],
    }


def restore_keystore_from_key(
    master_key: bytes,
    keystore_path: Path | str,
    new_passphrase: bytes,
    calibrate: bool = True,
    argon2_params: Optional[dict] = None,
) -> object:
    """
    Rebuild ``keystore.json`` from a reconstructed Master Key.

    Uses the same BIP39 round-trip as seed-phrase restore (entropy → mnemonic
    → ``recover_from_seed``), which also re-derives the deterministic HKDF
    salt/genesis seed used by ``create_new``.

    Returns the unlocked :class:`~ghostdrive.crypto.keystore.KeystoreManager`.
    """
    from ghostdrive.crypto.keystore import (
        KeystoreManager,
        entropy_to_mnemonic,
    )

    try:
        phrase = entropy_to_mnemonic(master_key)
    except CryptoError as exc:
        raise RecoveryKitError(f"Master key is not valid BIP39 entropy: {exc}") from exc

    km = KeystoreManager(Path(keystore_path))
    try:
        km.recover_from_seed(
            phrase,
            new_passphrase,
            calibrate=calibrate,
            argon2_params=argon2_params,
        )
    except CryptoError as exc:
        raise RecoveryKitError(f"Keystore restore failed: {exc}") from exc
    return km
