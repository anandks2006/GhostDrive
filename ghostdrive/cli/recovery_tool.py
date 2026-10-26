"""ghostdrive-restore — offline standalone recovery tool for GhostDrive.

Runs with NO server, database, network, or backend credentials: it only needs
the Python crypto stack (argon2, cryptography, mnemonic) that GhostDrive
already ships. Use it on a fresh machine to rebuild ``keystore.json`` from
any ``threshold`` of the exported Shamir shares.

Typical disaster scenario
-------------------------
Laptop dead, passphrase forgotten, app gone — but you stored 3 of the 5
``.gdshare`` files in separate places::

    # 1. Inspect what you have (no secrets printed)
    python -m ghostdrive.cli.recovery_tool verify share1.gdshare share2.gdshare share3.gdshare

    # 2. Rebuild the keystore offline (prompts for the NEW vault passphrase)
    python -m ghostdrive.cli.recovery_tool restore share1.gdshare share2.gdshare share3.gdshare \\
        --keystore ./keystore.json

    # 3. Reinstall GhostDrive and point it at that keystore.json — the app's
    #    cold-start restore then pulls the encrypted index snapshot from the
    #    configured backends using the rebuilt key.

The tool also accepts a kit directory instead of individual files::

    python -m ghostdrive.cli.recovery_tool restore ./ghostdrive-recovery-kit/

and can *export* a kit from an existing keystore (requires its passphrase,
still fully offline)::

    python -m ghostdrive.cli.recovery_tool export --keystore ./keystore.json --out ./kit

Deliberately import-light: only ``ghostdrive.crypto.*`` and
``ghostdrive.services.recovery_kit`` — no FastAPI, no SQLite, no backends.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path
from typing import Optional

from ghostdrive.crypto.shamir import (
    DEFAULT_THRESHOLD,
    DEFAULT_TOTAL_SHARES,
    text_to_share,
)
from ghostdrive.exceptions import GhostDriveError
from ghostdrive.services.recovery_kit import (
    KIT_FILENAME,
    RecoveryKitError,
    combine_recovery_kit,
    collect_shares,
    export_recovery_kit,
    load_manifest,
    restore_keystore_from_key,
    share_summary,
)

__all__ = ["main", "build_parser"]


def _split_sources(sources: list[str]) -> tuple[list[str], Optional[str]]:
    """
    Partition CLI sources into (share inputs, kit directory).

    A source is treated as a kit directory when it contains
    ``ghostdrive-recovery-kit.json`` (or is an existing directory without the
    ``GDSHARE1:`` prefix).
    """
    shares: list[str] = []
    kit_dir: Optional[str] = None
    for src in sources:
        path = Path(src)
        if path.is_dir() and (path / KIT_FILENAME).exists():
            if kit_dir is not None:
                raise SystemExit("Provide at most one kit directory.")
            kit_dir = str(path)
        else:
            shares.append(src)
    return shares, kit_dir


def _resolve_binary_shares(sources: list[str]) -> tuple[list[bytes], Optional[dict]]:
    """Return (binary shares, manifest-or-None) from mixed CLI sources."""
    share_srcs, kit_dir = _split_sources(sources)
    manifest = load_manifest(kit_dir) if kit_dir else None
    if manifest is None and len(share_srcs) == 1 and Path(share_srcs[0]).is_dir():
        # A bare directory without a manifest is still worth a clear error.
        raise SystemExit(f"{share_srcs[0]} is a directory but not a recovery kit.")
    if manifest is None and share_srcs:
        # Shares passed as individual files: if they live next to a kit
        # manifest, pick it up automatically so commitment verification works.
        for src in share_srcs:
            parent = Path(str(src)).expanduser().resolve().parent
            if (parent / KIT_FILENAME).exists():
                manifest = load_manifest(parent)
                kit_dir = str(parent)
                break
    if manifest is not None:
        # Fill in share filenames from the manifest if the user passed none.
        if not share_srcs:
            share_srcs = list(manifest.get("share_files", []))
    shares = collect_shares(share_srcs, kit_dir=kit_dir)
    return shares, manifest


def _print_summary(shares: list[bytes], manifest: Optional[dict]) -> None:
    summary = share_summary(shares)
    print(f"Shares provided : {summary['provided']}")
    print(f"Threshold       : {summary['threshold']}")
    print(f"Total in kit    : {summary['total']}")
    print(f"Share indexes   : {', '.join(str(i) for i in summary['indexes'])}")
    if manifest:
        print(f"Kit id          : {manifest.get('kit_id', '?')}")
        print(f"Created         : {manifest.get('created_at', '?')}")
    missing = summary["threshold"] - summary["provided"] if summary["threshold"] else 0
    if missing > 0:
        print(f"Need {missing} more share(s) to restore.")


def _cmd_verify(args: argparse.Namespace) -> int:
    shares, manifest = _resolve_binary_shares(list(args.shares))
    _print_summary(shares, manifest)
    threshold = (manifest or {}).get("threshold") or share_summary(shares)["threshold"]
    if len(shares) < threshold:
        print("NOT ENOUGH SHARES.", file=sys.stderr)
        return 2
    if manifest:
        # Prove the shares belong to this kit without printing the key.
        combine_recovery_kit(shares, commitment=manifest.get("commitment"))
        print("Commitment      : OK (shares belong to this kit)")
    else:
        print("Commitment      : n/a (no kit manifest provided)")
    print("Shares are valid.")
    return 0


def _prompt_new_passphrase(args: argparse.Namespace) -> bytes:
    if getattr(args, "passphrase", None):
        return args.passphrase.encode("utf-8")
    env = os.environ.get("GHOSTDRIVE_NEW_PASSPHRASE")
    if env:
        return env.encode("utf-8")
    first = getpass.getpass("New vault passphrase: ")
    second = getpass.getpass("Confirm passphrase: ")
    if first != second:
        print("Passphrases do not match.", file=sys.stderr)
        raise SystemExit(1)
    if not first:
        print("Passphrase cannot be empty.", file=sys.stderr)
        raise SystemExit(1)
    return first.encode("utf-8")


def _cmd_restore(args: argparse.Namespace) -> int:
    shares, manifest = _resolve_binary_shares(list(args.shares))
    _print_summary(shares, manifest)

    keystore_path = Path(args.keystore)
    if keystore_path.exists() and not args.force:
        raise SystemExit(
            f"{keystore_path} already exists. Pass --force to overwrite it."
        )

    commitment = (manifest or {}).get("commitment")
    if commitment is None and args.commitment:
        commitment = args.commitment
    secret = combine_recovery_kit(shares, commitment=commitment)

    passphrase = _prompt_new_passphrase(args)
    km = restore_keystore_from_key(
        secret,
        keystore_path,
        passphrase,
        calibrate=not args.fast,
        argon2_params=(
            {"time_cost": 1, "memory_cost": 8_192, "parallelism": 1, "hash_len": 32}
            if args.fast
            else None
        ),
    )
    # Zero our copy of the raw key; the manager holds it in a ctypes buffer.
    del secret
    del passphrase

    assert km.is_unlocked
    print(f"Keystore restored: {keystore_path}")
    print("Next: install GhostDrive and start it with this keystore.json;")
    print("      the cold-start index restore will follow automatically.")
    return 0


def _cmd_export(args: argparse.Namespace) -> int:
    """Export a recovery kit from an existing keystore.json (offline)."""
    from ghostdrive.crypto.keystore import KeystoreManager

    keystore_path = Path(args.keystore)
    if not keystore_path.exists():
        raise SystemExit(f"No keystore at {keystore_path}.")

    km = KeystoreManager(keystore_path)
    if not km.is_unlocked:
        pw = args.passphrase or os.environ.get("GHOSTDRIVE_PASSPHRASE") \
            or getpass.getpass("Vault passphrase: ")
        try:
            km.unlock(pw.encode("utf-8"))
        except GhostDriveError:
            print("Unlock failed: incorrect passphrase.", file=sys.stderr)
            return 1

    manifest = export_recovery_kit(
        bytes(km.master_key),
        args.out,
        threshold=args.threshold,
        total=args.total,
        label=args.label or "",
    )
    km.lock()
    print(f"Recovery kit written to {Path(args.out).resolve()}")
    print(f"  kit id     : {manifest['kit_id']}")
    print(f"  threshold  : {manifest['threshold']} of {manifest['total']}")
    for name in manifest["share_files"]:
        print(f"  - {name}")
    print("Store each share file in a DIFFERENT secure location.")
    return 0


def _cmd_import_keystore(args: argparse.Namespace) -> int:
    """Validate share text pasted on stdin (for scripted environments)."""
    raw = sys.stdin.read()
    parts = [p.strip() for p in raw.replace(",", "\n").splitlines() if p.strip()]
    shares = []
    for p in parts:
        try:
            shares.append(text_to_share(p))
        except GhostDriveError as exc:
            print(f"Skipping input: {exc}", file=sys.stderr)
    if not shares:
        print("No valid shares found on stdin.", file=sys.stderr)
        return 2
    _print_summary(shares, None)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ghostdrive-restore",
        description="Offline standalone GhostDrive recovery (Shamir key shares).",
    )
    parser.add_argument("--version", action="version", version="ghostdrive-restore 1")
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "shares",
        nargs="+",
        metavar="SHARE",
        help="Share files, share text (GDSHARE1:...), or a kit directory.",
    )

    verify = sub.add_parser(
        "verify", parents=[common],
        help="Check share validity/threshold without reconstructing anything.",
    )
    verify.set_defaults(func=_cmd_verify)

    restore = sub.add_parser(
        "restore", parents=[common],
        help="Reconstruct the Master Key and rebuild keystore.json.",
    )
    restore.add_argument("--keystore", default="keystore.json", help="Output keystore path.")
    restore.add_argument("--passphrase", help="New passphrase (else prompt / GHOSTDRIVE_NEW_PASSPHRASE).")
    restore.add_argument("--commitment", help="Manifest commitment if the manifest is unavailable.")
    restore.add_argument("--force", action="store_true", help="Overwrite an existing keystore.")
    restore.add_argument("--fast", action="store_true", help="Use test Argon2 params (insecure, for tests).")
    restore.set_defaults(func=_cmd_restore)

    export = sub.add_parser("export", help="Export a recovery kit from keystore.json (offline).")
    export.add_argument("--keystore", default="keystore.json")
    export.add_argument("--out", default="./ghostdrive-recovery-kit", help="Output directory.")
    export.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD)
    export.add_argument("--total", type=int, default=DEFAULT_TOTAL_SHARES)
    export.add_argument("--label", default="")
    export.add_argument("--passphrase", help="Vault passphrase (else prompt / GHOSTDRIVE_PASSPHRASE).")
    export.set_defaults(func=_cmd_export)

    stdin = sub.add_parser("check-stdin", help="Validate share text piped on stdin.")
    stdin.set_defaults(func=_cmd_import_keystore)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except SystemExit as exc:
        # Command handlers signal usage errors with SystemExit(msg).
        if isinstance(exc.code, str):
            print(exc.code, file=sys.stderr)
            return 1
        return int(exc.code or 0)
    except (RecoveryKitError, GhostDriveError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
