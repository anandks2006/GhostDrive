"""ghostdrive-cli -- headless companion for GhostDrive.

Commands mirror the web UI and use the exact same service layer, so scripts,
Kaggle/Colab notebooks and scheduled jobs can operate a vault without a browser.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import importlib.util
import json
import os
import socket
import sys
import tempfile
from pathlib import Path
from typing import Optional

from ghostdrive import __version__
from ghostdrive.crypto.keystore import KeystoreManager
from ghostdrive.utils.platform import get_app_data_dir
from ghostdrive.web.state import state


def _passphrase(args) -> str:
    value = getattr(args, "passphrase", None) or os.environ.get("GHOSTDRIVE_PASSPHRASE")
    if value:
        return value
    return getpass.getpass("Vault passphrase: ")


def _open_vault(args) -> KeystoreManager:
    if not state.keystore_path.exists():
        raise SystemExit(f"No vault found at {state.keystore_path}. Run 'ghostdrive-cli init' first.")
    km = KeystoreManager(state.keystore_path)
    if not km.is_unlocked:
        try:
            km.unlock(_passphrase(args).encode("utf-8"))
        except Exception as exc:
            raise SystemExit(f"Unlock failed: {exc}")
    from ghostdrive.web.routes.auth import _open_db
    _open_db(km)
    state.km = km
    return km


def _resolve_file(identifier: str):
    from ghostdrive.services import files as files_service
    try:
        return files_service.get_file_row(identifier)
    except FileNotFoundError:
        pass
    rows = files_service.list_files("/", search=identifier).get("files", [])
    exact = [row for row in rows if row["filename"] == identifier]
    if not exact:
        raise SystemExit(f"No file matching {identifier!r}.")
    return files_service.get_file_row(exact[0]["id"])


def _human(n: int) -> str:
    value = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def _cmd_init(args) -> int:
    if state.keystore_path.exists() and not args.force:
        raise SystemExit(f"Vault already exists at {state.keystore_path}. Use --force to overwrite.")
    km = KeystoreManager(state.keystore_path)
    seed = km.create_new((args.passphrase or _passphrase(args)).encode("utf-8"), calibrate=not args.fast)
    km.verify_and_save(seed)
    state.km = km
    from ghostdrive.web.routes.auth import _open_db
    _open_db(km)
    print("Vault initialized.")
    print(f"Data directory: {state.app_data_dir}")
    print("\nSeed phrase (store offline, never share):")
    print(seed)
    return 0


def _cmd_unlock(args) -> int:
    _open_vault(args)
    print(f"Vault unlocked. Database: {state.db_path}")
    return 0


def _cmd_status(args) -> int:
    unlocked = state.km is not None and state.km.is_unlocked
    print(f"GhostDrive {__version__}")
    print(f"Data directory : {state.app_data_dir}")
    print(f"Keystore       : {'present' if state.keystore_path.exists() else 'missing'} ({state.keystore_path})")
    print(f"Database       : {'present' if state.db_path.exists() else 'missing'} ({state.db_path})")
    print(f"Session        : {'unlocked' if unlocked else 'locked'}")
    if args.passphrase or os.environ.get("GHOSTDRIVE_PASSPHRASE"):
        _open_vault(args)
        summary = state.db.get_analytics_summary()
        print(f"Files          : {summary['file_count']}")
        print(f"Logical bytes  : {_human(summary['logical_bytes'])}")
    return 0


def _cmd_ls(args) -> int:
    from ghostdrive.services import files as files_service
    _open_vault(args)
    result = files_service.list_files(args.path, args.category, args.search)
    files = result["files"]
    if args.json:
        print(json.dumps(files, indent=2))
        return 0
    if not files:
        print("(no files)")
        return 0
    print(f"{'ID':36}  {'SIZE':>10}  {'TIER':<10}  NAME")
    for row in files:
        print(f"{row['id']:36}  {_human(row['size']):>10}  {row['tier']:<10}  {row['path']}")
    return 0


def _cmd_upload(args) -> int:
    from ghostdrive.services import files as files_service
    _open_vault(args)
    path = Path(args.file)
    if not path.is_file():
        raise SystemExit(f"File not found: {path}")
    result = asyncio.run(files_service.upload_stream(
        path,
        path.name,
        None,
        args.tier,
        args.destination,
    ))
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Uploaded {result['filename']} ({_human(result['size'])}) -> {args.tier}, id={result['file_id']}")
    return 0


def _cmd_download(args) -> int:
    from ghostdrive.services import files as files_service
    _open_vault(args)
    row = _resolve_file(args.file)

    async def _write():
        total = 0
        with open(args.output, "wb") as handle:
            async for block in files_service.iter_file(row["id"]):
                handle.write(block)
                total += len(block)
        return total

    total = asyncio.run(_write())
    print(f"Downloaded {row['name']} ({_human(total)}) -> {args.output}")
    return 0


def _cmd_rm(args) -> int:
    from ghostdrive.services import files as files_service
    _open_vault(args)
    row = _resolve_file(args.file)
    result = asyncio.run(files_service.delete_file(row["id"], purge=args.purge))
    print(result["message"])
    return 0


def _cmd_trash(args) -> int:
    from ghostdrive.services import files as files_service
    _open_vault(args)
    if args.empty:
        result = asyncio.run(files_service.empty_trash(args.older_than_days))
        print(f"Purged {result['purged']} item(s) from Trash.")
        return 0
    rows = files_service.trash(args.older_than_days)["files"]
    if not rows:
        print("(trash is empty)")
        return 0
    for row in rows:
        print(f"{row['id']}  {_human(row['size']):>10}  {row['filename']}")
    return 0


def _cmd_share(args) -> int:
    from ghostdrive.services import sharing as sharing_service
    _open_vault(args)
    row = _resolve_file(args.file)
    link = sharing_service.create_link(
        row["id"],
        args.recipient,
        args.ttl_hours,
        args.passcode is not None,
        args.passcode,
        args.max_downloads,
    )
    base = args.base_url.rstrip("/")
    print(f"Share link: {base}/s/{link['token']}")
    print(f"Expires at: {link['expires_at']}")
    if args.passcode:
        print("Passcode required (share it separately).")
    return 0


def _cmd_backends(args) -> int:
    from ghostdrive.services import backends as backend_service
    _open_vault(args)
    if args.test:
        results = asyncio.run(backend_service.health_check_all())
        for item in results["results"]:
            state_text = "OK" if item["reachable"] else f"FAIL ({item['error']})"
            print(f"{item['type']:<16} {state_text}")
        return 0
    view = backend_service.list_backends_view()
    for row in view["configured_backends"]:
        print(
            f"{row['id']}  {row['provider']:<24} {row['tier']:<16} "
            f"{row['status']:<10} latency={row['latency_ms']}ms used={_human(row['used_bytes'])}"
        )
    return 0


def _cmd_verify(args) -> int:
    from ghostdrive.services import files as files_service
    _open_vault(args)
    row = _resolve_file(args.file)
    result = asyncio.run(files_service.verify_file(row["id"]))
    print(f"{result['filename']}: {'HEALTHY' if result['healthy'] else 'CORRUPT'} "
          f"({result['chunks_checked']} chunks)")
    if args.json:
        print(json.dumps(result, indent=2))
    return 0 if result["healthy"] else 2


def _cmd_doctor(args) -> int:
    print(f"GhostDrive doctor -- {__version__}")
    failures = 0

    data_dir = get_app_data_dir()
    try:
        with tempfile.NamedTemporaryFile(dir=data_dir, prefix=".gd_doctor_", delete=True) as handle:
            handle.write(b"ok")
            handle.flush()
        print(f"[OK]   data directory writable: {data_dir}")
    except Exception as exc:
        failures += 1
        print(f"[FAIL] data directory: {exc}")

    try:
        import keyring
        backend = keyring.get_keyring()
        print(f"[OK]   keyring backend: {backend.__class__.__name__}")
    except Exception as exc:
        failures += 1
        print(f"[FAIL] keyring: {exc}")

    try:
        socket.setdefaulttimeout(3)
        socket.gethostbyname("api.telegram.org")
        print("[OK]   network reachable (api.telegram.org)")
    except Exception as exc:
        print(f"[WARN] offline mode: {exc}")

    for module, label in (
        ("telethon", "Telegram (telethon)"),
        ("discord", "Discord (discord.py)"),
        ("paramiko", "NAS SFTP (paramiko)"),
        ("zfec", "Reed-Solomon (zfec)"),
        ("sqlcipher3", "SQLCipher database"),
        ("mlkem", "Post-quantum sharing (mlkem)"),
    ):
        if importlib.util.find_spec(module) is not None:
            print(f"[OK]   {label}")
        else:
            print(f"[WARN] optional dependency missing: {label}")

    print(f"Keystore: {'present' if state.keystore_path.exists() else 'missing'} ({state.keystore_path})")
    return 1 if failures else 0


def _cmd_serve(args) -> int:
    import uvicorn
    from ghostdrive.web.server import app, find_available_port

    host = args.host
    port = args.port or find_available_port(8000)
    url = f"http://{host}:{port}"
    print(f"GhostDrive web UI: {url}")
    if not args.no_browser:
        import threading
        import webbrowser
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    uvicorn.run(app, host=host, port=port, log_level=args.log_level)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ghostdrive-cli",
        description="Headless GhostDrive control (same services as the web UI).",
    )
    parser.add_argument("--passphrase", help="Vault passphrase (otherwise prompt / GHOSTDRIVE_PASSPHRASE).")
    parser.add_argument("--version", action="version", version=f"ghostdrive {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="Run the web interface.")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=0)
    serve.add_argument("--log-level", default="info")
    serve.add_argument("--no-browser", action="store_true")
    serve.set_defaults(func=_cmd_serve)

    init = sub.add_parser("init", help="Create a new vault and print its seed phrase.")
    init.add_argument("--force", action="store_true")
    init.add_argument("--fast", action="store_true", help="Use test Argon2 parameters (insecure).")
    init.set_defaults(func=_cmd_init)

    unlock = sub.add_parser("unlock", help="Verify the passphrase and open the database.")
    unlock.set_defaults(func=_cmd_unlock)

    status = sub.add_parser("status", help="Show vault paths and (optionally) totals.")
    status.set_defaults(func=_cmd_status)

    ls = sub.add_parser("ls", help="List files.")
    ls.add_argument("path", nargs="?", default="/")
    ls.add_argument("--category", default=None)
    ls.add_argument("--search", default=None)
    ls.add_argument("--json", action="store_true")
    ls.set_defaults(func=_cmd_ls)

    upload = sub.add_parser("upload", help="Upload a file.")
    upload.add_argument("file")
    upload.add_argument("--tier", default="IMPORTANT", choices=["CRITICAL", "IMPORTANT", "DISPOSABLE"])
    upload.add_argument("--destination", default="/")
    upload.add_argument("--json", action="store_true")
    upload.set_defaults(func=_cmd_upload)

    download = sub.add_parser("download", help="Download a file by id or name.")
    download.add_argument("file")
    download.add_argument("-o", "--output", required=True)
    download.set_defaults(func=_cmd_download)

    rm = sub.add_parser("rm", help="Move a file to Trash (or purge it).")
    rm.add_argument("file")
    rm.add_argument("--purge", action="store_true")
    rm.set_defaults(func=_cmd_rm)

    trash = sub.add_parser("trash", help="List or empty Trash.")
    trash.add_argument("--empty", action="store_true")
    trash.add_argument("--older-than-days", type=int, default=None)
    trash.set_defaults(func=_cmd_trash)

    share = sub.add_parser("share", help="Create a public share link.")
    share.add_argument("file")
    share.add_argument("--recipient", default="public")
    share.add_argument("--ttl-hours", type=int, default=72)
    share.add_argument("--passcode", default=None)
    share.add_argument("--max-downloads", type=int, default=None)
    share.add_argument("--base-url", default="http://127.0.0.1:8000")
    share.set_defaults(func=_cmd_share)

    backends = sub.add_parser("backends", help="List configured backends or test health.")
    backends.add_argument("--test", action="store_true")
    backends.set_defaults(func=_cmd_backends)

    verify = sub.add_parser("verify", help="Re-hash and verify a file's chunks.")
    verify.add_argument("file")
    verify.add_argument("--json", action="store_true")
    verify.set_defaults(func=_cmd_verify)

    doctor = sub.add_parser("doctor", help="Check environment and optional dependencies.")
    doctor.set_defaults(func=_cmd_doctor)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except SystemExit as exc:
        raise
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    finally:
        try:
            state.clean_shutdown()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
