"""Backend management service used by the web API and CLI."""

from __future__ import annotations

import json
import logging
import shutil
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from ghostdrive.backends.base import HealthResult
from ghostdrive.crypto.credential_store import credential_store
from ghostdrive.platform import get_drive_monitor
from ghostdrive.pipeline.drive_registration import DriveRegistrar
from ghostdrive.services.context import (
    active_backends,
    build_backend,
    ensure_local_backend,
    require_db,
)

logger = logging.getLogger("ghostdrive.services.backends")

_REMOTE_TIERS = {
    "telegram": "REMOTE_PRIMARY",
    "discord": "REMOTE_SECONDARY",
}
_DISPLAY_NAMES = {
    "telegram": "Telegram MTProto",
    "discord": "Discord Bot Channel",
    "local": "Local Encrypted Locker",
    "local_fs": "Local Encrypted Locker",
    "external_drive": "External USB Drive",
    "nas": "Network Attached Storage",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _label_for(row, db) -> str:
    stored = db.get_setting(f"backend_label_{row['id']}", "")
    if stored:
        return stored
    registry = db.get_drive_registry_by_backend(row["id"])
    if registry is not None:
        return registry["drive_label"]
    return _DISPLAY_NAMES.get(row["type"], row["type"].title())


def _tier_for(backend_type: str) -> str:
    return _REMOTE_TIERS.get(backend_type, "LOCAL_LOCKER")


def list_backends_view() -> dict:
    """Return the backend cards shown in the UI, backed by the database."""
    db = require_db()
    ensure_local_backend()

    configured = []
    for row in db.list_backends(include_deprecated=True):
        configured.append({
            "id": row["id"],
            "name": _label_for(row, db),
            "provider": _DISPLAY_NAMES.get(row["type"], row["type"].title()),
            "provider_key": row["type"],
            "tier": _tier_for(row["type"]),
            "enabled": row["status"] != "deprecated",
            "status": "DISABLED" if row["status"] == "deprecated" else "ONLINE" if row["status"] == "healthy" else row["status"].upper(),
            "used_bytes": int(row["quota_used"] or 0),
            "quota_cap_bytes": int(row["quota_limit"] or 0),
            "quota_reserved_bytes": int(row["quota_reserved"] or 0),
            "latency_ms": float(row["latency_ms"]) if row["latency_ms"] is not None else 0.0,
            "last_health_check": row["last_health_check"],
            "last_error": row["last_error"],
        })

    return {
        "tiers": {
            "REMOTE_PRIMARY": ["Telegram MTProto"],
            "REMOTE_SECONDARY": ["Discord Bot Channel"],
            "LOCAL_LOCKER": ["Local Encrypted Locker", "External USB Drive", "NAS (SFTP/SMB)"],
        },
        "configured_backends": configured,
    }


async def test_connectivity(
    provider: str,
    credentials: dict,
    backend_id: Optional[str] = None,
) -> dict:
    """Actually exercise a backend plugin's health_check()."""
    db = require_db()
    provider_key = provider.lower().replace(" ", "_")
    started = time.perf_counter()

    try:
        if backend_id:
            row = db.get_backend(backend_id)
            if row is None:
                return {"success": False, "latency_ms": 0, "message": "Backend not found."}
            obj = build_backend(row)
        elif "telegram" in provider_key:
            from ghostdrive.backends.telegram_backend import TelegramBackend
            obj = TelegramBackend(
                api_id=credentials.get("api_id"),
                api_hash=credentials.get("api_hash"),
                phone=credentials.get("phone"),
                _skip_keyring=True,
            )
        elif "discord" in provider_key:
            from ghostdrive.backends.discord_backend import DiscordBackend
            obj = DiscordBackend(
                channel_id=credentials.get("channel_id"),
                bot_token=credentials.get("bot_token"),
                _skip_keyring=True,
            )
        elif any(token in provider_key for token in ("local", "locker", "folder")):
            from ghostdrive.backends.local_fs_backend import LocalFSBackend
            obj = LocalFSBackend(
                root_path=credentials.get("path") or credentials.get("folder_path")
            )
        elif "nas" in provider_key or "sftp" in provider_key or "smb" in provider_key:
            from ghostdrive.backends.nas_backend import NASBackend
            obj = NASBackend(
                protocol=credentials.get("protocol", "sftp"),
                host=credentials.get("host", ""),
                port=credentials.get("port"),
                username=credentials.get("username"),
                password=credentials.get("password"),
                private_key_path=credentials.get("private_key_path"),
                share=credentials.get("share"),
                remote_dir=credentials.get("remote_dir", "GhostDriveData"),
            )
        elif "external" in provider_key or "usb" in provider_key:
            from ghostdrive.backends.external_drive_backend import ExternalDriveBackend
            obj = ExternalDriveBackend(drive_uuid=credentials.get("drive_uuid", ""))
        else:
            return {
                "success": False,
                "latency_ms": 0,
                "message": f"Unsupported backend provider: {provider}",
            }

        result: HealthResult = await obj.health_check()
        latency = result.latency_ms or (time.perf_counter() - started) * 1000
        if result.reachable and backend_id:
            db.update_backend_health(backend_id, "healthy", latency_ms=latency, error=None)
        elif backend_id:
            db.update_backend_health(backend_id, "unreachable", latency_ms=latency, error=result.error)

        return {
            "success": bool(result.reachable),
            "latency_ms": round(latency, 2),
            "quota_remaining": result.quota_remaining,
            "message": (
                f"{provider} reachable in {latency:.1f} ms."
                if result.reachable
                else f"{provider} unreachable: {result.error}"
            ),
        }
    except Exception as exc:
        logger.warning("Backend connectivity test failed for %s: %s", provider, exc)
        return {
            "success": False,
            "latency_ms": round((time.perf_counter() - started) * 1000, 2),
            "message": f"{provider} test failed: {exc}",
        }


def _insert_backend(
    db,
    backend_type: str,
    credentials_ref: str,
    label: str,
    quota_limit: int = 1 << 62,
    priority: int = 100,
) -> str:
    backend_id = str(uuid.uuid4())
    with db.transaction():
        db._conn.execute(
            """INSERT INTO backends
               (id, type, credentials_ref, status, priority, quota_used, quota_limit, quota_reserved)
               VALUES (?, ?, ?, 'healthy', ?, 0, ?, 0)""",
            (backend_id, backend_type, credentials_ref, priority, quota_limit),
        )
        db.set_setting(f"backend_label_{backend_id}", label)
    return backend_id


def save_backend(
    provider: str,
    name: str,
    tier: str,
    enabled: bool,
    credentials: dict,
    quota_cap_gb: float = 0.0,
) -> dict:
    """Create a real backend row from the settings wizard payload."""
    db = require_db()
    provider_key = provider.lower().replace(" ", "_")
    name = (name or "").strip() or _DISPLAY_NAMES.get(provider_key, provider)
    quota_limit = int(quota_cap_gb * 1024 ** 3) if quota_cap_gb and quota_cap_gb > 0 else (1 << 62)

    if any(token in provider_key for token in ("local", "locker", "folder")):
        folder = credentials.get("path") or credentials.get("folder_path")
        if not folder:
            raise ValueError("Local Folder Locker requires a 'path'.")
        folder_path = Path(folder).expanduser().resolve()
        folder_path.mkdir(parents=True, exist_ok=True)
        registrar = DriveRegistrar(db)
        result = registrar.register_local_folder(folder_path, name)
        with db.transaction():
            db.set_setting(f"backend_label_{result['backend_id']}", name)
            db._conn.execute(
                "UPDATE backends SET quota_limit = ? WHERE id = ?",
                (quota_limit if quota_cap_gb > 0 else shutil.disk_usage(folder_path).total, result["backend_id"]),
            )
        return {"status": "success", "backend_id": result["backend_id"], "message": f"Local locker {name!r} registered."}

    if "external" in provider_key or "usb" in provider_key:
        drive_uuid = credentials.get("drive_uuid")
        if not drive_uuid:
            raise ValueError("External drive registration requires 'drive_uuid'.")
        drives = []
        try:
            drives = get_drive_monitor().list_drives()
        except Exception as exc:
            logger.warning("Could not enumerate drives: %s", exc)
        drive = next((d for d in drives if d.drive_uuid == drive_uuid), None)
        capacity = int(credentials.get("capacity_bytes") or (drive.capacity_bytes if drive else 0))
        mount = credentials.get("mount_hint") or (drive.mountpoint if drive else "")
        backend_id = _insert_backend(
            db, "external_drive", drive_uuid, name, quota_limit=capacity or quota_limit
        )
        with db.transaction():
            db.insert_drive_registry({
                "backend_id": backend_id,
                "drive_uuid": drive_uuid,
                "drive_serial": credentials.get("drive_serial") or (drive.drive_serial if drive else None),
                "drive_label": name,
                "drive_type": credentials.get("drive_type") or (drive.drive_type if drive else "unknown"),
                "capacity_bytes": capacity,
                "mount_hint": mount,
                "registered_at": _now_iso(),
            })
        return {"status": "success", "backend_id": backend_id, "message": f"External drive {name!r} registered."}

    if "nas" in provider_key or "sftp" in provider_key or "smb" in provider_key:
        config = {
            "protocol": credentials.get("protocol", "sftp"),
            "host": credentials.get("host", ""),
            "port": credentials.get("port"),
            "username": credentials.get("username"),
            "password": credentials.get("password"),
            "private_key_path": credentials.get("private_key_path"),
            "share": credentials.get("share"),
            "remote_dir": credentials.get("remote_dir", "GhostDriveData"),
        }
        if not config["host"] or not config["username"]:
            raise ValueError("NAS backend requires 'host' and 'username'.")
        ref = f"nas_config_{uuid.uuid4()}"
        credential_store.store(ref, json.dumps(config))
        backend_id = _insert_backend(db, "nas", ref, name, quota_limit=quota_limit)
        return {"status": "success", "backend_id": backend_id, "message": f"NAS backend {name!r} registered."}

    if "telegram" in provider_key:
        api_id = credentials.get("api_id")
        api_hash = credentials.get("api_hash")
        phone = credentials.get("phone")
        if not api_id or not api_hash or not phone:
            raise ValueError("Telegram requires api_id, api_hash, and phone.")
        credential_store.store("telegram_api_id", str(api_id))
        credential_store.store("telegram_api_hash", str(api_hash))
        credential_store.store("telegram_phone", str(phone))
        backend_id = _insert_backend(db, "telegram", "telegram_credentials", name, quota_limit=quota_limit)
        return {
            "status": "success",
            "backend_id": backend_id,
            "message": "Telegram credentials saved. Complete phone/OTP authentication before uploading.",
        }

    if "discord" in provider_key:
        token = credentials.get("bot_token")
        channel_id = credentials.get("channel_id")
        if not token or not channel_id:
            raise ValueError("Discord requires bot_token and channel_id.")
        credential_store.store("discord_bot_token", str(token))
        credential_store.store("discord_channel_id", str(channel_id))
        backend_id = _insert_backend(db, "discord", "discord_credentials", name, quota_limit=quota_limit)
        return {"status": "success", "backend_id": backend_id, "message": f"Discord backend {name!r} registered."}

    raise ValueError(f"Unsupported backend provider: {provider}")


def toggle_backend(backend_id: str, enabled: bool) -> dict:
    db = require_db()
    row = db.get_backend(backend_id)
    if row is None:
        raise FileNotFoundError(f"Backend {backend_id} not found.")
    if not enabled and row["type"] in ("local", "local_fs"):
        active_local = sum(
            1
            for candidate in db.list_backends()
            if candidate["type"] in ("local", "local_fs")
        )
        if active_local <= 1:
            raise ValueError("Cannot disable the only local vault. Add another local backend first.")
    db.update_backend_status(backend_id, "healthy" if enabled else "deprecated")
    return {
        "status": "success",
        "backend_id": backend_id,
        "enabled": enabled,
        "message": f"Backend {_label_for(row, db)!r} {'enabled' if enabled else 'disabled'}.",
    }


def remove_backend(backend_id: str, force: bool = False) -> dict:
    db = require_db()
    row = db.get_backend(backend_id)
    if row is None:
        raise FileNotFoundError(f"Backend {backend_id} not found.")
    if row["type"] in ("local", "local_fs"):
        # Never allow removing the last local vault -- it is the offline fallback.
        local_count = sum(1 for r in db.list_backends() if r["type"] in ("local", "local_fs"))
        if local_count <= 1 and not force:
            raise ValueError("Cannot remove the only local vault. Add another backend first.")
    registrar = DriveRegistrar(db)
    registrar.deregister_backend(backend_id, force=force)
    credential_store.delete(row["credentials_ref"] or "")
    return {"status": "success", "message": f"Backend {_label_for(row, db)!r} removed."}


async def health_check_all() -> dict:
    db = require_db()
    _, objects = await active_backends(connect_remote=False)
    results = []
    for row in db.list_backends():
        obj = objects.get(row["id"])
        if obj is None:
            continue
        started = time.perf_counter()
        try:
            result = await obj.health_check()
            latency = result.latency_ms or (time.perf_counter() - started) * 1000
            status = "healthy" if result.reachable else "unreachable"
            db.update_backend_health(row["id"], status, latency_ms=latency, error=result.error)
            results.append({
                "backend_id": row["id"],
                "type": row["type"],
                "reachable": result.reachable,
                "latency_ms": round(latency, 2),
                "error": result.error,
            })
        except Exception as exc:
            db.update_backend_health(row["id"], "unreachable", error=str(exc)[:500])
            results.append({
                "backend_id": row["id"],
                "type": row["type"],
                "reachable": False,
                "latency_ms": None,
                "error": str(exc),
            })
    return {"status": "success", "results": results}


def list_connected_drives() -> dict:
    require_db()
    try:
        drives = get_drive_monitor().list_drives()
    except Exception as exc:
        logger.warning("Drive enumeration failed: %s", exc)
        drives = []
    return {
        "drives": [
            {
                "drive_uuid": d.drive_uuid,
                "drive_serial": d.drive_serial,
                "mountpoint": d.mountpoint,
                "drive_type": d.drive_type,
                "capacity_bytes": d.capacity_bytes,
                "filesystem": getattr(d, "filesystem", None),
            }
            for d in drives
        ]
    }


def discover_nas() -> dict:
    db = require_db()
    return {"services": DriveRegistrar(db).suggest_nas_backends()}
