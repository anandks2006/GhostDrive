"""Application context helpers shared by web routes and the CLI.

All backend construction lives here so that the web routes and the CLI use the
exact same code paths.  Every helper fails loudly when the vault is locked;
routes translate those exceptions into HTTP errors.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import uuid
from pathlib import Path
from typing import Any, Optional

from ghostdrive.backends.base import BackendBase
from ghostdrive.backends.discord_backend import DiscordBackend
from ghostdrive.backends.external_drive_backend import ExternalDriveBackend
from ghostdrive.backends.local_fs_backend import LocalFSBackend
from ghostdrive.backends.nas_backend import NASBackend
from ghostdrive.backends.s3_backend import S3Backend
from ghostdrive.backends.telegram_backend import TelegramBackend
from ghostdrive.crypto.credential_store import credential_store
from ghostdrive.crypto.nonce import NonceManager
from ghostdrive.web.state import state

logger = logging.getLogger("ghostdrive.services.context")

REMOTE_BACKEND_TYPES = {"telegram", "discord", "s3"}
LOCAL_BACKEND_TYPES = {"local", "local_fs", "external_drive", "nas"}


def require_unlocked() -> None:
    """Raise RuntimeError unless the keystore is unlocked and the DB is open."""
    if state.km is None or not state.km.is_unlocked:
        raise RuntimeError("Vault is locked. Unlock the keystore first.")
    if state.db is None or getattr(state.db, "_conn", None) is None:
        raise RuntimeError("Database is not open.")


def require_db():
    """Return the open GhostDriveDB instance, raising RuntimeError otherwise."""
    require_unlocked()
    return state.db


def get_master_key() -> bytes:
    require_unlocked()
    return state.km.master_key


def hkdf_salt() -> bytes:
    require_unlocked()
    return state.km.hkdf_salt


def nonce_manager() -> NonceManager:
    require_db()
    return NonceManager(state.app_data_dir, db=state.db)


def build_backend(row: Any) -> BackendBase:
    """Instantiate the correct BackendBase implementation for a DB row."""
    backend_type = str(row["type"]).lower()
    credentials_ref = row["credentials_ref"] or ""
    backend_id = row["id"]

    if backend_type in ("local", "local_fs", "local_folder"):
        obj = LocalFSBackend(credentials_ref=credentials_ref)
    elif backend_type == "external_drive":
        registry = state.db.get_drive_registry_by_backend(backend_id)
        drive_uuid = registry["drive_uuid"] if registry else credentials_ref
        if not drive_uuid:
            raise RuntimeError("External drive has no registered drive UUID.")
        obj = ExternalDriveBackend(drive_uuid=drive_uuid)
    elif backend_type == "nas":
        raw = credential_store.load(credentials_ref) if credentials_ref else None
        try:
            config = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            raise RuntimeError("Stored NAS configuration is not valid JSON.")
        obj = NASBackend(**config)
    elif backend_type == "s3":
        raw = credential_store.load(credentials_ref) if credentials_ref else None
        try:
            config = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            raise RuntimeError("Stored S3 configuration is not valid JSON.")
        obj = S3Backend(**config)
    elif backend_type == "telegram":
        obj = TelegramBackend()
    elif backend_type == "discord":
        obj = DiscordBackend()
    else:
        raise RuntimeError(f"Unsupported backend type: {backend_type!r}")

    # The upload pipeline addresses backends by their DB identifier.
    obj.id = backend_id
    return obj


def ensure_local_backend() -> str:
    """Return a healthy local-folder backend id, creating the default vault if needed.

    A local vault is always available so that GhostDrive remains usable offline
    and so that tests never depend on network credentials.
    """
    db = require_db()
    for row in db.list_backends():
        if row["type"] in ("local", "local_fs"):
            return row["id"]

    vault = Path(state.app_data_dir) / "vault"
    vault.mkdir(parents=True, exist_ok=True)
    try:
        capacity = shutil.disk_usage(vault).total
    except OSError:
        capacity = 100 * 1024 * 1024 * 1024

    backend_id = str(uuid.uuid4())
    with db.transaction():
        db._conn.execute(
            """INSERT INTO backends
               (id, type, credentials_ref, status, priority, quota_used, quota_limit, quota_reserved)
               VALUES (?, 'local', ?, 'healthy', 100, 0, ?, 0)""",
            (backend_id, str(vault), capacity),
        )
    logger.info("Created default local vault backend at %s", vault)
    return backend_id


async def active_backends(
    connect_remote: bool = True,
    timeout: float = 8.0,
) -> tuple[list[Any], dict[str, BackendBase]]:
    """Build backend objects for every configured backend.

    Remote providers are connected (with a timeout) before being considered
    eligible for an upload.  Unreachable remotes are marked degraded rather
    than breaking the whole upload.
    """
    db = require_db()
    rows: list[Any] = []
    objects: dict[str, BackendBase] = {}

    for row in db.list_backends():
        try:
            obj = build_backend(row)
        except Exception as exc:
            logger.warning("Skipping backend %s (%s): %s", row["id"][:8], row["type"], exc)
            continue

        if row["type"] in REMOTE_BACKEND_TYPES and connect_remote:
            try:
                await asyncio.wait_for(obj.connect(), timeout=timeout)
                obj._connected = True
            except Exception as exc:
                logger.warning("Backend %s (%s) unreachable: %s", row["id"][:8], row["type"], exc)
                db.update_backend_health(
                    row["id"], "unreachable", error=str(exc)[:500]
                )
                continue

        rows.append(row)
        objects[row["id"]] = obj

    if not rows:
        local_id = ensure_local_backend()
        row = db.get_backend(local_id)
        if row is not None:
            rows.append(row)
            objects[local_id] = build_backend(row)

    return rows, objects

