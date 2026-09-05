"""
drive_registration.py -- DriveRegistrar engine for registering, monitoring, and deregistering drives.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import List, Dict

from ghostdrive.database.db import GhostDriveDB
from ghostdrive.platform import get_drive_monitor
from ghostdrive.platform.drive_monitor import DriveIdentity
from ghostdrive.exceptions import (
    SecureEraseBlockedError,
    DriveIdentityError,
    DatabaseError,
)

logger = logging.getLogger(__name__)

try:
    import keyring as _keyring
    _KEYRING_AVAILABLE = True
except ImportError:
    _KEYRING_AVAILABLE = False

try:
    from zeroconf import Zeroconf, ServiceBrowser
    _ZEROCONF_AVAILABLE = True
except ImportError:
    _ZEROCONF_AVAILABLE = False


class NASDiscoveryListener:
    """Listener to gather mDNS discovery results."""
    def __init__(self) -> None:
        self.services: List[Dict] = []

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        info = zc.get_service_info(type_, name)
        if info:
            addresses = [str(addr) for addr in info.parsed_addresses()]
            host = addresses[0] if addresses else info.server
            port = info.port
            
            protocol = "unknown"
            if "sftp" in type_ or "ssh" in type_:
                protocol = "sftp"
            elif "smb" in type_ or "microsoft-ds" in type_:
                protocol = "smb"

            self.services.append({
                "name": name.split(".")[0],
                "host": host,
                "port": port,
                "protocol": protocol,
            })

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        pass

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        pass


class DriveRegistrar:
    """
    DriveRegistrar manages backend registration, redundancy checks before removal (S9 guardrail),
    hotplugging drive detection, and passive mDNS NAS discovery.
    """

    def __init__(self, db: GhostDriveDB) -> None:
        self.db = db

    def list_connected_drives(self) -> List[DriveIdentity]:
        """List all physically connected and mounted drives via the platform layer."""
        try:
            monitor = get_drive_monitor()
            return monitor.list_drives()
        except Exception as exc:
            logger.error("Failed to list connected drives: %s", exc)
            return []

    def register_external_drive(self, drive: DriveIdentity, label: str) -> dict:
        """
        Register a connected drive as a backend.
        Stores the root path in the OS keyring and inserts metadata into drive_registry.
        """
        if not drive.drive_uuid:
            raise DriveIdentityError("Cannot register a drive without a unique filesystem UUID.")

        backend_id = str(uuid_generator())
        now = datetime_now_iso()

        # Store the target root path securely in the OS keyring
        keyring_key = f"local_root_{backend_id}"
        root_path = Path(drive.mountpoint) / "GhostDriveData"
        
        if _KEYRING_AVAILABLE:
            try:
                from ghostdrive.crypto.credential_store import credential_store
                credential_store.store(keyring_key, str(root_path))
                logger.info("Saved drive root path (encrypted) to OS keyring under account: %s", keyring_key)
            except Exception as exc:
                logger.warning("Failed to write drive path to OS keyring: %s", exc)
        else:
            logger.warning("OS keyring not available. Storing plain path link.")

        # Database transaction
        try:
            with self.db.transaction():
                # 1. Insert into backends table
                # Free tier limit / effectively unlimited for local storage: 4 EB sentinel or physical capacity
                self.db._conn.execute(
                    """INSERT INTO backends
                       (id, type, credentials_ref, status, priority, quota_used, quota_limit, quota_reserved)
                       VALUES (?, 'local', ?, 'healthy', 100, 0, ?, 0)""",
                    (backend_id, keyring_key, drive.capacity_bytes),
                )
                
                # 2. Insert into drive_registry table
                self.db.insert_drive_registry({
                    "backend_id": backend_id,
                    "drive_uuid": drive.drive_uuid,
                    "drive_serial": drive.drive_serial,
                    "drive_label": label,
                    "drive_type": drive.drive_type,
                    "capacity_bytes": drive.capacity_bytes,
                    "mount_hint": drive.mountpoint,
                    "registered_at": now,
                })
            
            logger.info("Registered external drive backend: %s (UUID: %s)", label, drive.drive_uuid)
            return {
                "backend_id": backend_id,
                "drive_label": label,
                "drive_uuid": drive.drive_uuid,
                "mountpoint": drive.mountpoint,
            }
        except Exception as exc:
            # Cleanup keyring on failure
            if _KEYRING_AVAILABLE:
                try:
                    _keyring.delete_password("ghostdrive", keyring_key)
                except Exception:
                    pass
            raise DatabaseError(f"Failed to register drive in database: {exc}")

    def register_local_folder(self, folder_path: Path, label: str) -> dict:
        """
        Register a local folder/directory as a backend.
        Stores the folder path in the OS keyring and inserts metadata into drive_registry.
        """
        import shutil
        import uuid

        backend_id = uuid_generator()
        now = datetime_now_iso()

        # Store the target root path securely in the OS keyring
        keyring_key = f"local_root_{backend_id}"
        root_path = folder_path.resolve()

        if _KEYRING_AVAILABLE:
            try:
                from ghostdrive.crypto.credential_store import credential_store
                credential_store.store(keyring_key, str(root_path))
                logger.info("Saved folder root path (encrypted) to OS keyring under account: %s", keyring_key)
            except Exception as exc:
                logger.warning("Failed to write folder path to OS keyring: %s", exc)
        else:
            logger.warning("OS keyring not available. Storing plain path link.")

        # Get disk usage for capacity
        try:
            usage = shutil.disk_usage(root_path)
            capacity = usage.total
        except Exception:
            capacity = 100 * 1024 * 1024 * 1024  # 100 GB default fallback

        # Database transaction
        try:
            with self.db.transaction():
                # 1. Insert into backends table
                self.db._conn.execute(
                    """INSERT INTO backends
                       (id, type, credentials_ref, status, priority, quota_used, quota_limit, quota_reserved)
                       VALUES (?, 'local', ?, 'healthy', 100, 0, ?, 0)""",
                    (backend_id, keyring_key, capacity),
                )
                
                # 2. Insert into drive_registry table
                folder_uuid = f"folder-{uuid.uuid4()}"
                self.db.insert_drive_registry({
                    "backend_id": backend_id,
                    "drive_uuid": folder_uuid,
                    "drive_serial": f"folder-serial-{uuid.uuid4().hex[:8]}",
                    "drive_label": label,
                    "drive_type": "unknown",
                    "capacity_bytes": capacity,
                    "mount_hint": str(root_path),
                    "registered_at": now,
                })
            
            logger.info("Registered local folder backend: %s (Path: %s)", label, root_path)
            return {
                "backend_id": backend_id,
                "drive_label": label,
                "drive_uuid": folder_uuid,
                "mountpoint": str(root_path),
            }
        except Exception as exc:
            # Cleanup keyring on failure
            if _KEYRING_AVAILABLE:
                try:
                    _keyring.delete_password("ghostdrive", keyring_key)
                except Exception:
                    pass
            raise DatabaseError(f"Failed to register local folder in database: {exc}")

    def deregister_backend(self, backend_id: str, force: bool = False) -> None:
        """
        Deregister a backend from the system.
        Implements the S9 guardrail to check for chunk redundancy before removing.
        """
        # --- S9 Guardrail: Redundancy check ---
        under_redundant_chunks = []
        
        try:
            with self.db.transaction():
                # Get all chunks stored on this backend
                chunks = self.db._conn.execute(
                    "SELECT DISTINCT chunk_id FROM chunk_locations WHERE backend_id = ? AND status = 'confirmed'",
                    (backend_id,),
                ).fetchall()

                for chunk in chunks:
                    chunk_id = chunk["chunk_id"]
                    
                    # Query file tier to get redundancy level
                    file_row = self.db._conn.execute(
                        "SELECT f.tier FROM chunks c JOIN files f ON c.file_id = f.id WHERE c.id = ?",
                        (chunk_id,),
                    ).fetchone()
                    
                    tier = file_row["tier"] if file_row else "IMPORTANT"
                    redundancy_level = 2
                    if tier == "CRITICAL":
                        redundancy_level = 4
                    elif tier == "IMPORTANT":
                        redundancy_level = 3

                    required_redundancy = redundancy_level - 1

                    # Count confirmed locations on OTHER backends
                    loc_count_row = self.db._conn.execute(
                        "SELECT COUNT(DISTINCT backend_id) as count FROM chunk_locations WHERE chunk_id = ? AND status = 'confirmed' AND backend_id != ?",
                        (chunk_id, backend_id),
                    ).fetchone()
                    loc_count = loc_count_row["count"] if loc_count_row else 0

                    if loc_count < required_redundancy:
                        under_redundant_chunks.append((chunk_id, loc_count, required_redundancy))

            if under_redundant_chunks and not force:
                raise SecureEraseBlockedError(
                    f"Cannot remove backend — {len(under_redundant_chunks)} chunks exist ONLY on this backend or have insufficient redundancy. "
                    "Add another backend first, or check 'Accept permanent data loss' to remove anyway."
                )

            # Perform removal
            keyring_key = f"local_root_{backend_id}"
            with self.db.transaction():
                # 1. Delete locations on this backend (two-phase commit handles cleanup)
                self.db._conn.execute("DELETE FROM chunk_locations WHERE backend_id = ?", (backend_id,))
                
                # 2. Delete registry and backend
                self.db._conn.execute("DELETE FROM drive_registry WHERE backend_id = ?", (backend_id,))
                self.db._conn.execute("DELETE FROM backends WHERE id = ?", (backend_id,))

            # 3. Clean OS keyring
            if _KEYRING_AVAILABLE:
                try:
                    _keyring.delete_password("ghostdrive", keyring_key)
                    logger.info("Deleted drive root path from OS keyring: %s", keyring_key)
                except Exception:
                    pass

            logger.info("Backend %s successfully deregistered.", backend_id)

        except SecureEraseBlockedError:
            raise
        except Exception as exc:
            raise DatabaseError(f"Failed to deregister backend: {exc}")

    def suggest_nas_backends(self) -> List[Dict]:
        """
        Discover local NAS backends passively via mDNS (zeroconf).
        Scans for SFTP (SSH) and SMB services. Blocks for max 2 seconds.
        """
        if not _ZEROCONF_AVAILABLE:
            logger.warning("zeroconf is not installed. Passive NAS discovery unavailable.")
            return []

        listener = NASDiscoveryListener()
        try:
            zeroconf = Zeroconf()
            
            # Browser for SSH/SFTP and SMB services
            [
                ServiceBrowser(zeroconf, "_sftp-ssh._tcp.local.", listener),
                ServiceBrowser(zeroconf, "_smb._tcp.local.", listener),
                ServiceBrowser(zeroconf, "_microsoft-ds._tcp.local.", listener),
            ]
            
            # Wait 2 seconds for discovery
            time.sleep(2.0)
            zeroconf.close()
            
            logger.info("mDNS passive NAS discovery found %d services.", len(listener.services))
            return listener.services
        except Exception as exc:
            logger.debug("mDNS discovery encountered an error: %s", exc)
            return []


def uuid_generator() -> str:
    import uuid
    return str(uuid.uuid4())


def datetime_now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
