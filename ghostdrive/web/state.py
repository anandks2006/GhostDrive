"""
state.py -- Global application state, connection management, and clean shutdown handler.
"""

import json
import logging
import asyncio
from typing import Optional, Dict, Any, List
from pathlib import Path

from ghostdrive.crypto.credential_store import credential_store
from ghostdrive.crypto.keystore import KeystoreManager
from ghostdrive.database.db import GhostDriveDB
from ghostdrive.utils.platform import get_app_data_dir

logger = logging.getLogger("ghostdrive_web")

class GlobalState:
    """Singleton holding initialized active components for the web session."""
    def __init__(self):
        self.app_data_dir: Path = get_app_data_dir()
        self.keystore_path: Path = self.app_data_dir / "keystore.json"
        self.db_path: Path = self.app_data_dir / "ghostdrive.db"
        self.km: Optional[KeystoreManager] = None
        self.db: Optional[GhostDriveDB] = None
        self.active_uploads: Dict[str, Dict[str, Any]] = {}
        self.active_downloads: Dict[str, Dict[str, Any]] = {}
        self.telemetry_clients: set = set()
        self.background_tasks: set = set()
        self.scrub_job: Optional[str] = None
        self.settings: Dict[str, Any] = {
            "theme": "dark",
            "accent_color": "#c4f56a",
            "autostart": False,
            "desktop_notifications": True,
            "log_level": "INFO",
            "proxy_type": "none",
            "proxy_host": "",
            "proxy_port": 0,
        }
        self._settings_loaded = False

    def load_persisted_settings(self) -> None:
        """Merge values stored in the DB settings table into ``state.settings``."""
        if self.db is None or getattr(self.db, "_conn", None) is None:
            return
        for key, default in self.settings.items():
            try:
                raw = self.db.get_setting(f"pref_{key}", "")
            except Exception:
                raw = ""
            if not raw:
                continue
            try:
                self.settings[key] = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                self.settings[key] = raw
        self._settings_loaded = True

    def persist_settings(self) -> None:
        """Store the current in-memory preferences in the DB settings table."""
        if self.db is None or getattr(self.db, "_conn", None) is None:
            return
        with self.db.transaction():
            for key, value in self.settings.items():
                self.db.set_setting(f"pref_{key}", json.dumps(value))

    def clean_shutdown(self) -> None:
        """Executes safe halt logic committing WAL checkpoints and zeroing memory (Spec §9.7)."""
        logger.info("Executing clean shutdown sequence...")
        
        # 1. Close database and run WAL checkpoint
        if self.db is not None:
            try:
                if getattr(self.db, "_conn", None) is not None:
                    logger.info("Checkpointing database WAL and closing connection...")
                    self.db.wal_checkpoint()
                    self.db.close()
                else:
                    logger.info("Database connection was already closed.")
            except Exception as exc:
                logger.error("Error during DB shutdown checkpoint: %s", exc)
            self.db = None

        # 2. Lock keystore (zero keys from memory)
        credential_store.clear_active_key()
        if self.km is not None:
            logger.info("Zeroing cryptographic master key from memory...")
            self.km.lock()
            self.km = None

        # 3. Cancel background scrub/heal helpers
        for task in list(self.background_tasks):
            try:
                task.cancel()
            except Exception:
                pass
        self.background_tasks.clear()
        self.scrub_job = None

        logger.info("Shutdown complete.")

state = GlobalState()
