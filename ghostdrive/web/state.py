"""
state.py -- Global application state, connection management, and clean shutdown handler.
"""

import logging
import asyncio
from typing import Optional, Dict, Any, List
from pathlib import Path

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
        self.settings: Dict[str, Any] = {
            "theme": "dark",
            "accent_color": "#8b5cf6",
            "autostart": False,
            "desktop_notifications": True,
            "log_level": "INFO",
            "proxy_type": "none",
            "proxy_host": "",
            "proxy_port": 0,
        }

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
        if self.km is not None:
            logger.info("Zeroing cryptographic master key from memory...")
            self.km.lock()
            self.km = None

        logger.info("Shutdown complete.")

state = GlobalState()
