"""
__main__.py -- Main startup entry point for the GhostDrive GUI.
"""

import sys
import os
import signal
import asyncio
import logging
from pathlib import Path

from PyQt6.QtWidgets import QApplication
import qasync

from ghostdrive.gui.styles import get_stylesheet
from ghostdrive.gui.preflight_wizard import PreflightWizard
from ghostdrive.gui.unlock_view import UnlockView
from ghostdrive.gui.main_view import MainWindow
from ghostdrive.database.db import GhostDriveDB
from ghostdrive.crypto.keystore import KeystoreManager

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("ghostdrive_gui")

# Global variables for cleanup reference
_km_ref = None
_db_ref = None

def clean_shutdown() -> None:
    """Executes safe halt logic committing WAL checkpoints and zeroing memory."""
    logger.info("Executing clean shutdown sequence...")
    
    global _db_ref, _km_ref
    
    # 1. Close database and run WAL checkpoint
    if _db_ref:
        try:
            logger.info("Checkpointing database WAL and closing connection...")
            _db_ref.wal_checkpoint()
            _db_ref.close()
        except Exception as exc:
            logger.error("Error during DB shutdown checkpoint: %s", exc)
        _db_ref = None

    # 2. Lock keystore (zero keys from memory)
    if _km_ref:
        logger.info("Zeroing cryptographic master key from memory...")
        _km_ref.lock()
        _km_ref = None
        
    logger.info("Shutdown complete.")


def handle_signal(sig, frame) -> None:
    logger.info("Termination signal received.")
    QApplication.quit()


def main() -> None:
    """Main GUI launcher."""
    # Register signal handlers for clean terminations
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    app = QApplication(sys.argv)
    app.setObjectName("GhostDriveApp")
    
    # Load initial stylesheet (Dark mode by default)
    app.setStyleSheet(get_stylesheet("dark"))

    # Initialize qasync Event Loop
    loop = qasync.QEventLoop(app)
    asyncio.set_event_loop(loop)

    # Setup cleanup callback
    app.aboutToQuit.connect(clean_shutdown)

    # 1. Start Pre-flight Diagnostics Wizard
    wizard = PreflightWizard()
    if wizard.exec() != PreflightWizard.DialogCode.Accepted:
        logger.warning("Pre-flight system checks rejected or closed. Exiting.")
        sys.exit(0)

    # 2. Setup Keystore Manager
    keystore_path = Path("keystore.json")
    km = KeystoreManager(keystore_path)
    
    global _km_ref
    _km_ref = km

    # 3. Setup Unlock/Setup Screen
    unlock_view = UnlockView(keystore_path=keystore_path)
    unlock_view.setWindowTitle("Unlock GhostDrive")
    unlock_view.setMinimumSize(500, 480)
    unlock_view.resize(500, 480)
    
    main_window = None

    def on_unlocked(unlocked_km) -> None:
        nonlocal main_window
        logger.info("Keystore unlocked successfully.")
        
        # Instantiate/open database connection
        from ghostdrive.crypto.hkdf import derive_index_mac_key
        import hmac as _hmac, hashlib as _hashlib

        master_key = unlocked_km._master_key_buf.key
        hkdf_salt = unlocked_km._hkdf_salt
        genesis_seed = unlocked_km._genesis_seed

        ledger_key = derive_index_mac_key(master_key, hkdf_salt)
        db_path = Path("ghostdrive.db")
        db = GhostDriveDB(db_path, ledger_key, genesis_seed)
        db.open()
        
        global _db_ref
        _db_ref = db

        # Open the main dashboard
        main_window = MainWindow(unlocked_km, db)
        main_window.show()

        unlock_view.hide()

    unlock_view.unlocked.connect(on_unlocked)
    unlock_view.show()

    # Start the qasync event loop execution context
    with loop:
        loop.run_forever()


if __name__ == "__main__":
    main()
