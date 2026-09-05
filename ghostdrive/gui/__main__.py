"""
__main__.py -- Main startup entry point for the GhostDrive GUI.
"""

import sys
import signal
import asyncio
import logging

from PyQt6.QtWidgets import QApplication
import qasync

from ghostdrive.gui.styles import get_stylesheet
from ghostdrive.gui.preflight_wizard import PreflightWizard
from ghostdrive.gui.unlock_view import UnlockView
from ghostdrive.gui.main_view import MainWindow
from ghostdrive.database.db import GhostDriveDB
from ghostdrive.crypto.keystore import KeystoreManager

# Setup logging with Log Sanitization (spec §9.7)
import logging.handlers
from pathlib import Path
from ghostdrive.utils.log_sanitizer import SanitizedFormatter

log_file_path = Path("ghostdrive.log")
file_handler = logging.handlers.RotatingFileHandler(
    log_file_path,
    maxBytes=5 * 1024 * 1024,  # default 5MB
    backupCount=3,
    encoding="utf-8"
)
file_handler.setFormatter(SanitizedFormatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))

stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setFormatter(SanitizedFormatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))

logging.basicConfig(
    level=logging.INFO,
    handlers=[stream_handler, file_handler]
)
logger = logging.getLogger("ghostdrive_gui")

# Global variables for cleanup reference
_km_ref = None
_db_ref = None
_main_window_ref = None

def clean_shutdown() -> None:
    """Executes safe halt logic committing WAL checkpoints and zeroing memory."""
    logger.info("Executing clean shutdown sequence...")
    
    global _db_ref, _km_ref
    
    # 1. Close database and run WAL checkpoint
    if _db_ref:
        try:
            if getattr(_db_ref, "_conn", None) is not None:
                logger.info("Checkpointing database WAL and closing connection...")
                _db_ref.wal_checkpoint()
                _db_ref.close()
            else:
                logger.info("Database connection was already closed.")
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
    global _main_window_ref
    if _main_window_ref:
        asyncio.create_task(_main_window_ref.async_shutdown())
    else:
        QApplication.quit()


def main() -> None:
    """Main GUI launcher."""
    # Register signal handlers for clean terminations
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    app = QApplication(sys.argv)
    app.setObjectName("GhostDriveApp")
    
    # Load saved UI preferences on startup
    from PyQt6.QtCore import QSettings
    settings = QSettings("GhostDrive", "Preferences")
    theme = settings.value("theme", "dark", type=str)
    accent = settings.value("accent_color", "#8b5cf6", type=str)
    app.setStyleSheet(get_stylesheet(theme, accent))

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
    from ghostdrive.utils.platform import get_app_data_dir
    app_data = get_app_data_dir()
    keystore_path = app_data / "keystore.json"
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

        master_key = unlocked_km._master_key_buf.key
        hkdf_salt = unlocked_km._hkdf_salt
        genesis_seed = unlocked_km._genesis_seed

        ledger_key = derive_index_mac_key(master_key, hkdf_salt)
        db_path = app_data / "ghostdrive.db"
        db = GhostDriveDB(db_path, ledger_key, genesis_seed, master_key)
        
        try:
            db.open()
        except Exception as exc:
            logger.error("Failed to decrypt or open the database: %s", exc)
            from PyQt6.QtWidgets import QMessageBox
            
            reply = QMessageBox.question(
                unlock_view,
                "Database Decryption Failed",
                "The secure database (ghostdrive.db) could not be decrypted.\n\n"
                "This typically happens if the database was created with a different keystore passphrase, "
                "or if the file is corrupted.\n\n"
                "Would you like to reset the database and start fresh?\n"
                "(Warning: This deletes the local metadata index. Replicated chunks on remote backends will not be affected.)",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                try:
                    # Close connection and delete database files
                    db.close()
                    for suffix in ["", "-wal", "-journal", "-shm"]:
                        p = db_path.with_suffix(db_path.suffix + suffix)
                        if p.exists():
                            p.unlink()
                    logger.info("Deleted corrupted/incompatible database files. Retrying open...")
                    
                    # Re-instantiate and open
                    db = GhostDriveDB(db_path, ledger_key, genesis_seed, master_key)
                    db.open()
                except Exception as retry_exc:
                    logger.error("Failed to recreate database: %s", retry_exc)
                    QMessageBox.critical(
                        unlock_view,
                        "Database Error",
                        f"Failed to recreate a fresh database:\n{retry_exc}"
                    )
                    return
            else:
                # User chose not to reset, exit gracefully
                QApplication.quit()
                return
        
        global _db_ref, _main_window_ref
        _db_ref = db

        # Open the main dashboard
        main_window = MainWindow(unlocked_km, db)
        _main_window_ref = main_window
        main_window.show()

        unlock_view.hide()

    unlock_view.unlocked.connect(on_unlocked)
    unlock_view.show()

    # Start the qasync event loop execution context
    with loop:
        loop.run_forever()


if __name__ == "__main__":
    main()
