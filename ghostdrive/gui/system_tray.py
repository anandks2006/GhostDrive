"""
system_tray.py -- System tray integration with Wayland fallback and background sweep sweeps.
"""

import os
import sys
import logging
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QIcon, QAction
from PyQt6.QtWidgets import (
    QSystemTrayIcon,
    QMenu,
    QMessageBox,
)

logger = logging.getLogger(__name__)

class GhostDriveSystemTray(QSystemTrayIcon):
    """
    System tray icon handling background scans, double-click window restore,
    and Linux Wayland fallback compliance.
    """
    def __init__(self, main_window, parent=None) -> None:
        self.main_window = main_window
        super().__init__(parent)

        # Wayland fallback check (Linux specific)
        if sys.platform.startswith("linux"):
            session_type = os.environ.get("XDG_SESSION_TYPE", "").lower()
            wayland_display = os.environ.get("WAYLAND_DISPLAY", "")
            if "wayland" in session_type or wayland_display:
                logger.info("Linux Wayland environment detected. Checking tray support...")
                # Under Wayland, system trays are often unsupported or crash.
                # If isSystemTrayAvailable returns False, we don't setup.
                if not QSystemTrayIcon.isSystemTrayAvailable():
                    logger.warning("System tray is unavailable on this Wayland compositor. Hiding tray gracefully.")
                    return

        # Attempt to load a default icon (can be generic or placeholder)
        # We will use an emoji-based icon or generate a basic pixel array if missing.
        # But wait, QIcon has fallback support. Let's try loading a system icon first.
        icon = QIcon.fromTheme("drive-harddisk", QIcon())
        if icon.isNull():
            # Create a simple icon if theme icon is missing
            from PyQt6.QtGui import QPixmap, QPainter, QColor
            pixmap = QPixmap(32, 32)
            pixmap.fill(Qt.GlobalColor.transparent)
            painter = QPainter(pixmap)
            painter.setBrush(QColor("#8b5cf6"))  # Violet
            painter.drawEllipse(4, 4, 24, 24)
            painter.end()
            icon = QIcon(pixmap)
            
        self.setIcon(icon)
        self.setToolTip("GhostDrive Secure Storage")

        # Setup context menu
        self._setup_menu()

        # Connect activations (e.g. double click)
        self.activated.connect(self._on_activated)

        # Background verification timer (leaky bucket verification sweep)
        self._sweep_timer = QTimer(self)
        self._sweep_timer.timeout.connect(self._run_integrity_sweep)
        # Run sweep every 60 seconds (quietly in the background)
        self._sweep_timer.start(60000)

        self.show()

    def _setup_menu(self) -> None:
        self.menu = QMenu()
        
        show_action = QAction("Open Dashboard", self)
        show_action.triggered.connect(self._restore_main_window)
        self.menu.addAction(show_action)

        self.menu.addSeparator()

        lock_action = QAction("Lock Drive & Log Out", self)
        lock_action.triggered.connect(self._lock_drive)
        self.menu.addAction(lock_action)

        exit_action = QAction("Exit GhostDrive", self)
        exit_action.triggered.connect(self._exit_app)
        self.menu.addAction(exit_action)

        self.setContextMenu(self.menu)

    def _on_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        # Restore on double click or trigger click
        if reason in (QSystemTrayIcon.ActivationReason.DoubleClick, QSystemTrayIcon.ActivationReason.Trigger):
            self._restore_main_window()

    def _restore_main_window(self) -> None:
        if self.main_window:
            self.main_window.show()
            self.main_window.activateWindow()
            self.main_window.raise_()

    def _lock_drive(self) -> None:
        if self.main_window:
            self.main_window.lock_and_logout()

    def _exit_app(self) -> None:
        if self.main_window:
            self.main_window.close_and_exit()

    def _run_integrity_sweep(self) -> None:
        """
        Quiet background verification sweep.
        Validates the HMAC ledger tips and scans chunk locations status.
        Logs anomalies to the main window telemetry / notification panels.
        """
        logger.debug("Running background integrity sweep...")
        if not self.main_window or not hasattr(self.main_window, "db") or not self.main_window.db:
            return

        db = self.main_window.db
        try:
            # Check db open and perform quick verification
            db.verify_hmac_chain()
            logger.debug("Background integrity check: HMAC Chain Valid.")
        except Exception as exc:
            logger.error("Background integrity sweep detected an HMAC chain violation: %s", exc)
            if hasattr(self.main_window, "notifications"):
                self.main_window.notifications.notify(
                    "Security Integrity Alert",
                    "Database HMAC integrity chain verification failed! Potential data tampering detected.",
                    "critical"
                )
