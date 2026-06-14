"""
settings_panel.py -- MainWindow controller mixin handling theme changing, recovery seed phrase, changing keystore passphrase, and autostart preferences.
"""

import os
import logging
from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication, QMessageBox, QInputDialog, QLineEdit

from ghostdrive.gui.widgets import StyledButton
from ghostdrive.gui.styles import get_stylesheet

logger = logging.getLogger(__name__)

class SettingsPanelMixin:
    """Mixin controller containing settings panel actions (theme, accent, seed recovery, passphrase update, autostart)."""

    def on_theme_changed(self, idx: int) -> None:
        theme = "dark" if idx == 0 else "light"
        self.current_theme = theme
        QApplication.instance().setStyleSheet(get_stylesheet(theme, self.current_accent))

    def on_accent_changed(self, idx: int) -> None:
        accents = {
            0: "#8b5cf6",  # Neon Violet
            1: "#06b6d4",  # Electric Cyan
            2: "#10b981",  # Emerald Green
            3: "#ef4444",  # Crimson Red
            4: "#f59e0b",  # Amber Orange
        }
        self.current_accent = accents.get(idx, "#8b5cf6")
        QApplication.instance().setStyleSheet(get_stylesheet(self.current_theme, self.current_accent))
        self.notifications.notify("Accent Color Updated", f"Accent color updated successfully.", "success")

    def on_reveal_seed_clicked(self) -> None:
        # Prompt for passphrase confirmation before revealing
        passwd, confirmed = QInputDialog.getText(
            self, "Security Verification", 
            "Enter your secure passphrase to reveal seed phrase:", 
            QLineEdit.EchoMode.Password
        )
        if confirmed and passwd:
            try:
                # Validate key by trying to export mnemonic
                mnemonic = self.km.export_seed_phrase()
                self.seed_text.setText(mnemonic)
                self.seed_text.setEchoMode(QLineEdit.EchoMode.Normal)
                self.seed_btn.setEnabled(False)
            except Exception as exc:
                QMessageBox.critical(self, "Access Denied", f"Incorrect password or locked keystore: {exc}")

    def on_change_passphrase_clicked(self) -> None:
        curr_pass = self.curr_pass_input.text()
        new_pass = self.new_pass_input.text()

        if not curr_pass or not new_pass:
            QMessageBox.warning(self, "Validation Error", "All fields are required.")
            return

        if len(new_pass) < 8:
            QMessageBox.warning(self, "Validation Error", "New passphrase must be at least 8 characters.")
            return

        try:
            # Verify current passphrase by unlocking a temporary KeystoreManager
            from ghostdrive.crypto.keystore import KeystoreManager
            temp_km = KeystoreManager(self.km.keystore_path)
            temp_km.unlock(curr_pass.encode("utf-8"))
            temp_km.lock()  # Safe zeroing after verification
            
            # If successful, change passphrase on the active keystore
            self.km.change_passphrase(new_pass.encode("utf-8"))
            
            QMessageBox.information(self, "Success", "Passphrase has been updated successfully.")
            self.curr_pass_input.clear()
            self.new_pass_input.clear()
            self.notifications.notify("Passphrase Updated", "Your keystore passphrase has been changed successfully.", "success")
        except Exception as exc:
            logger.error("Passphrase change failed: %s", exc)
            QMessageBox.critical(self, "Error", f"Failed to change passphrase. Verify current passphrase is correct.")

    def on_autostart_toggled(self, checked: bool) -> None:
        from ghostdrive.gui.autostart import AutoStartManager
        if checked:
            success = AutoStartManager.enable()
            if success:
                self.notifications.notify("Auto-Start Enabled", "GhostDrive will start automatically on system boot.", "success")
            else:
                self.notifications.notify("Auto-Start Error", "Failed to enable auto-start shortcut.", "important")
        else:
            success = AutoStartManager.disable()
            if success:
                self.notifications.notify("Auto-Start Disabled", "GhostDrive will no longer start automatically.", "info")
            else:
                self.notifications.notify("Auto-Start Error", "Failed to disable auto-start shortcut.", "important")
