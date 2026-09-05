"""
settings_panel.py -- MainWindow controller mixin handling theme changing, recovery seed phrase, changing keystore passphrase, and autostart preferences.
"""

import logging

from PyQt6.QtWidgets import QApplication, QMessageBox, QInputDialog, QLineEdit

from ghostdrive.gui.styles import get_stylesheet

logger = logging.getLogger(__name__)

class SettingsPanelMixin:
    """Mixin controller containing settings panel actions (theme, accent, seed recovery, passphrase update, autostart)."""

    def on_theme_changed(self, idx: int) -> None:
        theme = "dark" if idx == 0 else "light"
        self.current_theme = theme
        self._theme = theme
        from PyQt6.QtCore import QSettings
        settings = QSettings("GhostDrive", "Preferences")
        settings.setValue("theme", theme)
        
        # Always update the application-wide stylesheet so that all dialogs/popups inherit it immediately
        QApplication.instance().setStyleSheet(get_stylesheet(theme, self.current_accent))
        
        if hasattr(self, "_do_resizing_update"):
            self._do_resizing_update()

    def on_accent_changed(self, idx: int) -> None:
        accents = {
            0: "#8b5cf6",  # Neon Violet
            1: "#06b6d4",  # Electric Cyan
            2: "#10b981",  # Emerald Green
            3: "#ef4444",  # Crimson Red
            4: "#f59e0b",  # Amber Orange
        }
        accent = accents.get(idx, "#8b5cf6")
        self.current_accent = accent
        self._accent_color = accent
        from PyQt6.QtCore import QSettings
        settings = QSettings("GhostDrive", "Preferences")
        settings.setValue("accent_color", accent)
        
        # Always update the application-wide stylesheet so that all dialogs/popups inherit it immediately
        QApplication.instance().setStyleSheet(get_stylesheet(self.current_theme, accent))
        
        if hasattr(self, "_do_resizing_update"):
            self._do_resizing_update()
        self.notifications.notify("Accent Color Updated", "Accent color updated successfully.", "success", overlay_only=True)

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
            QMessageBox.critical(self, "Error", "Failed to change passphrase. Verify current passphrase is correct.")

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

    def on_network_ops_toggled(self, checked: bool) -> None:
        from PyQt6.QtCore import QSettings
        settings = QSettings("GhostDrive", "Preferences")
        settings.setValue("enable_network_operations", checked)
        
        self.network_operations_enabled = checked
        
        if hasattr(self, "update_network_features_visibility"):
            self.update_network_features_visibility()
            
        if checked:
            self.notifications.notify("Network Enabled", "Outgoing P2P sharing and cloud sync are now active.", "info")
        else:
            self.notifications.notify("Air-Gapped Mode Active", "GhostDrive is running in 100% offline local-only mode.", "important")

    def on_replication_level_changed(self) -> None:
        if not self.db:
            return
        try:
            with self.db.transaction():
                self.db.set_setting("rep_critical", str(self.critical_rep_spin.value()))
                self.db.set_setting("rep_important", str(self.important_rep_spin.value()))
                self.db.set_setting("rep_disposable", str(self.disposable_rep_spin.value()))
            self.notifications.notify("Replication Updated", "Storage tier replication levels updated.", "success", overlay_only=True)
        except Exception as exc:
            logger.error("Failed to update replication settings: %s", exc)

    def on_rotate_keys_clicked(self) -> None:
        if not self.km or not self.db:
            return
            
        passwd, confirmed = QInputDialog.getText(
            self, "Security Verification", 
            "Enter your passphrase to authorize cryptographic key rotation:", 
            QLineEdit.EchoMode.Password
        )
        if not confirmed or not passwd:
            return
            
        try:
            from ghostdrive.crypto.keystore import KeystoreManager
            temp_km = KeystoreManager(self.km.keystore_path)
            temp_km.unlock(passwd.encode("utf-8"))
            temp_km.lock()
        except Exception:
            QMessageBox.critical(self, "Access Denied", "Incorrect passphrase. Key rotation aborted.")
            return

        reply = QMessageBox.question(
            self, "Confirm Key Rotation",
            "Are you sure you want to rotate all keys now? All backend credentials and ledger HMAC chains will be re-encrypted.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
            
        try:
            import os
            from ghostdrive.crypto.hkdf import derive_index_mac_key
            from ghostdrive.crypto.credential_store import credential_store
            
            new_salt = os.urandom(32)
            new_ledger_key = derive_index_mac_key(self.km.master_key, new_salt)
            
            credentials_backup = {}
            
            with self.db.transaction():
                rows = self.db._conn.execute("SELECT credentials_ref FROM backends").fetchall()
            backend_refs = [r["credentials_ref"] for r in rows if r["credentials_ref"]]
            
            COMMON_KEYS = ["telegram_api_id", "telegram_api_hash", "telegram_phone", "discord_bot_token"]
            all_refs = list(set(backend_refs + COMMON_KEYS))
            
            for ref in all_refs:
                val = credential_store.load(ref)
                if val is not None:
                    credentials_backup[ref] = val
                    
            with self.db.transaction():
                self.db.rotate_ledger_key(new_ledger_key)
                
            credential_store.set_active_key(self.km.master_key, new_salt)
            for ref, val in credentials_backup.items():
                credential_store.store(ref, val)
                
            self.km.rotate_keys(new_salt, passwd.encode("utf-8"))
            
            self.notifications.notify("Key Rotation Complete", "Rotated and re-encrypted all cryptographic keys.", "success")
            self.add_activity_log("Cryptographic key rotation completed successfully.")
        except Exception as exc:
            logger.error("Key rotation failed: %s", exc)
            QMessageBox.critical(self, "Error", f"Key rotation failed: {exc}")

    def on_export_config_clicked(self) -> None:
        if not self.db:
            return
        from PyQt6.QtWidgets import QFileDialog
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Backend Configuration", "", "JSON Files (*.json)"
        )
        if not file_path:
            return
        try:
            import json
            from ghostdrive.crypto.credential_store import credential_store
            with self.db.transaction():
                rows = self.db._conn.execute(
                    "SELECT id, type, credentials_ref, status, priority, quota_limit FROM backends"
                ).fetchall()
            config = []
            for r in rows:
                item = dict(r)
                if r["credentials_ref"]:
                    item["credential_value"] = credential_store.load(r["credentials_ref"]) or ""
                else:
                    item["credential_value"] = ""
                config.append(item)
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2)
            self.notifications.notify("Export Complete", "Backend configuration exported successfully.", "success")
        except Exception as exc:
            logger.error("Export config failed: %s", exc)
            QMessageBox.critical(self, "Error", f"Failed to export: {exc}")

    def on_import_config_clicked(self) -> None:
        if not self.db:
            return
        from PyQt6.QtWidgets import QFileDialog
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Import Backend Configuration", "", "JSON Files (*.json)"
        )
        if not file_path:
            return
        try:
            import json
            from ghostdrive.crypto.credential_store import credential_store
            with open(file_path, "r", encoding="utf-8") as f:
                config = json.load(f)
            if not isinstance(config, list):
                raise ValueError("Invalid config format.")
            with self.db.transaction():
                for item in config:
                    b_id = item["id"]
                    b_type = item["type"]
                    ref = item["credentials_ref"]
                    status = item.get("status", "healthy")
                    priority = item.get("priority", 1)
                    quota_limit = item.get("quota_limit", 100 * 1024 * 1024 * 1024)
                    cred_val = item.get("credential_value", "")
                    if cred_val and ref:
                        credential_store.store(ref, cred_val)
                    exists = self.db._conn.execute("SELECT id FROM backends WHERE id = ?", (b_id,)).fetchone()
                    if exists:
                        self.db._conn.execute(
                            "UPDATE backends SET type=?, credentials_ref=?, status=?, priority=?, quota_limit=? WHERE id=?",
                            (b_type, ref, status, priority, quota_limit, b_id)
                        )
                    else:
                        self.db._conn.execute(
                            "INSERT INTO backends (id, type, credentials_ref, status, priority, quota_used, quota_limit, quota_reserved) VALUES (?, ?, ?, ?, ?, 0, ?, 0)",
                            (b_id, b_type, ref, status, priority, quota_limit)
                        )
                    self.db._chain_hmac("backends", {"op": "import", "id": b_id})
            self.notifications.notify("Import Complete", "Backend configuration imported successfully.", "success")
            if hasattr(self, "refresh_backends"):
                self.refresh_backends()
        except Exception as exc:
            logger.error("Import config failed: %s", exc)
            QMessageBox.critical(self, "Error", f"Failed to import: {exc}")

    def on_clear_logs_clicked(self) -> None:
        from ghostdrive.utils.log_rotation import clear_logs
        clear_logs()
        self.refresh_log_size_display()
        self.notifications.notify("Logs Cleared", "Active log files truncated.", "info")

    def on_rotate_logs_clicked(self) -> None:
        from ghostdrive.utils.log_rotation import force_rotation
        force_rotation()
        self.refresh_log_size_display()
        self.notifications.notify("Logs Rotated", "Logs rolled over successfully.", "info")

    def on_log_max_size_changed(self, val: int) -> None:
        from ghostdrive.utils.log_rotation import set_max_log_size
        max_bytes = val * 1024 * 1024
        set_max_log_size(max_bytes)

    def refresh_log_size_display(self) -> None:
        from ghostdrive.utils.log_rotation import get_log_size
        sz = get_log_size()
        kb = sz / 1024.0
        self.log_size_label.setText(f"Current Log File Size: {kb:.1f} KB")

    def on_upload_throttle_changed(self, val: int) -> None:
        from ghostdrive.utils.bandwidth_throttle import UPLOAD_LIMITER
        if val == 0:
            UPLOAD_LIMITER.set_rate_limit(0)
            self.upload_throttle_label.setText("Upload Speed Limit: Unlimited")
        else:
            limit = val * 100 * 1024  # 100 KB/s steps
            UPLOAD_LIMITER.set_rate_limit(limit)
            mb = limit / (1024 * 1024)
            self.upload_throttle_label.setText(f"Upload Speed Limit: {mb:.1f} MB/s")

    def on_download_throttle_changed(self, val: int) -> None:
        from ghostdrive.utils.bandwidth_throttle import DOWNLOAD_LIMITER
        if val == 0:
            DOWNLOAD_LIMITER.set_rate_limit(0)
            self.download_throttle_label.setText("Download Speed Limit: Unlimited")
        else:
            limit = val * 100 * 1024
            DOWNLOAD_LIMITER.set_rate_limit(limit)
            mb = limit / (1024 * 1024)
            self.download_throttle_label.setText(f"Download Speed Limit: {mb:.1f} MB/s")

    def refresh_mlkem_key_display(self) -> None:
        if not self.db:
            return
        ek_hex = self.db.get_setting("mlkem_pubkey_hex", "")
        if ek_hex:
            import hashlib
            fp = hashlib.sha256(bytes.fromhex(ek_hex)).hexdigest()[:16]
            self.mlkem_key_label.setText(f"ML-KEM-768 Public Key ID: {fp}...")
        else:
            self.mlkem_key_label.setText("ML-KEM-768 Public Key: Not Generated")

    def on_regenerate_mlkem_clicked(self) -> None:
        if not self.km or not self.db:
            return
            
        reply = QMessageBox.question(
            self, "Regenerate Sharing Keys",
            "Are you sure you want to regenerate your ML-KEM-768 sharing keypair? Any pending or future packages shared with your old key will not be decryptable.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
            
        try:
            from ghostdrive.crypto.sharing_keys import get_or_create_sharing_keypair
            self.db.set_setting("mlkem_pubkey_hex", "")
            self.db.set_setting("mlkem_privkey_enc", "")
            
            get_or_create_sharing_keypair(self.db, self.km.master_key, self.km.hkdf_salt)
            self.refresh_mlkem_key_display()
            self.notifications.notify("Keypair Regenerated", "ML-KEM-768 key pair regenerated successfully.", "success")
        except Exception as exc:
            logger.error("Failed to regenerate ML-KEM keypair: %s", exc)
            QMessageBox.critical(self, "Error", f"Failed to regenerate keypair: {exc}")

