"""
backend_settings.py -- PyQt6 dashboard widget for managing storage backends, registration, and NAS settings.

Security model for 3rd-party credentials (Discord, Telegram):
  - All credentials are encrypted with AES-256-GCM before being written to the OS Keyring.
  - The encryption key is derived from the master key via HKDF-SHA512 with the dedicated
    info string b"ghostdrive-v1-backend-credentials" — cryptographically isolated from
    chunk encryption, secrets vault, and all other subkeys.
  - Layer 1: OS Keyring (DPAPI on Windows / libsecret on Linux / Keychain on macOS)
    provides OS-user-level access control.
  - Layer 2: AES-256-GCM makes the stored blob unreadable without the unlocked keystore,
    even if the OS Keyring is bypassed (e.g. raw registry access, copy of keyring DB).
  - Credentials are never logged, never written to SQLite, and never held in plain strings
    longer than necessary — they are discarded from QLineEdit memory immediately after use.
"""

import logging
import qasync
from typing import Any
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QMessageBox,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QTabWidget,
    QFormLayout,
)

from ghostdrive.gui.widgets import GlassCard, StyledButton, StyledComboBox
from ghostdrive.gui.styles import ResilientDialog
from ghostdrive.pipeline.drive_registration import DriveRegistrar
from ghostdrive.gui.resilience_panel import ResiliencePanel
from ghostdrive.exceptions import SecureEraseBlockedError

logger = logging.getLogger(__name__)

# ─── Protocol index constants ─────────────────────────────────────────────────
_PROTO_SFTP      = 0
_PROTO_SMB       = 1
_PROTO_TELEGRAM  = 2
_PROTO_DISCORD   = 3

# Static backend IDs for 3rd-party services
_TELEGRAM_BACKEND_ID = "telegram-backend-id"
_DISCORD_BACKEND_ID  = "discord-backend-id"

# Keyring keys — must match what MainWindow._init_backends queries
_TELEGRAM_KEYRING_KEYS = ("telegram_api_id", "telegram_api_hash", "telegram_phone")
_DISCORD_KEYRING_KEYS  = ("discord_channel_id", "discord_bot_token")




# ─── Telegram Authentication Dialogs ──────────────────────────────────────────

class TelegramOtpDialog(ResilientDialog):
    """Prompts user for the Telegram login OTP code."""
    def __init__(self, parent: QWidget | None, prompt: str = "Enter the Telegram OTP code sent to your app or SMS:") -> None:
        super().__init__(parent, base_width=380, base_height=180)
        self.setWindowTitle("Telegram Authentication")
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        self.label = QLabel(prompt, self)
        self.label.setWordWrap(True)
        self.label.setStyleSheet("color: #f4f4f5; font-size: 12px;")
        layout.addWidget(self.label)

        self.code_input = QLineEdit(self)
        self.code_input.setPlaceholderText("Enter OTP Code")
        self.code_input.setObjectName("TelegramOtpInput")
        layout.addWidget(self.code_input)

        btn_layout = QHBoxLayout()
        self.cancel_btn = StyledButton("Cancel", self, secondary=True)
        self.cancel_btn.clicked.connect(self.reject)
        self.ok_btn = StyledButton("Submit", self, primary=True)
        self.ok_btn.clicked.connect(self.accept)

        btn_layout.addWidget(self.cancel_btn)
        btn_layout.addWidget(self.ok_btn)
        layout.addLayout(btn_layout)

    def get_code(self) -> str:
        return self.code_input.text().strip()


class TelegramPasswordDialog(ResilientDialog):
    """Prompts user for the Telegram 2FA cloud password."""
    def __init__(self, parent: QWidget | None, prompt: str = "Enter your Telegram 2FA Cloud Password:") -> None:
        super().__init__(parent, base_width=380, base_height=180)
        self.setWindowTitle("Telegram 2FA Password")
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        self.label = QLabel(prompt, self)
        self.label.setWordWrap(True)
        self.label.setStyleSheet("color: #f4f4f5; font-size: 12px;")
        layout.addWidget(self.label)

        self.pass_input = QLineEdit(self)
        self.pass_input.setPlaceholderText("Enter 2FA Password")
        self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.pass_input.setObjectName("Telegram2faInput")
        layout.addWidget(self.pass_input)

        btn_layout = QHBoxLayout()
        self.cancel_btn = StyledButton("Cancel", self, secondary=True)
        self.cancel_btn.clicked.connect(self.reject)
        self.ok_btn = StyledButton("Submit", self, primary=True)
        self.ok_btn.clicked.connect(self.accept)

        btn_layout.addWidget(self.cancel_btn)
        btn_layout.addWidget(self.ok_btn)
        layout.addLayout(btn_layout)

    def get_password(self) -> str:
        return self.pass_input.text().strip()


# ─── NAS Discovery Thread ─────────────────────────────────────────────────────

class NASDiscoveryThread(QThread):
    """Background thread to handle passive mDNS NAS discovery without blocking GUI thread."""
    discovery_complete = pyqtSignal(list)

    def __init__(self, registrar: DriveRegistrar) -> None:
        super().__init__()
        self.registrar = registrar

    def run(self) -> None:
        try:
            results = self.registrar.suggest_nas_backends()
            self.discovery_complete.emit(results)
        except Exception as exc:
            logger.error("NAS discovery thread failed: %s", exc)
            self.discovery_complete.emit([])


# ─── BackendSettingsPanel ─────────────────────────────────────────────────────

class BackendSettingsPanel(QWidget):
    """
    BackendSettingsPanel manages backend registration, drive picking,
    passive NAS discovery, manual SFTP/SMB/Telegram/Discord entry, and handles
    the S9 redundancy check before backend removal.

    All third-party credentials (Discord bot token, Telegram API hash, etc.) are
    encrypted with AES-256-GCM before being stored in the OS Keyring. They are
    never persisted in plain text anywhere on disk.
    """

    def __init__(self, parent: QWidget | None = None, db: Any = None) -> None:
        super().__init__(parent)
        self.db = db
        self.registrar = DriveRegistrar(db)

        # Main Layout: Vertical layout with Title Header and Tab Widget
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 24, 24, 24)
        main_layout.setSpacing(16)

        # Header section
        header_lay = QHBoxLayout()
        title_lbl = QLabel("Storage Channels & Hardware", self)
        title_lbl.setObjectName("Heading")
        header_lay.addWidget(title_lbl)
        header_lay.addStretch()
        main_layout.addLayout(header_lay)

        # QTabWidget for high-level structural separation
        self.tabs = QTabWidget(self)
        self.tabs.setObjectName("BackendTabs")
        main_layout.addWidget(self.tabs)

        # ─── TAB 1: Configured Channels ───
        tab_active = QWidget(self.tabs)
        layout_active = QVBoxLayout(tab_active)
        layout_active.setContentsMargins(12, 16, 12, 16)
        layout_active.setSpacing(12)

        active_card = GlassCard(tab_active)
        active_layout = QVBoxLayout(active_card)
        active_layout.setContentsMargins(20, 20, 20, 20)
        active_layout.setSpacing(12)

        active_title = QLabel("📂 Active Storage Channels", active_card)
        active_title.setObjectName("SubHeading")
        active_layout.addWidget(active_title)

        active_desc = QLabel(
            "These channels form your distributed replication network. Secure file chunks are automatically "
            "mirrored and synchronized across these backends to meet redundancy requirements.",
            active_card
        )
        active_desc.setObjectName("MutedLabel")
        active_desc.setWordWrap(True)
        active_layout.addWidget(active_desc)

        self.backends_table = QTableWidget(active_card)
        self.backends_table.setColumnCount(4)
        self.backends_table.setHorizontalHeaderLabels(["TYPE", "USED / LIMIT", "STATUS", "ACTION"])
        header = self.backends_table.horizontalHeader()
        if header is not None:
            header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        active_layout.addWidget(self.backends_table)

        layout_active.addWidget(active_card)
        self.tabs.addTab(tab_active, "☁️ Active Channels")

        # ─── TAB 2: Link New Channel ───
        tab_add = QWidget(self.tabs)
        layout_add = QHBoxLayout(tab_add)
        layout_add.setContentsMargins(12, 16, 12, 16)
        layout_add.setSpacing(16)

        # Left Column: Inbound Hardware Scan / LAN mDNS Discovery
        left_col = QWidget(tab_add)
        left_col_layout = QVBoxLayout(left_col)
        left_col_layout.setContentsMargins(0, 0, 0, 0)
        left_col_layout.setSpacing(16)

        # USB Local Drives Table Card
        drive_card = GlassCard(left_col)
        drive_layout = QVBoxLayout(drive_card)
        drive_layout.setContentsMargins(16, 16, 16, 16)
        drive_layout.setSpacing(10)

        drive_hdr = QHBoxLayout()
        drive_hdr.addWidget(QLabel("🔌 Connected USB SSD/HDD", drive_card))
        self.refresh_drives_btn = StyledButton("Scan USB", drive_card, secondary=True)
        self.refresh_drives_btn.clicked.connect(self.refresh_connected_drives)
        drive_hdr.addWidget(self.refresh_drives_btn)
        drive_layout.addLayout(drive_hdr)

        self.drives_table = QTableWidget(drive_card)
        self.drives_table.setColumnCount(4)
        self.drives_table.setHorizontalHeaderLabels(["LABEL", "MOUNT", "SIZE", "ACTION"])
        header = self.drives_table.horizontalHeader()
        if header is not None:
            header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.drives_table.setMinimumHeight(140)
        drive_layout.addWidget(self.drives_table)
        left_col_layout.addWidget(drive_card)

        # LAN mDNS NAS Suggestions Table Card
        nas_card = GlassCard(left_col)
        nas_layout = QVBoxLayout(nas_card)
        nas_layout.setContentsMargins(16, 16, 16, 16)
        nas_layout.setSpacing(10)

        nas_hdr = QHBoxLayout()
        nas_hdr.addWidget(QLabel("📡 LAN NAS Discovery (mDNS)", nas_card))
        self.refresh_nas_btn = StyledButton("Scan LAN", nas_card, secondary=True)
        self.refresh_nas_btn.clicked.connect(self.start_nas_discovery)
        nas_hdr.addWidget(self.refresh_nas_btn)
        nas_layout.addLayout(nas_hdr)

        self.nas_table = QTableWidget(nas_card)
        self.nas_table.setColumnCount(3)
        self.nas_table.setHorizontalHeaderLabels(["NAME", "ADDRESS / SERVICE", "ACTION"])
        header = self.nas_table.horizontalHeader()
        if header is not None:
            header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.nas_table.setMinimumHeight(140)
        nas_layout.addWidget(self.nas_table)
        left_col_layout.addWidget(nas_card)

        # Local Folders / Directories Card
        folder_card = GlassCard(left_col)
        folder_layout = QVBoxLayout(folder_card)
        folder_layout.setContentsMargins(16, 16, 16, 16)
        folder_layout.setSpacing(10)

        folder_hdr = QHBoxLayout()
        folder_hdr.addWidget(QLabel("📂 Local Folders / Backups", folder_card))
        self.add_folder_btn = StyledButton("Link Folder", folder_card, primary=True)
        self.add_folder_btn.clicked.connect(self.on_link_local_folder_clicked)
        folder_hdr.addWidget(self.add_folder_btn)
        folder_layout.addLayout(folder_hdr)

        folder_desc = QLabel(
            "Configure any local directory as an encrypted storage backend to hide or back up data.",
            folder_card
        )
        folder_desc.setObjectName("MutedLabel")
        folder_desc.setWordWrap(True)
        folder_layout.addWidget(folder_desc)
        left_col_layout.addWidget(folder_card)

        layout_add.addWidget(left_col, stretch=1)

        # Right Column: Manual Config Form (SFTP / SMB / Telegram / Discord)
        manual_card = GlassCard(tab_add)
        manual_layout = QVBoxLayout(manual_card)
        manual_layout.setContentsMargins(20, 20, 20, 20)
        manual_layout.setSpacing(16)

        manual_title = QLabel("➕ Manual Channel Setup", manual_card)
        manual_title.setObjectName("SubHeading")
        manual_layout.addWidget(manual_title)

        form_widget = QWidget(manual_card)
        self.form_lay = QFormLayout(form_widget)
        self.form_lay.setContentsMargins(0, 8, 0, 8)
        self.form_lay.setSpacing(12)

        self.proto_combo = StyledComboBox(form_widget)
        self.proto_combo.addItems(["SFTP", "SMB", "Telegram", "Discord"])
        self.proto_combo.currentIndexChanged.connect(self.on_proto_changed)
        self.form_lay.addRow("Protocol Type:", self.proto_combo)

        self.host_input = QLineEdit(form_widget)
        self.host_input.setPlaceholderText("e.g. 192.168.1.200")
        self.host_input.setObjectName("HostInput")
        self._host_label = QLabel("Host Address:", form_widget)
        self.form_lay.addRow(self._host_label, self.host_input)

        self.share_user_input = QLineEdit(form_widget)
        self.share_user_input.setPlaceholderText("Username or Share name")
        self.share_user_input.setObjectName("ShareUserInput")
        self._share_label = QLabel("User / Share:", form_widget)
        self.form_lay.addRow(self._share_label, self.share_user_input)

        self.pass_input = QLineEdit(form_widget)
        self.pass_input.setPlaceholderText("Password or Private Key Path")
        self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.pass_input.setObjectName("PassInput")
        self._pass_label = QLabel("Credentials:", form_widget)
        self.form_lay.addRow(self._pass_label, self.pass_input)

        manual_layout.addWidget(form_widget)

        # Encryption notice — shown for 3rd-party backends
        self._cred_notice = QLabel(
            "🔒 Credentials will be encrypted with AES-256-GCM (master-key derived) "
            "before being stored in the OS Keyring.",
            manual_card
        )
        self._cred_notice.setObjectName("MutedLabel")
        self._cred_notice.setWordWrap(True)
        self._cred_notice.setVisible(False)
        manual_layout.addWidget(self._cred_notice)

        self.add_manual_btn = StyledButton("Add Storage Channel", manual_card, primary=True)
        self.add_manual_btn.clicked.connect(self.on_add_manual_nas)
        manual_layout.addWidget(self.add_manual_btn)
        manual_layout.addStretch()

        layout_add.addWidget(manual_card, stretch=1)
        self.tabs.addTab(tab_add, "➕ Link New Channel")

        # ─── TAB 3: Resilience & Redundancy ───
        tab_resilience = QWidget(self.tabs)
        layout_resilience = QVBoxLayout(tab_resilience)
        layout_resilience.setContentsMargins(12, 16, 12, 16)
        layout_resilience.setSpacing(12)

        self.resilience_card = ResiliencePanel(tab_resilience, db)
        layout_resilience.addWidget(self.resilience_card)
        self.tabs.addTab(tab_resilience, "🛡️ Resilience & Redundancy")

        # ─── TAB 4: Routing Policy ───
        tab_routing = QWidget(self.tabs)
        layout_routing = QVBoxLayout(tab_routing)
        layout_routing.setContentsMargins(12, 16, 12, 16)
        layout_routing.setSpacing(12)

        routing_card = GlassCard(tab_routing)
        self.routing_layout = QVBoxLayout(routing_card)
        self.routing_layout.setContentsMargins(20, 20, 20, 20)
        self.routing_layout.setSpacing(12)

        routing_title = QLabel("⚙️ Storage Tier Routing Policy", routing_card)
        routing_title.setObjectName("SubHeading")
        self.routing_layout.addWidget(routing_title)

        routing_desc = QLabel(
            "Assign specifically which storage backends should be used for each file security tier (CRITICAL, IMPORTANT, and DISPOSABLE). "
            "Leave all unchecked for a tier to fallback to routing chunks to all healthy backends.",
            routing_card
        )
        routing_desc.setObjectName("MutedLabel")
        routing_desc.setWordWrap(True)
        self.routing_layout.addWidget(routing_desc)

        self.routing_container = QWidget(routing_card)
        self.routing_container_layout = QVBoxLayout(self.routing_container)
        self.routing_container_layout.setContentsMargins(0, 0, 0, 0)
        self.routing_container_layout.setSpacing(10)
        self.routing_layout.addWidget(self.routing_container)

        # Min healthy alert threshold layout
        threshold_layout = QHBoxLayout()
        threshold_label = QLabel("Alert Threshold: Show warning/critical popups if active healthy backends fall below:", routing_card)
        threshold_label.setStyleSheet("color: #f4f4f5; font-size: 12px;")
        threshold_layout.addWidget(threshold_label)

        self.threshold_spin = StyledComboBox(routing_card)
        for i in range(1, 6):
            self.threshold_spin.addItem(f"{i} Backend(s)", i)
        threshold_layout.addWidget(self.threshold_spin)
        threshold_layout.addStretch()
        self.routing_layout.addLayout(threshold_layout)

        self.save_routing_btn = StyledButton("Save Routing & Alert Policy", routing_card, primary=True)
        self.save_routing_btn.clicked.connect(self.save_routing_policy)
        self.routing_layout.addWidget(self.save_routing_btn)

        layout_routing.addWidget(routing_card)
        self.tabs.addTab(tab_routing, "⚙️ Routing Policy")

        # Discovery thread tracking
        self.discovery_thread = None

    # ─── Helper: locate MainWindow ────────────────────────────────────────────

    def _get_main_window(self):
        """Walk up the parent tree to find the MainWindow instance."""
        from ghostdrive.gui.main_view import MainWindow
        w = self.parent()
        while w is not None:
            if isinstance(w, MainWindow):
                return w
            w = w.parent()
        return None

    # ─── Helper: encrypt & store credential in OS Keyring ────────────────────

    def _store_encrypted_credential(self, keyring_key: str, plaintext: str) -> bool:
        """
        Encrypt plaintext via the process-global credential_store (AES-256-GCM + OS Keyring)
        and write the blob to the OS Keyring.
        Returns True on success, False on failure (error dialog already shown).
        """
        from ghostdrive.crypto.credential_store import credential_store
        if not credential_store.is_unlocked:
            QMessageBox.critical(
                self, "Security Error",
                "The keystore must be unlocked to securely encrypt and store credentials. "
                "Please unlock GhostDrive first."
            )
            return False
        try:
            credential_store.store(keyring_key, plaintext)
            return True
        except Exception as exc:
            logger.error("Failed to encrypt/store credential '%s': %s", keyring_key, exc)
            QMessageBox.critical(
                self, "Encryption Error",
                f"Failed to securely store credential: {exc}"
            )
            return False

    def update_protocols_visibility(self, show_network: bool) -> None:
        """Update available protocols in the dropdown based on network feature visibility."""
        try:
            self.proto_combo.currentIndexChanged.disconnect(self.on_proto_changed)
        except TypeError:
            pass
            
        current_proto = self.proto_combo.currentText()
        self.proto_combo.clear()
        
        if show_network:
            self.proto_combo.addItems(["SFTP", "SMB", "Telegram", "Discord"])
        else:
            self.proto_combo.addItems(["SFTP", "SMB"])
            
        idx = self.proto_combo.findText(current_proto)
        if idx >= 0:
            self.proto_combo.setCurrentIndex(idx)
        else:
            self.proto_combo.setCurrentIndex(0)
            
        self.proto_combo.currentIndexChanged.connect(self.on_proto_changed)
        self.on_proto_changed(self.proto_combo.currentIndex())

    # ─── Refresh ──────────────────────────────────────────────────────────────

    def refresh(self) -> None:
        """Refresh all dynamic UI tables."""
        import asyncio
        self.refresh_active_backends()
        asyncio.create_task(self.refresh_connected_drives())
        self.resilience_card.refresh()
        self.refresh_routing_policy()

    def refresh_active_backends(self) -> None:
        """Fetch active backends from DB and populate table."""
        self.backends_table.setRowCount(0)
        if not self.db:
            return

        try:
            backends = self.db._conn.execute(
                "SELECT id, type, status, quota_used, quota_limit FROM backends"
            ).fetchall()
        except Exception as exc:
            logger.error("Failed to query active backends: %s", exc)
            return

        self.backends_table.setRowCount(len(backends))
        for idx, b in enumerate(backends):
            b_id = b["id"]
            b_type = b["type"].upper()

            # Format limit & used
            used_mb = b["quota_used"] / (1024 * 1024)
            limit_mb = b["quota_limit"] / (1024 * 1024)
            quota_text = f"{used_mb:.1f} MB / {limit_mb:.1f} MB"

            status_text = b["status"].upper()

            self.backends_table.setItem(idx, 0, QTableWidgetItem(b_type))
            self.backends_table.setItem(idx, 1, QTableWidgetItem(quota_text))
            self.backends_table.setItem(idx, 2, QTableWidgetItem(status_text))

            # Action button: remove
            remove_btn = StyledButton("Remove", self.backends_table, danger=True)
            # Use default function parameter binding to freeze current value of b_id
            remove_btn.clicked.connect(lambda checked=False, bid=b_id: self.on_remove_backend(bid))
            self.backends_table.setCellWidget(idx, 3, remove_btn)

    @qasync.asyncSlot()
    async def refresh_connected_drives(self) -> None:
        """Query platform drive monitor for connected drives and render them."""
        import asyncio
        self.drives_table.setRowCount(0)
        connected_drives = await asyncio.to_thread(self.registrar.list_connected_drives)


        # Check which are already registered
        registered_uuids = set()
        if self.db and self.db._conn:
            try:
                registered_uuids = {
                    row["drive_uuid"] for row in self.db._conn.execute("SELECT drive_uuid FROM drive_registry").fetchall()
                }
            except Exception:
                pass

        self.drives_table.setRowCount(len(connected_drives))
        for idx, drive in enumerate(connected_drives):
            size_gb = drive.capacity_bytes / (1024 * 1024 * 1024)

            self.drives_table.setItem(idx, 0, QTableWidgetItem(drive.label or "Local Disk"))
            self.drives_table.setItem(idx, 1, QTableWidgetItem(drive.mountpoint))
            self.drives_table.setItem(idx, 2, QTableWidgetItem(f"{size_gb:.1f} GB"))

            if drive.drive_uuid in registered_uuids:
                status_lbl = QLabel("Registered", self.drives_table)
                status_lbl.setStyleSheet("color: #10b981; font-weight: bold; margin-left: 10px;")
                self.drives_table.setCellWidget(idx, 3, status_lbl)
            elif not drive.drive_uuid:
                status_lbl = QLabel("No UUID", self.drives_table)
                status_lbl.setStyleSheet("color: #71717a; margin-left: 10px;")
                self.drives_table.setCellWidget(idx, 3, status_lbl)
            else:
                reg_btn = StyledButton("Register", self.drives_table, primary=True)
                reg_btn.clicked.connect(lambda checked=False, drv=drive: self.on_register_drive(drv))
                self.drives_table.setCellWidget(idx, 3, reg_btn)

    # ─── Event handlers ───────────────────────────────────────────────────────

    def on_register_drive(self, drive) -> None:
        """Register the connected drive as a backend."""
        try:
            self.registrar.register_external_drive(drive, drive.label or "USB SSD")
            QMessageBox.information(self, "Success", f"Successfully registered drive '{drive.label}' as a local backend.")
            self.refresh()
        except Exception as exc:
            QMessageBox.critical(self, "Registration Error", f"Failed to register drive: {exc}")

    def on_link_local_folder_clicked(self) -> None:
        """Prompt user to select a local directory, enter a label, and register it."""
        from PyQt6.QtWidgets import QFileDialog, QInputDialog
        from pathlib import Path
        
        folder_path_str = QFileDialog.getExistingDirectory(self, "Select Folder to Link as Backend")
        if not folder_path_str:
            return
            
        folder_path = Path(folder_path_str)
        if not folder_path.exists() or not folder_path.is_dir():
            QMessageBox.warning(self, "Invalid Directory", "The selected path is not a valid directory.")
            return
            
        label, ok = QInputDialog.getText(
            self, "Link Local Folder", "Enter a friendly label for this folder:",
            text=f"Folder Backup ({folder_path.name})"
        )
        if not ok or not label.strip():
            return
            
        try:
            self.registrar.register_local_folder(folder_path, label.strip())
            QMessageBox.information(
                self, "Success",
                f"Successfully registered folder '{label.strip()}' as a local backend.\n"
                "GhostDrive will now use this folder as a secure replica store."
            )
            
            # Dynamically connect the new backend in the live session
            main_win = self._get_main_window()
            if main_win:
                main_win.load_and_connect_local_backends()
                
            self.refresh()
        except Exception as exc:
            QMessageBox.critical(self, "Registration Error", f"Failed to register local folder: {exc}")

    def on_remove_backend(self, backend_id: str) -> None:
        """Remove backend with S9 redundancy check warning if needed."""
        try:
            self.registrar.deregister_backend(backend_id, force=False)
            self._cleanup_3rd_party_backend(backend_id)
            QMessageBox.information(self, "Success", "Backend deregistered successfully.")
            self.refresh()
        except SecureEraseBlockedError as exc:
            # S9 redundancy check failed!
            dialog = S9WarningDialog(self, str(exc))
            if dialog.exec() == QDialog.DialogCode.Accepted:
                try:
                    self.registrar.deregister_backend(backend_id, force=True)
                    self._cleanup_3rd_party_backend(backend_id)
                    QMessageBox.information(self, "Success", "Backend removed with force override. Redundant chunk healing is now queued.")
                    self.refresh()
                except Exception as override_exc:
                    QMessageBox.critical(self, "Error", f"Failed to remove backend: {override_exc}")
        except Exception as exc:
            QMessageBox.critical(self, "Error", f"Failed to remove backend: {exc}")

    def _cleanup_3rd_party_backend(self, backend_id: str) -> None:
        """
        If backend_id is a known 3rd-party backend, wipe its encrypted credential
        blobs from the OS Keyring and remove it from the active_backends dictionary.
        """
        from ghostdrive.crypto.credential_store import credential_store

        if backend_id == _TELEGRAM_BACKEND_ID:
            for k in _TELEGRAM_KEYRING_KEYS:
                credential_store.delete(k)
                logger.info("Wiped Telegram credential '%s' from OS Keyring.", k)
            main_win = self._get_main_window()
            if main_win and "telegram" in main_win.active_backends:
                del main_win.active_backends["telegram"]
                logger.info("Removed Telegram backend from active_backends.")

        elif backend_id == _DISCORD_BACKEND_ID:
            for k in _DISCORD_KEYRING_KEYS:
                credential_store.delete(k)
                logger.info("Wiped Discord credential '%s' from OS Keyring.", k)
            main_win = self._get_main_window()
            if main_win and "discord" in main_win.active_backends:
                del main_win.active_backends["discord"]
                logger.info("Removed Discord backend from active_backends.")

    def start_nas_discovery(self) -> None:
        """Launch background NAS discovery thread."""
        self.refresh_nas_btn.setEnabled(False)
        self.refresh_nas_btn.setText("Scanning...")
        self.nas_table.setRowCount(0)

        self.discovery_thread = NASDiscoveryThread(self.registrar)
        self.discovery_thread.discovery_complete.connect(self.on_nas_discovery_complete)
        self.discovery_thread.start()

    def on_nas_discovery_complete(self, results: list) -> None:
        self.refresh_nas_btn.setEnabled(True)
        self.refresh_nas_btn.setText("Scan LAN")
        self.nas_table.setRowCount(len(results))

        for idx, r in enumerate(results):
            name = r["name"]
            addr = f"{r['host']}:{r['port']} ({r['protocol'].upper()})"

            self.nas_table.setItem(idx, 0, QTableWidgetItem(name))
            self.nas_table.setItem(idx, 1, QTableWidgetItem(addr))

            config_btn = StyledButton("Setup", self.nas_table, primary=True)
            config_btn.clicked.connect(lambda checked=False, svc=r: self.on_prefill_nas_config(svc))
            self.nas_table.setCellWidget(idx, 2, config_btn)

    def on_prefill_nas_config(self, service: dict) -> None:
        """Prefill the manual NAS config fields when discovery result is clicked."""
        self.proto_combo.setCurrentText(service["protocol"].upper())
        self.host_input.setText(service["host"])
        if service["protocol"] == "sftp":
            self.share_user_input.setPlaceholderText("Username")
            self.pass_input.setPlaceholderText("SSH Private Key Path")
        else:
            self.share_user_input.setPlaceholderText("SMB Share Name")
            self.pass_input.setPlaceholderText("Password")

    def on_proto_changed(self, idx: int) -> None:
        """Dynamically update form labels and field visibility based on selected protocol."""
        if idx == _PROTO_SFTP:
            self._host_label.setText("Host Address:")
            self.host_input.setPlaceholderText("e.g. 192.168.1.200")
            self._share_label.setText("User / Share:")
            self.share_user_input.setPlaceholderText("Username")
            self.share_user_input.setVisible(True)
            self._share_label.setVisible(True)
            self._pass_label.setText("Credentials:")
            self.pass_input.setPlaceholderText("SSH Private Key Path")
            self.pass_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self._cred_notice.setVisible(False)

        elif idx == _PROTO_SMB:
            self._host_label.setText("Host Address:")
            self.host_input.setPlaceholderText("e.g. 192.168.1.200")
            self._share_label.setText("SMB Share:")
            self.share_user_input.setPlaceholderText("SMB Share Name")
            self.share_user_input.setVisible(True)
            self._share_label.setVisible(True)
            self._pass_label.setText("Credentials:")
            self.pass_input.setPlaceholderText("Password")
            self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)
            self._cred_notice.setVisible(False)

        elif idx == _PROTO_TELEGRAM:
            self._host_label.setText("API ID:")
            self.host_input.setPlaceholderText("Numeric ID from my.telegram.org")
            self._share_label.setText("Phone Number:")
            self.share_user_input.setPlaceholderText("+1234567890 (with country code)")
            self.share_user_input.setVisible(True)
            self._share_label.setVisible(True)
            self._pass_label.setText("API Hash:")
            self.pass_input.setPlaceholderText("32-character hex hash from my.telegram.org")
            self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)
            self._cred_notice.setVisible(True)

        elif idx == _PROTO_DISCORD:
            self._host_label.setText("Channel ID:")
            self.host_input.setPlaceholderText("Discord channel ID (numeric)")
            # Discord has no username/share field — hide it to avoid confusion
            self.share_user_input.setVisible(False)
            self._share_label.setVisible(False)
            self._pass_label.setText("Bot Token:")
            self.pass_input.setPlaceholderText("Discord bot token (keep this secret!)")
            self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)
            self._cred_notice.setVisible(True)

    @qasync.asyncSlot()
    async def on_add_manual_nas(self) -> None:
        """
        Register the channel in the database and (for 3rd-party backends)
        encrypt and store credentials in the OS Keyring.
        """
        proto_idx = self.proto_combo.currentIndex()
        proto     = self.proto_combo.currentText().lower()

        # ── 3rd-party backends: Telegram ──────────────────────────────────────
        if proto_idx == _PROTO_TELEGRAM:
            api_id_str   = self.host_input.text().strip()
            phone        = self.share_user_input.text().strip()
            api_hash     = self.pass_input.text().strip()

            if not api_id_str or not api_hash:
                QMessageBox.warning(self, "Validation Error", "API ID and API Hash are required.")
                return
            if not api_id_str.isdigit():
                QMessageBox.warning(self, "Validation Error", "API ID must be a numeric integer.")
                return

            # Perform interactive OTP authentication first
            from ghostdrive.backends.telegram_backend import TelegramBackend
            tg = TelegramBackend(
                api_id=int(api_id_str),
                api_hash=api_hash,
                phone=phone,
                _skip_keyring=True
            )

            def code_cb() -> str:
                dialog = TelegramOtpDialog(self)
                if dialog.exec() == QDialog.DialogCode.Accepted:
                    return dialog.get_code()
                raise Exception("Telegram OTP authentication cancelled.")

            def password_cb() -> str:
                dialog = TelegramPasswordDialog(self)
                if dialog.exec() == QDialog.DialogCode.Accepted:
                    return dialog.get_password()
                raise Exception("Telegram 2FA password authentication cancelled.")

            # Temporarily disable button to prevent double-submit
            self.add_manual_btn.setEnabled(False)
            self.add_manual_btn.setText("Authenticating...")

            try:
                await tg.first_run_authenticate(
                    phone=phone,
                    code_callback=code_cb,
                    password_callback=password_cb
                )
            except Exception as exc:
                logger.error("Telegram first-run authentication failed: %s", exc)
                QMessageBox.critical(
                    self, "Authentication Failed",
                    f"Failed to authenticate with Telegram:\n{exc}"
                )
                return
            finally:
                self.add_manual_btn.setEnabled(True)
                self.add_manual_btn.setText("Add Storage Channel")

            # Encrypt and store each credential separately in OS Keyring
            ok = (
                self._store_encrypted_credential("telegram_api_id",   api_id_str)
                and self._store_encrypted_credential("telegram_api_hash", api_hash)
                and (not phone or self._store_encrypted_credential("telegram_phone", phone))
            )
            if not ok:
                return  # Error dialog already shown by _store_encrypted_credential

            # Register in database with a large cloud quota
            if not self._register_3rd_party_in_db(_TELEGRAM_BACKEND_ID, "telegram"):
                return

            # Clear fields immediately — don't leave secrets in memory longer than needed
            self._clear_and_zero_fields()

            # Dynamically connect the backend in the live session
            main_win = self._get_main_window()
            if main_win:
                main_win.register_and_connect_3rd_party_backend()

            QMessageBox.information(self, "Success",
                "Telegram backend authenticated, encrypted, and stored successfully. "
                "GhostDrive is now connecting to Telegram in the background.")
            self.refresh()
            return

        # ── 3rd-party backends: Discord ───────────────────────────────────────
        if proto_idx == _PROTO_DISCORD:
            channel_id_str = self.host_input.text().strip()
            bot_token      = self.pass_input.text().strip()

            if not channel_id_str or not bot_token:
                QMessageBox.warning(self, "Validation Error", "Channel ID and Bot Token are required.")
                return
            if not channel_id_str.isdigit():
                QMessageBox.warning(self, "Validation Error", "Channel ID must be a numeric integer.")
                return

            ok = (
                self._store_encrypted_credential("discord_channel_id", channel_id_str)
                and self._store_encrypted_credential("discord_bot_token", bot_token)
            )
            if not ok:
                return

            if not self._register_3rd_party_in_db(_DISCORD_BACKEND_ID, "discord"):
                return

            self._clear_and_zero_fields()

            main_win = self._get_main_window()
            if main_win:
                main_win.register_and_connect_3rd_party_backend()

            QMessageBox.information(self, "Success",
                "Discord backend credentials encrypted and stored securely. "
                "GhostDrive is now connecting to Discord in the background.")
            self.refresh()
            return

        # ── Local NAS: SFTP / SMB ─────────────────────────────────────────────
        host            = self.host_input.text().strip()
        share_or_user   = self.share_user_input.text().strip()
        credentials_ref = self.pass_input.text().strip()

        if not host or not share_or_user or not credentials_ref:
            QMessageBox.warning(self, "Validation Error", "All config fields are required.")
            return

        backend_id = None
        if self.registrar.db and self.registrar.db._conn:
            row = self.registrar.db._conn.execute("SELECT lower(hex(randomblob(16)))").fetchone()
            if row:
                backend_id = str(row[0])
        if not backend_id:
            import uuid
            backend_id = str(uuid.uuid4())

        # Save to OS keyring securely (NAS credentials, no master-key encryption needed —
        # these are paths/usernames, not secret tokens)
        keyring_account = f"{proto}_cred_{backend_id}"
        try:
            from ghostdrive.crypto.credential_store import credential_store
            credential_store.store(keyring_account, credentials_ref)
        except Exception as exc:
            logger.warning("Failed to save NAS credentials to credential_store: %s", exc)

        if not self.db or not self.db._conn:
            QMessageBox.critical(self, "Error", "Database connection is not available.")
            return

        try:
            with self.db.transaction():
                self.db._conn.execute(
                    """INSERT INTO backends
                       (id, type, credentials_ref, status, priority, quota_used, quota_limit, quota_reserved)
                       VALUES (?, ?, ?, 'healthy', 100, 0, 107374182400, 0)""",
                    (backend_id, proto, keyring_account),
                )
            QMessageBox.information(self, "Success", f"Registered manual {proto.upper()} NAS storage backend successfully.")
            self._clear_and_zero_fields()
            self.refresh()
        except Exception as exc:
            QMessageBox.critical(self, "Database Error", f"Failed to register NAS backend: {exc}")

    def _register_3rd_party_in_db(self, backend_id: str, backend_type: str) -> bool:
        """
        Insert a 3rd-party backend row into the database if it doesn't already exist.
        Returns True on success, False on failure.
        """
        if not self.db or not self.db._conn:
            QMessageBox.critical(self, "Error", "Database connection is not available.")
            return False
        try:
            with self.db.transaction():
                existing = self.db._conn.execute(
                    "SELECT id FROM backends WHERE id = ?", (backend_id,)
                ).fetchone()
                if not existing:
                    self.db._conn.execute(
                        """INSERT INTO backends
                           (id, type, credentials_ref, status, priority, quota_used, quota_limit, quota_reserved)
                           VALUES (?, ?, ?, 'healthy', 100, 0, 4611686018427387904, 0)""",
                        (backend_id, backend_type, f"keyring:encrypted:{backend_type}_creds"),
                    )
            return True
        except Exception as exc:
            QMessageBox.critical(self, "Database Error", f"Failed to register backend: {exc}")
            return False

    def _clear_and_zero_fields(self) -> None:
        """Clear all credential input fields immediately after use."""
        self.host_input.clear()
        self.share_user_input.clear()
        self.pass_input.clear()


class S9WarningDialog(ResilientDialog):
    """Warning dialog detailing S9 redundancy check details and force checkbox."""

    def __init__(self, parent: QWidget, error_message: str) -> None:
        super().__init__(parent, base_width=420, base_height=260)
        self.setWindowTitle("Data Loss Warning")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        title = QLabel("⚠️ S9 REDUNDANCY EXCLUSION ALERT", self)
        title.setStyleSheet("color: #ef4444; font-weight: bold; font-size: 14px;")
        layout.addWidget(title)

        msg = QLabel(error_message, self)
        msg.setWordWrap(True)
        msg.setStyleSheet("color: #f4f4f5;")
        layout.addWidget(msg)

        # Threat mitigation text
        threat_lbl = QLabel(
            "Removing this backend will reduce file replicas below the target tier "
            "minimum count. A hardware crash on another active backend will result in "
            "permanent files erasure/corruption.", self
        )
        threat_lbl.setWordWrap(True)
        threat_lbl.setStyleSheet("color: #f59e0b; font-size: 11px;")
        layout.addWidget(threat_lbl)

        # Force checkbox
        self.checkbox = QCheckBox("I understand the threat and accept permanent data loss.", self)
        self.checkbox.setStyleSheet("color: #ef4444; font-weight: bold; font-size: 11px;")
        self.checkbox.toggled.connect(self.on_checkbox_toggled)
        layout.addWidget(self.checkbox)

        # Dialog buttons
        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Ok,
            Qt.Orientation.Horizontal, self
        )
        ok_btn = self.buttons.button(QDialogButtonBox.StandardButton.Ok)
        if ok_btn:
            ok_btn.setEnabled(False)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)

    def on_checkbox_toggled(self, checked: bool) -> None:
        ok_btn = self.buttons.button(QDialogButtonBox.StandardButton.Ok)
        if ok_btn:
            ok_btn.setEnabled(checked)

    def refresh_routing_policy(self) -> None:
        """Fetch backends and settings to rebuild routing policy checkboxes."""
        if not self.db:
            return

        # Clear existing container
        while self.routing_container_layout.count():
            item = self.routing_container_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

        # Query backends
        try:
            backends = self.db._conn.execute("SELECT id, type FROM backends").fetchall()
        except Exception as exc:
            logger.error("Failed to query backends for routing policy: %s", exc)
            return

        # Load current policy settings
        critical_routed = [x.strip() for x in self.db.get_setting("routing_critical_backends", "").split(",") if x.strip()]
        important_routed = [x.strip() for x in self.db.get_setting("routing_important_backends", "").split(",") if x.strip()]
        disposable_routed = [x.strip() for x in self.db.get_setting("routing_disposable_backends", "").split(",") if x.strip()]

        try:
            alert_min_str = self.db.get_setting("alert_min_healthy", "")
            alert_min = int(alert_min_str) if alert_min_str.strip() else (2 if len(backends) >= 3 else 1)
        except Exception:
            alert_min = 2 if len(backends) >= 3 else 1

        idx = self.threshold_spin.findData(alert_min)
        if idx >= 0:
            self.threshold_spin.setCurrentIndex(idx)

        # Store references to checkboxes we create so we can read them when saving
        self._routing_checkboxes = []  # list of tuples: (checkbox, backend_id, tier_name)

        if not backends:
            no_backends_lbl = QLabel("No storage channels configured yet. Link a channel to setup routing policy.", self.routing_container)
            no_backends_lbl.setStyleSheet("color: #9ca3af; font-style: italic; font-size: 12px; margin-top: 10px;")
            self.routing_container_layout.addWidget(no_backends_lbl)
            self.save_routing_btn.setEnabled(False)
            return

        self.save_routing_btn.setEnabled(True)

        tiers = [
            ("CRITICAL", "🔴 CRITICAL Tier (e.g. Telegram / SFTP)", critical_routed, "#ef4444"),
            ("IMPORTANT", "🟡 IMPORTANT Tier (e.g. Discord / Local FS)", important_routed, "#f59e0b"),
            ("DISPOSABLE", "⚪ DISPOSABLE Tier (e.g. Local FS / Temp)", disposable_routed, "#9ca3af")
        ]

        for tier_id, tier_label, routed_ids, color in tiers:
            tier_header = QLabel(tier_label, self.routing_container)
            tier_header.setStyleSheet(f"font-weight: bold; font-size: 12px; color: {color}; margin-top: 10px;")
            self.routing_container_layout.addWidget(tier_header)

            flow_widget = QWidget(self.routing_container)
            flow_layout = QHBoxLayout(flow_widget)
            flow_layout.setContentsMargins(10, 0, 10, 0)
            flow_layout.setSpacing(15)

            for b in backends:
                b_id = b["id"]
                b_type = b["type"].upper()
                
                # Pre-fill check value
                checked = b_id in routed_ids

                # Text: TYPE (last 6 of ID)
                cb = QCheckBox(f"{b_type} ({b_id[:6]})", flow_widget)
                cb.setChecked(checked)
                cb.setStyleSheet("color: #f4f4f5; font-size: 11px;")
                flow_layout.addWidget(cb)
                self._routing_checkboxes.append((cb, b_id, tier_id))

            flow_layout.addStretch()
            self.routing_container_layout.addWidget(flow_widget)

    def save_routing_policy(self) -> None:
        """Collect checked backends per tier and save settings to database."""
        if not self.db:
            return

        critical_ids = []
        important_ids = []
        disposable_ids = []

        for cb, b_id, tier_id in self._routing_checkboxes:
            if cb.isChecked():
                if tier_id == "CRITICAL":
                    critical_ids.append(b_id)
                elif tier_id == "IMPORTANT":
                    important_ids.append(b_id)
                elif tier_id == "DISPOSABLE":
                    disposable_ids.append(b_id)

        alert_min = self.threshold_spin.currentData()

        try:
            self.db.set_setting("routing_critical_backends", ",".join(critical_ids))
            self.db.set_setting("routing_important_backends", ",".join(important_ids))
            self.db.set_setting("routing_disposable_backends", ",".join(disposable_ids))
            self.db.set_setting("alert_min_healthy", str(alert_min))

            # Trigger a health alert evaluation immediately to update main view connection indicators
            mw = self._get_main_window()
            if mw and hasattr(mw, "health_daemon") and mw.health_daemon:
                import asyncio
                asyncio.create_task(mw.health_daemon._evaluate_backend_alerts())

            QMessageBox.information(
                self, "Settings Saved",
                "Storage tier routing and alert threshold policy updated successfully."
            )
        except Exception as exc:
            logger.error("Failed to save routing policy settings: %s", exc)
            QMessageBox.critical(self, "Error", f"Failed to save routing settings: {exc}")
