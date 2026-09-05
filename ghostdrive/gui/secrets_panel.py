"""
secrets_panel.py -- PyQt6 dashboard widget for managing encrypted passwords, notes, API keys, and SSH keys.
"""

import logging
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QTextEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QSplitter,
    QFormLayout,
)
from ghostdrive.gui.widgets import GlassCard, StyledButton, StyledComboBox
from ghostdrive.crypto.secrets_vault import SecretsVault, generate_totp

logger = logging.getLogger(__name__)

class SecretsPanel(QWidget):
    """
    SecretsPanel implements a premium, zero-knowledge credentials manager.
    Displays and manages encrypted passwords (with live TOTP), secure notes,
    API keys, and SSH keys.
    """

    def __init__(self, parent: QWidget = None, db = None) -> None:
        super().__init__(parent)
        self.db = db
        self.vault: SecretsVault | None = None
        self.selected_secret_id: str | None = None

        # Main Layout
        layout = QHBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # Splitter for left list / right details
        splitter = QSplitter(Qt.Orientation.Horizontal, self)
        splitter.setStyleSheet("QSplitter::handle { background-color: #27272a; width: 1px; }")

        # ─── LEFT COLUMN: Search & List ───
        left_widget = QWidget(splitter)
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 10, 0)
        left_layout.setSpacing(12)

        # Header: Title + compact Add button side-by-side
        header_layout = QHBoxLayout()
        title_lbl = QLabel("Secrets Vault", left_widget)
        title_lbl.setObjectName("Heading")
        header_layout.addWidget(title_lbl)
        
        self.add_btn = StyledButton("+ Add Secret", left_widget, primary=True)
        self.add_btn.clicked.connect(self.on_add_clicked)
        header_layout.addWidget(self.add_btn)
        left_layout.addLayout(header_layout)

        # Toolbar: Search box + Filter combo side-by-side
        toolbar_layout = QHBoxLayout()
        toolbar_layout.setSpacing(8)

        self.search_input = QLineEdit(left_widget)
        self.search_input.setPlaceholderText("Search vault...")
        self.search_input.textChanged.connect(self.refresh_list)
        toolbar_layout.addWidget(self.search_input, stretch=2)

        self.filter_combo = StyledComboBox(left_widget)
        self.filter_combo.addItems(["All", "Pass", "Note", "API", "SSH"])
        self.filter_combo.currentIndexChanged.connect(self.refresh_list)
        self.filter_combo.setFixedWidth(80)
        toolbar_layout.addWidget(self.filter_combo, stretch=1)
        
        left_layout.addLayout(toolbar_layout)

        # Secrets List
        self.list_widget = QListWidget(left_widget)
        self.list_widget.setObjectName("SecretsList")
        self.list_widget.currentItemChanged.connect(self.on_item_selected)
        left_layout.addWidget(self.list_widget)

        splitter.addWidget(left_widget)

        # ─── RIGHT COLUMN: Details & Edit ───
        right_widget = QWidget(splitter)
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(10, 0, 0, 0)
        right_layout.setSpacing(12)

        # Container card
        self.details_card = GlassCard(right_widget)
        self.details_layout = QVBoxLayout(self.details_card)
        self.details_layout.setContentsMargins(20, 20, 20, 20)
        self.details_layout.setSpacing(14)

        # Placeholder label when nothing is selected
        self.placeholder_lbl = QLabel("🔐 Select an item to view or edit details.\nUnlock your credentials in a zero-knowledge environment.", self.details_card)
        self.placeholder_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.placeholder_lbl.setStyleSheet("color: #9ca3af; font-size: 14px; font-weight: 500;")
        self.details_layout.addWidget(self.placeholder_lbl)

        # Form widgets (hidden by default)
        self.form_widget = QWidget(self.details_card)
        self.form_layout = QFormLayout(self.form_widget)
        self.form_layout.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        self.form_layout.setSpacing(12)

        # Label Field
        self.label_input = QLineEdit(self.form_widget)
        self.label_input.setPlaceholderText("e.g. My GitHub Token")
        self.form_layout.addRow("Label:", self.label_input)

        # Kind Field
        self.kind_combo = StyledComboBox(self.form_widget)
        self.kind_combo.addItems(["Password", "Secure Note", "API Key", "SSH Key"])
        self.kind_combo.currentIndexChanged.connect(self.on_kind_changed)
        self.form_layout.addRow("Type:", self.kind_combo)

        # Username Field
        self.user_input = QLineEdit(self.form_widget)
        self.form_layout.addRow("Username / ID:", self.user_input)

        # Secret / Password Field (with show/hide and copy)
        secret_box = QHBoxLayout()
        self.secret_input = QLineEdit(self.form_widget)
        self.secret_input.setEchoMode(QLineEdit.EchoMode.Password)
        secret_box.addWidget(self.secret_input)

        self.toggle_btn = StyledButton("Reveal", self.form_widget, secondary=True)
        self.toggle_btn.clicked.connect(self.toggle_secret_visibility)
        secret_box.addWidget(self.toggle_btn)

        self.copy_btn = StyledButton("Copy", self.form_widget, secondary=True)
        self.copy_btn.clicked.connect(self.copy_secret)
        secret_box.addWidget(self.copy_btn)
        self.form_layout.addRow("Secret / Value:", secret_box)

        # TOTP Seed Field
        self.totp_seed_input = QLineEdit(self.form_widget)
        self.totp_seed_input.setPlaceholderText("Base32 TOTP Seed (Optional)")
        self.form_layout.addRow("TOTP Seed:", self.totp_seed_input)

        # Live TOTP Display Field
        self.totp_display_lbl = QLabel("------", self.form_widget)
        self.totp_display_lbl.setStyleSheet("font-size: 24px; font-weight: bold; color: #10b981; font-family: Courier;")
        self.form_layout.addRow("Live 2FA Code:", self.totp_display_lbl)

        # Notes / Text Field
        self.notes_input = QTextEdit(self.form_widget)
        self.notes_input.setPlaceholderText("Encrypted secure notes...")
        self.notes_input.setMinimumHeight(120)
        self.form_layout.addRow("Notes:", self.notes_input)

        self.details_layout.addWidget(self.form_widget)

        # Action Buttons
        self.actions_box = QHBoxLayout()
        self.save_btn = StyledButton("Save Changes", self.details_card, primary=True)
        self.save_btn.clicked.connect(self.on_save_clicked)
        self.actions_box.addWidget(self.save_btn)

        self.delete_btn = StyledButton("Delete Entry", self.details_card, danger=True)
        self.delete_btn.clicked.connect(self.on_delete_clicked)
        self.actions_box.addWidget(self.delete_btn)
        self.details_layout.addLayout(self.actions_box)

        # Hide form and actions initially
        self.form_widget.setVisible(False)
        self.actions_box.setEnabled(False)

        right_layout.addWidget(self.details_card)
        splitter.addWidget(right_widget)
        layout.addWidget(splitter)

        # Live TOTP Timer
        self.totp_timer = QTimer(self)
        self.totp_timer.timeout.connect(self.update_live_totp)
        self.totp_timer.start(1000)

    def set_vault(self, vault: SecretsVault | None) -> None:
        """Invoked when the database is unlocked or locked."""
        self.vault = vault
        if not vault:
            self.lock()
        else:
            self.refresh_list()

    def lock(self) -> None:
        """Clear all sensitive decrypted information from the UI."""
        self.vault = None
        self.selected_secret_id = None
        self.list_widget.clear()
        self.label_input.clear()
        self.user_input.clear()
        self.secret_input.clear()
        self.totp_seed_input.clear()
        self.notes_input.clear()
        self.totp_display_lbl.setText("------")
        self.form_widget.setVisible(False)
        self.placeholder_lbl.setVisible(True)
        self.actions_box.setEnabled(False)

    def refresh_list(self) -> None:
        """Query and populate the list of secrets based on search and filters."""
        self.list_widget.clear()
        if not self.vault:
            return

        # Map kind filter
        filter_idx = self.filter_combo.currentIndex()
        kind_map = {1: "password", 2: "note", 3: "api_key", 4: "ssh_key"}
        filter_kind = kind_map.get(filter_idx, None)

        try:
            secrets = self.vault.list_secrets(filter_kind)
        except Exception as exc:
            logger.error("Failed to list secrets: %s", exc)
            return

        search_query = self.search_input.text().lower()

        for s in secrets:
            label = s["label"]
            kind = s["kind"]
            
            if search_query and search_query not in label.lower() and search_query not in kind.lower():
                continue

            item = QListWidgetItem(f"{label} ({kind.upper().replace('_', ' ')})")
            item.setData(Qt.ItemDataRole.UserRole, s["id"])
            self.list_widget.addItem(item)

    def on_item_selected(self, current: QListWidgetItem, previous: QListWidgetItem) -> None:
        """Fires when an item in the secrets list is clicked."""
        if not current or not self.vault:
            return

        self.selected_secret_id = current.data(Qt.ItemDataRole.UserRole)
        try:
            secret = self.vault.get_secret(self.selected_secret_id)
        except Exception as exc:
            QMessageBox.critical(self, "Decryption Error", f"Failed to decrypt secret: {exc}")
            return

        if not secret:
            return

        # Show form & actions
        self.placeholder_lbl.setVisible(False)
        self.form_widget.setVisible(True)
        self.actions_box.setEnabled(True)

        # Reset echo mode for security
        self.secret_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.toggle_btn.setText("Reveal")

        # Load values
        self.label_input.setText(secret["label"])
        
        kind_index = {"password": 0, "note": 1, "api_key": 2, "ssh_key": 3}.get(secret["kind"], 0)
        self.kind_combo.setCurrentIndex(kind_index)

        payload = secret["payload"]
        self.user_input.setText(payload.get("username", ""))
        self.secret_input.setText(payload.get("secret", ""))
        self.totp_seed_input.setText(payload.get("totp_seed", ""))
        self.notes_input.setText(payload.get("notes", ""))

        self.on_kind_changed(kind_index)
        self.update_live_totp()

    def on_kind_changed(self, idx: int) -> None:
        """Adjust field visibility depending on the type of secret selected."""
        # idx: 0 = Password, 1 = Note, 2 = API Key, 3 = SSH Key
        is_password = (idx == 0)
        is_note = (idx == 1)
        is_ssh = (idx == 3)

        # Labels
        self.form_layout.labelForField(self.user_input).setText("Username / Email:" if is_password else "Key ID / Username:")
        self.form_layout.labelForField(self.user_input).setVisible(not is_note)
        self.user_input.setVisible(not is_note)

        self.form_layout.labelForField(self.secret_input.parentWidget()).setVisible(not is_note)
        self.secret_input.setVisible(not is_note)
        self.toggle_btn.setVisible(not is_note)
        self.copy_btn.setVisible(not is_note)

        self.form_layout.labelForField(self.totp_seed_input).setVisible(is_password)
        self.totp_seed_input.setVisible(is_password)

        self.form_layout.labelForField(self.totp_display_lbl).setVisible(is_password)
        self.totp_display_lbl.setVisible(is_password)

        # SSH Fingerprint display placeholder
        if is_ssh:
            self.form_layout.labelForField(self.secret_input.parentWidget()).setText("Private Key:")
            self.form_layout.labelForField(self.notes_input).setText("Public Key:")
        else:
            self.form_layout.labelForField(self.secret_input.parentWidget()).setText("Password / Token:" if is_password else "API Key:")
            self.form_layout.labelForField(self.notes_input).setText("Secure Notes:")

    def toggle_secret_visibility(self) -> None:
        if self.secret_input.echoMode() == QLineEdit.EchoMode.Password:
            self.secret_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.toggle_btn.setText("Hide")
        else:
            self.secret_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.toggle_btn.setText("Reveal")

    def copy_secret(self) -> None:
        text = self.secret_input.text()
        if text:
            from PyQt6.QtWidgets import QApplication
            QApplication.clipboard().setText(text)
            
            # Auto-clear clipboard after 30 seconds for security
            # Only clear if the user has not copied anything else since
            def clear_clip():
                if QApplication.clipboard().text() == text:
                    QApplication.clipboard().clear()
                    logger.debug("SecretsPanel: Clipboard cleared automatically for security.")
            QTimer.singleShot(30000, clear_clip)

    def update_live_totp(self) -> None:
        """Regenerate and display the live 2FA code."""
        if not self.vault or self.kind_combo.currentIndex() != 0:
            return
        
        seed = self.totp_seed_input.text()
        if seed:
            code = generate_totp(seed)
            self.totp_display_lbl.setText(code)
        else:
            self.totp_display_lbl.setText("------")

    def on_add_clicked(self) -> None:
        """Set up the UI to add a brand new secret."""
        if not self.vault:
            return

        self.selected_secret_id = None
        self.list_widget.setCurrentItem(None)

        self.placeholder_lbl.setVisible(False)
        self.form_widget.setVisible(True)
        self.actions_box.setEnabled(True)

        self.label_input.setText("New Secret Entry")
        self.kind_combo.setCurrentIndex(0)
        self.user_input.clear()
        self.secret_input.clear()
        self.totp_seed_input.clear()
        self.notes_input.clear()
        self.totp_display_lbl.setText("------")
        self.secret_input.setEchoMode(QLineEdit.EchoMode.Normal)
        self.toggle_btn.setText("Hide")

    def on_save_clicked(self) -> None:
        """Encrypt and persist the secret record in the database."""
        if not self.vault:
            return

        label = self.label_input.text().strip()
        if not label:
            QMessageBox.warning(self, "Validation Error", "Label is required.")
            return

        kinds = {0: "password", 1: "note", 2: "api_key", 3: "ssh_key"}
        kind = kinds.get(self.kind_combo.currentIndex(), "password")

        payload = {
            "username": self.user_input.text(),
            "secret": self.secret_input.text(),
            "totp_seed": self.totp_seed_input.text().strip() if kind == "password" else "",
            "notes": self.notes_input.toPlainText(),
        }

        try:
            if self.selected_secret_id:
                # Update
                self.vault.update_secret(self.selected_secret_id, label, payload)
                QMessageBox.information(self, "Success", "Secret updated successfully.")
            else:
                # Add
                self.selected_secret_id = self.vault.add_secret(label, kind, payload)
                QMessageBox.information(self, "Success", "Secret added successfully.")
            
            self.refresh_list()
        except Exception as exc:
            QMessageBox.critical(self, "Database Error", f"Failed to save secret: {exc}")

    def on_delete_clicked(self) -> None:
        """Delete the selected secret record."""
        if not self.vault or not self.selected_secret_id:
            return

        reply = QMessageBox.warning(
            self, "Confirm Delete",
            f"Are you sure you want to permanently delete '{self.label_input.text()}'?\nThis operation is irreversible.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            try:
                self.vault.delete_secret(self.selected_secret_id)
                self.lock()
                self.refresh_list()
                QMessageBox.information(self, "Deleted", "Secret deleted successfully.")
            except Exception as exc:
                QMessageBox.critical(self, "Database Error", f"Failed to delete secret: {exc}")
