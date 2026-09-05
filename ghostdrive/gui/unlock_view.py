"""
unlock_view.py -- Keystore unlock and first-run wizard views.
"""

import json
import logging
import qasync
from pathlib import Path
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QLabel,
    QStackedWidget,
    QTextEdit,
    QMessageBox,
)

from ghostdrive.gui.widgets import StyledButton, PasswordLineEdit, GlassCard
from ghostdrive.crypto.keystore import KeystoreManager
from ghostdrive.exceptions import SeedPhraseError, CryptoError, AuthenticationError
from ghostdrive.gui.styles import ResizingResilientMixin

logger = logging.getLogger(__name__)

DEFAULT_KEYSTORE_PATH = Path("keystore.json")


class UnlockView(QWidget, ResizingResilientMixin):
    """Handles keystore unlocking, first-run wizard, and seed recovery."""
    unlocked = pyqtSignal(object)  # Emitted with the unlocked KeystoreManager instance

    def __init__(self, parent: QWidget = None, keystore_path: Path = DEFAULT_KEYSTORE_PATH) -> None:
        super().__init__(parent)
        self._keystore_path = keystore_path
        self._km = KeystoreManager(self._keystore_path)

        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(40, 40, 40, 40)
        self.layout.setSpacing(20)

        # Title / Logo header
        self.header_label = QLabel("GHOSTDRIVE", self)
        self.header_label.setObjectName("Heading")
        self.header_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.layout.addWidget(self.header_label)

        # Stacked widget to switch between Unlock, Create Keystore, and Recover modes
        self.stack = QStackedWidget(self)
        self.layout.addWidget(self.stack)

        # Initialize subviews
        self._setup_first_run_chooser_view()
        self._setup_unlock_view()
        self._setup_create_view()
        self._setup_recover_view()
        self._setup_recover_bootstrap_view()
        self._setup_recover_progress_view()
        self._setup_recover_complete_view()

        # Route to correct initial view
        self.route_initial_view()

        # Initialize resizing resiliency framework with saved UI preferences
        from PyQt6.QtCore import QSettings
        settings = QSettings("GhostDrive", "Preferences")
        theme = settings.value("theme", "dark", type=str)
        accent = settings.value("accent_color", "#8b5cf6", type=str)
        self.init_resizing_resiliency(500, 480, theme, accent)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self.handle_resize_event()

    def route_initial_view(self) -> None:
        """Decide whether to show the unlock view or first-run setup wizard."""
        if self._keystore_path.exists():
            self.stack.setCurrentWidget(self.unlock_widget)
        else:
            self.stack.setCurrentWidget(self.first_run_chooser_widget)

    def _setup_first_run_chooser_view(self) -> None:
        from PyQt6.QtWidgets import QFrame
        self.first_run_chooser_widget = QWidget(self)
        layout = QVBoxLayout(self.first_run_chooser_widget)
        layout.setSpacing(20)
        
        layout.addStretch()
        
        # Welcoming Header
        welcome_lbl = QLabel("Welcome to GhostDrive", self.first_run_chooser_widget)
        welcome_lbl.setObjectName("SubHeading")
        welcome_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(welcome_lbl)
        
        sub_lbl = QLabel("Select an option to initialize your secure drive:", self.first_run_chooser_widget)
        sub_lbl.setStyleSheet("color: #9ca3af; font-size: 13px;")
        sub_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(sub_lbl)
        
        # Choice Card
        card = GlassCard(self.first_run_chooser_widget)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(24, 24, 24, 24)
        card_layout.setSpacing(16)
        
        # Option 1: Start Fresh
        fresh_btn = StyledButton("Start Fresh (Create New Vault)", card, primary=True)
        fresh_btn.clicked.connect(lambda: self.stack.setCurrentWidget(self.create_widget))
        card_layout.addWidget(fresh_btn)
        
        fresh_desc = QLabel("Initialize a new secure vault, generate a 24-word seed phrase, and configure your local drive.", card)
        fresh_desc.setWordWrap(True)
        fresh_desc.setStyleSheet("color: #9ca3af; font-size: 11px; margin-bottom: 8px;")
        card_layout.addWidget(fresh_desc)
        
        # Divider
        divider = QFrame(card)
        divider.setFrameShape(QFrame.Shape.HLine)
        divider.setFrameShadow(QFrame.Shadow.Sunken)
        divider.setStyleSheet("background-color: #374151;")
        card_layout.addWidget(divider)
        
        # Option 2: Recover
        recover_btn = StyledButton("Recover / Migrate Existing Vault", card, secondary=True)
        recover_btn.clicked.connect(lambda: self.stack.setCurrentWidget(self.recover_widget))
        card_layout.addWidget(recover_btn)
        
        recover_desc = QLabel("Restore your secure database and OS Keyring credentials from a remote cloud or NAS backup using your 24-word seed phrase.", card)
        recover_desc.setWordWrap(True)
        recover_desc.setStyleSheet("color: #9ca3af; font-size: 11px;")
        card_layout.addWidget(recover_desc)
        
        layout.addWidget(card)
        layout.addStretch()
        
        self.stack.addWidget(self.first_run_chooser_widget)

    # ─── 1. Unlock Screen ──────────────────────────────────────────────────────

    def _setup_unlock_view(self) -> None:
        self.unlock_widget = QWidget(self)
        layout = QVBoxLayout(self.unlock_widget)
        layout.setSpacing(16)

        layout.addStretch()

        card = GlassCard(self.unlock_widget)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(24, 24, 24, 24)
        card_layout.setSpacing(16)

        lbl = QLabel("Enter password to unlock your drive:", card)
        card_layout.addWidget(lbl)

        self.pass_input = PasswordLineEdit("Passphrase", card)
        self.pass_input.returnPressed.connect(self.on_unlock_clicked)
        self.pass_input.textChanged.connect(self.clear_unlock_error)
        card_layout.addWidget(self.pass_input)

        # Inline error label right under the passphrase input box
        self.unlock_error_label = QLabel("", card)
        self.unlock_error_label.setStyleSheet("color: #ef4444; font-size: 11px; font-weight: bold;")
        self.unlock_error_label.setWordWrap(True)
        self.unlock_error_label.setVisible(False)
        card_layout.addWidget(self.unlock_error_label)

        self.unlock_btn = StyledButton("Unlock Secure Drive", card, primary=True)
        self.unlock_btn.clicked.connect(self.on_unlock_clicked)
        card_layout.addWidget(self.unlock_btn)

        layout.addWidget(card)

        # Recovery link
        self.recover_link = StyledButton("Lost password? Recover from 24-word seed", self.unlock_widget, secondary=True)
        self.recover_link.clicked.connect(lambda: self.stack.setCurrentWidget(self.recover_widget))
        layout.addWidget(self.recover_link, alignment=Qt.AlignmentFlag.AlignCenter)

        layout.addStretch()

        self.stack.addWidget(self.unlock_widget)

    def clear_unlock_error(self) -> None:
        self.unlock_error_label.setVisible(False)
        self.unlock_error_label.setText("")

    def on_unlock_clicked(self) -> None:
        self.clear_unlock_error()
        password = self.pass_input.text()
        if not password:
            self.unlock_error_label.setText("Password cannot be empty.")
            self.unlock_error_label.setVisible(True)
            return

        self.unlock_btn.setEnabled(False)
        self.unlock_btn.setText("Deriving keys (Argon2id)...")
        
        # Keep UI responsive during Argon2id key derivation by forcing event processing
        from PyQt6.QtWidgets import QApplication
        QApplication.processEvents()

        try:
            self._km.unlock(password.encode("utf-8"))
            self.pass_input.blockSignals(True)
            self.pass_input.clear()
            self.pass_input.blockSignals(False)
            self.unlock_btn.setText("Unlock Secure Drive")
            self.unlock_btn.setEnabled(True)
            self.unlocked.emit(self._km)
        except AuthenticationError:
            self.unlock_error_label.setText("Incorrect password.")
            self.unlock_error_label.setVisible(True)
            self.pass_input.blockSignals(True)
            self.pass_input.clear()
            self.pass_input.blockSignals(False)
            self.unlock_btn.setText("Unlock Secure Drive")
            self.unlock_btn.setEnabled(True)
        except CryptoError:
            self.unlock_error_label.setText("Corrupted keystore or encryption error.")
            self.unlock_error_label.setVisible(True)
            self.pass_input.blockSignals(True)
            self.pass_input.clear()
            self.pass_input.blockSignals(False)
            self.unlock_btn.setText("Unlock Secure Drive")
            self.unlock_btn.setEnabled(True)

    # ─── 2. First-Run Setup Screen ─────────────────────────────────────────────

    def _setup_create_view(self) -> None:
        self.create_widget = QWidget(self)
        layout = QVBoxLayout(self.create_widget)
        layout.setSpacing(16)

        layout.addStretch()

        self.create_card = GlassCard(self.create_widget)
        card_layout = QVBoxLayout(self.create_card)
        card_layout.setContentsMargins(24, 24, 24, 24)
        card_layout.setSpacing(16)

        # State 1: Choose password
        self.create_lbl = QLabel("Choose a strong passphrase to encrypt your keys:", self.create_card)
        card_layout.addWidget(self.create_lbl)

        self.new_pass_input = PasswordLineEdit("New Passphrase", self.create_card)
        self.new_pass_input.textChanged.connect(self._update_password_strength)
        card_layout.addWidget(self.new_pass_input)

        # Password strength bar description
        self.strength_label = QLabel("Strength: Weak (length < 8)", self.create_card)
        self.strength_label.setObjectName("MutedLabel")
        card_layout.addWidget(self.strength_label)

        self.gen_btn = StyledButton("Generate 24-Word Seed Phrase", self.create_card, primary=True)
        self.gen_btn.clicked.connect(self.on_generate_seed_clicked)
        card_layout.addWidget(self.gen_btn)

        self.back_btn_first_run = StyledButton("Back to Set Up Options", self.create_card, secondary=True)
        self.back_btn_first_run.clicked.connect(self.route_initial_view)
        card_layout.addWidget(self.back_btn_first_run)

        layout.addWidget(self.create_card)

        layout.addStretch()

        self.stack.addWidget(self.create_widget)

    def _update_password_strength(self, text: str) -> None:
        if len(text) < 8:
            self.strength_label.setText("Strength: Weak (length < 8)")
            self.strength_label.setStyleSheet("color: #ef4444;")
        elif any(c.isdigit() for c in text) and any(c.isupper() for c in text) and len(text) >= 12:
            self.strength_label.setText("Strength: Strong")
            self.strength_label.setStyleSheet("color: #10b981;")
        else:
            self.strength_label.setText("Strength: Moderate")
            self.strength_label.setStyleSheet("color: #f59e0b;")

    def on_generate_seed_clicked(self) -> None:
        password = self.new_pass_input.text()
        if len(password) < 8:
            QMessageBox.warning(self, "Security Validation", "Password must be at least 8 characters.")
            return

        try:
            # Generate the mnemonic seed
            self._temp_password = password
            self._mnemonic = self._km.create_new(password.encode("utf-8"))
            
            # Switch to mnemonic display subview
            self._show_mnemonic_display()
        except Exception as exc:
            QMessageBox.critical(self, "Generation Error", f"Failed to initialize keystore: {exc}")

    def _show_mnemonic_display(self) -> None:
        # Create temporary screen for seed viewing
        display_widget = QWidget(self)
        layout = QVBoxLayout(display_widget)
        layout.setSpacing(16)

        layout.addStretch()

        card = GlassCard(display_widget)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(24, 24, 24, 24)
        card_layout.setSpacing(16)

        title = QLabel("Write Down Your 24-Word Seed Phrase", card)
        title.setObjectName("SubHeading")
        card_layout.addWidget(title)

        desc = QLabel(
            "This phrase is the ONLY way to recover your drive. "
            "Write it down on paper and store it securely. Never share it.",
            card
        )
        desc.setWordWrap(True)
        card_layout.addWidget(desc)

        seed_box = QTextEdit(card)
        seed_box.setText(self._mnemonic)
        seed_box.setReadOnly(True)
        seed_box.setStyleSheet("font-family: monospace; font-size: 14px;")
        card_layout.addWidget(seed_box)

        next_btn = StyledButton("I Have Written It Down", card, primary=True)
        next_btn.clicked.connect(lambda: self._show_mnemonic_verify(display_widget))
        card_layout.addWidget(next_btn)

        layout.addWidget(card)

        layout.addStretch()

        self.stack.addWidget(display_widget)
        self.stack.setCurrentWidget(display_widget)

    def _show_mnemonic_verify(self, display_widget) -> None:
        # Create temporary screen for verification
        verify_widget = QWidget(self)
        layout = QVBoxLayout(verify_widget)
        layout.setSpacing(16)

        layout.addStretch()

        card = GlassCard(verify_widget)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(24, 24, 24, 24)
        card_layout.setSpacing(16)

        title = QLabel("Verify Your Seed Phrase", card)
        title.setObjectName("SubHeading")
        card_layout.addWidget(title)

        desc = QLabel("Enter your 24-word seed phrase exactly to confirm backup:", card)
        desc.setWordWrap(True)
        card_layout.addWidget(desc)

        self.verify_input = QTextEdit(card)
        self.verify_input.setPlaceholderText("Enter all 24 words separated by spaces...")
        self.verify_input.setStyleSheet("font-family: monospace; font-size: 12px;")
        card_layout.addWidget(self.verify_input)

        confirm_btn = StyledButton("Confirm and Write Keystore", card, primary=True)
        confirm_btn.clicked.connect(lambda: self.on_verify_confirm_clicked(verify_widget, display_widget))
        card_layout.addWidget(confirm_btn)

        layout.addWidget(card)

        layout.addStretch()

        self.stack.addWidget(verify_widget)
        self.stack.setCurrentWidget(verify_widget)

    def on_verify_confirm_clicked(self, verify_widget, display_widget) -> None:
        entered_seed = self.verify_input.toPlainText().strip().lower()
        if not entered_seed:
            QMessageBox.warning(self, "Verification", "Please enter the seed phrase.")
            return

        try:
            # Match checking and save
            self._km.verify_and_save(entered_seed)
            QMessageBox.information(self, "Keystore Created", "Keystore has been initialized and saved successfully.")
            
            # Clean up widgets
            self.stack.removeWidget(verify_widget)
            self.stack.removeWidget(display_widget)
            
            # Emit unlocked signal
            self.unlocked.emit(self._km)
        except SeedPhraseError as exc:
            QMessageBox.critical(self, "Verification Failed", f"The seed phrase entered does not match: {exc}")
        except Exception as exc:
            QMessageBox.critical(self, "Error Saving", f"Failed to save keystore: {exc}")

    # ─── 3. Mnemonic Recovery Screen ──────────────────────────────────────────

    def _setup_recover_view(self) -> None:
        self.recover_widget = QWidget(self)
        layout = QVBoxLayout(self.recover_widget)
        layout.setSpacing(16)

        layout.addStretch()

        card = GlassCard(self.recover_widget)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(24, 24, 24, 24)
        card_layout.setSpacing(16)

        lbl = QLabel("Enter your 24-word seed phrase to restore access:", card)
        card_layout.addWidget(lbl)

        self.recover_seed_input = QTextEdit(card)
        self.recover_seed_input.setPlaceholderText("word1 word2 ... word24")
        self.recover_seed_input.setStyleSheet("font-family: monospace;")
        card_layout.addWidget(self.recover_seed_input)

        lbl2 = QLabel("Choose a new passphrase for the restored keystore:", card)
        card_layout.addWidget(lbl2)

        self.recover_pass_input = PasswordLineEdit("New Passphrase", card)
        card_layout.addWidget(self.recover_pass_input)

        self.recover_btn = StyledButton("Recover Keystore", card, primary=True)
        self.recover_btn.clicked.connect(self.on_recover_clicked)
        card_layout.addWidget(self.recover_btn)

        layout.addWidget(card)

        # Cancel button
        cancel_btn = StyledButton("Cancel and Return", self.recover_widget, secondary=True)
        cancel_btn.clicked.connect(self.route_initial_view)
        layout.addWidget(cancel_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        layout.addStretch()

        self.stack.addWidget(self.recover_widget)

    def on_recover_clicked(self) -> None:
        seed = self.recover_seed_input.toPlainText().strip().lower()
        password = self.recover_pass_input.text()

        if not seed or not password:
            QMessageBox.warning(self, "Validation Error", "All fields are required.")
            return

        if len(password) < 8:
            QMessageBox.warning(self, "Security Validation", "Password must be at least 8 characters.")
            return

        self.recover_btn.setEnabled(False)
        self.recover_btn.setText("Restoring and deriving keys...")
        
        from PyQt6.QtWidgets import QApplication
        QApplication.processEvents()

        try:
            # Recover keystore from seed (writes keystore.json and unlocks manager)
            self._km.recover_from_seed(seed, password.encode("utf-8"))
            
            # Transition to Step 2: Bootstrap Backend Connection
            self.recover_seed_input.clear()
            self.recover_pass_input.clear()
            self.recover_btn.setText("Recover Keystore")
            self.recover_btn.setEnabled(True)
            
            # Show Step 2
            self.stack.setCurrentWidget(self.recover_bootstrap_widget)
            
        except SeedPhraseError as exc:
            QMessageBox.critical(self, "Recovery Failed", f"Invalid seed phrase: {exc}")
            self.recover_btn.setText("Recover Keystore")
            self.recover_btn.setEnabled(True)
        except Exception as exc:
            QMessageBox.critical(self, "Recovery Failed", f"An error occurred during recovery: {exc}")
            self.recover_btn.setText("Recover Keystore")
            self.recover_btn.setEnabled(True)

    def _setup_recover_bootstrap_view(self) -> None:
        from ghostdrive.gui.widgets import StyledComboBox, StyledLineEdit
        
        self.recover_bootstrap_widget = QWidget(self)
        layout = QVBoxLayout(self.recover_bootstrap_widget)
        layout.setSpacing(16)
        
        layout.addStretch()
        
        card = GlassCard(self.recover_bootstrap_widget)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(24, 24, 24, 24)
        card_layout.setSpacing(16)
        
        title = QLabel("Step 2: Connect to a Bootstrap Backend", card)
        title.setObjectName("SubHeading")
        card_layout.addWidget(title)
        
        desc = QLabel(
            "Select the remote backend where your encrypted backup is stored. "
            "GhostDrive will connect, download your index and keys, and restore your vault.",
            card
        )
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #9ca3af; font-size: 12px;")
        card_layout.addWidget(desc)
        
        card_layout.addWidget(QLabel("Bootstrap Protocol:", card))
        self.rec_backend_combo = StyledComboBox(card)
        self.rec_backend_combo.addItems(["Telegram", "SFTP NAS"])
        card_layout.addWidget(self.rec_backend_combo)
        
        # Stacked widget for the dynamic protocol forms
        self.rec_form_stack = QStackedWidget(card)
        
        # 1. Telegram Form
        tg_widget = QWidget(self.rec_form_stack)
        tg_layout = QVBoxLayout(tg_widget)
        tg_layout.setContentsMargins(0, 0, 0, 0)
        tg_layout.setSpacing(12)
        
        self.rec_tg_api_id = StyledLineEdit("API ID (from my.telegram.org)", tg_widget)
        self.rec_tg_api_hash = StyledLineEdit("API Hash", tg_widget)
        self.rec_tg_phone = StyledLineEdit("Phone Number (with country code, e.g. +1234567890)", tg_widget)
        
        tg_layout.addWidget(QLabel("Telegram API Credentials:", tg_widget))
        tg_layout.addWidget(self.rec_tg_api_id)
        tg_layout.addWidget(self.rec_tg_api_hash)
        tg_layout.addWidget(self.rec_tg_phone)
        
        self.rec_form_stack.addWidget(tg_widget)
        
        # 2. SFTP NAS Form
        nas_widget = QWidget(self.rec_form_stack)
        nas_layout = QVBoxLayout(nas_widget)
        nas_layout.setContentsMargins(0, 0, 0, 0)
        nas_layout.setSpacing(12)
        
        self.rec_nas_host = StyledLineEdit("Host (e.g. 192.168.1.100)", nas_widget)
        self.rec_nas_username = StyledLineEdit("Username", nas_widget)
        self.rec_nas_password = PasswordLineEdit("Password / Key Passphrase", nas_widget)
        self.rec_nas_dir = StyledLineEdit("Remote Directory (e.g. GhostDriveData)", nas_widget)
        self.rec_nas_dir.setText("GhostDriveData")
        
        nas_layout.addWidget(QLabel("SFTP NAS Credentials:", nas_widget))
        nas_layout.addWidget(self.rec_nas_host)
        nas_layout.addWidget(self.rec_nas_username)
        nas_layout.addWidget(self.rec_nas_password)
        nas_layout.addWidget(self.rec_nas_dir)
        
        self.rec_form_stack.addWidget(nas_widget)
        
        card_layout.addWidget(self.rec_form_stack)
        
        self.rec_backend_combo.currentIndexChanged.connect(self._on_rec_proto_changed)
        
        # Connect button
        self.rec_connect_btn = StyledButton("Connect & Restore", card, primary=True)
        self.rec_connect_btn.clicked.connect(self.on_rec_connect_clicked)
        card_layout.addWidget(self.rec_connect_btn)
        
        layout.addWidget(card)
        
        # Cancel link
        cancel_btn = StyledButton("Cancel and Return", self.recover_bootstrap_widget, secondary=True)
        cancel_btn.clicked.connect(lambda: self.stack.setCurrentWidget(self.unlock_widget))
        layout.addWidget(cancel_btn, alignment=Qt.AlignmentFlag.AlignCenter)
        
        layout.addStretch()
        
        self.stack.addWidget(self.recover_bootstrap_widget)
        
    def _on_rec_proto_changed(self, index: int) -> None:
        self.rec_form_stack.setCurrentIndex(index)

    def _setup_recover_progress_view(self) -> None:
        from PyQt6.QtWidgets import QProgressBar
        self.recover_progress_widget = QWidget(self)
        layout = QVBoxLayout(self.recover_progress_widget)
        layout.setSpacing(16)
        
        layout.addStretch()
        
        card = GlassCard(self.recover_progress_widget)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(24, 24, 24, 24)
        card_layout.setSpacing(20)
        
        title = QLabel("Step 3: Restoring Your Secure Vault", card)
        title.setObjectName("SubHeading")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card_layout.addWidget(title)
        
        self.rec_progress_bar = QProgressBar(card)
        self.rec_progress_bar.setRange(0, 100)
        self.rec_progress_bar.setValue(0)
        self.rec_progress_bar.setTextVisible(True)
        self.rec_progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #374151;
                border-radius: 6px;
                text-align: center;
                background-color: #1f2937;
                color: #ffffff;
                font-weight: bold;
            }
            QProgressBar::chunk {
                background-color: #8b5cf6;
                border-radius: 5px;
            }
        """)
        card_layout.addWidget(self.rec_progress_bar)
        
        self.rec_status_label = QLabel("Initializing recovery channel...", card)
        self.rec_status_label.setWordWrap(True)
        self.rec_status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.rec_status_label.setStyleSheet("color: #9ca3af; font-size: 13px;")
        card_layout.addWidget(self.rec_status_label)
        
        layout.addWidget(card)
        layout.addStretch()
        
        self.stack.addWidget(self.recover_progress_widget)

    def _setup_recover_complete_view(self) -> None:
        self.recover_complete_widget = QWidget(self)
        layout = QVBoxLayout(self.recover_complete_widget)
        layout.setSpacing(16)
        
        layout.addStretch()
        
        card = GlassCard(self.recover_complete_widget)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(24, 24, 24, 24)
        card_layout.setSpacing(16)
        
        title = QLabel("Step 4: Recovery Successful!", card)
        title.setObjectName("SubHeading")
        card_layout.addWidget(title)
        
        desc = QLabel(
            "Your secure vault metadata and cryptographic credentials have been completely restored "
            "from the remote backend.",
            card
        )
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #10b981; font-size: 13px; font-weight: bold;")
        card_layout.addWidget(desc)
        
        self.rec_metrics_label = QLabel(card)
        self.rec_metrics_label.setWordWrap(True)
        self.rec_metrics_label.setStyleSheet("color: #e5e7eb; font-size: 12px; font-family: monospace;")
        card_layout.addWidget(self.rec_metrics_label)
        
        self.rec_local_warning_label = QLabel(card)
        self.rec_local_warning_label.setWordWrap(True)
        self.rec_local_warning_label.setStyleSheet("color: #f59e0b; font-size: 12px; font-weight: bold;")
        self.rec_local_warning_label.setVisible(False)
        card_layout.addWidget(self.rec_local_warning_label)
        
        self.rec_launch_btn = StyledButton("Launch GhostDrive", card, primary=True)
        self.rec_launch_btn.clicked.connect(self.on_recovery_launch_clicked)
        card_layout.addWidget(self.rec_launch_btn)
        
        layout.addWidget(card)
        layout.addStretch()
        
        self.stack.addWidget(self.recover_complete_widget)

    @qasync.asyncSlot()
    async def on_rec_connect_clicked(self) -> None:
        logger.debug("on_rec_connect_clicked start")
        self.rec_connect_btn.setEnabled(False)
        self.stack.setCurrentWidget(self.recover_progress_widget)
        self.rec_progress_bar.setValue(10)
        self.rec_status_label.setText("Reading keys and deriving credentials...")
        
        from PyQt6.QtWidgets import QApplication
        QApplication.processEvents()
        
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from ghostdrive.crypto.hkdf import (
            derive_index_backup_name,
            derive_credentials_backup_name,
            derive_index_backup_enc_key,
            derive_backend_credentials_key
        )
        
        try:
            # 1. Obtain master key and salt from unlocked KeystoreManager
            master_key = self._km.master_key
            salt = self._km.hkdf_salt
            
            # 2. Derive backup names and encryption keys
            index_backup_name_hex = derive_index_backup_name(master_key, salt).hex()
            credentials_backup_name_hex = derive_credentials_backup_name(master_key, salt).hex()
            
            index_enc_key = derive_index_backup_enc_key(master_key, salt)
            creds_enc_key = derive_backend_credentials_key(master_key, salt)
            
            protocol = self.rec_backend_combo.currentText()
            backend_obj = None
            
            self.rec_progress_bar.setValue(25)
            self.rec_status_label.setText(f"Establishing connection to {protocol}...")
            QApplication.processEvents()
            
            # 3. Instantiate and connect backend
            if protocol == "Telegram":
                api_id_str = self.rec_tg_api_id.text().strip()
                api_hash = self.rec_tg_api_hash.text().strip()
                phone = self.rec_tg_phone.text().strip()
                
                if not api_id_str or not api_hash or not phone:
                    raise ValueError("All Telegram fields are required.")
                if not api_id_str.isdigit():
                    raise ValueError("Telegram API ID must be a number.")
                
                api_id = int(api_id_str)
                
                from ghostdrive.backends.telegram_backend import TelegramBackend
                from ghostdrive.gui.backend_settings import TelegramOtpDialog, TelegramPasswordDialog
                from PyQt6.QtWidgets import QDialog
                
                backend_obj = TelegramBackend(
                    api_id=api_id,
                    api_hash=api_hash,
                    phone=phone,
                    _skip_keyring=True
                )
                backend_obj.type = "telegram"
                
                def code_cb() -> str:
                    dialog = TelegramOtpDialog(self)
                    if dialog.exec() == QDialog.DialogCode.Accepted:
                        return dialog.get_code()
                    raise Exception("Telegram OTP verification cancelled.")
                    
                def password_cb() -> str:
                    dialog = TelegramPasswordDialog(self)
                    if dialog.exec() == QDialog.DialogCode.Accepted:
                        return dialog.get_password()
                    raise Exception("Telegram 2FA password verification cancelled.")
                
                # Run Telegram authentication
                await backend_obj.first_run_authenticate(
                    phone=phone,
                    code_callback=code_cb,
                    password_callback=password_cb
                )
                await backend_obj.connect()
                backend_obj._connected = True
                
            elif protocol == "SFTP NAS":
                host = self.rec_nas_host.text().strip()
                username = self.rec_nas_username.text().strip()
                password = self.rec_nas_password.text().strip()
                remote_dir = self.rec_nas_dir.text().strip()
                
                if not host or not username or not password:
                    raise ValueError("Host, Username, and Password are required for SFTP NAS.")
                
                from ghostdrive.backends.nas_backend import NASBackend
                backend_obj = NASBackend(
                    protocol="sftp",
                    host=host,
                    username=username,
                    password=password,
                    remote_dir=remote_dir
                )
                backend_obj.type = "nas"
                
                logger.debug("Connecting to SFTP NAS...")
                await backend_obj.connect()
                backend_obj._connected = True
                logger.debug("SFTP NAS connected")
                
            else:
                raise ValueError(f"Unsupported recovery protocol: {protocol}")
                
            self.rec_progress_bar.setValue(50)
            self.rec_status_label.setText("Searching for encrypted backup snapshots...")
            QApplication.processEvents()
            
            # 4. Download backup snapshot and credentials bundle
            snapshot_data = bytearray()
            credentials_data = bytearray()
            
            if backend_obj.type == "telegram":
                # Find DB snapshot
                messages = await backend_obj._client.get_messages("me", search="sub-block 9999")
                target_msg = None
                prefix_8 = index_backup_name_hex[:8]
                for m in messages:
                    if m.message and f"GhostDrive {prefix_8}" in m.message:
                        target_msg = m
                        break
                if not target_msg:
                    raise FileNotFoundError("Encrypted database snapshot not found on Telegram.")
                    
                async for block in backend_obj.download(str(target_msg.id)):
                    snapshot_data.extend(block)
                    
                # Find Credentials bundle
                messages_creds = await backend_obj._client.get_messages("me", search="sub-block 9998")
                target_msg_creds = None
                creds_prefix_8 = credentials_backup_name_hex[:8]
                for m in messages_creds:
                    if m.message and f"GhostDrive {creds_prefix_8}" in m.message:
                        target_msg_creds = m
                        break
                if not target_msg_creds:
                    raise FileNotFoundError("Encrypted credentials bundle not found on Telegram.")
                    
                async for block in backend_obj.download(str(target_msg_creds.id)):
                    credentials_data.extend(block)
                    
            elif backend_obj.type == "nas":
                ref_db = f"sftp:{backend_obj.remote_dir}/{index_backup_name_hex}_9999.gdc"
                ref_creds = f"sftp:{backend_obj.remote_dir}/{credentials_backup_name_hex}_9998.gdc"
                
                try:
                    async for block in backend_obj.download(ref_db):
                        snapshot_data.extend(block)
                except Exception as e:
                    raise FileNotFoundError(f"Encrypted database snapshot not found on SFTP: {e}")
                    
                try:
                    async for block in backend_obj.download(ref_creds):
                        credentials_data.extend(block)
                except Exception as e:
                    raise FileNotFoundError(f"Encrypted credentials bundle not found on SFTP: {e}")
            
            self.rec_progress_bar.setValue(75)
            self.rec_status_label.setText("Decrypting and reconstructing vault...")
            QApplication.processEvents()
            logger.debug("Starting decryption...")
            
            # 5. Decrypt database snapshot
            aesgcm_db = AESGCM(index_enc_key)
            nonce_db = bytes(snapshot_data[:12])
            ciphertext_db = bytes(snapshot_data[12:])
            decrypted_db_bytes = aesgcm_db.decrypt(nonce_db, ciphertext_db, None)
            
            # 6. Decrypt credentials bundle
            aesgcm_creds = AESGCM(creds_enc_key)
            nonce_creds = bytes(credentials_data[:12])
            ciphertext_creds = bytes(credentials_data[12:])
            decrypted_creds_bytes = aesgcm_creds.decrypt(nonce_creds, ciphertext_creds, None)
            creds = json.loads(decrypted_creds_bytes.decode("utf-8"))
            
            # Write database snapshot to ghostdrive.db in the same directory as the keystore file.
            # This ensures it resolves to the correct absolute app-data directory in production,
            # while remaining fully testable in temporary directories during test runs.
            db_path = self._keystore_path.parent / "ghostdrive.db"
            for suffix in ["", "-wal", "-journal", "-shm"]:
                p = db_path.with_suffix(db_path.suffix + suffix)
                if p.exists():
                    try:
                        p.unlink()
                    except Exception:
                        pass
                        
            with open(db_path, "wb") as f:
                f.write(decrypted_db_bytes)
                
            # 8. Store credentials to OS Keyring
            from ghostdrive.crypto.credential_store import credential_store
            credential_store.set_active_key(master_key, salt)
            
            # Save all credentials from the bundle
            for k, val in creds.items():
                credential_store.store(k, val)
                
            # Also save the bootstrap credentials so the recovered backend remains connected!
            if protocol == "Telegram":
                credential_store.store("telegram_api_id", str(api_id))
                credential_store.store("telegram_api_hash", api_hash)
                credential_store.store("telegram_phone", phone)
                # Save the session string that was authenticated
                if hasattr(backend_obj, "_session_str") and backend_obj._session_str:
                    credential_store.store("telegram_session", backend_obj._session_str)
            elif protocol == "SFTP NAS":
                # For NAS we save the credentials under its ref
                credential_ref = "keyring:encrypted:nas_creds"
                credential_store.store(credential_ref, password)
            
            # 9. Query restored DB for metrics and check local backends
            from ghostdrive.database.db import GhostDriveDB
            from ghostdrive.crypto.hkdf import derive_index_mac_key
            
            ledger_key = derive_index_mac_key(master_key, salt)
            genesis_seed = self._km.genesis_seed
            
            temp_db = GhostDriveDB(
                db_path,
                bytes(bytearray(ledger_key)),
                bytes(bytearray(genesis_seed)),
                bytes(bytearray(master_key))
            )
            temp_db.open()
            
            # Count restored files
            files_row = temp_db._conn.execute("SELECT COUNT(*) FROM files WHERE tombstone = 0").fetchone()
            files_count = files_row[0] if files_row else 0
            
            # Count secrets in vault
            secrets_row = temp_db._conn.execute("SELECT COUNT(*) FROM secrets_vault").fetchone()
            secrets_count = secrets_row[0] if secrets_row else 0
            
            # Check for offline/local backends
            local_rows = temp_db._conn.execute(
                "SELECT id, type FROM backends WHERE type IN ('local_fs', 'external_drive')"
            ).fetchall()
            
            # Bootstrapped logical clock tip
            clock_row = temp_db._conn.execute("SELECT logical_clock FROM hmac_ledger WHERE id = 1").fetchone()
            logical_clock = clock_row["logical_clock"] if clock_row else 0
            
            temp_db.close()
            
            # Format metrics message
            metrics_txt = (
                f"Logical Clock: {logical_clock}\n"
                f"Restored Files: {files_count}\n"
                f"Secrets Vault Entries: {secrets_count}\n"
                f"Cryptographic Credentials: {len(creds)} restored to OS Keyring."
            )
            self.rec_metrics_label.setText(metrics_txt)
            
            # Show local backends warning if any
            if local_rows:
                local_names = [f"'{r['type']}' ({r['id']})" for r in local_rows]
                warning_txt = (
                    "⚠️ WARNING: The following offline or local backends were detected in your database:\n"
                    f"{', '.join(local_names)}\n\n"
                    "Please go to Settings > Backends to re-associate their local folders or USB mount paths."
                )
                self.rec_local_warning_label.setText(warning_txt)
                self.rec_local_warning_label.setVisible(True)
            else:
                self.rec_local_warning_label.setVisible(False)
                
            self.rec_progress_bar.setValue(100)
            self.rec_status_label.setText("Decryption and recovery completed successfully.")
            QApplication.processEvents()
            
            # Go to step 4
            self.stack.setCurrentWidget(self.recover_complete_widget)
            logger.info("Recovery completed successfully")
            
        except Exception as e:
            logger.error("Disaster recovery connection/bootstrap failed: %s", e)
            QMessageBox.critical(
                self,
                "Recovery Error",
                f"Failed to restore secure vault:\n{e}\n\n"
                "Please check your credentials and network connection and try again."
            )
            self.stack.setCurrentWidget(self.recover_bootstrap_widget)
            self.rec_connect_btn.setEnabled(True)

    def on_recovery_launch_clicked(self) -> None:
        self.unlocked.emit(self._km)

