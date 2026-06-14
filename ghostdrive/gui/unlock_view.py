"""
unlock_view.py -- Keystore unlock and first-run wizard views.
"""

from pathlib import Path
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QStackedWidget,
    QTextEdit,
    QMessageBox,
    QLineEdit,
)

from ghostdrive.gui.widgets import StyledButton, StyledLineEdit, PasswordLineEdit, GlassCard
from ghostdrive.crypto.keystore import KeystoreManager
from ghostdrive.exceptions import KeystoreError, SeedPhraseError, CryptoError, AuthenticationError
from ghostdrive.gui.styles import ResizingResilientMixin

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
        self._setup_unlock_view()
        self._setup_create_view()
        self._setup_recover_view()

        # Route to correct initial view
        self.route_initial_view()

        # Initialize resizing resiliency framework
        self.init_resizing_resiliency(500, 480)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self.handle_resize_event()

    def route_initial_view(self) -> None:
        """Decide whether to show the unlock view or first-run setup wizard."""
        if self._keystore_path.exists():
            self.stack.setCurrentWidget(self.unlock_widget)
        else:
            self.stack.setCurrentWidget(self.create_widget)

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
        except CryptoError as exc:
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
        seed_box.setStyleSheet("font-family: monospace; font-size: 14px; background-color: #24242a;")
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
        cancel_btn.clicked.connect(lambda: self.stack.setCurrentWidget(self.unlock_widget))
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
            # Recover keystore from seed
            self._km.recover_from_seed(seed, password.encode("utf-8"))
            QMessageBox.information(self, "Recovery Successful", "Keystore recovered successfully. Logging in...")
            self.recover_seed_input.clear()
            self.recover_pass_input.clear()
            
            self.recover_btn.setText("Recover Keystore")
            self.recover_btn.setEnabled(True)
            self.stack.setCurrentWidget(self.unlock_widget)
            
            # Emit unlocked signal
            self.unlocked.emit(self._km)
        except SeedPhraseError as exc:
            QMessageBox.critical(self, "Recovery Failed", f"Invalid seed phrase: {exc}")
            self.recover_btn.setText("Recover Keystore")
            self.recover_btn.setEnabled(True)
        except Exception as exc:
            QMessageBox.critical(self, "Recovery Failed", f"An error occurred during recovery: {exc}")
            self.recover_btn.setText("Recover Keystore")
            self.recover_btn.setEnabled(True)
