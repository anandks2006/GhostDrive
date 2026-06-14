"""
dialogs.py -- Dialog components for the GhostDrive GUI (About, Conflict, Inspector).
"""

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QButtonGroup,
    QRadioButton,
    QScrollArea,
    QWidget,
)
from ghostdrive.gui.widgets import StyledButton, GlassCard
from ghostdrive.gui.styles import ResilientDialog

class AboutDialog(ResilientDialog):
    """Presents application version, licensing, and keyboard shortcut list."""
    def __init__(self, parent=None) -> None:
        super().__init__(parent, base_width=450, base_height=320)
        self.setWindowTitle("About GhostDrive")
        self.setModal(True)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)
        
        title = QLabel("🛡️ GhostDrive Personal Cloud", self)
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #8b5cf6;")
        layout.addWidget(title)
        
        version = QLabel("Version: 0.1.0-alpha\nLicense: AGPL-3.0", self)
        version.setStyleSheet("color: #d1d5db; line-height: 1.4;")
        layout.addWidget(version)
        
        shortcuts_lbl = QLabel("<b>Keyboard Shortcuts Cheat-sheet:</b>", self)
        shortcuts_lbl.setStyleSheet("color: #f3f4f6; margin-top: 8px;")
        layout.addWidget(shortcuts_lbl)
        
        shortcuts_card = GlassCard(self)
        card_layout = QVBoxLayout(shortcuts_card)
        card_layout.setContentsMargins(10, 10, 10, 10)
        
        shortcuts_text = (
            "• <b>Delete</b>: Soft-delete selected files (or purge in Trash)\n"
            "• <b>F5</b>: Refresh file list ledger & backend status\n"
            "• <b>Ctrl + U</b>: Launch manual file ingestion prompt\n"
            "• <b>Ctrl + L</b>: Lock keystore and log out instantly"
        )
        shortcuts_desc = QLabel(shortcuts_text, shortcuts_card)
        shortcuts_desc.setStyleSheet("color: #9ca3af; font-size: 11px;")
        card_layout.addWidget(shortcuts_desc)
        layout.addWidget(shortcuts_card)
        
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        close_btn = StyledButton("Close", self, secondary=True)
        close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)


class DuplicateConflictDialog(ResilientDialog):
    """Prompts user when importing a file that already exists in the registry."""
    def __init__(self, file_name: str, parent=None) -> None:
        super().__init__(parent, base_width=420, base_height=240)
        self.setWindowTitle("File Conflict Detected")
        self.setModal(True)
        
        self.selected_action = "cancel"  # Default fallback action
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)
        
        title = QLabel("⚠️ Duplicate File Name", self)
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: #f59e0b;")
        layout.addWidget(title)
        
        desc = QLabel(f"A file named '{file_name}' already exists in your drive ledger. What would you like to do?", self)
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #d1d5db;")
        layout.addWidget(desc)
        
        # Radio buttons button group
        self.button_group = QButtonGroup(self)
        
        self.radio_overwrite = QRadioButton("Overwrite existing file record", self)
        self.radio_overwrite.setChecked(True)
        self.button_group.addButton(self.radio_overwrite, 0)
        layout.addWidget(self.radio_overwrite)
        
        self.radio_rename = QRadioButton("Keep both (auto-rename imported file)", self)
        self.button_group.addButton(self.radio_rename, 1)
        layout.addWidget(self.radio_rename)
        
        self.radio_cancel = QRadioButton("Cancel upload", self)
        self.button_group.addButton(self.radio_cancel, 2)
        layout.addWidget(self.radio_cancel)
        
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        
        ok_btn = StyledButton("Apply", self, primary=True)
        ok_btn.clicked.connect(self._on_ok_clicked)
        cancel_btn = StyledButton("Cancel", self, secondary=True)
        cancel_btn.clicked.connect(self.reject)
        
        btn_layout.addWidget(cancel_btn)
        btn_layout.addWidget(ok_btn)
        layout.addLayout(btn_layout)

    def _on_ok_clicked(self) -> None:
        if self.radio_overwrite.isChecked():
            self.selected_action = "overwrite"
        elif self.radio_rename.isChecked():
            self.selected_action = "rename"
        else:
            self.selected_action = "cancel"
        self.accept()


class FileInspectorDialog(ResilientDialog):
    """Presents detailed cryptographic, metadata, and backend mapping info for a file."""
    def __init__(self, file_row: dict, db, parent=None) -> None:
        super().__init__(parent, base_width=520, base_height=420)
        self.setWindowTitle("Cryptographic File Properties")
        self.setModal(True)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)
        
        title = QLabel(f"📄 Properties: {file_row['name']}", self)
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: #8b5cf6;")
        layout.addWidget(title)
        
        # Scroll area for long metadata text
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("background-color: transparent; border: none;")
        
        scroll_content = QWidget(scroll)
        scroll_content.setObjectName("ScrollContent")
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setContentsMargins(0, 0, 0, 0)
        scroll_layout.setSpacing(10)
        
        # Fetch chunk locations mapping details from DB
        locations = []
        if db:
            try:
                with db.transaction():
                    locations = db._conn.execute(
                        """SELECT cl.backend_id, cl.status, cl.reference_id, b.type, cl.sub_block_index, c.chunk_index
                           FROM chunk_locations cl
                           JOIN backends b ON cl.backend_id = b.id
                           JOIN chunks c ON cl.chunk_id = c.id
                           WHERE c.file_id = ?
                           ORDER BY c.chunk_index ASC, cl.sub_block_index ASC""",
                        (file_row["id"],)
                    ).fetchall()
            except Exception as exc:
                print(f"[Inspector Error] Failed to fetch chunk locations: {exc}")
        
        loc_lines = []
        for loc in locations:
            ref = loc["reference_id"]
            ref_short = ref[:12] + "..." if len(ref) > 12 else ref
            loc_lines.append(
                f"• Chunk {loc['chunk_index']} (Sub-block {loc['sub_block_index']}):\n"
                f"  Backend: {loc['type'].upper()} ({loc['status']})\n"
                f"  Reference ID: {ref_short or 'N/A'}"
            )
        loc_str = "\n".join(loc_lines)
        
        metadata_text = (
            f"<b>Database UUID:</b> {file_row['id']}\n"
            f"<b>Ledger Name:</b> {file_row['name']}\n"
            f"<b>Virtual Path:</b> {file_row['path']}\n"
            f"<b>Physical Size:</b> {file_row['size']} bytes\n"
            f"<b>Redundancy Tier:</b> {file_row['tier']}\n"
            f"<b>Revision Version:</b> v{file_row.get('version', 1)}\n"
            f"<b>Created Date:</b> {file_row['created_at']}\n"
            f"<b>Modified Date:</b> {file_row['modified_at']}\n"
            f"<b>Logical Clock:</b> {file_row.get('logical_clock', 0)}\n"
            f"<b>Encryption Algorithm:</b> ChaCha20-Poly1305 (AEAD)\n"
            f"<b>Key Derivation Protocol:</b> HKDF-SHA512 + Argon2id\n"
            f"<b>Integrity Verification Tip:</b> HMAC-SHA512 Tip Chain\n\n"
            f"<b>Replicated Backend Mirrors:</b>\n"
            f"{loc_str if loc_str else 'No backend locations registered yet.'}"
        )
        
        meta_label = QLabel(metadata_text, scroll_content)
        meta_label.setWordWrap(True)
        meta_label.setStyleSheet("color: #d1d5db; line-height: 1.4; font-size: 11px;")
        scroll_layout.addWidget(meta_label)
        
        scroll.setWidget(scroll_content)
        layout.addWidget(scroll)
        
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        close_btn = StyledButton("Close", self, secondary=True)
        close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)
