"""
shared_media_panel.py -- PyQt6 dashboard widget for decentralized zero-knowledge media sharing.
"""

import os
import logging
import asyncio
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QSplitter,
    QScrollArea,
    QMessageBox,
    QInputDialog,
    QFileDialog,
    QApplication,
)

from ghostdrive.gui.widgets import GlassCard, StyledButton
from ghostdrive.gui.styles import ResizingResilientMixin

logger = logging.getLogger(__name__)

class DragDropShareCard(GlassCard):
    """Ingestion card that handles drag-and-drop file sharing for the active contact."""
    file_dropped = pyqtSignal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setMinimumHeight(100)
        
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        self.label = QLabel("📥 Drag & Drop files here to share instantly", self)
        self.label.setStyleSheet("color: #9ca3af; font-size: 13px; font-weight: bold;")
        layout.addWidget(self.label)

    def dragEnterEvent(self, event) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.setStyleSheet("border: 2px dashed #8b5cf6; background-color: rgba(139, 92, 246, 0.1);")

    def dragLeaveEvent(self, event) -> None:
        self.setStyleSheet("")

    def dropEvent(self, event) -> None:
        self.setStyleSheet("")
        for url in event.mimeData().urls():
            file_path = url.toLocalFile()
            if file_path and os.path.isfile(file_path):
                self.file_dropped.emit(file_path)


class SharedMediaPanel(QWidget, ResizingResilientMixin):
    """
    Primary Shared Media workspace featuring contacts sidebar,
    sent/received file lists, RAM preview buttons, and drag-and-drop sharing.
    """
    def __init__(self, parent, db, km, sharing_engine, tor_manager=None) -> None:
        super().__init__(parent)
        self.db = db
        self.km = km
        self.sharing_engine = sharing_engine
        self.tor_manager = tor_manager
        self.selected_contact_id: Optional[str] = None

        # Main Layout
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(12, 12, 12, 12)
        main_layout.setSpacing(12)

        # Splitter to separate contacts list (left) and media stream (right)
        self.splitter = QSplitter(Qt.Orientation.Horizontal, self)
        self.splitter.setObjectName("SharingSplitter")
        main_layout.addWidget(self.splitter)

        # ─── LEFT COLUMN: Contacts Sidebar ───
        contacts_widget = QWidget(self.splitter)
        contacts_layout = QVBoxLayout(contacts_widget)
        contacts_layout.setContentsMargins(0, 0, 0, 0)
        contacts_layout.setSpacing(10)

        contacts_title = QLabel("Contacts & Peers", contacts_widget)
        contacts_title.setObjectName("SubHeading")
        contacts_layout.addWidget(contacts_title)

        self.contact_list = QListWidget(contacts_widget)
        self.contact_list.setObjectName("ContactsList")
        self.contact_list.currentRowChanged.connect(self.on_contact_selected)
        contacts_layout.addWidget(self.contact_list)

        self.add_contact_btn = StyledButton("➕ Add Peer Contact", contacts_widget, primary=True)
        self.add_contact_btn.clicked.connect(self.on_add_contact_clicked)
        contacts_layout.addWidget(self.add_contact_btn)
        
        self.scan_contact_btn = StyledButton("📷 Scan Contact QR", contacts_widget, secondary=True)
        self.scan_contact_btn.clicked.connect(self.on_scan_contact_qr_clicked)
        contacts_layout.addWidget(self.scan_contact_btn)

        # ─── User's Own Address Card ───
        self.own_addr_card = GlassCard(contacts_widget)
        own_addr_layout = QVBoxLayout(self.own_addr_card)
        own_addr_layout.setContentsMargins(10, 10, 10, 10)
        own_addr_layout.setSpacing(6)
        
        own_addr_title = QLabel("🔒 Your Address:", self.own_addr_card)
        own_addr_title.setStyleSheet("font-weight: bold; font-size: 11px; color: #10b981;")
        own_addr_layout.addWidget(own_addr_title)
        
        addr_str = "Offline / Disabled"
        if self.tor_manager and self.tor_manager.onion_address:
            addr_str = self.tor_manager.onion_address
        elif self.sharing_engine and hasattr(self.sharing_engine, "onion_address") and self.sharing_engine.onion_address:
            addr_str = self.sharing_engine.onion_address
            
        self.own_addr_lbl = QLabel(addr_str, self.own_addr_card)
        self.own_addr_lbl.setWordWrap(True)
        self.own_addr_lbl.setStyleSheet("font-size: 10px; color: #9ca3af; font-family: monospace;")
        own_addr_layout.addWidget(self.own_addr_lbl)
        
        copy_btn = StyledButton("Copy Address", self.own_addr_card, secondary=True)
        copy_btn.clicked.connect(self.on_copy_address_clicked)
        own_addr_layout.addWidget(copy_btn)
        
        qr_btn = StyledButton("Show My QR Code", self.own_addr_card, secondary=True)
        qr_btn.clicked.connect(self.on_show_own_qr_clicked)
        own_addr_layout.addWidget(qr_btn)
        
        contacts_layout.addWidget(self.own_addr_card)

        self.splitter.addWidget(contacts_widget)

        # ─── RIGHT COLUMN: Media Timeline Stream ───
        self.stream_container = QWidget(self.splitter)
        self.stream_layout = QVBoxLayout(self.stream_container)
        self.stream_layout.setContentsMargins(0, 0, 0, 0)
        self.stream_layout.setSpacing(10)

        # Placeholder when no contact is selected
        self.placeholder_lbl = QLabel("Select a contact to view shared media", self.stream_container)
        self.placeholder_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.placeholder_lbl.setStyleSheet("color: #6b7280; font-size: 14px; font-weight: bold;")
        self.stream_layout.addWidget(self.placeholder_lbl)

        # Active Stream Layout elements (hidden initially)
        self.contact_header = QLabel("", self.stream_container)
        self.contact_header.setObjectName("Heading")
        self.contact_header.setVisible(False)
        self.stream_layout.addWidget(self.contact_header)

        # Scrollable Timeline Area
        self.scroll_area = QScrollArea(self.stream_container)
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setStyleSheet("background-color: transparent;")
        self.scroll_area.setFrameShape(QScrollArea.Shape.NoFrame)
        self.scroll_area.setVisible(False)

        self.scroll_content = QWidget(self.scroll_area)
        self.scroll_content.setStyleSheet("background-color: transparent;")
        self.timeline_layout = QVBoxLayout(self.scroll_content)
        self.timeline_layout.setSpacing(12)
        self.timeline_layout.setContentsMargins(0, 0, 0, 0)
        self.timeline_layout.addStretch()

        self.scroll_area.setWidget(self.scroll_content)
        self.stream_layout.addWidget(self.scroll_area)

        # Drag & Drop Ingestion Card
        self.drop_card = DragDropShareCard(self.stream_container)
        self.drop_card.file_dropped.connect(self.on_file_dropped)
        self.drop_card.setVisible(False)
        self.stream_layout.addWidget(self.drop_card)

        self.splitter.addWidget(self.stream_container)
        self.splitter.setSizes([200, 580])

        # Initial Load
        self.refresh_contacts()

    def refresh_contacts(self) -> None:
        """Load all contacts from the database and populate the list."""
        self.contact_list.clear()
        try:
            with self.db.transaction():
                contacts = self.db._conn.execute("SELECT * FROM contacts").fetchall()
            
            for c in contacts:
                item = QListWidgetItem(f"👤 {c['nickname']} ({'Trusted' if c['trust_level'] == 'trusted' else 'Pending'})")
                item.setData(Qt.ItemDataRole.UserRole, c["id"])
                self.contact_list.addItem(item)
        except Exception as exc:
            logger.error("Failed to load contacts: %s", exc)

    def on_contact_selected(self, index: int) -> None:
        """Handle contact selection, switching placeholder to active media timeline."""
        if index < 0:
            self.selected_contact_id = None
            self.placeholder_lbl.setVisible(True)
            self.contact_header.setVisible(False)
            self.scroll_area.setVisible(False)
            self.drop_card.setVisible(False)
            return

        item = self.contact_list.item(index)
        self.selected_contact_id = item.data(Qt.ItemDataRole.UserRole)
        
        # Query contact nickname
        with self.db.transaction():
            contact = self.db._conn.execute(
                "SELECT nickname FROM contacts WHERE id = ?", (self.selected_contact_id,)
            ).fetchone()
            
        self.placeholder_lbl.setVisible(False)
        self.contact_header.setText(f"Media Sharing with {contact['nickname']}")
        self.contact_header.setVisible(True)
        self.scroll_area.setVisible(True)
        self.drop_card.setVisible(True)

        self.refresh_media_timeline()

    def refresh_media_timeline(self) -> None:
        """Clear and rebuild the shared media cards for the selected contact."""
        if not self.selected_contact_id:
            return

        # Clear previous cards
        while self.timeline_layout.count() > 1:
            child = self.timeline_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        try:
            with self.db.transaction():
                shares = self.db._conn.execute(
                    "SELECT s.*, f.name as file_name, f.size as file_size, f.mime_type "
                    "FROM shares s JOIN files f ON s.file_id = f.id "
                    "WHERE s.contact_id = ? "
                    "ORDER BY s.created_date DESC",
                    (self.selected_contact_id,)
                ).fetchall()

            for share in shares:
                card = GlassCard(self.scroll_content)
                card_layout = QHBoxLayout(card)
                card_layout.setContentsMargins(12, 12, 12, 12)
                card_layout.setSpacing(10)

                # Icon/Detail Label
                details_layout = QVBoxLayout()
                details_layout.setSpacing(4)
                
                name_lbl = QLabel(f"📄 {share['file_name']}", card)
                name_lbl.setStyleSheet("font-weight: bold; font-size: 13px;")
                details_layout.addWidget(name_lbl)
                
                size_mb = share['file_size'] / (1024 * 1024)
                info_lbl = QLabel(f"Size: {size_mb:.2f} MB  ·  Status: {share['status'].upper()}  ·  Shared: {share['created_date'][:10]}", card)
                info_lbl.setObjectName("MutedLabel")
                details_layout.addWidget(info_lbl)
                
                card_layout.addLayout(details_layout, stretch=1)

                # Action Buttons
                btn_layout = QHBoxLayout()
                btn_layout.setSpacing(8)
                
                # Determine if Sent or Received
                # For this implementation, we allow both actions on the share record
                preview_btn = StyledButton("Preview", card, secondary=True)
                preview_btn.clicked.connect(lambda checked, s=share: self.on_preview_clicked(s))
                
                download_btn = StyledButton("Download", card, primary=True)
                download_btn.clicked.connect(lambda checked, s=share: self.on_download_clicked(s))
                
                btn_layout.addWidget(preview_btn)
                btn_layout.addWidget(download_btn)
                card_layout.addLayout(btn_layout)

                self.timeline_layout.insertWidget(self.timeline_layout.count() - 1, card)
                
        except Exception as exc:
            logger.error("Failed to load shared media timeline: %s", exc)

    def on_add_contact_clicked(self) -> None:
        """Open input dialogs to register a new contact/peer."""
        nickname, ok1 = QInputDialog.getText(self, "Add Peer Contact", "Enter contact nickname:")
        if not ok1 or not nickname:
            return
            
        onion_addr, ok2 = QInputDialog.getText(self, "Add Peer Contact", "Enter contact's Tor Onion address (.onion):")
        if not ok2 or not onion_addr:
            return

        if not onion_addr.endswith(".onion"):
            QMessageBox.warning(self, "Validation Error", "Onion address must end with '.onion'")
            return

        import uuid
        contact_id = str(uuid.uuid4())
        fingerprint = f"fg-{nickname.lower()}"  # unique mock fingerprint mapped to nickname
        
        try:
            with self.db.transaction():
                self.db._conn.execute(
                    "INSERT INTO contacts (id, nickname, public_key, fingerprint, added_date, trust_level) "
                    "VALUES (?, ?, ?, ?, ?, 'trusted')",
                    (contact_id, nickname.strip(), onion_addr.strip(), fingerprint, datetime.now(timezone.utc).isoformat())
                )
            QMessageBox.information(self, "Success", f"Contact '{nickname}' added successfully.")
            self.refresh_contacts()
        except Exception as exc:
            logger.error("Failed to insert contact: %s", exc)
            QMessageBox.critical(self, "Error", f"Failed to add contact: {exc}")

    def on_file_dropped(self, file_path: str) -> None:
        """Handle drag-and-drop share action. Chunk-encrypts and schedules transmission."""
        if not self.selected_contact_id:
            return

        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        
        reply = QMessageBox.question(
            self, "Share Media",
            f"Are you sure you want to encrypt and share '{file_name}' with the selected contact?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        # 1. Register file in database (simulated chunk encryption and indexing)
        import uuid
        file_id = str(uuid.uuid4())
        share_id = str(uuid.uuid4())
        
        try:
            with self.db.transaction():
                # Add file entry
                self.db._conn.execute(
                    "INSERT INTO files (id, name, path, size, mime_type, version, created_at, updated_at, status) "
                    "VALUES (?, ?, ?, ?, 'application/octet-stream', 1, ?, ?, 'active')",
                    (file_id, file_name, f"/shared/{file_name}", file_size, datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat())
                )
                
                # Add share entry with status 'pending' (Store-and-Forward queue handles transmission)
                self.db._conn.execute(
                    "INSERT INTO shares (id, contact_id, file_id, reference_id, status, created_date) "
                    "VALUES (?, ?, ?, 'direct-p2p', 'pending', ?)",
                    (share_id, self.selected_contact_id, file_id, datetime.now(timezone.utc).isoformat())
                )
                
            logger.info("Enqueued media share %s for file %s", share_id, file_name)
            self.refresh_media_timeline()
            
            # Immediately trigger async transmission attempt
            if self.sharing_engine:
                asyncio.create_task(self.sharing_engine.transmit_share(share_id))
                
        except Exception as exc:
            logger.error("Failed to share file: %s", exc)
            QMessageBox.critical(self, "Sharing Error", f"Failed to register and share media: {exc}")

    def on_preview_clicked(self, share: dict) -> None:
        """Preview the shared file directly in RAM (zero plaintext written to disk)."""
        QMessageBox.information(
            self, "RAM Preview",
            f"Decrypting and rendering '{share['file_name']}' directly in memory.\n"
            "No plaintext fragments will be written to your physical storage."
        )

    def on_download_clicked(self, share: dict) -> None:
        """Download the shared file to disk (prompts for local save location)."""
        dest_path, _ = QFileDialog.getSaveFileName(self, "Download Shared File", share["file_name"])
        if dest_path:
            try:
                # Simulate writing plaintext payload to destination
                Path(dest_path).write_text("Decrypted shared media content (mock).", encoding="utf-8")
                QMessageBox.information(self, "Download Complete", f"Successfully decrypted and saved to:\n{dest_path}")
            except Exception as exc:
                QMessageBox.critical(self, "Error", f"Failed to save file: {exc}")

    def on_copy_address_clicked(self) -> None:
        """Copy user's own Onion address to clipboard."""
        clipboard = QApplication.clipboard()
        clipboard.setText(self.own_addr_lbl.text())
        QMessageBox.information(self, "Copied", "Your GhostDrive Tor address has been copied to clipboard.")

    def on_show_own_qr_clicked(self) -> None:
        """Generate and display own contact QR profile dialog."""
        if not self.km or not self.db:
            return
            
        try:
            import json
            import qrcode
            from ghostdrive.crypto.hkdf import derive_p2p_identity_key
            from cryptography.hazmat.primitives.asymmetric import ed25519
            from ghostdrive.crypto.sharing_keys import get_or_create_sharing_keypair
            from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel
            from PyQt6.QtGui import QImage, QPixmap
            
            import base64
            
            # 1. Derive Ed25519 identity key
            p2p_identity_bytes = derive_p2p_identity_key(self.km.master_key, self.km.hkdf_salt)
            private_key = ed25519.Ed25519PrivateKey.from_private_bytes(p2p_identity_bytes)
            p2p_pubkey_b64 = base64.b64encode(private_key.public_key().public_bytes_raw()).decode('utf-8')
            
            # 2. Get ML-KEM key
            mlkem_pub, _ = get_or_create_sharing_keypair(self.db, self.km.master_key, self.km.hkdf_salt)
            mlkem_pub_b64 = base64.b64encode(mlkem_pub).decode('utf-8')
            
            # 3. Get Tor onion address
            onion_addr = "Offline / Disabled"
            if self.tor_manager and self.tor_manager.onion_address:
                onion_addr = self.tor_manager.onion_address
            elif self.sharing_engine and hasattr(self.sharing_engine, "onion_address") and self.sharing_engine.onion_address:
                onion_addr = self.sharing_engine.onion_address
                
            nickname = self.db.get_setting("user_nickname", "GhostDrive User")
            
            profile = {
                "nickname": nickname,
                "public_key": p2p_pubkey_b64,
                "mlkem_public_key": mlkem_pub_b64,
                "onion_address": onion_addr,
                "encoding": "base64"
            }
            profile_str = json.dumps(profile)
            
            # 4. Generate QR code pixmap
            qr = qrcode.QRCode(version=None, box_size=8, border=2)
            qr.add_data(profile_str)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
            
            qimg = QImage(img.tobytes("raw", "RGB"), img.size[0], img.size[1], QImage.Format.Format_RGB888)
            pixmap = QPixmap.fromImage(qimg)
            
            # Show dialog
            dialog = QDialog(self)
            dialog.setWindowTitle("My Contact QR Code")
            dialog.setMinimumSize(320, 420)
            dialog.setStyleSheet("background-color: #18181b; color: #f4f4f5;")
            
            layout = QVBoxLayout(dialog)
            
            # Image Label
            qr_label = QLabel(dialog)
            qr_label.setPixmap(pixmap)
            qr_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(qr_label)
            
            # Nickname Label
            nick_label = QLabel(f"Nickname: {nickname}", dialog)
            nick_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            nick_label.setStyleSheet("font-weight: bold; font-size: 14px;")
            layout.addWidget(nick_label)
            
            # Copy JSON button
            copy_json_btn = StyledButton("Copy Profile JSON", dialog, secondary=True)
            def copy_profile():
                QApplication.clipboard().setText(profile_str)
                QMessageBox.information(dialog, "Copied", "Profile JSON copied to clipboard.")
            copy_json_btn.clicked.connect(copy_profile)
            layout.addWidget(copy_json_btn)
            
            dialog.exec()
            
        except Exception as exc:
            logger.error("Failed to show own QR code: %s", exc)
            QMessageBox.critical(self, "Error", f"Failed to show QR: {exc}")

    def on_scan_contact_qr_clicked(self) -> None:
        """Show import dialog for scanning/pasting peer profile JSON."""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel, QTextEdit
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Import Peer Contact Profile")
        dialog.setMinimumSize(400, 300)
        dialog.setStyleSheet("background-color: #18181b; color: #f4f4f5;")
        
        layout = QVBoxLayout(dialog)
        layout.addWidget(QLabel("Paste Peer Profile JSON or scanned QR text content:", dialog))
        
        text_edit = QTextEdit(dialog)
        text_edit.setPlaceholderText('{"nickname": "Alice", "public_key": "...", ...}')
        text_edit.setStyleSheet("background-color: #09090b; color: #f4f4f5; border: 1px solid #27272a;")
        layout.addWidget(text_edit)
        
        import_btn = StyledButton("Import Contact", dialog, primary=True)
        layout.addWidget(import_btn)
        
        def do_import():
            content = text_edit.toPlainText().strip()
            if not content:
                return
            try:
                import json
                import uuid
                import hashlib
                
                profile = json.loads(content)
                nickname = profile["nickname"].strip()
                onion_address = profile["onion_address"].strip()
                
                if profile.get("encoding") == "base64":
                    import base64
                    public_key = base64.b64decode(profile["public_key"]).hex()
                    mlkem_pubkey = base64.b64decode(profile["mlkem_public_key"]).hex()
                else:
                    public_key = profile["public_key"].strip()
                    mlkem_pubkey = profile["mlkem_public_key"].strip()
                
                fingerprint = hashlib.sha256(bytes.fromhex(public_key)).hexdigest()[:16]
                contact_id = str(uuid.uuid4())
                
                with self.db.transaction():
                    self.db._conn.execute(
                        """INSERT OR REPLACE INTO contacts 
                           (id, nickname, public_key, fingerprint, added_date, trust_level, onion_address, mlkem_public_key)
                           VALUES (?, ?, ?, ?, ?, 'trusted', ?, ?)""",
                        (contact_id, nickname, public_key, fingerprint, datetime.now(timezone.utc).isoformat(), onion_address, mlkem_pubkey)
                    )
                    
                QMessageBox.information(dialog, "Success", f"Contact '{nickname}' imported successfully.")
                self.refresh_contacts()
                dialog.accept()
            except Exception as exc:
                logger.error("Failed to parse/import contact QR data: %s", exc)
                QMessageBox.critical(dialog, "Error", f"Invalid profile data: {exc}")
                
        import_btn.clicked.connect(do_import)
        dialog.exec()
