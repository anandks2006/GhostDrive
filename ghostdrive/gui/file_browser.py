"""
file_browser.py -- MainWindow controller mixin handling file browsing, list/grid views, search, downloads, and trash operations.
"""

import os
import sys
import uuid
import logging
import asyncio
from pathlib import Path
from datetime import datetime, timezone

from PyQt6.QtCore import Qt, QSize, pyqtSignal, QTimer, QUrl
from PyQt6.QtGui import QIcon, QPixmap
from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QTableWidgetItem,
    QDialog,
    QMessageBox,
    QMenu,
)

from ghostdrive.gui.widgets import StyledButton, ThumbnailWidget, ClickableGlassCard
from ghostdrive.exceptions import AuthenticationError

logger = logging.getLogger(__name__)

class FileBrowserMixin:
    """Mixin controller containing file browsing list/grid view, folder navigation, download, delete, and trash logic."""

    def switch_files_view_mode(self, idx: int) -> None:
        """Switch between list view (0) and grid card view (1)."""
        self.files_layout_stack.setCurrentIndex(idx)
        if idx == 0:
            self.list_mode_btn.setObjectName("PrimaryButton")
            self.grid_mode_btn.setObjectName("")
        else:
            self.list_mode_btn.setObjectName("")
            self.grid_mode_btn.setObjectName("PrimaryButton")
        self.list_mode_btn.setStyle(self.list_mode_btn.style())
        self.grid_mode_btn.setStyle(self.grid_mode_btn.style())
        self.refresh_files()

    def refresh_files(self) -> None:
        """Fetch all files matching current search filter and redraw table and grid."""
        if not self.db:
            return

        # Toggle breadcrumb widget visibility based on root directory vs subfolder
        if hasattr(self, "breadcrumb_widget") and self.breadcrumb_widget:
            if self.current_folder_path == "/files":
                self.breadcrumb_widget.hide()
            else:
                self.breadcrumb_widget.show()

        query = self.search_input.text().strip()
        tier_filter = self.tier_filter_combo.currentText()
        
        try:
            with self.db.transaction():
                sql = "SELECT * FROM files WHERE tombstone = 0"
                params = []
                if query:
                    sql += " AND name LIKE ?"
                    params.append(f"%{query}%")
                if tier_filter != "All Tiers":
                    sql += " AND tier = ?"
                    params.append(tier_filter)
                sql += " ORDER BY created_at DESC"
                
                rows = self.db._conn.execute(sql, params).fetchall()

            # Determine virtual directory prefix
            prefix = self.current_folder_path + "/"
            
            # Group into unique subfolders and files inside the current folder path
            folders = set()
            display_files = []
            
            for row in rows:
                path = row["path"]
                if path.startswith(prefix):
                    rel = path[len(prefix):]
                    parts = rel.split("/")
                    if len(parts) > 1:
                        folders.add(parts[0])
                    else:
                        display_files.append(row)
                elif path == self.current_folder_path:
                    display_files.append(row)

            # Disable sorting temporarily during rebuild to prevent layout jumps
            self.files_table.setSortingEnabled(False)
            self.files_table.setRowCount(0)
            self._table_file_ids = []
            self._table_item_types = []
            
            # Sort folders alphabetically
            sorted_folders = sorted(list(folders))
            for folder_name in sorted_folders:
                r_idx = self.files_table.rowCount()
                self.files_table.insertRow(r_idx)
                
                self._table_file_ids.append(folder_name)
                self._table_item_types.append("folder")
                
                # Column 0: Preview (Folder emoji)
                preview_item = QTableWidgetItem("📁")
                preview_item.setFlags(preview_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                preview_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.files_table.setItem(r_idx, 0, preview_item)
                
                # Column 1: Name
                folder_item = QTableWidgetItem(folder_name)
                folder_item.setFlags(folder_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.files_table.setItem(r_idx, 1, folder_item)
                
                self.files_table.setItem(r_idx, 2, QTableWidgetItem("—"))
                self.files_table.setItem(r_idx, 3, QTableWidgetItem("—"))
                self.files_table.setItem(r_idx, 4, QTableWidgetItem("—"))

            for row in display_files:
                r_idx = self.files_table.rowCount()
                self.files_table.insertRow(r_idx)
                
                self._table_file_ids.append(row["id"])
                self._table_item_types.append("file")
                
                # Column 0: Preview (Thumbnail widget)
                thumb_widget = ThumbnailWidget(
                    file_path=row["name"],
                    max_size=QSize(24, 24),
                    parent=self.files_table,
                    thumbnail_blob=row["thumbnail_blob"] if "thumbnail_blob" in row.keys() else None,
                    file_id=row["id"],
                    on_thumbnail_generated=lambda blob, f_id=row["id"]: self._save_thumbnail_to_db(f_id, blob)
                )
                self.files_table.setCellWidget(r_idx, 0, thumb_widget)
                
                # Column 1: Name
                file_item = QTableWidgetItem(row["name"])
                file_item.setFlags(file_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.files_table.setItem(r_idx, 1, file_item)
                
                self.files_table.setItem(r_idx, 2, QTableWidgetItem(self._format_bytes(row["size"])))
                self.files_table.setItem(r_idx, 3, QTableWidgetItem(row["tier"]))
                self.files_table.setItem(r_idx, 4, QTableWidgetItem(row["created_at"][:19].replace("T", " ")))

            # Re-enable sorting
            self.files_table.setSortingEnabled(True)

            # 2. Redraw Grid Cards View
            while self.files_grid_layout.count():
                item = self.files_grid_layout.takeAt(0)
                widget = item.widget()
                if widget is not None:
                    widget.deleteLater()

            scroll_width = self.files_grid_scroll.viewport().width()
            scale = getattr(self, "_scale_factor", 1.0)
            card_width = max(80, int(145 * scale))
            folder_card_height = max(90, int(100 * scale))
            file_card_height = max(150, int(170 * scale))
            columns = max(1, scroll_width // card_width)
            self._current_grid_columns = columns
            grid_idx = 0
            
            # Render folder cards
            for folder_name in sorted_folders:
                card = ClickableGlassCard(
                    self.files_grid_container,
                    double_click_callback=lambda name=folder_name: self.navigate_to_folder(name)
                )
                card.setProperty("item_type", "folder")
                card.setFixedWidth(card_width)
                card.setFixedHeight(folder_card_height)
                
                card_layout = QVBoxLayout(card)
                card_layout.setContentsMargins(8, 8, 8, 8)
                card_layout.setSpacing(6)
                
                preview = QLabel("📁", card)
                preview.setStyleSheet(f"font-size: {int(32 * scale)}px;")
                preview.setAlignment(Qt.AlignmentFlag.AlignCenter)
                card_layout.addWidget(preview)
                
                name_lbl = QLabel(folder_name, card)
                name_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
                name_lbl.setWordWrap(True)
                name_lbl.setStyleSheet("font-weight: bold;")
                card_layout.addWidget(name_lbl)
                
                grid_row = grid_idx // columns
                grid_col = grid_idx % columns
                self.files_grid_layout.addWidget(card, grid_row, grid_col)
                grid_idx += 1

            # Render file cards
            for row in display_files:
                card = ClickableGlassCard(
                    self.files_grid_container,
                    click_callback=lambda r=row: self.show_file_metadata(r)
                )
                card.setProperty("item_type", "file")
                card.setFixedWidth(card_width)
                card.setFixedHeight(file_card_height)
                
                card_layout = QVBoxLayout(card)
                card_layout.setContentsMargins(8, 8, 8, 8)
                card_layout.setSpacing(6)

                scaled_sz = int(100 * scale)
                preview = ThumbnailWidget(
                    file_path=row["name"],
                    max_size=QSize(scaled_sz, scaled_sz),
                    parent=card,
                    thumbnail_blob=row["thumbnail_blob"] if "thumbnail_blob" in row.keys() else None,
                    file_id=row["id"],
                    on_thumbnail_generated=lambda blob, f_id=row["id"]: self._save_thumbnail_to_db(f_id, blob)
                )
                card_layout.addWidget(preview, alignment=Qt.AlignmentFlag.AlignCenter)

                name_lbl = QLabel(row["name"], card)
                name_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
                name_lbl.setWordWrap(True)
                card_layout.addWidget(name_lbl)

                size_lbl = QLabel(self._format_bytes(row["size"]), card)
                size_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
                size_lbl.setObjectName("MutedLabel")
                card_layout.addWidget(size_lbl)

                grid_row = grid_idx // columns
                grid_col = grid_idx % columns
                self.files_grid_layout.addWidget(card, grid_row, grid_col)
                grid_idx += 1

        except Exception as exc:
            logger.error("Failed to load files from database: %s", exc)

    def _save_thumbnail_to_db(self, file_id: str, blob: bytes) -> None:
        if not self.db:
            return
        try:
            with self.db.transaction():
                self.db.update_file_thumbnail(file_id, blob)
            logger.info("Saved generated thumbnail to database for file_id=%s", file_id)
        except Exception as exc:
            logger.error("Failed to save generated thumbnail to database: %s", exc)

    def on_search_query_changed(self, text: str) -> None:
        self.refresh_files()

    def on_file_selected(self) -> None:
        selected_ranges = self.files_table.selectedRanges()
        if not selected_ranges:
            return
        
        # Determine the selected row from list
        r = selected_ranges[0].topRow()
        if r < len(self._table_item_types):
            t = self._table_item_types[r]
            fid = self._table_file_ids[r]
            if t == "file":
                self.selected_file_id = fid
                # Fetch full metadata row
                with self.db.transaction():
                    row = self.db._conn.execute("SELECT * FROM files WHERE id = ?", (fid,)).fetchone()
                if row:
                    self.show_file_metadata(dict(row))
            else:
                self.selected_file_id = None
                self.meta_title.setText(f"Folder: {fid}")
                self.meta_desc.setText("Double click to enter virtual folder.")
                self.download_btn.setVisible(False)
                self.delete_btn.setVisible(False)

    def show_file_metadata(self, file_row) -> None:
        self.selected_file_id = file_row["id"]
        self.selected_file_row = file_row
        
        self.meta_title.setText(file_row["name"])
        desc_text = (
            f"Path: {file_row['path']}\n"
            f"Size: {self._format_bytes(file_row['size'])}\n"
            f"MIME: {file_row['mime_type']}\n"
            f"Tier: {file_row['tier']}\n"
            f"Modified: {file_row['modified_at']}"
        )
        self.meta_desc.setText(desc_text)
        self.download_btn.setVisible(True)
        self.delete_btn.setVisible(True)

    def on_download_selected_clicked(self) -> None:
        """Retrieve and decrypt selected file chunks from backends."""
        selected_ids = self.get_selected_file_ids()
        if not selected_ids:
            if hasattr(self, "selected_file_row") and self.selected_file_row:
                selected_ids = [self.selected_file_row["id"]]
            else:
                return

        if len(selected_ids) == 1:
            with self.db.transaction():
                file_row = self.db._conn.execute(
                    "SELECT * FROM files WHERE id = ?", (selected_ids[0],)
                ).fetchone()
            if not file_row:
                return
            save_path, _ = QFileDialog.getSaveFileName(self, "Save Decrypted File", file_row["name"])
            if not save_path:
                return
            asyncio.create_task(self._download_selected_task(file_row, save_path))
        else:
            dest_dir = QFileDialog.getExistingDirectory(self, "Select Destination Directory")
            if not dest_dir:
                return
            for f_id in selected_ids:
                with self.db.transaction():
                    file_row = self.db._conn.execute(
                        "SELECT * FROM files WHERE id = ?", (f_id,)
                ).fetchone()
                if file_row:
                    save_path = os.path.join(dest_dir, file_row["name"])
                    asyncio.create_task(self._download_selected_task(file_row, save_path))

    async def _download_selected_task(self, file_row: dict, save_path: str) -> None:
        self.notifications.notify("Download Started", f"Downloading '{file_row['name']}'...", "info")
        self.add_activity_log(f"Downloading '{file_row['name']}'...")
        try:
            await self._download_file_core(file_row, save_path)
            self.notifications.notify("Download Completed", f"Successfully downloaded '{file_row['name']}'.", "success")
            self.add_activity_log(f"Successfully downloaded '{file_row['name']}'.")
        except Exception as exc:
            logger.error("Download pipeline failed: %s", exc)
            text = f"Failed to retrieve or decrypt file: {exc}"
            QTimer.singleShot(0, lambda: QMessageBox.critical(self, "Download Error", text))
            self.add_activity_log(f"Failed download of '{file_row['name']}': {exc}")

    def download_file_sync_for_drag(self, file_row: dict) -> str:
        import tempfile
        import threading
        temp_dir = tempfile.gettempdir()
        save_path = os.path.join(temp_dir, file_row["name"])
        
        if os.path.exists(save_path):
            return save_path
            
        self.notifications.notify("Exporting File", f"Preparing '{file_row['name']}' for drag-export...", "info")
        
        def run_async_in_thread():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(self._download_file_core(file_row, save_path))
            except Exception as e:
                logger.error("Sync download for drag failed: %s", e)
            finally:
                loop.close()
                
        t = threading.Thread(target=run_async_in_thread)
        t.start()
        t.join()
        
        if os.path.exists(save_path):
            return save_path
        return ""

    async def _download_file_core(self, file_row: dict, save_path: str) -> None:
        # Fetch all chunks and locations from DB
        with self.db.transaction():
            chunks = self.db._conn.execute(
                "SELECT * FROM chunks WHERE file_id = ? ORDER BY chunk_index ASC",
                (file_row["id"],)
            ).fetchall()

        decrypted_data = bytearray()

        for chunk in chunks:
            with self.db.transaction():
                locs = self.db._conn.execute(
                    """SELECT cl.*, b.type, b.priority
                       FROM chunk_locations cl
                       JOIN backends b ON cl.backend_id = b.id
                       WHERE cl.chunk_id = ? AND cl.status = 'confirmed'
                       ORDER BY b.priority DESC""",
                    (chunk["id"],)
                ).fetchall()
            
            if not locs:
                raise ValueError(f"No confirmed locations found for chunk index {chunk['chunk_index']}.")

            chunk_plaintext = None
            
            for loc in locs:
                b_name = loc["type"]
                backend_obj = self.active_backends.get(b_name)
                if not backend_obj:
                    continue

                try:
                    if not getattr(backend_obj, "_connected", False):
                        await backend_obj.connect()
                        backend_obj._connected = True

                    # Download sub-block bytes
                    chunk_ciphertext = bytearray()
                    async for block in backend_obj.download(loc["reference_id"]):
                        chunk_ciphertext.extend(block)

                    if not chunk_ciphertext:
                        raise ValueError("Downloaded chunk ciphertext is empty.")

                    # Decrypt chunk
                    from ghostdrive.crypto.nonce import NonceManager
                    from ghostdrive.crypto.chunk_crypto import ChunkDecryptor
                    from ghostdrive.crypto.hkdf import derive_chunk_key

                    chunk_key = derive_chunk_key(self.km.master_key, self.km.hkdf_salt)
                    nonce = NonceManager.counter_to_nonce(chunk["nonce_counter"])

                    tag = chunk_ciphertext[-16:]
                    ct_body = chunk_ciphertext[:-16]

                    decryptor = ChunkDecryptor(key=chunk_key, nonce=nonce, expected_tag=tag)
                    
                    # Feed cipher blocks
                    from ghostdrive.crypto.chunk_crypto import BLOCK_SIZE
                    offset = 0
                    while offset < len(ct_body):
                        block = ct_body[offset : offset + BLOCK_SIZE]
                        decryptor.feed(block)
                        offset += BLOCK_SIZE

                    chunk_plaintext = decryptor.verify_and_decrypt()
                    break

                except Exception as e:
                    logger.error("Download/Decryption failed for chunk %s on %s: %s", chunk["id"][:8], b_name, e)
                    
                    from ghostdrive.exceptions import AuthenticationError
                    res_code = "auth_failed" if isinstance(e, AuthenticationError) else "not_found"
                    
                    # Record failure in integrity log + fail the location in SQLite
                    with self.db.transaction():
                        log_id = str(uuid.uuid4())
                        self.db._conn.execute(
                            """INSERT INTO integrity_log (id, chunk_id, checked_at, result, backend_id)
                               VALUES (?, ?, ?, ?, ?)""",
                            (log_id, chunk["id"], datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), res_code, loc["backend_id"])
                        )
                        self.db.prune_integrity_log(chunk["id"], keep=10)
                        
                        self.db.fail_chunk_location(chunk["id"], loc["sub_block_index"], loc["backend_id"])
            
            if chunk_plaintext is None:
                raise ValueError(f"CRITICAL: Failed to retrieve or decrypt chunk index {chunk['chunk_index']} from any backend.")
            
            decrypted_data.extend(chunk_plaintext)

        with open(save_path, "wb") as f:
            f.write(decrypted_data)

    def on_delete_selected_clicked(self) -> None:
        if hasattr(self, "selected_file_id") and self.selected_file_id:
            self.soft_delete_file(self.selected_file_id)

    def soft_delete_file(self, file_id: str) -> None:
        """Tombstones a file in the DB registry."""
        if not self.db:
            return
        
        reply = QMessageBox.question(
            self, "Confirm Deletion", "Are you sure you want to delete this file?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            try:
                # Check file tier
                with self.db.transaction():
                    f_row = self.db._conn.execute("SELECT tier FROM files WHERE id = ?", (file_id,)).fetchone()
                
                if f_row and f_row["tier"] == "DISPOSABLE":
                    # Instant purge/vacuum for DISPOSABLE files (Spec 7.8)
                    asyncio.create_task(self._purge_file_permanent_no_prompt(file_id))
                else:
                    with self.db.transaction():
                        self.db.tombstone_file(file_id)
                    self.notifications.notify("File Deleted", "Moved file to trash folder.", "info")
                    self.refresh_files()
                    self.refresh_trash()
                
                # Clear meta panel
                self.meta_title.setText("Select a file to view detail metadata.")
                self.meta_desc.setText("")
                self.download_btn.setVisible(False)
                self.delete_btn.setVisible(False)
            except Exception as exc:
                QMessageBox.critical(self, "Error", f"Failed to delete: {exc}")

    async def _purge_file_permanent_no_prompt(self, file_id: str) -> None:
        """Completely vacuums file metadata and deletes chunk sub-blocks from backends without prompts."""
        try:
            # 1. Fetch chunks and location references
            with self.db.transaction():
                chunks = self.db._conn.execute(
                    "SELECT * FROM chunks WHERE file_id = ?", (file_id,)
                ).fetchall()

            for chunk in chunks:
                with self.db.transaction():
                    locations = self.db._conn.execute(
                        "SELECT cl.*, b.type FROM chunk_locations cl JOIN backends b ON cl.backend_id = b.id WHERE cl.chunk_id = ?",
                        (chunk["id"],)
                    ).fetchall()

                # Call delete() on corresponding backends
                for loc in locations:
                    b_name = loc["type"]
                    backend_obj = self.active_backends.get(b_name)
                    if backend_obj:
                        if not getattr(backend_obj, "_connected", False):
                            await backend_obj.connect()
                            backend_obj._connected = True
                        
                        await backend_obj.delete(loc["reference_id"])

            # Remove chunk locations, chunk records, and file record from DB via public API
            with self.db.transaction():
                self.db.purge_file_permanently(file_id)

            self.notifications.notify("Purged", "Permanently vacuumed DISPOSABLE file.", "info")
            self.refresh_files()
            self.refresh_trash()

        except Exception as exc:
            logger.error("Failed to purge DISPOSABLE file: %s", exc)
            text = f"Failed to purge DISPOSABLE file: {exc}"
            QTimer.singleShot(0, lambda: QMessageBox.critical(self, "Error", text))

    def refresh_trash(self) -> None:
        if not self.db:
            return

        try:
            with self.db.transaction():
                rows = self.db._conn.execute(
                    "SELECT * FROM files WHERE tombstone = 1 ORDER BY tombstone_at DESC"
                ).fetchall()

            self.trash_table.setRowCount(0)
            self._trash_file_ids = []

            for row in rows:
                r_idx = self.trash_table.rowCount()
                self.trash_table.insertRow(r_idx)
                self._trash_file_ids.append(row["id"])

                self.trash_table.setItem(r_idx, 0, QTableWidgetItem(row["name"]))
                self.trash_table.setItem(r_idx, 1, QTableWidgetItem(row["path"]))
                self.trash_table.setItem(r_idx, 2, QTableWidgetItem(self._format_bytes(row["size"])))

                # Action widget: Restore / Purge
                act_widget = QWidget()
                act_layout = QHBoxLayout(act_widget)
                act_layout.setContentsMargins(4, 4, 4, 4)
                act_layout.setSpacing(6)

                rest_btn = StyledButton("Restore", secondary=True)
                rest_btn.clicked.connect(lambda _, f_id=row["id"]: self.restore_file(f_id))
                act_layout.addWidget(rest_btn)

                purge_btn = StyledButton("Purge", danger=True)
                purge_btn.clicked.connect(lambda _, f_id=row["id"]: self.purge_file_permanent(f_id))
                act_layout.addWidget(purge_btn)

                self.trash_table.setCellWidget(r_idx, 3, act_widget)

        except Exception as exc:
            logger.error("Failed to load trash rows: %s", exc)

    def restore_file(self, file_id: str) -> None:
        try:
            with self.db.transaction():
                self.db.restore_file(file_id)
            self.notifications.notify("File Restored", "File restored to dashboard browser.", "success")
            self.refresh_files()
            self.refresh_trash()
        except Exception as exc:
            QMessageBox.critical(self, "Error", f"Failed to restore file: {exc}")

    def purge_file_permanent(self, file_id: str) -> None:
        """Completely vacuums file metadata and deletes chunk sub-blocks from backends."""
        reply = QMessageBox.question(
            self, "Permanent Purge", "Are you sure you want to permanently delete this file and all its backend chunks?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            asyncio.create_task(self._purge_file_permanent_task(file_id))

    async def _purge_file_permanent_task(self, file_id: str) -> None:
        try:
            # 1. Fetch chunks and location references
            with self.db.transaction():
                chunks = self.db._conn.execute(
                    "SELECT * FROM chunks WHERE file_id = ?", (file_id,)
                ).fetchall()

            for chunk in chunks:
                with self.db.transaction():
                    locations = self.db._conn.execute(
                        "SELECT cl.*, b.type FROM chunk_locations cl JOIN backends b ON cl.backend_id = b.id WHERE cl.chunk_id = ?",
                        (chunk["id"],)
                    ).fetchall()

                # Call delete() on corresponding backends
                for loc in locations:
                    b_name = loc["type"]
                    backend_obj = self.active_backends.get(b_name)
                    if backend_obj:
                        if not getattr(backend_obj, "_connected", False):
                            await backend_obj.connect()
                            backend_obj._connected = True
                        
                        await backend_obj.delete(loc["reference_id"])

            # 2. Call the public database API to delete and record HMACs
            with self.db.transaction():
                self.db.purge_file_permanently(file_id)

            self.notifications.notify("Purged", "Permanently vacuumed file.", "info")
            self.refresh_trash()

        except Exception as exc:
            logger.error("Failed to purge file permanently: %s", exc)
            text = f"Failed to purge file: {exc}"
            QTimer.singleShot(0, lambda: QMessageBox.critical(self, "Error", text))

    def on_empty_trash_clicked(self) -> None:
        reply = QMessageBox.question(
            self, "Empty Trash Bin", "Permanently vacuum all files in the Trash Bin?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            for file_id in list(self._trash_file_ids):
                asyncio.create_task(self._purge_file_permanent_task(file_id))

    def soft_delete_file_sync(self, file_id: str) -> None:
        if not self.db:
            return
        try:
            with self.db.transaction():
                self.db.tombstone_file(file_id)
        except Exception as exc:
            logger.error("Failed to soft-delete file synchronously: %s", exc)

    def navigate_up(self) -> None:
        if self.current_folder_path == "/files":
            return
        parts = self.current_folder_path.split("/")
        if len(parts) > 2:
            self.current_folder_path = "/".join(parts[:-1])
        else:
            self.current_folder_path = "/files"
        self.path_label.setText(f"Path: {self.current_folder_path}")
        self.refresh_files()

    def navigate_to_folder(self, folder_name: str) -> None:
        self.current_folder_path = f"{self.current_folder_path}/{folder_name}"
        self.path_label.setText(f"Path: {self.current_folder_path}")
        self.refresh_files()

    def on_table_double_clicked(self, row: int, col: int) -> None:
        if 0 <= row < len(self._table_item_types):
            if self._table_item_types[row] == "folder":
                folder_name = self._table_file_ids[row]
                self.navigate_to_folder(folder_name)

    def get_selected_file_ids(self) -> list:
        selected_rows = set()
        for item in self.files_table.selectedItems():
            selected_rows.add(item.row())
        
        file_ids = []
        for r in sorted(list(selected_rows)):
            if r < len(self._table_item_types) and self._table_item_types[r] == "file":
                file_ids.append(self._table_file_ids[r])
        return file_ids

    def get_selected_trash_ids(self) -> list:
        selected_rows = set()
        for item in self.trash_table.selectedItems():
            selected_rows.add(item.row())
        
        file_ids = []
        for r in sorted(list(selected_rows)):
            if r < len(self._trash_file_ids):
                file_ids.append(self._trash_file_ids[r])
        return file_ids

    def restore_selected_trash(self) -> None:
        selected_ids = self.get_selected_trash_ids()
        if not selected_ids:
            return
        try:
            with self.db.transaction():
                for file_id in selected_ids:
                    self.db.restore_file(file_id)
            self.notifications.notify("Files Restored", f"Restored {len(selected_ids)} file(s) to dashboard.", "success")
            self.refresh_files()
            self.refresh_trash()
        except Exception as exc:
            QMessageBox.critical(self, "Error", f"Failed to restore selected files: {exc}")

    def purge_selected_trash(self) -> None:
        selected_ids = self.get_selected_trash_ids()
        if not selected_ids:
            return
        reply = QMessageBox.question(
            self, "Permanent Purge", f"Are you sure you want to permanently delete {len(selected_ids)} selected file(s) and all their backend chunks?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            for file_id in selected_ids:
                asyncio.create_task(self._purge_file_permanent_task(file_id))

    def show_files_context_menu(self, pos) -> None:
        selected_ids = self.get_selected_file_ids()
        if not selected_ids:
            return
        
        menu = QMenu(self)
        menu.setStyleSheet("QMenu { background-color: #18181b; border: 1px solid #27272a; color: #f4f4f5; }")
        
        down_act = menu.addAction("Download Selected")
        delete_act = menu.addAction("Delete Selected")
        
        act = menu.exec(self.files_table.viewport().mapToGlobal(pos))
        if act == down_act:
            self.on_download_selected_clicked()
        elif act == delete_act:
            self.on_delete_selected_clicked()

    def show_trash_context_menu(self, pos) -> None:
        selected_ids = self.get_selected_trash_ids()
        if not selected_ids:
            return
            
        menu = QMenu(self)
        menu.setStyleSheet("QMenu { background-color: #18181b; border: 1px solid #27272a; color: #f4f4f5; }")
        
        rest_act = menu.addAction("Restore Selected")
        purge_act = menu.addAction("Purge Permanently")
        
        act = menu.exec(self.trash_table.viewport().mapToGlobal(pos))
        if act == rest_act:
            self.restore_selected_trash()
        elif act == purge_act:
            self.purge_selected_trash()
