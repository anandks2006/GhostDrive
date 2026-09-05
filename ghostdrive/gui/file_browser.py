"""
file_browser.py -- MainWindow controller mixin handling file browsing, list/grid views, search, downloads, and trash operations.
"""

import os
from pathlib import Path
try:
    import sqlcipher3 as sqlite3
except ImportError:
    try:
        import pysqlcipher3 as sqlite3  # type: ignore
    except ImportError:
        import sqlite3
import uuid
import logging
import asyncio
from datetime import datetime, timezone
from typing import Optional, Any

from PyQt6.QtCore import Qt, QSize, QObject, pyqtSignal, QTimer
from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QTableWidgetItem,
    QMessageBox,
    QMenu,
    QFileDialog,
)

from ghostdrive.gui.widgets import StyledButton, ThumbnailWidget, ClickableGlassCard

logger = logging.getLogger(__name__)


class ProgressSignaler(QObject):
    progress = pyqtSignal(int)
    completed = pyqtSignal()
    failed = pyqtSignal(str)

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

        # Dynamically refresh unique tags lists
        if not hasattr(self, "_refreshing_tags"):
            self._refreshing_tags = True
            try:
                self.refresh_tags_combo()
            finally:
                delattr(self, "_refreshing_tags")
                
        query = self.search_input.text().strip()
        tier_filter = self.tier_filter_combo.currentText()
        tag_filter = self.tag_filter_combo.currentText() if hasattr(self, "tag_filter_combo") else "All Tags"
        
        try:
            with self.db.transaction():
                sql = "SELECT * FROM files WHERE tombstone = 0"
                params = []
                
                use_fts = False
                if query:
                    use_fts = True
                    sql += " AND id IN (SELECT file_id FROM files_fts WHERE files_fts MATCH ?)"
                    cleaned_query = query.replace('"', '""')
                    params.append(f'{cleaned_query}*')
                    
                if tier_filter != "All Tiers":
                    sql += " AND tier = ?"
                    params.append(tier_filter)
                if tag_filter != "All Tags":
                    sql += " AND tags LIKE ?"
                    params.append(f"%{tag_filter}%")
                sql += " ORDER BY created_at DESC"
                
                try:
                    rows = self.db._conn.execute(sql, params).fetchall()
                except sqlite3.OperationalError:
                    if use_fts:
                        sql = "SELECT * FROM files WHERE tombstone = 0 AND name LIKE ?"
                        params = [f"%{query}%"]
                        if tier_filter != "All Tiers":
                            sql += " AND tier = ?"
                            params.append(tier_filter)
                        if tag_filter != "All Tags":
                            sql += " AND tags LIKE ?"
                            params.append(f"%{tag_filter}%")
                        sql += " ORDER BY created_at DESC"
                        rows = self.db._conn.execute(sql, params).fetchall()
                    else:
                        raise

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

            self.refresh_folder_tree()
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
        if not hasattr(self, "_search_timer"):
            self._search_timer = QTimer()
            self._search_timer.setSingleShot(True)
            self._search_timer.timeout.connect(self.refresh_files)
        self._search_timer.start(300)  # 300ms debounce delay

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
                self.quick_download_btn.setVisible(False)
                self.delete_btn.setVisible(False)
                if hasattr(self, "tags_label"):
                    self.tags_label.setVisible(False)
                    self.tags_input.setVisible(False)
                    self.save_tags_btn.setVisible(False)
                if hasattr(self, "version_history_label"):
                    self.version_history_label.setVisible(False)
                    self.version_list.setVisible(False)
                    self.restore_version_btn.setVisible(False)

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
        self.quick_download_btn.setVisible(True)
        self.delete_btn.setVisible(True)
        if hasattr(self, "tags_label"):
            self.tags_label.setVisible(True)
            self.tags_input.setText(file_row.get("tags", ""))
            self.tags_input.setVisible(True)
            self.save_tags_btn.setVisible(True)
        if hasattr(self, "version_history_label"):
            self.version_list.clear()
            try:
                with self.db.transaction():
                    versions = self.db.get_file_versions(file_row["id"])
                from PyQt6.QtWidgets import QListWidgetItem
                for v in versions:
                    ts = v['created_at'].replace('T', ' ')[:19]
                    v_name = f"v{v['version']} - {ts}"
                    if v["id"] == file_row["id"]:
                        v_name += " (Active)"
                    item = QListWidgetItem(v_name)
                    item.setData(Qt.ItemDataRole.UserRole, v["id"])
                    self.version_list.addItem(item)
                self.version_history_label.setVisible(True)
                self.version_list.setVisible(True)
                self.restore_version_btn.setVisible(True)
            except Exception as exc:
                logger.error("Failed to load versions for metadata: %s", exc)

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

    def on_save_to_downloads_clicked(self) -> None:
        """Download selected file directly to the user's Downloads folder without prompting."""
        selected_ids = self.get_selected_file_ids()
        if not selected_ids:
            if hasattr(self, "selected_file_row") and self.selected_file_row:
                selected_ids = [self.selected_file_row["id"]]
            else:
                return

        from PyQt6.QtCore import QStandardPaths
        downloads_dir = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.DownloadLocation)
        if not downloads_dir or not os.path.exists(downloads_dir):
            downloads_dir = os.path.expanduser("~/Downloads")
            
        for f_id in selected_ids:
            with self.db.transaction():
                file_row = self.db._conn.execute(
                    "SELECT * FROM files WHERE id = ?", (f_id,)
                ).fetchone()
            if file_row:
                save_path = os.path.join(downloads_dir, file_row["name"])
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
        from PyQt6.QtWidgets import QProgressDialog
        from PyQt6.QtCore import QEventLoop
        
        temp_dir = tempfile.gettempdir()
        save_path = os.path.join(temp_dir, file_row["name"])
        
        if os.path.exists(save_path):
            return save_path
            
        self.notifications.notify("Exporting File", f"Preparing '{file_row['name']}' for drag-export...", "info")
        
        # Setup QProgressDialog with custom styling
        progress_dialog = QProgressDialog("Downloading file...", "Cancel", 0, 100, self)
        progress_dialog.setWindowTitle("Exporting File")
        progress_dialog.setWindowModality(Qt.WindowModality.WindowModal)
        progress_dialog.setMinimumDuration(0)
        progress_dialog.setValue(0)
        progress_dialog.setStyleSheet("""
            QProgressDialog {
                background-color: #18181b;
                border: 1px solid rgba(255, 255, 255, 0.08);
                border-radius: 12px;
            }
            QLabel {
                color: #f4f4f5;
                font-size: 12px;
            }
            QProgressBar {
                background-color: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 6px;
                text-align: center;
                color: #ffffff;
                font-weight: bold;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #a855f7, stop:1 #6366f1);
                border-radius: 5px;
            }
            QPushButton {
                background-color: rgba(255, 255, 255, 0.08);
                border: 1px solid rgba(255, 255, 255, 0.15);
                border-radius: 6px;
                color: #f4f4f5;
                padding: 6px 12px;
            }
            QPushButton:hover {
                background-color: rgba(255, 255, 255, 0.15);
            }
        """)
        
        signaler = ProgressSignaler()
        signaler.progress.connect(progress_dialog.setValue)
        
        loop = QEventLoop()
        
        cancelled = False
        def on_cancel():
            nonlocal cancelled
            cancelled = True
            loop.quit()
        
        progress_dialog.canceled.connect(on_cancel)
        
        error_msg = None
        def on_completed():
            loop.quit()
            
        def on_failed(err):
            nonlocal error_msg
            error_msg = err
            loop.quit()
            
        signaler.completed.connect(on_completed)
        signaler.failed.connect(on_failed)
        
        def run_async_in_thread():
            thread_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(thread_loop)
            try:
                thread_loop.run_until_complete(
                    self._download_file_core(
                        file_row,
                        save_path,
                        progress_callback=lambda p: signaler.progress.emit(p),
                        cancel_check=lambda: cancelled
                    )
                )
                if not cancelled:
                    signaler.completed.emit()
            except Exception as e:
                logger.error("Sync download for drag failed: %s", e)
                signaler.failed.emit(str(e))
            finally:
                thread_loop.close()
                
        t = threading.Thread(target=run_async_in_thread)
        t.start()
        
        loop.exec()
        progress_dialog.close()
        
        if cancelled or error_msg:
            t.join()
            if os.path.exists(save_path):
                try:
                    os.remove(save_path)
                except Exception as cleanup_exc:
                    logger.error("Failed to delete cancelled download file: %s", cleanup_exc)
            
            if error_msg and not cancelled:
                QMessageBox.critical(self, "Download Error", f"Failed to download/decrypt file during drag-out:\n{error_msg}")
            return ""
            
        t.join()
        if os.path.exists(save_path):
            return save_path
        return ""

    async def _download_file_core(
        self,
        file_row: dict,
        save_path: str,
        progress_callback: Optional[Any] = None,
        cancel_check: Optional[Any] = None
    ) -> None:
        # Fetch all chunks and locations from DB
        with self.db.transaction():
            chunks = self.db._conn.execute(
                "SELECT * FROM chunks WHERE file_id = ? ORDER BY chunk_index ASC",
                (file_row["id"],)
            ).fetchall()

        decrypted_data = bytearray()

        for idx, chunk in enumerate(chunks):
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
            chunk_ciphertext = bytearray()
            
            # Check local cache first
            cache_dir = Path(os.path.expanduser("~")) / ".ghostdrive" / "cache"
            chunk_path = cache_dir / chunk["id"]
            if chunk_path.exists():
                chunk_ciphertext = bytearray(chunk_path.read_bytes())
                
            if chunk_ciphertext:
                try:
                    from ghostdrive.crypto.nonce import NonceManager
                    from ghostdrive.crypto.chunk_crypto import ChunkDecryptor
                    from ghostdrive.crypto.hkdf import derive_chunk_key

                    # Check if there is a shared chunk key in SecretsVault
                    chunk_key = None
                    try:
                        from ghostdrive.crypto.secrets_vault import SecretsVault
                        vault = SecretsVault(self.db, self.km.master_key, self.km.hkdf_salt)
                        secrets = vault.list_secrets("password")
                        for s in secrets:
                            if s["label"] == f"share_key_{file_row['id']}":
                                chunk_key = bytes.fromhex(s["payload"]["chunk_key_hex"])
                                break
                    except Exception:
                        pass
                    if chunk_key is None:
                        chunk_key = derive_chunk_key(self.km.master_key, self.km.hkdf_salt)
                    nonce = NonceManager.counter_to_nonce(chunk["nonce_counter"])

                    tag = chunk_ciphertext[-16:]
                    ct_body = chunk_ciphertext[:-16]

                    decryptor = ChunkDecryptor(key=chunk_key, nonce=nonce, expected_tag=tag)
                    
                    from ghostdrive.crypto.chunk_crypto import BLOCK_SIZE
                    offset = 0
                    while offset < len(ct_body):
                        block = ct_body[offset : offset + BLOCK_SIZE]
                        decryptor.feed(block)
                        offset += BLOCK_SIZE
                        
                    chunk_plaintext = decryptor.verify_and_decrypt()
                except Exception as e:
                    logger.warning("Failed to decrypt chunk %s from local cache: %s", chunk["id"][:8], e)
                    chunk_ciphertext = bytearray()

            if not chunk_plaintext:
                if chunk["sub_block_count"] >= 6:
                    # Erasure coding reassembly
                    shards_by_idx = {}
                    for shard_loc in locs:
                        if shard_loc["sub_block_index"] not in shards_by_idx:
                            shards_by_idx[shard_loc["sub_block_index"]] = shard_loc
                            
                    downloaded_shards = {}
                    for sub_idx, loc in sorted(shards_by_idx.items()):
                        if len(downloaded_shards) >= 4:
                            break
                        b_id = loc["backend_id"]
                        backend_obj = self.active_backends.get(b_id) or self.active_backends.get(loc["type"])
                        if not backend_obj:
                            continue
                        try:
                            if not getattr(backend_obj, "_connected", False):
                                await backend_obj.connect()
                                backend_obj._connected = True
                                
                            ct_blocks = bytearray()
                            async for block in backend_obj.download(loc["reference_id"]):
                                ct_blocks.extend(block)
                            if ct_blocks:
                                downloaded_shards[sub_idx] = bytes(ct_blocks)
                        except Exception as e:
                            logger.error("Failed to download shard index %d: %s", sub_idx, e)
                            
                    if len(downloaded_shards) < 4:
                        raise ValueError(f"CRITICAL: Insufficient shards available to reconstruct chunk index {chunk['chunk_index']}.")
                        
                    # Reconstruct zfec
                    padlen = (chunk["sub_block_count"] - 6) // 10
                    blocks = []
                    sharenums = []
                    for sub_idx in sorted(downloaded_shards.keys()):
                        if len(blocks) < 4:
                            blocks.append(downloaded_shards[sub_idx])
                            sharenums.append(sub_idx)
                            
                    from zfec.easyfec import Decoder
                    dec = Decoder(4, 6)
                    chunk_ciphertext = dec.decode(blocks, sharenums, padlen)
                    
                    # Decrypt reconstructed chunk
                    from ghostdrive.crypto.nonce import NonceManager
                    from ghostdrive.crypto.chunk_crypto import ChunkDecryptor
                    from ghostdrive.crypto.hkdf import derive_chunk_key

                    chunk_key = None
                    try:
                        from ghostdrive.crypto.secrets_vault import SecretsVault
                        vault = SecretsVault(self.db, self.km.master_key, self.km.hkdf_salt)
                        secrets = vault.list_secrets("password")
                        for s in secrets:
                            if s["label"] == f"share_key_{file_row['id']}":
                                chunk_key = bytes.fromhex(s["payload"]["chunk_key_hex"])
                                break
                    except Exception:
                        pass
                    if chunk_key is None:
                        chunk_key = derive_chunk_key(self.km.master_key, self.km.hkdf_salt)
                    nonce = NonceManager.counter_to_nonce(chunk["nonce_counter"])

                    tag = chunk_ciphertext[-16:]
                    ct_body = chunk_ciphertext[:-16]

                    decryptor = ChunkDecryptor(key=chunk_key, nonce=nonce, expected_tag=tag)
                    
                    from ghostdrive.crypto.chunk_crypto import BLOCK_SIZE
                    offset = 0
                    while offset < len(ct_body):
                        block = ct_body[offset : offset + BLOCK_SIZE]
                        decryptor.feed(block)
                        offset += BLOCK_SIZE
                        
                    chunk_plaintext = decryptor.verify_and_decrypt()
                else:
                    for loc in locs:
                        b_id = loc["backend_id"]
                        backend_obj = self.active_backends.get(b_id) or self.active_backends.get(loc["type"])
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

                            # Check if there is a shared chunk key in SecretsVault
                            chunk_key = None
                            try:
                                from ghostdrive.crypto.secrets_vault import SecretsVault
                                vault = SecretsVault(self.db, self.km.master_key, self.km.hkdf_salt)
                                secrets = vault.list_secrets("password")
                                for s in secrets:
                                    if s["label"] == f"share_key_{file_row['id']}":
                                        chunk_key = bytes.fromhex(s["payload"]["chunk_key_hex"])
                                        break
                            except Exception:
                                pass
                            if chunk_key is None:
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
                            logger.error("Download/Decryption failed for chunk %s on %s: %s", chunk["id"][:8], loc["type"], e)
                            
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

            if cancel_check and cancel_check():
                raise ValueError("Download cancelled by user.")
            if progress_callback:
                total_chunks = len(chunks) or 1
                percent = int(((idx + 1) / total_chunks) * 100)
                progress_callback(percent)

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
                self.quick_download_btn.setVisible(False)
                self.delete_btn.setVisible(False)
                if hasattr(self, "tags_label"):
                    self.tags_label.setVisible(False)
                    self.tags_input.setVisible(False)
                    self.save_tags_btn.setVisible(False)
                if hasattr(self, "version_history_label"):
                    self.version_history_label.setVisible(False)
                    self.version_list.setVisible(False)
                    self.restore_version_btn.setVisible(False)
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
                    b_id = loc["backend_id"]
                    backend_obj = self.active_backends.get(b_id) or self.active_backends.get(loc["type"])
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
                    b_id = loc["backend_id"]
                    backend_obj = self.active_backends.get(b_id) or self.active_backends.get(loc["type"])
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
        save_down_act = menu.addAction("Save to Downloads")
        
        # Batch operations submenu
        batch_menu = menu.addMenu("Batch Operations")
        batch_menu.setStyleSheet("QMenu { background-color: #18181b; border: 1px solid #27272a; color: #f4f4f5; }")
        batch_tag_act = batch_menu.addAction("Tag Selected...")
        batch_move_act = batch_menu.addAction("Move Selected...")
        batch_retier_act = batch_menu.addAction("Change Storage Tier...")
        
        delete_act = menu.addAction("Delete Selected")
        
        act = menu.exec(self.files_table.viewport().mapToGlobal(pos))
        if act == down_act:
            self.on_download_selected_clicked()
        elif act == save_down_act:
            self.on_save_to_downloads_clicked()
        elif act == batch_tag_act:
            self.on_batch_tag_selected(selected_ids)
        elif act == batch_move_act:
            self.on_batch_move_selected(selected_ids)
        elif act == batch_retier_act:
            self.on_batch_retier_selected(selected_ids)
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

    def refresh_folder_tree(self) -> None:
        """Query all files, build a virtual tree of paths, and populate the folder tree sidebar."""
        if not self.db or not hasattr(self, "folder_tree"):
            return
            
        try:
            with self.db.transaction():
                # Get all unique paths of non-tombstone files
                rows = self.db._conn.execute("SELECT DISTINCT path FROM files WHERE tombstone = 0").fetchall()
        except Exception as exc:
            logger.error("Failed to query paths for folder tree: %s", exc)
            return

        folders = {"/files"}
        for row in rows:
            path = row["path"]
            parts = path.split("/")
            if len(parts) > 2:
                # Parent path is e.g. "/files/docs"
                parent_path = "/".join(parts[:-1])
                temp_parts = parts[:-1]
                for i in range(2, len(temp_parts) + 1):
                    folders.add("/".join(temp_parts[:i]))

        self.folder_tree.blockSignals(True)
        self.folder_tree.clear()
        
        from PyQt6.QtWidgets import QTreeWidgetItem
        path_to_item = {}
        sorted_folders = sorted(list(folders), key=lambda p: (p.count("/"), p))
        
        for folder_path in sorted_folders:
            name = folder_path.split("/")[-1] if folder_path != "/files" else "Files"
            item = QTreeWidgetItem([f"📁 {name}"])
            item.setData(0, Qt.ItemDataRole.UserRole, folder_path)
            
            if folder_path == "/files":
                self.folder_tree.addTopLevelItem(item)
                path_to_item[folder_path] = item
            else:
                parent_path = "/".join(folder_path.split("/")[:-1])
                parent_item = path_to_item.get(parent_path)
                if parent_item:
                    parent_item.addChild(item)
                    path_to_item[folder_path] = item
                else:
                    self.folder_tree.addTopLevelItem(item)
                    path_to_item[folder_path] = item
                    
        root_item = path_to_item.get("/files")
        if root_item:
            root_item.setExpanded(True)
            
        self.folder_tree.blockSignals(False)

    def on_folder_tree_item_clicked(self, item, column) -> None:
        folder_path = item.data(0, Qt.ItemDataRole.UserRole)
        if folder_path:
            self.current_folder_path = folder_path
            self.path_label.setText(f"Path: {self.current_folder_path}")
            self.refresh_files()

    def on_save_tags_clicked(self) -> None:
        """Save edited tags string to active selected file in the database."""
        if not hasattr(self, "selected_file_id") or not self.selected_file_id or not self.db:
            return
        
        tags_str = self.tags_input.text().strip()
        # Clean comma separated tags list
        tags_list = [t.strip() for t in tags_str.split(",") if t.strip()]
        cleaned_tags = ",".join(tags_list)
        
        try:
            with self.db.transaction():
                self.db.update_file_tags(self.selected_file_id, cleaned_tags)
            self.notifications.notify("Tags Updated", "Saved tags to file.", "success", overlay_only=True)
            self.add_activity_log(f"Updated tags for file to: {cleaned_tags}")
            
            # Update cache row tags value
            if hasattr(self, "selected_file_row") and self.selected_file_row:
                self.selected_file_row["tags"] = cleaned_tags
                
            self.refresh_files()
        except Exception as exc:
            logger.error("Failed to update tags in DB: %s", exc)
            QMessageBox.critical(self, "Error", f"Failed to save tags: {exc}")

    def refresh_tags_combo(self) -> None:
        """Query all files for unique tags and populate the tag filter combo box."""
        if not self.db or not hasattr(self, "tag_filter_combo"):
            return
            
        try:
            with self.db.transaction():
                rows = self.db._conn.execute("SELECT DISTINCT tags FROM files WHERE tombstone = 0 AND tags != ''").fetchall()
        except Exception as exc:
            logger.error("Failed to query tags: %s", exc)
            return

        unique_tags = set()
        for row in rows:
            for tag in row["tags"].split(","):
                cleaned = tag.strip()
                if cleaned:
                    unique_tags.add(cleaned)
                    
        self.tag_filter_combo.blockSignals(True)
        current_selection = self.tag_filter_combo.currentText()
        self.tag_filter_combo.clear()
        self.tag_filter_combo.addItem("All Tags")
        for tag in sorted(list(unique_tags)):
            self.tag_filter_combo.addItem(tag)
            
        idx = self.tag_filter_combo.findText(current_selection)
        if idx >= 0:
            self.tag_filter_combo.setCurrentIndex(idx)
        else:
            self.tag_filter_combo.setCurrentIndex(0)
        self.tag_filter_combo.blockSignals(False)

    def on_batch_tag_selected(self, selected_ids: list[str]) -> None:
        from PyQt6.QtWidgets import QInputDialog
        tag_str, ok = QInputDialog.getText(
            self, "Batch Tagging", "Enter tags to apply to selected files (comma-separated):"
        )
        if ok and tag_str:
            tags_list = [t.strip() for t in tag_str.split(",") if t.strip()]
            cleaned_tags = ",".join(tags_list)
            try:
                with self.db.transaction():
                    for file_id in selected_ids:
                        self.db.update_file_tags(file_id, cleaned_tags)
                self.notifications.notify("Batch Tagging Complete", f"Tagged {len(selected_ids)} file(s).", "success")
                self.refresh_files()
            except Exception as exc:
                QMessageBox.critical(self, "Error", f"Failed batch tagging: {exc}")

    def on_batch_move_selected(self, selected_ids: list[str]) -> None:
        from PyQt6.QtWidgets import QInputDialog
        target_dir, ok = QInputDialog.getText(
            self, "Batch Move", "Enter target virtual directory path (e.g. /files/docs):",
            text=self.current_folder_path
        )
        if ok and target_dir:
            target_dir = target_dir.strip()
            if not target_dir.startswith("/files"):
                QMessageBox.warning(self, "Invalid Path", "Paths must start with /files")
                return
            try:
                with self.db.transaction():
                    for file_id in selected_ids:
                        row = self.db._conn.execute("SELECT name FROM files WHERE id = ?", (file_id,)).fetchone()
                        if row:
                            new_path = f"{target_dir}/{row['name']}"
                            clock = self.db._increment_clock()
                            self.db._conn.execute(
                                "UPDATE files SET path = ?, logical_clock = ? WHERE id = ?",
                                (new_path, clock, file_id)
                            )
                            self.db._chain_hmac("files", {"op": "move_file", "id": file_id, "new_path": new_path})
                self.notifications.notify("Batch Move Complete", f"Moved {len(selected_ids)} file(s) to {target_dir}.", "success")
                self.refresh_files()
            except Exception as exc:
                QMessageBox.critical(self, "Error", f"Failed batch move: {exc}")

    def on_batch_retier_selected(self, selected_ids: list[str]) -> None:
        from PyQt6.QtWidgets import QInputDialog
        items = ["CRITICAL", "IMPORTANT", "DISPOSABLE"]
        tier, ok = QInputDialog.getItem(
            self, "Change Storage Tier", "Select new storage tier for selected files:", items, 0, False
        )
        if ok and tier:
            try:
                with self.db.transaction():
                    for file_id in selected_ids:
                        clock = self.db._increment_clock()
                        self.db._conn.execute(
                            "UPDATE files SET tier = ?, logical_clock = ? WHERE id = ?",
                            (tier, clock, file_id)
                        )
                        self.db._chain_hmac("files", {"op": "change_tier", "id": file_id, "tier": tier})
                self.notifications.notify("Batch Retier Complete", f"Changed tier of {len(selected_ids)} file(s) to {tier}.", "success")
                self.refresh_files()
            except Exception as exc:
                QMessageBox.critical(self, "Error", f"Failed batch retier: {exc}")

    def on_restore_version_clicked(self) -> None:
        """Restore selected version as the active file version in the metadata panel."""
        if not hasattr(self, "selected_file_id") or not self.selected_file_id or not self.db:
            return
            
        selected_item = self.version_list.currentItem()
        if not selected_item:
            QMessageBox.warning(self, "Selection Required", "Please select a version from the list to restore.")
            return
            
        version_id_to_restore = selected_item.data(Qt.ItemDataRole.UserRole)
        if version_id_to_restore == self.selected_file_id:
            QMessageBox.information(self, "Active Version", "The selected version is already the active version.")
            return
            
        try:
            with self.db.transaction():
                self.db.restore_file_version(self.selected_file_id, version_id_to_restore)
            self.notifications.notify("Version Restored", "Restored version successfully as active.", "success")
            self.add_activity_log(f"Restored version: {selected_item.text()}")
            
            # Refresh active file view
            self.refresh_files()
            
            # Update meta panel selection
            with self.db.transaction():
                # Since we created a new active version row, we query it (it will be the latest version in the chain)
                versions = self.db.get_file_versions(version_id_to_restore)
            if versions:
                self.show_file_metadata(dict(versions[0]))
        except Exception as exc:
            logger.error("Failed to restore version: %s", exc)
            QMessageBox.critical(self, "Error", f"Failed to restore version: {exc}")
