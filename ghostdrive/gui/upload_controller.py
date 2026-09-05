"""
upload_controller.py -- MainWindow controller mixin handling file ingestion and async chunk uploading.
"""

import uuid
import time
import logging
import asyncio
import qasync
import mimetypes
from pathlib import Path
from datetime import datetime, timezone

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import QFileDialog, QMessageBox, QDialog, QLabel, QProgressBar, QTableWidgetItem
from ghostdrive.gui.widgets import StyledButton

logger = logging.getLogger(__name__)

class UploadControllerMixin:
    """Mixin controller containing file ingestion, chunking, and upload progress tracking."""

    def on_manual_upload_clicked(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Upload")
        if file_path:
            self.ingest_file(file_path)

    @qasync.asyncSlot()
    async def ingest_file(self, file_path_str: str) -> None:
        """Run the ingestion pipeline (Tier Advisor, key derivation, upload scheduling)."""
        if getattr(self, "_shutting_down", False):
            logger.warning("Shutdown in progress. Rejecting new upload task: %s", file_path_str)
            return

        if getattr(self, "_read_only_mode", False):
            QMessageBox.warning(self, "Read-Only Mode", "Drive is in read-only emergency mode. Uploads are disabled.")
            return

        path = Path(file_path_str)
        if not path.exists() or not path.is_file():
            return

        file_name = path.name
        file_size = path.stat().st_size
        
        mime_type, _ = mimetypes.guess_type(file_path_str)
        mime_type = mime_type or "application/octet-stream"

        # Check duplicate file conflicts in the current virtual directory context
        target_path = f"{self.current_folder_path}/{file_name}"
        conflict_row = None
        if self.db:
            try:
                with self.db.transaction():
                    conflict_row = self.db._conn.execute(
                        "SELECT id FROM files WHERE tombstone = 0 AND path = ?",
                        (target_path,)
                    ).fetchone()
            except Exception as exc:
                logger.error("Failed to query conflict checks: %s", exc)

        if conflict_row:
            from ghostdrive.gui.dialogs import DuplicateConflictDialog
            conflict_dialog = DuplicateConflictDialog(file_name, self)
            if conflict_dialog.exec() != QDialog.DialogCode.Accepted:
                return
            
            action = conflict_dialog.selected_action
            if action == "cancel":
                return
            elif action == "overwrite":
                self.soft_delete_file_sync(conflict_row["id"])
            elif action == "rename":
                base_name = path.stem
                ext = path.suffix
                counter = 1
                while True:
                    new_name = f"{base_name}_{counter}{ext}"
                    new_path = f"{self.current_folder_path}/{new_name}"
                    with self.db.transaction():
                        exists = self.db._conn.execute(
                            "SELECT id FROM files WHERE tombstone = 0 AND path = ?",
                            (new_path,)
                        ).fetchone()
                    if not exists:
                        file_name = new_name
                        target_path = new_path
                        break
                    counter += 1

        # 1. Trigger the Storage Tier Advisor Dialog
        from ghostdrive.gui.main_view import TierAdvisorDialog
        dialog = TierAdvisorDialog(self, file_name, file_size, mime_type)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        tier = dialog.selected_tier
        file_id = str(uuid.uuid4())
        now_str = datetime.now(timezone.utc).isoformat()

        # Generate thumbnail blob at ingestion time if it is an image/PDF
        thumbnail_blob = await asyncio.to_thread(_generate_thumbnail_sync, path)

        # 2. Insert File Record in DB
        file_record = {
            "id": file_id,
            "name": file_name,
            "path": target_path,
            "size": file_size,
            "mime_type": mime_type,
            "tier": tier,
            "created_at": now_str,
            "modified_at": now_str,
            "version": 1,
            "version_of": None,
            "tombstone": 0,
            "tombstone_at": None,
            "thumbnail_blob": thumbnail_blob,
        }
        
        try:
            with self.db.transaction():
                self.db.insert_file(file_record)
            self.add_activity_log(f"Ingested '{file_name}' as {tier} tier.")
        except Exception as exc:
            QMessageBox.critical(self, "Database Error", f"Failed to record file in index ledger: {exc}")
            return

        # 3. Resolve active replication targets based on tier
        backends = self._resolve_backends_for_tier(tier)
        if not backends:
            QMessageBox.critical(self, "Ingestion Error", "No healthy storage backends available for upload.")
            return

        # Pre-flight disk space check
        for b in backends:
            try:
                free_space = await b.available_space()
                if free_space > 0 and free_space < file_size:
                    QMessageBox.critical(
                        self, "Insufficient Space",
                        f"Backend '{b.id}' ({b.type.upper()}) has insufficient space.\n"
                        f"Required: {self._format_bytes(file_size)}\n"
                        f"Available: {self._format_bytes(free_space)}"
                    )
                    return
            except Exception as exc:
                logger.warning("Failed to check available space on backend %s: %s", b.id, exc)

        # 4. Split into chunks and enqueue
        from ghostdrive.pipeline.chunker import split_file
        logical_chunk_size = min(getattr(b, "logical_chunk_bytes", 50*1024*1024) for b in backends)
        
        try:
            chunks = list(split_file(path, logical_chunk_bytes=logical_chunk_size))
        except Exception as exc:
            QMessageBox.critical(self, "Chunking Error", f"Failed to slice file into chunks: {exc}")
            return

        # 5. Start uploading chunks asynchronously
        self.notifications.notify("Upload Started", f"Ingesting '{file_name}' as {tier} tier...", "info")
        
        secure_erase = getattr(dialog, "secure_erase_original", False)
        total_uploads = len(backends) * len(chunks)
        if secure_erase:
            if not hasattr(self, "_active_file_uploads"):
                self._active_file_uploads = {}
            self._active_file_uploads[file_id] = {
                "path": path,
                "name": file_name,
                "total_uploads": total_uploads,
                "completed_uploads": set(),
            }

        for b_obj in backends:
            for desc in chunks:
                queue_row = self._add_to_queue_table(file_name, desc.chunk_index, len(chunks), b_obj.type)
                task = asyncio.create_task(
                    self.upload_chunk_task(path, desc, file_id, mime_type, b_obj, queue_row)
                )
                if hasattr(self, "_upload_tasks"):
                    self._upload_tasks.add(task)
                    task.add_done_callback(self._upload_tasks.discard)

    def _resolve_backends_for_tier(self, tier: str) -> list:
        critical_rep = int(self.db.get_setting("rep_critical", "4"))
        important_rep = int(self.db.get_setting("rep_important", "3"))
        disposable_rep = int(self.db.get_setting("rep_disposable", "2"))
        needed_count = critical_rep if tier == "CRITICAL" else (important_rep if tier == "IMPORTANT" else disposable_rep)
        
        tier_key = f"routing_{tier.lower()}_backends"
        routing_ids_str = self.db.get_setting(tier_key, "")
        routing_ids = [x.strip() for x in routing_ids_str.split(",") if x.strip()]

        try:
            with self.db.transaction():
                rows = self.db._conn.execute(
                    "SELECT id, type FROM backends WHERE status = 'healthy' ORDER BY priority DESC"
                ).fetchall()
        except Exception as exc:
            logger.error("Failed to query backends list: %s", exc)
            return []

        if routing_ids:
            filtered_rows = [r for r in rows if r["id"] in routing_ids]
            if filtered_rows:
                rows = filtered_rows

        resolved = []
        for r in rows:
            b_id = r["id"]
            b_obj = self.active_backends.get(b_id) or self.active_backends.get(r["type"])
            if b_obj:
                resolved.append(b_obj)
                if len(resolved) >= needed_count:
                    break
        return resolved

    def _table_item(self, text: str) -> QTableWidgetItem:
        item = QTableWidgetItem(text)
        item.setFlags(Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled)
        return item

    def _add_to_queue_table(self, name: str, idx: int, total: int, backend_name: str) -> int:
        r_idx = self.queue_table.rowCount()
        self.queue_table.insertRow(r_idx)
        
        self.queue_table.setItem(r_idx, 0, self._table_item(name))
        self.queue_table.setItem(r_idx, 1, self._table_item(f"Chunk {idx+1}/{total}"))
        self.queue_table.setItem(r_idx, 2, self._table_item(backend_name.upper()))
        
        progress_bar = QProgressBar(self.queue_table)
        progress_bar.setValue(0)
        progress_bar.setStyleSheet("QProgressBar { height: 16px; text-align: center; }")
        self.queue_table.setCellWidget(r_idx, 3, progress_bar)
        
        self.queue_table.setItem(r_idx, 4, self._table_item("Queued"))
        return r_idx

    def _update_queue_status(self, row: int, progress: int, speed_mbs: float = 0.0, failed: bool = False, retry_slot=None) -> None:
        p_bar = self.queue_table.cellWidget(row, 3)
        if isinstance(p_bar, QProgressBar):
            p_bar.setValue(progress)

        status_item = self.queue_table.item(row, 4)
        if status_item:
            if failed:
                status_item.setText("Failed")
                status_item.setForeground(QColor("#ef4444"))
                if retry_slot:
                    # Action button: Retry
                    retry_btn = StyledButton("Retry", self.queue_table, secondary=True)
                    retry_btn.clicked.connect(retry_slot)
                    self.queue_table.setCellWidget(row, 4, retry_btn)
            elif progress == 100:
                status_item.setText("Completed")
                status_item.setForeground(QColor("#10b981"))
                # Remove progress bar, draw finished label
                lbl = QLabel("100% finished")
                lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
                lbl.setStyleSheet("color: #10b981; font-weight: bold;")
                self.queue_table.setCellWidget(row, 3, lbl)
            else:
                status_item.setText(f"Uploading ({speed_mbs:.1f} MB/s)" if speed_mbs > 0 else "Uploading...")

    async def upload_chunk_task(self, path: Path, desc, file_id: str, mime_type: str, backend_obj, queue_row: int) -> None:
        """Performs encryption and network transmission on a thread-pool."""
        from ghostdrive.pipeline.upload import ChunkUploader
        from ghostdrive.crypto.nonce import NonceManager

        self.active_uploads += 1
        if hasattr(self, "queue_card") and self.queue_card:
            self.queue_card.setVisible(True)
        try:
            self._update_queue_status(queue_row, 10, 0.0)

            nonce_mgr = NonceManager(data_dir=Path(".nonces") / backend_obj.type, db=self.db)
            uploader = ChunkUploader(
                db=self.db,
                backend=backend_obj,
                master_key=self.km.master_key,
                hkdf_salt=self.km.hkdf_salt,
                nonce_manager=nonce_mgr,
                active_backends=getattr(self, "active_backends", None)
            )

            # Connect on-demand
            if not getattr(backend_obj, "_connected", False):
                await backend_obj.connect()
                backend_obj._connected = True

            self._update_queue_status(queue_row, 30, 0.0)

            t0 = time.perf_counter()
            # Upload chunk
            await uploader.upload_chunk(path, desc, file_id, mime_type)
            duration = time.perf_counter() - t0

            speed = (desc.size / (1024 * 1024)) / max(0.1, duration)
            self._update_queue_status(queue_row, 100, speed)

            # Mark upload as completed for this backend and chunk
            if hasattr(self, "_active_file_uploads") and file_id in self._active_file_uploads:
                info = self._active_file_uploads[file_id]
                info["completed_uploads"].add((backend_obj.type, desc.chunk_index))
                if len(info["completed_uploads"]) == info["total_uploads"]:
                    self._active_file_uploads.pop(file_id)
                    asyncio.create_task(self.secure_erase_original_file(info["path"], info["name"]))

            # Refresh views
            self.refresh_files()
            self.telemetry_view.set_current_speed(speed)
            QTimer.singleShot(2500, lambda: self.telemetry_view.set_current_speed(0.0))
            self.add_activity_log(f"Uploaded chunk {desc.chunk_index+1} of '{path.name}' to {backend_obj.type.upper()}.")

        except Exception as exc:
            logger.error("Chunk upload task failed: %s", exc)
            
            # Setup retry trigger slot
            def retry_slot():
                return self.trigger_chunk_retry(path, desc, file_id, mime_type, backend_obj, queue_row)
            self._update_queue_status(queue_row, 0, 0.0, failed=True, retry_slot=retry_slot)
            
            self.notifications.notify(
                "Upload Failed", 
                f"Failed to upload chunk {desc.chunk_index+1} of '{path.name}' to {backend_obj.type.upper()}.",
                "important"
            )
            self.add_activity_log(f"Failed chunk {desc.chunk_index+1} upload of '{path.name}' to {backend_obj.type.upper()}.")
        finally:
            self.active_uploads = max(0, self.active_uploads - 1)
            if self.active_uploads == 0:
                if hasattr(self, "queue_card") and self.queue_card:
                    self.queue_card.setVisible(False)

    def trigger_chunk_retry(self, path: Path, desc, file_id: str, mime_type: str, backend_obj, queue_row: int) -> None:
        # Clear status and start task again
        task = asyncio.create_task(
            self.upload_chunk_task(path, desc, file_id, mime_type, backend_obj, queue_row)
        )
        if hasattr(self, "_upload_tasks"):
            self._upload_tasks.add(task)
            task.add_done_callback(self._upload_tasks.discard)

    async def secure_erase_original_file(self, path: Path, file_name: str) -> None:
        """Securely erases the original file after successful ingestion to Hidden Space."""
        from ghostdrive.platform.secure_erase import SecureEraseLevel
        from ghostdrive.pipeline.secure_erase import DestructiveOperationGuard, SecureEraseOperation
        import blake3
        import uuid
        
        logger.info("Starting secure erase of original file for Hidden Space: %s", path)
        try:
            # Register allowed path in the guard
            DestructiveOperationGuard.allow_path(path)
            
            # Construct a SecureEraseOperation for the guard
            dry_run_details = f"L1-FILE:{path.resolve()}:{path.stat().st_size}"
            dry_run_hash = blake3.blake3(dry_run_details.encode()).hexdigest()
            
            op = SecureEraseOperation(
                id=str(uuid.uuid4()),
                op_level="L1",
                op_type="file_erase",
                target_path=path,
                target_label=file_name,
                method="software_overwrite",
                initiated_by="user",
                dry_run_hash=dry_run_hash,
                session_id="hidden-space-ingestion",
            )
            
            # Execute secure erase using the DestructiveOperationGuard
            guard = DestructiveOperationGuard()
            await guard.execute_erase(op, self.db, vault_dir=Path(".nonexistent"), erase_level=SecureEraseLevel.PASS_3)
            
            # Notify the user
            self.notifications.notify(
                "Hidden Space Ingestion",
                f"Securely wiped original file '{file_name}' from disk. File now exists only in your secure Hidden Space.",
                "success"
            )
            self.add_activity_log(f"Securely wiped original file '{file_name}' after ingestion to Hidden Space.")
            
        except Exception as exc:
            logger.error("Failed to securely erase original file: %s", exc)
            self.notifications.notify(
                "Hidden Space Warning",
                f"Failed to securely erase original file '{file_name}': {exc}",
                "important"
            )


def _generate_thumbnail_sync(file_path: Path) -> bytes | None:
    suffix = file_path.suffix.lower()
    try:
        if suffix in (".jpg", ".jpeg", ".png", ".bmp", ".gif", ".webp"):
            from PIL import Image
            with Image.open(file_path) as img:
                img.thumbnail((100, 100))
                from io import BytesIO
                buf = BytesIO()
                img.save(buf, format="PNG")
                return buf.getvalue()
        elif suffix == ".pdf":
            import fitz
            doc = fitz.open(file_path)
            thumbnail_blob = None
            if doc.page_count > 0:
                page = doc.load_page(0)
                zoom = 2.0
                mat = fitz.Matrix(zoom, zoom)
                pix = page.get_pixmap(matrix=mat)
                thumbnail_blob = pix.tobytes("png")
            doc.close()
            return thumbnail_blob
    except Exception as e:
        logger.error("Failed to generate ingestion thumbnail: %s", e)
    return None

