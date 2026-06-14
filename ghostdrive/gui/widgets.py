"""
widgets.py -- Reusable custom styled widgets for GhostDrive PyQt6 GUI.
"""

import os
from pathlib import Path
from typing import Optional
from PyQt6.QtCore import Qt, QSize, pyqtSignal, QThread
from PyQt6.QtGui import QPixmap, QIcon, QAction
from PyQt6.QtWidgets import (
    QWidget,
    QPushButton,
    QFrame,
    QLineEdit,
    QLabel,
    QVBoxLayout,
)

# Pillow & PyMuPDF (fitz) imports
try:
    from PIL import Image, ImageQt
except ImportError:
    Image = None

try:
    import fitz  # PyMuPDF
except ImportError:
    fitz = None


class GlassCard(QFrame):
    """Container widget mimicking modern acrylic/glassmorphic styling."""
    def __init__(self, parent: QWidget = None) -> None:
        super().__init__(parent)
        self.setObjectName("GlassCard")


class StyledButton(QPushButton):
    """Button widget conforming to theme stylesheet rules."""
    def __init__(self, text: str = "", parent: QWidget = None, primary: bool = False, danger: bool = False, secondary: bool = False) -> None:
        super().__init__(text, parent)
        if primary:
            self.setObjectName("PrimaryButton")
        elif danger:
            self.setObjectName("DangerButton")
        elif secondary:
            self.setObjectName("SecondaryButton")


class StyledLineEdit(QLineEdit):
    """Input line widget conforming to theme stylesheet rules."""
    def __init__(self, placeholder: str = "", parent: QWidget = None) -> None:
        super().__init__(parent)
        self.setPlaceholderText(placeholder)


class PasswordLineEdit(QLineEdit):
    """Secure password input line with inline show/hide toggle."""
    def __init__(self, placeholder: str = "", parent: QWidget = None) -> None:
        super().__init__(parent)
        self.setPlaceholderText(placeholder)
        self.setEchoMode(QLineEdit.EchoMode.Password)
        
        self.toggle_action = QAction(self)
        self.toggle_action.setIcon(self._get_icon(True))
        self.toggle_action.triggered.connect(self.toggle_visibility)
        self.addAction(self.toggle_action, QLineEdit.ActionPosition.TrailingPosition)

    def _get_icon(self, is_masked: bool) -> QIcon:
        from PyQt6.QtGui import QPixmap, QPainter, QFont
        from PyQt6.QtCore import Qt
        pixmap = QPixmap(24, 24)
        pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Render unicode symbol onto the pixmap
        char = "👁️" if is_masked else "🔒"
        font = QFont("Segoe UI Emoji", 11)
        painter.setFont(font)
        painter.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, char)
        painter.end()
        return QIcon(pixmap)

    def toggle_visibility(self) -> None:
        if self.echoMode() == QLineEdit.EchoMode.Password:
            self.setEchoMode(QLineEdit.EchoMode.Normal)
            self.toggle_action.setIcon(self._get_icon(False))
        else:
            self.setEchoMode(QLineEdit.EchoMode.Password)
            self.toggle_action.setIcon(self._get_icon(True))


# ─── Lazy Thumbnail Loader Thread ───────────

class ThumbnailLoaderWorker(QThread):
    """Background worker thread to generate and load image/PDF thumbnails to keep GUI fluid."""
    thumbnail_loaded = pyqtSignal(str, QPixmap)

    def __init__(self, file_path: str, max_size: QSize, file_id: Optional[str] = None) -> None:
        super().__init__()
        self._file_path = file_path
        self._max_size = max_size
        self._file_id = file_id

    def run(self) -> None:
        local_path = Path(self._file_path)
        if not local_path.exists() or not local_path.is_file():
            return

        suffix = local_path.suffix.lower()
        pixmap = None

        try:
            # 1. Image Thumbnails (JPEG, PNG, etc. via Pillow)
            if suffix in (".jpg", ".jpeg", ".png", ".bmp", ".gif", ".webp") and Image is not None:
                with Image.open(local_path) as img:
                    img.thumbnail((self._max_size.width(), self._max_size.height()))
                    # Convert PIL Image to QPixmap
                    qimage = ImageQt.ImageQt(img)
                    pixmap = QPixmap.fromImage(qimage)

            # 2. PDF Cover Page Previews (via PyMuPDF)
            elif suffix == ".pdf" and fitz is not None:
                doc = fitz.open(local_path)
                if doc.page_count > 0:
                    page = doc.load_page(0)  # Load first page
                    # Render page to a pixmap (image)
                    zoom = 2.0  # high fidelity render
                    mat = fitz.Matrix(zoom, zoom)
                    pix = page.get_pixmap(matrix=mat)
                    
                    # Convert raw bytes to QPixmap
                    qpixmap = QPixmap()
                    qpixmap.loadFromData(pix.tobytes("png"))
                    pixmap = qpixmap.scaled(
                        self._max_size,
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation,
                    )
                doc.close()
                
        except Exception as exc:
            # Silent fallback on generation issues, default to standard icon
            print(f"[Thumbnail Error] Failed to generate for {local_path.name}: {exc}")

        if pixmap and not pixmap.isNull():
            self.thumbnail_loaded.emit(self._file_path, pixmap)


class ThumbnailWidget(QWidget):
    """Lazy-loaded image and PDF cover preview container."""
    def __init__(
        self,
        file_path: str,
        max_size: QSize = QSize(80, 80),
        parent: QWidget = None,
        thumbnail_blob: Optional[bytes] = None,
        file_id: Optional[str] = None,
        on_thumbnail_generated=None
    ) -> None:
        super().__init__(parent)
        self._file_path = file_path
        self._max_size = max_size
        self._file_id = file_id
        self._thumbnail_blob = thumbnail_blob
        self.on_thumbnail_generated = on_thumbnail_generated
        self._worker = None

        # Setup standard layouts
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.label = QLabel(self)
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.label)

        if thumbnail_blob:
            self.load_from_blob(thumbnail_blob)
        else:
            self._set_default_icon()
            self.load_thumbnail()

    def _set_default_icon(self) -> None:
        suffix = Path(self._file_path).suffix.lower()
        is_small = self._max_size.width() < 40
        if suffix == ".pdf":
            self.label.setText("📄" if is_small else "📄 PDF")
        elif suffix in (".jpg", ".jpeg", ".png", ".webp", ".gif"):
            self.label.setText("🖼️" if is_small else "🖼️ IMG")
        else:
            self.label.setText("📦" if is_small else "📦 FILE")

    def load_from_blob(self, blob: bytes) -> None:
        pixmap = QPixmap()
        if pixmap.loadFromData(blob):
            scaled = pixmap.scaled(
                self._max_size,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation
            )
            self.label.setPixmap(scaled)
            self._full_pixmap = pixmap
        else:
            self._set_default_icon()

    def load_thumbnail(self) -> None:
        """Launch background worker to generate thumbnail without freezing main Qt thread."""
        suffix = Path(self._file_path).suffix.lower()
        if suffix not in (".jpg", ".jpeg", ".png", ".bmp", ".gif", ".webp", ".pdf"):
            return  # Skip generating for other types

        # Check if local file exists (either absolute path or on Desktop)
        local_path = Path(self._file_path)
        if not local_path.exists() or not local_path.is_file():
            desktop_path = Path("c:/Users/Anand/Desktop") / Path(self._file_path).name
            if not desktop_path.exists() or not desktop_path.is_file():
                return  # Cannot generate if local file doesn't exist

        self._worker = ThumbnailLoaderWorker(self._file_path, self._max_size, self._file_id)
        self._worker.thumbnail_loaded.connect(self._on_thumbnail_loaded)
        self._worker.start()

    def _on_thumbnail_loaded(self, path_str: str, pixmap: QPixmap) -> None:
        self._full_pixmap = pixmap
        scaled = pixmap.scaled(
            self._max_size,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation
        )
        self.label.setPixmap(scaled)

        # Notify callback to save generated thumbnail to DB
        if self.on_thumbnail_generated:
            from PyQt6.QtCore import QBuffer, QIODevice
            buffer = QBuffer()
            buffer.open(QIODevice.OpenModeFlag.WriteOnly)
            pixmap.save(buffer, "PNG")
            blob_bytes = bytes(buffer.data())
            self.on_thumbnail_generated(blob_bytes)

        # Prevent memory leak
        if self._worker:
            self._worker.quit()
            self._worker.wait()
            self._worker = None

    def resize_thumbnail(self, new_size: int) -> None:
        self._max_size = QSize(new_size, new_size)
        if hasattr(self, "_full_pixmap") and self._full_pixmap and not self._full_pixmap.isNull():
            scaled = self._full_pixmap.scaled(
                self._max_size,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation
            )
            self.label.setPixmap(scaled)


class ClickableGlassCard(GlassCard):
    """Subclass of GlassCard to safely handle mouse events without instance overrides."""
    def __init__(self, parent=None, double_click_callback=None, click_callback=None) -> None:
        super().__init__(parent)
        self.double_click_callback = double_click_callback
        self.click_callback = click_callback

    def mouseDoubleClickEvent(self, event) -> None:
        if self.double_click_callback:
            self.double_click_callback()
        super().mouseDoubleClickEvent(event)

    def mousePressEvent(self, event) -> None:
        if self.click_callback:
            self.click_callback()
        super().mousePressEvent(event)


