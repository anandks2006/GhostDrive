"""
main_view.py -- GhostDrive Primary Desktop Dashboard View.
"""

import os
import json
import uuid
import logging
import asyncio
import time
from pathlib import Path
from datetime import datetime

from PyQt6.QtCore import Qt, pyqtSignal, QTimer, QMimeData, QUrl
from PyQt6.QtGui import QPixmap, QShortcut, QKeySequence, QDrag
from PyQt6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QStackedWidget,
    QTableWidget,
    QHeaderView,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QComboBox,
    QSplitter,
    QScrollArea,
    QGridLayout,
    QMessageBox,
    QLineEdit,
    QCheckBox,
    QSpinBox,
    QApplication,
    QSlider,
    QSizePolicy,
)

import qasync

# GUI component imports
from ghostdrive.gui.widgets import StyledButton, StyledLineEdit, PasswordLineEdit, GlassCard, ThumbnailWidget
from ghostdrive.gui.styles import get_stylesheet, ResizingResilientMixin, ResilientDialog
from ghostdrive.gui.telemetry_view import TelemetryView
from ghostdrive.gui.notifications import NotificationManager
from ghostdrive.gui.system_tray import GhostDriveSystemTray

# Mixin controllers
from ghostdrive.gui.upload_controller import UploadControllerMixin
from ghostdrive.gui.file_browser import FileBrowserMixin
from ghostdrive.gui.settings_panel import SettingsPanelMixin

# Backend loaders
# Module-level credential file imports removed to comply with Spec §4.5 (keyring storage).

logger = logging.getLogger(__name__)

# ─── Storage Tier Advisor Dialog ──────────────────────────────────────────────

class TierAdvisorDialog(ResilientDialog):
    """Replication advice modal presented on file ingestion."""
    def __init__(self, parent: QWidget, file_name: str, file_size: int, mime_type: str) -> None:
        super().__init__(parent, base_width=420, base_height=320)
        self.setWindowTitle("Storage Tier Advisor")
        self.setWindowFlags(Qt.WindowType.CustomizeWindowHint | Qt.WindowType.WindowTitleHint)

        # Analyze file characteristics to recommend tier
        ext = Path(file_name).suffix.lower()
        ML_CHECKPOINT_EXTS = {".bin", ".pt", ".pth", ".safetensors", ".ckpt", ".pkl", ".npz", ".npy"}

        if ext in ML_CHECKPOINT_EXTS:
            suggested = "IMPORTANT"
            reason = "Machine learning checkpoint or weight file detected. Replicated to three backends."
            style = "color: #10b981; font-weight: bold;"
        elif ext in (".key", ".pem", ".json", ".asc", ".gpg", ".kdbx") or any(kw in file_name.lower() for kw in ["secret", "password", "ledger", "credential", "private"]):
            suggested = "CRITICAL"
            reason = "Sensitive keys, credentials, or secure configuration files detected. High replication is recommended."
            style = "color: #8b5cf6; font-weight: bold;"  # Violet
        elif file_size > 50 * 1024 * 1024 or ext in (".mp4", ".mkv", ".avi", ".iso", ".zip", ".tar", ".gz", ".7z"):
            suggested = "DISPOSABLE"
            reason = "Large media or archive file detected. Single-copy storage to conserve space."
            style = "color: #f59e0b; font-weight: bold;"  # Amber
        else:
            suggested = "IMPORTANT"
            reason = "Standard documents, codebase files, or images. Replicated to two backends."
            style = "color: #10b981; font-weight: bold;"  # Green

        self.selected_tier = suggested

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        title = QLabel("Storage Tier Ingestion Advisor", self)
        title.setObjectName("Heading")
        layout.addWidget(title)

        card = GlassCard(self)
        card_layout = QVBoxLayout(card)
        card_layout.setSpacing(8)

        rec_lbl = QLabel(f"Recommendation: <span style='{style}'>{suggested}</span>", card)
        rec_lbl.setObjectName("SubHeading")
        card_layout.addWidget(rec_lbl)

        reason_lbl = QLabel(reason, card)
        reason_lbl.setWordWrap(True)
        reason_lbl.setStyleSheet("color: #9ca3af; font-size: 12px;")
        card_layout.addWidget(reason_lbl)
        
        layout.addWidget(card)

        layout.addWidget(QLabel("Override suggested storage tier:", self))
        self.combo = QComboBox(self)
        self.combo.setObjectName("TierOverrideCombo")
        self.combo.addItems(["CRITICAL", "IMPORTANT", "DISPOSABLE"])
        self.combo.setCurrentText(suggested)
        layout.addWidget(self.combo)

        # Hidden Space Option
        self.hidden_space_check = QCheckBox("Ingest into Hidden Space (Securely wipe original file from disk)", self)
        self.hidden_space_check.setObjectName("HiddenSpaceCheckBox")
        self.hidden_space_check.setStyleSheet("color: #8b5cf6; font-weight: bold; margin-top: 6px;")
        layout.addWidget(self.hidden_space_check)

        # Buttons
        btn_layout = QHBoxLayout()
        cancel_btn = StyledButton("Cancel Ingestion", self, secondary=True)
        cancel_btn.clicked.connect(self.reject)
        confirm_btn = StyledButton("Confirm & Upload", self, primary=True)
        confirm_btn.clicked.connect(self.on_confirm)
        
        btn_layout.addWidget(cancel_btn)
        btn_layout.addWidget(confirm_btn)
        layout.addLayout(btn_layout)

    def on_confirm(self) -> None:
        self.selected_tier = self.combo.currentText()
        self.secure_erase_original = self.hidden_space_check.isChecked()
        self.accept()


# ─── Custom Drag-and-Drop QScrollArea ────────────────────────────────────────

class DragDropScrollArea(QScrollArea):
    """File grid area supporting drag and drop events."""
    files_dropped = pyqtSignal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setAcceptDrops(True)

    def dragEnterEvent(self, event) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event) -> None:
        for url in event.mimeData().urls():
            file_path = url.toLocalFile()
            if file_path and os.path.isfile(file_path):
                self.files_dropped.emit(file_path)


class DragOutTableWidget(QTableWidget):
    """QTableWidget that allows dragging files out to the OS explorer."""
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setDragEnabled(True)
        self.setAcceptDrops(False)
        self._drag_start_position = None

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_start_position = event.pos()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event) -> None:
        if not (event.buttons() & Qt.MouseButton.LeftButton) or self._drag_start_position is None:
            return
        if (event.pos() - self._drag_start_position).manhattanLength() < QApplication.startDragDistance():
            return
        
        self.perform_drag_export()

    def perform_drag_export(self) -> None:
        parent_window = self.window()
        if not hasattr(parent_window, "get_selected_file_ids"):
            return
            
        selected_ids = parent_window.get_selected_file_ids()
        if not selected_ids:
            return
            
        file_id = selected_ids[0]
        db = parent_window.db
        if not db:
            return
            
        with db.transaction():
            file_row = db._conn.execute(
                "SELECT * FROM files WHERE id = ?", (file_id,)
            ).fetchone()
            
        if not file_row:
            return
            
        temp_path = parent_window.download_file_sync_for_drag(file_row)
        if not temp_path or not os.path.exists(temp_path):
            return
            
        mime_data = QMimeData()
        mime_data.setUrls([QUrl.fromLocalFile(temp_path)])
        
        drag = QDrag(self)
        drag.setMimeData(mime_data)
        
        # Use simple default icon for drag
        from PyQt6.QtGui import QPainter, QColor
        pixmap = QPixmap(64, 64)
        pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pixmap)
        painter.setBrush(QColor("#8b5cf6"))
        painter.drawRoundedRect(4, 4, 56, 56, 8, 8)
        painter.end()
        drag.setPixmap(pixmap)
        
        drag.exec(Qt.DropAction.CopyAction)




# ─── Main Window Workspace ───────────────────────────────────────────────────

class MainWindow(QMainWindow, ResizingResilientMixin, UploadControllerMixin, FileBrowserMixin, SettingsPanelMixin):
    """The master GhostDrive workspace dashboard."""
    healing_completed = pyqtSignal()
    backends_changed = pyqtSignal()

    def __init__(self, km, db, parent=None) -> None:
        super().__init__(parent)
        self.km = km
        self.db = db
        self.healing_completed.connect(self.refresh_files)
        self.backends_changed.connect(self.refresh_backends_ui)
        self.current_theme = "dark"
        self.current_accent = "#8b5cf6"
        self.current_folder_path = "/files"
        self._table_item_types = []
        
        self.setWindowTitle("GhostDrive Desktop")
        self.setMinimumSize(1000, 680)

        # Setup notification manager
        self.notifications = NotificationManager(self)

        # Try to initialize system tray
        self.tray = GhostDriveSystemTray(self, self)
        self.notifications.set_tray_icon(self.tray)

        # Core active backend instances
        self.active_backends = {}
        self._init_backends()

        # Active upload tracking and read-only mode
        self.active_uploads = 0
        self._read_only_mode = False
        self._health_modal_shown = False

        # Initialize secrets vault and P2P sharing components
        from ghostdrive.crypto.secrets_vault import SecretsVault
        from ghostdrive.utils.tor_manager import TorManager
        from ghostdrive.pipeline.sharing import AdaptiveSharingEngine
        self.vault = SecretsVault(self.db, self.km.master_key, self.km.hkdf_salt)
        self.tor_manager = TorManager(data_dir=Path(".tor"))
        self.sharing_engine = AdaptiveSharingEngine(db=self.db, km=self.km, main_view=self)

        # Initialize Main UI structure
        self._setup_ui()

        # Setup Global Connection Indicator in status bar
        self.conn_indicator = QLabel("🟢 Online", self)
        self.conn_indicator.setStyleSheet("color: #10b981; font-weight: bold; font-size: 11px; margin-right: 12px;")
        self.statusBar().addPermanentWidget(self.conn_indicator)

        # Keyboard shortcuts
        self.delete_shortcut = QShortcut(QKeySequence(Qt.Key.Key_Delete), self)
        self.delete_shortcut.activated.connect(self.on_delete_shortcut_activated)
        
        self.f5_shortcut = QShortcut(QKeySequence(Qt.Key.Key_F5), self)
        self.f5_shortcut.activated.connect(self.on_f5_shortcut_activated)
        
        self.ctrl_u_shortcut = QShortcut(QKeySequence("Ctrl+U"), self)
        self.ctrl_u_shortcut.activated.connect(self.on_ctrl_u_shortcut_activated)
        
        self.ctrl_l_shortcut = QShortcut(QKeySequence("Ctrl+L"), self)
        self.ctrl_l_shortcut.activated.connect(self.lock_and_logout)

        # Load initial file lists
        self.refresh_files()
        self.refresh_trash()
        self.refresh_backends_ui()

        # Start background daemons for health & healing if an event loop is active
        try:
            asyncio.get_running_loop()
            from ghostdrive.pipeline.healing import HealthDaemon, HealingQueue
            self.health_daemon = HealthDaemon(
                db=self.db,
                active_backends=self.active_backends,
                km=self.km,
                notifications=self.notifications,
                main_view=self,
                loop_interval=30.0
            )
            self.healing_queue = HealingQueue(
                db=self.db,
                active_backends=self.active_backends,
                km=self.km,
                main_view=self,
                loop_interval=10.0
            )
            
            # Connect Qt custom signals for thread-safe UI updates
            self.health_daemon.signals.refresh_backends.connect(self.refresh_backends_ui)
            self.health_daemon.signals.trigger_health_alert.connect(self.trigger_health_alert_ui)
            self.healing_queue.signals.refresh_files.connect(self.refresh_files)
            self.healing_queue.signals.refresh_backends.connect(self.refresh_backends_ui)

            self.health_daemon.start()
            self.healing_queue.start()

            # Start Tor and Sharing Engine background tasks
            asyncio.create_task(self.tor_manager.start())
            asyncio.create_task(self.sharing_engine.start())

            # Schedule periodic backups (every 1 hour)
            async def backup_loop():
                await asyncio.sleep(60)  # Grace period at boot
                while True:
                    try:
                        await self.backup_index_and_credentials()
                    except Exception:
                        pass
                    await asyncio.sleep(3600)
            self._backup_task = asyncio.create_task(backup_loop())
        except RuntimeError:
            logger.warning("No running asyncio event loop. Background daemons not started.")
            self.health_daemon = None
            self.healing_queue = None

        # Initialize resizing resiliency framework
        self.init_resizing_resiliency(1000, 680)

        try:
            asyncio.get_running_loop()
            asyncio.create_task(self.connect_backends_on_startup())
        except RuntimeError:
            pass

    async def connect_backends_on_startup(self) -> None:
        """Connect to all active backends in the background on startup."""
        logger.info("Initializing backend connections on startup...")
        for name, obj in self.active_backends.items():
            try:
                if not getattr(obj, "_connected", False):
                    await obj.connect()
                    obj._connected = True
                    logger.info("Backend %s connected successfully on startup.", name)
            except Exception as exc:
                logger.error("Failed to connect backend %s on startup: %s", name, exc)
                try:
                    with self.db.transaction():
                        self.db._conn.execute(
                            "UPDATE backends SET status = 'unreachable' WHERE id = ?",
                            (obj.id,)
                        )
                except Exception:
                    pass
        self.refresh_backends_ui()
        # Run index synchronization immediately after connecting backends
        await self.sync_index_on_startup()

    def load_and_connect_local_backends(self) -> None:
        """Dynamically load newly registered local backends and connect them in the background."""
        self._init_backends()
        try:
            asyncio.get_running_loop()
            async def connect_new():
                for name, obj in self.active_backends.items():
                    if not getattr(obj, "_connected", False):
                        try:
                            await obj.connect()
                            obj._connected = True
                            logger.info("New local backend %s connected dynamically.", name)
                        except Exception as exc:
                            logger.error("Failed to connect new local backend %s dynamically: %s", name, exc)
                self.refresh_backends_ui()
            asyncio.create_task(connect_new())
        except RuntimeError:
            pass

    def _init_backends(self) -> None:
        """Register Telegram and Discord backends if credential keys exist and they are registered in the DB."""
        import keyring

        # Check DB presence first to avoid auto-importing stale/test credentials from the OS keyring
        has_tg = False
        has_dc = False
        if self.db:
            try:
                with self.db.transaction():
                    has_tg = self.db._conn.execute("SELECT 1 FROM backends WHERE id = 'telegram-backend-id'").fetchone() is not None
                    has_dc = self.db._conn.execute("SELECT 1 FROM backends WHERE id = 'discord-backend-id'").fetchone() is not None
            except Exception as exc:
                logger.error("Failed to check backend existence in database: %s", exc)

        # 1. Telegram Backend
        if has_tg:
            # Query keyring
            api_id_str = keyring.get_password("ghostdrive", "telegram_api_id")
            api_hash = keyring.get_password("ghostdrive", "telegram_api_hash")
            phone = keyring.get_password("ghostdrive", "telegram_phone")

            api_id = int(api_id_str) if api_id_str and api_id_str.isdigit() else None

            if api_id and api_hash:
                try:
                    from ghostdrive.backends.telegram_backend import TelegramBackend
                    tg = TelegramBackend(api_id=api_id, api_hash=api_hash, phone=phone)
                    tg.id = "telegram-backend-id"  # Static ID for DB linkage
                    tg.type = "telegram"
                    self.active_backends["telegram"] = tg
                except Exception as exc:
                    logger.error("Failed to load Telegram Backend: %s", exc)

        # 2. Discord Backend
        if has_dc:
            # Query keyring
            bot_token = keyring.get_password("ghostdrive", "discord_bot_token")
            channel_id_str = keyring.get_password("ghostdrive", "discord_channel_id")

            channel_id = int(channel_id_str) if channel_id_str and channel_id_str.isdigit() else None

            if bot_token and channel_id:
                try:
                    from ghostdrive.backends.discord_backend import DiscordBackend
                    dc = DiscordBackend(bot_token=bot_token, channel_id=channel_id)
                    dc.id = "discord-backend-id"  # Static ID for DB linkage
                    dc.type = "discord"
                    self.active_backends["discord"] = dc
                except Exception as exc:
                    logger.error("Failed to load Discord Backend: %s", exc)

        # 3. Load all registered local (physical drive & folder) backends from DB
        if self.db:
            try:
                with self.db.transaction():
                    local_rows = self.db._conn.execute(
                        "SELECT id, type, credentials_ref FROM backends WHERE type = 'local'"
                    ).fetchall()
            except Exception as exc:
                logger.error("Failed to query local backends from DB: %s", exc)
                local_rows = []

            for r in local_rows:
                b_id = r["id"]
                b_ref = r["credentials_ref"]
                
                # Check if already loaded in active_backends
                if b_id in self.active_backends:
                    continue

                # Query drive_registry to see if it is registered
                drive_row = None
                try:
                    with self.db.transaction():
                        drive_row = self.db._conn.execute(
                            "SELECT drive_uuid, drive_label, drive_type, mount_hint FROM drive_registry WHERE backend_id = ?",
                            (b_id,)
                        ).fetchone()
                except Exception as exc:
                    logger.error("Failed to query drive registry for backend %s: %s", b_id, exc)

                # Fetch root path from keyring
                path_str = None
                try:
                    from ghostdrive.crypto.credential_store import credential_store
                    path_str = credential_store.load(b_ref)
                except Exception as exc:
                    logger.debug("Failed to load root path from keyring for %s: %s", b_ref, exc)

                if not path_str and drive_row:
                    # Fallback to mount hint if keyring failed
                    path_str = drive_row["mount_hint"]

                if path_str:
                    try:
                        # Instantiate the correct local backend class
                        from pathlib import Path
                        if drive_row and (drive_row["drive_type"] == "folder" or drive_row["drive_uuid"].startswith("folder-")):
                            # It is a local folder backend!
                            from ghostdrive.backends.local_fs_backend import LocalFSBackend
                            b_obj = LocalFSBackend(root_path=Path(path_str))
                            b_obj.id = b_id
                            b_obj.type = "local"
                            b_obj.label = drive_row["drive_label"]
                        else:
                            # It is an external physical drive!
                            from ghostdrive.backends.external_drive_backend import ExternalDriveBackend
                            drive_uuid = drive_row["drive_uuid"] if drive_row else b_id
                            b_obj = ExternalDriveBackend(drive_uuid=drive_uuid, relative_root="GhostDriveData")
                            b_obj.id = b_id
                            b_obj.type = "local"
                            b_obj.label = drive_row["drive_label"] if drive_row else "External Drive"

                        self.active_backends[b_id] = b_obj
                        logger.info("Loaded registered local backend: %s (ID: %s)", getattr(b_obj, "label", b_id), b_id)
                    except Exception as exc:
                        logger.error("Failed to instantiate local backend %s: %s", b_id, exc)

        # Register backend rows in database if they don't exist
        if self.db:
            try:
                with self.db.transaction():
                    for name, obj in self.active_backends.items():
                        # Check if already in DB
                        row = self.db._conn.execute(
                            "SELECT id FROM backends WHERE id = ?", (obj.id,)
                        ).fetchone()
                        if not row:
                            self.db._conn.execute(
                                """INSERT INTO backends
                                   (id, type, credentials_ref, status, priority, quota_used, quota_limit, quota_reserved)
                                   VALUES (?, ?, ?, 'healthy', 100, 0, 4611686018427387904, 0)""",
                                (obj.id, name, f"keyring:{name}_token"),
                            )
            except Exception as exc:
                logger.error("Failed to write backends to DB schema: %s", exc)

    def _setup_ui(self) -> None:
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)

        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Horizontal splitter separates sidebar and main views panel
        splitter = QSplitter(Qt.Orientation.Horizontal, central_widget)
        splitter.setObjectName("MainSplitter")
        main_layout.addWidget(splitter)

        # ─── Navigation Sidebar (Left) ───
        sidebar_frame = QWidget(splitter)
        sidebar_frame.setObjectName("Sidebar")
        sidebar_frame.setMinimumWidth(210)
        sidebar_frame.setMaximumWidth(280)
        sidebar_layout = QVBoxLayout(sidebar_frame)
        sidebar_layout.setContentsMargins(12, 24, 8, 24)
        sidebar_layout.setSpacing(16)

        brand_lbl = QLabel("GHOSTDRIVE", sidebar_frame)
        brand_lbl.setObjectName("Heading")
        brand_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sidebar_layout.addWidget(brand_lbl)

        # Sidebar List items
        self.nav_list = QWidget(sidebar_frame)
        self.nav_list.setObjectName("NavListContainer")
        self.nav_list.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.nav_list_layout = QVBoxLayout(self.nav_list)
        self.nav_list_layout.setContentsMargins(0, 0, 0, 0)
        self.nav_list_layout.setSpacing(16)
        
        self.nav_buttons = []
        nav_items = ["Files", "Trash", "Backends", "Telemetry", "Secrets", "Shared Media", "Settings", "Storage Analytics"]
        
        for i, text in enumerate(nav_items):
            btn = QPushButton(text, self.nav_list)
            btn.setProperty("navBtn", "true")
            btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
            btn.setCheckable(True)
            if i == 0:
                btn.setChecked(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda checked, idx=i: self.set_nav_row(idx))
            self.nav_list_layout.addWidget(btn)
            self.nav_buttons.append(btn)
            
        sidebar_layout.addWidget(self.nav_list)

        # Sidebar Status Cards
        status_card = GlassCard(sidebar_frame)
        status_layout = QVBoxLayout(status_card)
        status_layout.setContentsMargins(16, 16, 16, 16)
        status_layout.setSpacing(12)
        
        status_title = QLabel("🟢 Drive Unlocked", status_card)
        status_title.setStyleSheet("font-weight: bold; color: #10b981;")
        status_layout.addWidget(status_title)
        
        lock_btn = StyledButton("Lock Keystore", status_card, danger=True)
        lock_btn.setObjectName("SidebarLockBtn")
        lock_btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        lock_btn.clicked.connect(self.lock_and_logout)
        status_layout.addWidget(lock_btn)

        help_btn = StyledButton("About & Help", status_card, secondary=True)
        help_btn.setObjectName("SidebarHelpBtn")
        help_btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        help_btn.clicked.connect(self.show_about_dialog)
        status_layout.addWidget(help_btn)
        
        sidebar_layout.addWidget(status_card)
        splitter.addWidget(sidebar_frame)

        # ─── Stacked Workspace (Right) ───
        right_container = QWidget(splitter)
        right_layout = QVBoxLayout(right_container)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)

        # Warning Banner (Spec 7.4 Alert Hierarchy)
        from PyQt6.QtWidgets import QFrame
        self.warning_banner = QFrame(right_container)
        self.warning_banner.setObjectName("WarningBanner")
        self.warning_banner.setStyleSheet("background-color: #f59e0b; border-bottom: 1px solid #d97706;")
        self.warning_banner.setVisible(False)
        
        banner_layout = QHBoxLayout(self.warning_banner)
        banner_layout.setContentsMargins(16, 6, 16, 6)
        
        self.banner_label = QLabel(self.warning_banner)
        self.banner_label.setStyleSheet("color: #1e1b4b; font-weight: bold; font-size: 13px;")
        banner_layout.addWidget(self.banner_label, stretch=1)
        
        self.banner_action_btn = StyledButton("Mirror Now", self.warning_banner, primary=True)
        self.banner_action_btn.clicked.connect(self.trigger_emergency_cross_mirroring)
        banner_layout.addWidget(self.banner_action_btn)
        
        right_layout.addWidget(self.warning_banner)

        self.stacked_views = QStackedWidget(right_container)
        self.stacked_views.setObjectName("StackedViews")
        right_layout.addWidget(self.stacked_views)
        
        # 1. Files Page
        self._setup_files_page()
        # 2. Trash Page
        self._setup_trash_page()
        # 3. Backends Page
        self._setup_backends_page()
        # 4. Telemetry Page
        self.telemetry_view = TelemetryView(self.stacked_views, self.db)
        self.stacked_views.addWidget(self.telemetry_view)
        
        # 5. Secrets Page
        from ghostdrive.gui.secrets_panel import SecretsPanel
        self.secrets_panel = SecretsPanel(self.stacked_views, self.db)
        self.secrets_panel.set_vault(self.vault)
        self.stacked_views.addWidget(self.secrets_panel)
        
        # 6. Shared Media Page
        from ghostdrive.gui.shared_media_panel import SharedMediaPanel
        self.shared_media_panel = SharedMediaPanel(self.stacked_views, self.db, self.km, self.sharing_engine, self.tor_manager)
        self.stacked_views.addWidget(self.shared_media_panel)
        
        # 7. Settings Page
        self._setup_settings_page()

        # 8. Storage Analytics Page
        from ghostdrive.gui.storage_analytics import StorageAnalyticsPanel
        self.analytics_panel = StorageAnalyticsPanel(self.stacked_views, self.db)
        self.stacked_views.addWidget(self.analytics_panel)

        splitter.addWidget(right_container)
        splitter.setSizes([220, 780])
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)

    # ─── Files View (Stack 0) ──────────────────────────────────────────────────

    def _setup_files_page(self) -> None:
        files_widget = QWidget(self.stacked_views)
        layout = QVBoxLayout(files_widget)
        layout.setContentsMargins(12, 24, 24, 24)
        layout.setSpacing(16)

        # Header Search & layout toggle
        top_layout = QHBoxLayout()
        self.search_input = StyledLineEdit("Search secure files...", files_widget)
        self.search_input.setObjectName("SearchInput")
        self.search_input.textChanged.connect(self.on_search_query_changed)
        top_layout.addWidget(self.search_input, stretch=3)

        self.tier_filter_combo = QComboBox(files_widget)
        self.tier_filter_combo.setObjectName("TierFilterCombo")
        self.tier_filter_combo.addItems(["All Tiers", "CRITICAL", "IMPORTANT", "DISPOSABLE"])
        self.tier_filter_combo.currentIndexChanged.connect(self.on_search_query_changed)
        self.tier_filter_combo.setFixedWidth(120)
        top_layout.addWidget(self.tier_filter_combo)

        self.tag_filter_combo = QComboBox(files_widget)
        self.tag_filter_combo.setObjectName("TagFilterCombo")
        self.tag_filter_combo.addItem("All Tags")
        self.tag_filter_combo.currentIndexChanged.connect(self.on_search_query_changed)
        self.tag_filter_combo.setFixedWidth(120)
        top_layout.addWidget(self.tag_filter_combo)

        # Breadcrumb layout for folder navigation wrapped in a QWidget
        self.breadcrumb_widget = QWidget(files_widget)
        self.breadcrumb_widget.setObjectName("BreadcrumbWidget")
        self.breadcrumb_layout = QHBoxLayout(self.breadcrumb_widget)
        self.breadcrumb_layout.setContentsMargins(0, 0, 0, 0)
        self.breadcrumb_layout.setSpacing(8)
        
        self.back_dir_btn = StyledButton("⬅️ Back", self.breadcrumb_widget, secondary=True)
        self.back_dir_btn.clicked.connect(self.navigate_up)
        self.breadcrumb_layout.addWidget(self.back_dir_btn)
        
        self.path_label = QLabel("Path: /files", self.breadcrumb_widget)
        self.path_label.setStyleSheet("font-weight: bold; color: #8b5cf6;")
        self.breadcrumb_layout.addWidget(self.path_label)
        self.breadcrumb_layout.addStretch()

        mode_layout = QHBoxLayout()
        self.list_mode_btn = StyledButton("List View", files_widget, secondary=True)
        self.list_mode_btn.setObjectName("ListModeBtn")
        self.list_mode_btn.clicked.connect(lambda: self.switch_files_view_mode(0))
        self.grid_mode_btn = StyledButton("Grid View", files_widget)
        self.grid_mode_btn.setObjectName("GridModeBtn")
        self.grid_mode_btn.clicked.connect(lambda: self.switch_files_view_mode(1))
        
        mode_layout.addWidget(self.list_mode_btn)
        mode_layout.addWidget(self.grid_mode_btn)
        top_layout.addLayout(mode_layout, stretch=1)

        self.upload_local_btn = StyledButton("Upload File", files_widget, primary=True)
        self.upload_local_btn.setObjectName("UploadLocalBtn")
        self.upload_local_btn.clicked.connect(self.on_manual_upload_clicked)
        top_layout.addWidget(self.upload_local_btn)

        layout.addLayout(top_layout)
        layout.addWidget(self.breadcrumb_widget)

        # Horizontal Splitter between File display lists/grids and Metadata detail card
        self.files_splitter = QSplitter(Qt.Orientation.Horizontal, files_widget)
        self.files_splitter.setObjectName("FilesSplitter")
        layout.addWidget(self.files_splitter)

        # Collapsible left folder sidebar
        from PyQt6.QtWidgets import QTreeWidget
        self.folder_tree = QTreeWidget(self.files_splitter)
        self.folder_tree.setObjectName("FolderTreeSidebar")
        self.folder_tree.setHeaderLabel("FOLDERS")
        self.folder_tree.setMinimumWidth(150)
        self.folder_tree.setIndentation(10)
        self.folder_tree.itemClicked.connect(self.on_folder_tree_item_clicked)

        # Files stack (Table list view vs Grid card view)
        self.files_layout_stack = QStackedWidget(self.files_splitter)
        self.files_layout_stack.setObjectName("FilesLayoutStack")

        # Layout 0: List (DragOutTableWidget)
        self.files_table = DragOutTableWidget(self.files_layout_stack)
        self.files_table.setObjectName("FileTable")
        self.files_table.setColumnCount(5)
        self.files_table.setHorizontalHeaderLabels(["PREVIEW", "NAME", "SIZE", "STORAGE TIER", "CREATED AT"])
        self.files_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.files_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.files_table.setColumnWidth(0, 60)
        self.files_table.verticalHeader().setDefaultSectionSize(32)
        self.files_table.itemSelectionChanged.connect(self.on_file_selected)
        
        # Configure selection, sorting, and context menu
        self.files_table.setSelectionMode(QHeaderView.SelectionMode.ExtendedSelection)
        self.files_table.setSortingEnabled(True)
        self.files_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.files_table.customContextMenuRequested.connect(self.show_files_context_menu)
        self.files_table.cellDoubleClicked.connect(self.on_table_double_clicked)
        
        self.files_layout_stack.addWidget(self.files_table)

        # Layout 1: Grid (QScrollArea containing Flow/Grid Layout)
        self.files_grid_scroll = DragDropScrollArea(self.files_layout_stack)
        self.files_grid_scroll.setObjectName("FilesGridScroll")
        self.files_grid_scroll.files_dropped.connect(self.ingest_file)
        self.files_grid_scroll.setWidgetResizable(True)
        
        self.files_grid_container = QWidget(self.files_grid_scroll)
        self.files_grid_container.setObjectName("FilesGridContainer")
        self.files_grid_layout = QGridLayout(self.files_grid_container)
        self.files_grid_layout.setSpacing(16)
        self.files_grid_layout.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        self.files_grid_scroll.setWidget(self.files_grid_container)
        self.files_layout_stack.addWidget(self.files_grid_scroll)

        self.files_splitter.addWidget(self.files_layout_stack)

        # Metadata side-panel
        self.metadata_panel = GlassCard(self.files_splitter)
        self.metadata_panel.setObjectName("MetadataPanel")
        self.metadata_panel.setMinimumWidth(220)
        self.metadata_layout = QVBoxLayout(self.metadata_panel)
        self.metadata_layout.setContentsMargins(12, 12, 12, 12)
        self.metadata_layout.setSpacing(10)

        self.meta_title = QLabel("Select a file to view detail metadata.", self.metadata_panel)
        self.meta_title.setWordWrap(True)
        self.meta_title.setStyleSheet("font-weight: bold;")
        self.metadata_layout.addWidget(self.meta_title)

        self.meta_desc = QLabel("", self.metadata_panel)
        self.meta_desc.setWordWrap(True)
        self.meta_desc.setObjectName("MutedLabel")
        self.metadata_layout.addWidget(self.meta_desc)

        self.download_btn = StyledButton("Download File", self.metadata_panel, primary=True)
        self.download_btn.setObjectName("MetaDownloadBtn")
        self.download_btn.clicked.connect(self.on_download_selected_clicked)
        self.download_btn.setVisible(False)
        self.metadata_layout.addWidget(self.download_btn)

        self.quick_download_btn = StyledButton("Save to Downloads", self.metadata_panel, secondary=True)
        self.quick_download_btn.setObjectName("MetaQuickDownloadBtn")
        self.quick_download_btn.clicked.connect(self.on_save_to_downloads_clicked)
        self.quick_download_btn.setVisible(False)
        self.metadata_layout.addWidget(self.quick_download_btn)

        self.delete_btn = StyledButton("Delete File", self.metadata_panel, danger=True)
        self.delete_btn.setObjectName("MetaDeleteBtn")
        self.delete_btn.clicked.connect(self.on_delete_selected_clicked)
        self.delete_btn.setVisible(False)
        self.metadata_layout.addWidget(self.delete_btn)

        # Tags edit area
        self.tags_label = QLabel("Tags (comma separated):", self.metadata_panel)
        self.tags_label.setStyleSheet("font-weight: bold; margin-top: 10px;")
        self.tags_label.setVisible(False)
        self.metadata_layout.addWidget(self.tags_label)
        
        self.tags_input = StyledLineEdit("e.g. personal, photo", self.metadata_panel)
        self.tags_input.setObjectName("MetaTagsInput")
        self.tags_input.setVisible(False)
        self.metadata_layout.addWidget(self.tags_input)
        
        self.save_tags_btn = StyledButton("Save Tags", self.metadata_panel, secondary=True)
        self.save_tags_btn.setObjectName("MetaSaveTagsBtn")
        self.save_tags_btn.clicked.connect(self.on_save_tags_clicked)
        self.save_tags_btn.setVisible(False)
        self.metadata_layout.addWidget(self.save_tags_btn)

        # Version History edit area
        self.version_history_label = QLabel("Version History:", self.metadata_panel)
        self.version_history_label.setStyleSheet("font-weight: bold; margin-top: 10px;")
        self.version_history_label.setVisible(False)
        self.metadata_layout.addWidget(self.version_history_label)
        
        self.version_list = QListWidget(self.metadata_panel)
        self.version_list.setObjectName("MetaVersionList")
        self.version_list.setStyleSheet("background-color: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.05); font-size: 11px; color: #f4f4f5;")
        self.version_list.setMaximumHeight(80)
        self.version_list.setVisible(False)
        self.metadata_layout.addWidget(self.version_list)
        
        self.restore_version_btn = StyledButton("Restore Version", self.metadata_panel, secondary=True)
        self.restore_version_btn.setObjectName("MetaRestoreVersionBtn")
        self.restore_version_btn.clicked.connect(self.on_restore_version_clicked)
        self.restore_version_btn.setVisible(False)
        self.metadata_layout.addWidget(self.restore_version_btn)

        # Recent Activity Feed Log widget inside metadata panel
        self.activity_card = GlassCard(self.metadata_panel)
        self.activity_layout = QVBoxLayout(self.activity_card)
        self.activity_layout.setContentsMargins(8, 8, 8, 8)
        self.activity_layout.setSpacing(6)
        
        self.activity_title = QLabel("🕒 Recent Activity Log", self.activity_card)
        self.activity_title.setStyleSheet("font-weight: bold; color: #8b5cf6; font-size: 11px;")
        self.activity_layout.addWidget(self.activity_title)
        
        self.activity_list = QListWidget(self.activity_card)
        self.activity_list.setObjectName("ActivityList")
        self.activity_list.setStyleSheet("background-color: transparent; border: none; font-size: 10px; color: #9ca3af;")
        self.activity_list.setWordWrap(True)
        self.activity_list.setMinimumHeight(140)
        self.activity_layout.addWidget(self.activity_list)
        
        self.metadata_layout.addWidget(self.activity_card, 1)
        self.files_splitter.addWidget(self.metadata_panel)
        self.files_splitter.setSizes([180, 500, 230])
        self.files_splitter.setStretchFactor(0, 1)
        self.files_splitter.setStretchFactor(1, 3)
        self.files_splitter.setStretchFactor(2, 1)

        # Bottom section: Upload Queue panel
        queue_card = GlassCard(files_widget)
        queue_layout = QVBoxLayout(queue_card)
        queue_layout.setContentsMargins(12, 12, 12, 12)
        queue_title = QLabel("Active / Pending Upload Queue", queue_card)
        queue_title.setObjectName("SubHeading")
        queue_layout.addWidget(queue_title)

        self.queue_table = QTableWidget(queue_card)
        self.queue_table.setObjectName("QueueTable")
        self.queue_table.setColumnCount(6)
        self.queue_table.setHorizontalHeaderLabels(["FILENAME", "CHUNK", "BACKEND", "SPEED", "PROGRESS", "RETRY"])
        self.queue_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.queue_table.setMinimumHeight(120)
        queue_layout.addWidget(self.queue_table)

        layout.addWidget(queue_card, stretch=1)
        self.stacked_views.addWidget(files_widget)

    def switch_files_view_mode(self, idx: int) -> None:
        self.files_layout_stack.setCurrentIndex(idx)
        if idx == 0:
            self.list_mode_btn.setObjectName("PrimaryButton")
            self.grid_mode_btn.setObjectName("")
        else:
            self.list_mode_btn.setObjectName("")
            self.grid_mode_btn.setObjectName("PrimaryButton")
        self.list_mode_btn.setStyle(self.list_mode_btn.style())
        self.grid_mode_btn.setStyle(self.grid_mode_btn.style())

    # ─── Trash View (Stack 1) ──────────────────────────────────────────────────

    def _setup_trash_page(self) -> None:
        trash_widget = QWidget(self.stacked_views)
        layout = QVBoxLayout(trash_widget)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        top_layout = QHBoxLayout()
        title = QLabel("Trash Bin (Soft-Deleted Files)", self)
        title.setObjectName("Heading")
        top_layout.addWidget(title)

        self.empty_trash_btn = StyledButton("Empty Trash Bin", self, danger=True)
        self.empty_trash_btn.setObjectName("EmptyTrashBtn")
        self.empty_trash_btn.clicked.connect(self.on_empty_trash_clicked)
        top_layout.addWidget(self.empty_trash_btn)

        layout.addLayout(top_layout)

        self.trash_table = QTableWidget(trash_widget)
        self.trash_table.setObjectName("TrashTable")
        self.trash_table.setColumnCount(4)
        self.trash_table.setHorizontalHeaderLabels(["NAME", "ORIGINAL PATH", "SIZE", "ACTIONS"])
        self.trash_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        # Configure selection, sorting, and context menu
        self.trash_table.setSelectionMode(QHeaderView.SelectionMode.ExtendedSelection)
        self.trash_table.setSortingEnabled(True)
        self.trash_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.trash_table.customContextMenuRequested.connect(self.show_trash_context_menu)
        
        layout.addWidget(self.trash_table)

        self.stacked_views.addWidget(trash_widget)

    # ─── Backends View (Stack 2) ───────────────────────────────────────────────

    def _setup_backends_page(self) -> None:
        backends_widget = QWidget(self.stacked_views)
        self.backends_layout = QVBoxLayout(backends_widget)
        self.backends_layout.setContentsMargins(24, 24, 24, 24)
        self.backends_layout.setSpacing(16)

        title = QLabel("Active Storage Backends", backends_widget)
        title.setObjectName("Heading")
        self.backends_layout.addWidget(title)

        self.backends_list_widget = QWidget(backends_widget)
        self.backends_list_layout = QVBoxLayout(self.backends_list_widget)
        self.backends_list_layout.setSpacing(12)
        self.backends_layout.addWidget(self.backends_list_widget)
        self.backends_layout.addStretch()

        self.stacked_views.addWidget(backends_widget)

    # ─── Settings View (Stack 4) ───────────────────────────────────────────────

    def _setup_settings_page(self) -> None:
        settings_widget = QWidget(self.stacked_views)
        main_layout = QVBoxLayout(settings_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        
        scroll = QScrollArea(settings_widget)
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("background-color: transparent; border: none;")
        main_layout.addWidget(scroll)
        
        scroll_content = QWidget(scroll)
        scroll_content.setObjectName("ScrollContent")
        scroll_content.setStyleSheet("background-color: transparent;")
        scroll.setWidget(scroll_content)
        
        layout = QVBoxLayout(scroll_content)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("Secure Drive Settings", scroll_content)
        title.setObjectName("Heading")
        layout.addWidget(title)

        # Card 1: Theme selection
        theme_card = GlassCard(scroll_content)
        theme_layout = QVBoxLayout(theme_card)
        theme_layout.addWidget(QLabel("Application Styling Theme:", theme_card))
        
        self.theme_combo = QComboBox(theme_card)
        self.theme_combo.setObjectName("ThemeSelector")
        self.theme_combo.addItems(["Dark Space Mode", "Clean Light Mode"])
        self.theme_combo.currentIndexChanged.connect(self.on_theme_changed)
        theme_layout.addWidget(self.theme_combo)
        layout.addWidget(theme_card)

        # Card 2: Keystore backup
        backup_card = GlassCard(scroll_content)
        backup_layout = QVBoxLayout(backup_card)
        backup_layout.setSpacing(10)
        backup_layout.addWidget(QLabel("BIP39 Seed Phrase Key Recovery Backup:", backup_card))
        
        self.seed_btn = StyledButton("Reveal 24-Word Recovery Phrase", backup_card, secondary=True)
        self.seed_btn.setObjectName("RevealSeedBtn")
        self.seed_btn.clicked.connect(self.on_reveal_seed_clicked)
        backup_layout.addWidget(self.seed_btn)

        self.seed_text = QLineEdit(backup_card)
        self.seed_text.setReadOnly(True)
        self.seed_text.setEchoMode(QLineEdit.EchoMode.Password)
        backup_layout.addWidget(self.seed_text)
        
        layout.addWidget(backup_card)

        # Card 3: Change Passphrase
        passwd_card = GlassCard(scroll_content)
        passwd_layout = QVBoxLayout(passwd_card)
        passwd_layout.setSpacing(10)
        passwd_layout.addWidget(QLabel("Change Keystore Passphrase:", passwd_card))
        
        self.curr_pass_input = PasswordLineEdit("Current Passphrase", passwd_card)
        self.curr_pass_input.setObjectName("CurrentPassInput")
        passwd_layout.addWidget(self.curr_pass_input)

        self.new_pass_input = PasswordLineEdit("New Passphrase (min 8 chars)", passwd_card)
        self.new_pass_input.setObjectName("NewPassInput")
        passwd_layout.addWidget(self.new_pass_input)

        self.change_pass_btn = StyledButton("Update Passphrase", passwd_card, primary=True)
        self.change_pass_btn.setObjectName("UpdatePassBtn")
        self.change_pass_btn.clicked.connect(self.on_change_passphrase_clicked)
        passwd_layout.addWidget(self.change_pass_btn)
        
        layout.addWidget(passwd_card)

        # Card 4: Accent Color selection
        accent_card = GlassCard(scroll_content)
        accent_layout = QVBoxLayout(accent_card)
        accent_layout.addWidget(QLabel("Primary UI Accent Color:", accent_card))
        
        self.accent_combo = QComboBox(accent_card)
        self.accent_combo.setObjectName("AccentSelector")
        self.accent_combo.addItems(["Neon Violet (Default)", "Electric Cyan", "Emerald Green", "Crimson Red", "Amber Orange"])
        self.accent_combo.currentIndexChanged.connect(self.on_accent_changed)
        accent_layout.addWidget(self.accent_combo)
        
        layout.addWidget(accent_card)

        # Card 5: System Preferences (Minimize to tray, Autostart)
        sys_card = GlassCard(scroll_content)
        sys_layout = QVBoxLayout(sys_card)
        sys_layout.addWidget(QLabel("System & Startup Preferences:", sys_card))
        
        self.minimize_to_tray_checkbox = QCheckBox("Minimize to system tray on close", sys_card)
        self.minimize_to_tray_checkbox.setObjectName("MinimizeToTrayCheckbox")
        sys_layout.addWidget(self.minimize_to_tray_checkbox)
        
        self.autostart_checkbox = QCheckBox("Launch GhostDrive automatically on system startup", sys_card)
        self.autostart_checkbox.setObjectName("AutostartCheckbox")
        
        # Connect autostart check toggling
        from ghostdrive.gui.autostart import AutoStartManager
        self.autostart_checkbox.setChecked(AutoStartManager.is_enabled())
        self.autostart_checkbox.toggled.connect(self.on_autostart_toggled)
        
        sys_layout.addWidget(self.autostart_checkbox)
        layout.addWidget(sys_card)

        # Card 6: Storage Tier Replication Levels
        rep_card = GlassCard(scroll_content)
        rep_layout = QVBoxLayout(rep_card)
        rep_layout.addWidget(QLabel("Replication Redundancy Levels (Active Backends Count):", rep_card))
        
        grid = QGridLayout()
        grid.setSpacing(10)
        
        grid.addWidget(QLabel("Critical Tier (Default 4):", rep_card), 0, 0)
        self.critical_rep_spin = QSpinBox(rep_card)
        self.critical_rep_spin.setRange(1, 10)
        grid.addWidget(self.critical_rep_spin, 0, 1)
        
        grid.addWidget(QLabel("Important Tier (Default 3):", rep_card), 1, 0)
        self.important_rep_spin = QSpinBox(rep_card)
        self.important_rep_spin.setRange(1, 10)
        grid.addWidget(self.important_rep_spin, 1, 1)
        
        grid.addWidget(QLabel("Disposable Tier (Default 2):", rep_card), 2, 0)
        self.disposable_rep_spin = QSpinBox(rep_card)
        self.disposable_rep_spin.setRange(1, 10)
        grid.addWidget(self.disposable_rep_spin, 2, 1)
        
        rep_layout.addLayout(grid)
        layout.addWidget(rep_card)

        # Load values from DB settings table
        if self.db:
            self.critical_rep_spin.setValue(int(self.db.get_setting("rep_critical", "4")))
            self.important_rep_spin.setValue(int(self.db.get_setting("rep_important", "3")))
            self.disposable_rep_spin.setValue(int(self.db.get_setting("rep_disposable", "2")))

        # Connect signals after values are loaded to prevent triggering notifications during setup
        self.critical_rep_spin.valueChanged.connect(self.on_replication_level_changed)
        self.important_rep_spin.valueChanged.connect(self.on_replication_level_changed)
        self.disposable_rep_spin.valueChanged.connect(self.on_replication_level_changed)

        # Card 7: Post-Quantum Crypto & Key Rotation
        rotation_card = GlassCard(scroll_content)
        rotation_layout = QVBoxLayout(rotation_card)
        rotation_layout.addWidget(QLabel("Cryptographic Key Rotation:", rotation_card))
        self.rotate_keys_btn = StyledButton("Rotate Cryptographic Keys", rotation_card, primary=True)
        self.rotate_keys_btn.setObjectName("RotateKeysBtn")
        self.rotate_keys_btn.clicked.connect(self.on_rotate_keys_clicked)
        rotation_layout.addWidget(self.rotate_keys_btn)
        
        self.mlkem_key_label = QLabel("ML-KEM-768 Public Key: None", rotation_card)
        self.mlkem_key_label.setStyleSheet("font-size: 10px; color: #a855f7; margin-top: 6px;")
        rotation_layout.addWidget(self.mlkem_key_label)
        
        self.generate_mlkem_btn = StyledButton("Regenerate ML-KEM-768 Keypair", rotation_card, secondary=True)
        self.generate_mlkem_btn.setObjectName("GenerateMlkemBtn")
        self.generate_mlkem_btn.clicked.connect(self.on_regenerate_mlkem_clicked)
        rotation_layout.addWidget(self.generate_mlkem_btn)
        
        layout.addWidget(rotation_card)

        # Card 8: Backend Config Export/Import
        config_card = GlassCard(scroll_content)
        config_layout = QVBoxLayout(config_card)
        config_layout.addWidget(QLabel("Backup & Restore Backend Configurations:", config_card))
        
        config_btn_layout = QHBoxLayout()
        self.export_config_btn = StyledButton("Export Config", config_card, secondary=True)
        self.export_config_btn.setObjectName("ExportConfigBtn")
        self.export_config_btn.clicked.connect(self.on_export_config_clicked)
        config_btn_layout.addWidget(self.export_config_btn)
        
        self.import_config_btn = StyledButton("Import Config", config_card, secondary=True)
        self.import_config_btn.setObjectName("ImportConfigBtn")
        self.import_config_btn.clicked.connect(self.on_import_config_clicked)
        config_btn_layout.addWidget(self.import_config_btn)
        config_layout.addLayout(config_btn_layout)
        layout.addWidget(config_card)

        # Card 9: Log Rotation & Maintenance
        log_card = GlassCard(scroll_content)
        log_layout = QVBoxLayout(log_card)
        log_layout.addWidget(QLabel("Log File Maintenance & Limits:", log_card))
        
        self.log_size_label = QLabel("Current Log File Size: 0.0 KB", log_card)
        log_layout.addWidget(self.log_size_label)
        
        limit_layout = QHBoxLayout()
        limit_layout.addWidget(QLabel("Max Log Size (MB):", log_card))
        self.log_size_spin = QSpinBox(log_card)
        self.log_size_spin.setRange(1, 50)
        self.log_size_spin.setValue(5)
        self.log_size_spin.valueChanged.connect(self.on_log_max_size_changed)
        limit_layout.addWidget(self.log_size_spin)
        log_layout.addLayout(limit_layout)
        
        log_btn_layout = QHBoxLayout()
        self.rotate_logs_btn = StyledButton("Rotate Logs Now", log_card, secondary=True)
        self.rotate_logs_btn.setObjectName("RotateLogsBtn")
        self.rotate_logs_btn.clicked.connect(self.on_rotate_logs_clicked)
        log_btn_layout.addWidget(self.rotate_logs_btn)
        
        self.clear_logs_btn = StyledButton("Purge Active Logs", log_card, secondary=True)
        self.clear_logs_btn.setObjectName("ClearLogsBtn")
        self.clear_logs_btn.clicked.connect(self.on_clear_logs_clicked)
        log_btn_layout.addWidget(self.clear_logs_btn)
        log_layout.addLayout(log_btn_layout)
        layout.addWidget(log_card)

        # Card 10: Bandwidth Rate Limiter
        throttle_card = GlassCard(scroll_content)
        throttle_layout = QVBoxLayout(throttle_card)
        throttle_layout.addWidget(QLabel("Bandwidth Throttle Control:", throttle_card))
        
        self.upload_throttle_label = QLabel("Upload Speed Limit: Unlimited", throttle_card)
        throttle_layout.addWidget(self.upload_throttle_label)
        self.upload_throttle_slider = QSlider(Qt.Orientation.Horizontal, throttle_card)
        self.upload_throttle_slider.setRange(0, 100)
        self.upload_throttle_slider.valueChanged.connect(self.on_upload_throttle_changed)
        throttle_layout.addWidget(self.upload_throttle_slider)
        
        self.download_throttle_label = QLabel("Download Speed Limit: Unlimited", throttle_card)
        throttle_layout.addWidget(self.download_throttle_label)
        self.download_throttle_slider = QSlider(Qt.Orientation.Horizontal, throttle_card)
        self.download_throttle_slider.setRange(0, 100)
        self.download_throttle_slider.valueChanged.connect(self.on_download_throttle_changed)
        throttle_layout.addWidget(self.download_throttle_slider)
        
        layout.addWidget(throttle_card)

        layout.addStretch()

        # Connect log size check timer on layout setup
        QTimer.singleShot(100, self.refresh_log_size_display)
        QTimer.singleShot(100, self.refresh_mlkem_key_display)

        self.stacked_views.addWidget(settings_widget)

    # ─── Business Logic Event Handlers ──────────────────────────────────────────

    def set_nav_row(self, row: int) -> None:
        if hasattr(self, 'nav_buttons'):
            for i, btn in enumerate(self.nav_buttons):
                btn.setChecked(i == row)
        self._on_navigation_changed(row)

    def _on_navigation_changed(self, row: int) -> None:
        self.stacked_views.setCurrentIndex(row)
        if row == 7 and hasattr(self, "analytics_panel"):
            self.analytics_panel.load_analytics_data()



    # ─── File Operations (Upload / Download / Search / Delete) ──────────────────

    def trigger_emergency_cross_mirroring(self) -> None:
        """Trigger replication sweep to mirror all files from active to target backend."""
        QMessageBox.information(
            self, "Emergency Cross-Mirroring",
            "Emergency Cross-Mirroring started. This will duplicate under-replicated chunks to newly added or available healthy backends."
        )
        if hasattr(self, "healing_queue") and self.healing_queue:
            asyncio.create_task(self.healing_queue.perform_healing_step())

    def trigger_health_alert_ui(self, healthy_count: int) -> None:
        """Invoked by HealthDaemon to apply the alert hierarchy (Spec 7.4)."""
        self._healthy_count = healthy_count
        
        self.set_read_only_mode(False)

        # Get total configured backends
        try:
            with self.db.transaction():
                row = self.db._conn.execute("SELECT COUNT(*) as cnt FROM backends").fetchone()
                total_configured = row["cnt"] if row else 0
        except Exception:
            total_configured = 0

        if total_configured == 0:
            self.conn_indicator.setText("⚪ No Backends")
            self.conn_indicator.setStyleSheet("color: #9ca3af; font-size: 11px; margin-right: 12px;")
            self.warning_banner.setVisible(False)
            self.statusBar().clearMessage()
            self._health_modal_shown = False
            return

        # Fetch min healthy threshold for modal trigger
        try:
            alert_min_str = self.db.get_setting("alert_min_healthy", "")
            alert_min = int(alert_min_str) if alert_min_str.strip() else (2 if total_configured >= 3 else 1)
        except Exception:
            alert_min = 2 if total_configured >= 3 else 1

        # Update Connection Indicator Text and Style
        if healthy_count >= total_configured:
            self.conn_indicator.setText("🟢 Online")
            self.conn_indicator.setStyleSheet("color: #10b981; font-weight: bold; font-size: 11px; margin-right: 12px;")
            self.warning_banner.setVisible(False)
            self.statusBar().clearMessage()
            self._health_modal_shown = False
        elif healthy_count > 0:
            self.conn_indicator.setText("🟡 Degraded")
            self.conn_indicator.setStyleSheet("color: #f59e0b; font-weight: bold; font-size: 11px; margin-right: 12px;")
            
            # Show warning banner
            self.warning_banner.setVisible(True)
            offline_cnt = total_configured - healthy_count
            self.banner_label.setText(f"⚠️ Warning: {offline_cnt} backend(s) offline. Redundancy degraded.")
            self.statusBar().showMessage(f"Warning: {healthy_count}/{total_configured} backends healthy.")
            self.statusBar().setStyleSheet("color: #f59e0b; font-size: 11px;")
            
            # Check for critical blocking modal
            if healthy_count < alert_min:
                if not self._health_modal_shown:
                    self._health_modal_shown = True
                    self.show_blocking_health_modal()
        else: # 0 healthy
            self.conn_indicator.setText("🔴 Offline")
            self.conn_indicator.setStyleSheet("color: #ef4444; font-weight: bold; font-size: 11px; margin-right: 12px;")
            
            self.warning_banner.setVisible(True)
            self.banner_label.setText("🛑 Emergency Read-Only Mode: 0 healthy backends detected.")
            self.statusBar().showMessage("Emergency: 0 backends healthy (Read-Only).")
            self.statusBar().setStyleSheet("color: #f87171; font-size: 11px;")
            self.set_read_only_mode(True)

    def show_blocking_health_modal(self) -> None:
        """Presents a blocking full-screen modal when only 1 backend is healthy."""
        if getattr(self, "_showing_blocking_modal", False):
            return
        self._showing_blocking_modal = True
        
        modal = ResilientDialog(self, base_width=450, base_height=220)
        modal.setWindowTitle("CRITICAL ALERT - Storage Degraded")
        modal.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.WindowTitleHint | Qt.WindowType.WindowCloseButtonHint)
        modal.setModal(True)
        
        layout = QVBoxLayout(modal)
        layout.setContentsMargins(24, 24, 24, 24)
        
        title = QLabel("🛑 Critical Redundancy Alert", modal)
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #ef4444;")
        layout.addWidget(title)
        
        desc = QLabel("Only 1 healthy storage backend is remaining. Your files are at high risk of data loss. Please add a new backend or trigger emergency replication.", modal)
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #d1d5db; margin-top: 8px; margin-bottom: 16px;")
        layout.addWidget(desc)
        
        btn_layout = QHBoxLayout()
        add_btn = StyledButton("Add Backend", modal, primary=True)
        add_btn.clicked.connect(lambda: [modal.accept(), self.set_nav_row(2)]) # Route to Backends page
        
        mirror_btn = StyledButton("Mirror Now", modal, secondary=True)
        mirror_btn.clicked.connect(lambda: [modal.accept(), self.trigger_emergency_cross_mirroring()])
        
        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(mirror_btn)
        layout.addLayout(btn_layout)
        
        self._health_modal = modal
        modal.finished.connect(lambda: [setattr(self, "_showing_blocking_modal", False), setattr(self, "_health_modal", None)])
        modal.open()

    def set_read_only_mode(self, enabled: bool) -> None:
        """Disables uploads and write operations when in emergency read-only mode."""
        self._read_only_mode = enabled
        if hasattr(self, "upload_local_btn") and self.upload_local_btn:
            self.upload_local_btn.setEnabled(not enabled)
            if enabled:
                self.upload_local_btn.setToolTip("Disabled: Drive is in read-only emergency mode.")
            else:
                self.upload_local_btn.setToolTip("")

    # ─── Trash Bin Logic (Restore / Vacuum Purge) ─────────────────────────────

    def refresh_backends_ui(self) -> None:
        # Clear current list
        while self.backends_list_layout.count():
            item = self.backends_list_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

        for name, b_obj in self.active_backends.items():
            card = GlassCard(self.backends_list_widget)
            card_layout = QHBoxLayout(card)
            card_layout.setContentsMargins(16, 16, 16, 16)

            info_layout = QVBoxLayout()
            
            # Determine friendly title based on label and type
            if hasattr(b_obj, "label") and b_obj.label:
                title_text = f"☁️ {b_obj.label.upper()} ({b_obj.type.upper()})"
            else:
                title_text = f"☁️ {name.upper()} BACKEND"
                
            b_title = QLabel(title_text, card)
            b_title.setObjectName("SubHeading")
            info_layout.addWidget(b_title)

            # Query backend details from DB (by ID first, fallback to type)
            used = 0
            limit = 4611686018427387904
            status = "healthy"
            if self.db:
                with self.db.transaction():
                    row = self.db._conn.execute(
                        "SELECT quota_used, quota_limit, status FROM backends WHERE id = ? OR type = ?", (name, name)
                    ).fetchone()
                if row:
                    used = row["quota_used"]
                    limit = row["quota_limit"]
                    status = row["status"]

            limit_str = self._format_bytes(limit) if limit < 4000000000000000000 else "Unlimited"
            lbl_text = f"Space Used: {self._format_bytes(used)} / {limit_str} (Status: {status})"
            
            # Add root path description for local folders or drives
            if b_obj.type == "local" and hasattr(b_obj, "root_path") and b_obj.root_path:
                lbl_text += f"\nPath: {b_obj.root_path.as_posix()}"
                
            quota_lbl = QLabel(lbl_text, card)
            quota_lbl.setObjectName("MutedLabel")
            info_layout.addWidget(quota_lbl)

            card_layout.addLayout(info_layout, stretch=3)

            # Test Connection Button
            test_btn = StyledButton("Test Connection", card, secondary=True)
            test_btn.clicked.connect(lambda _, b=b_obj: self.test_backend_connection(b))
            card_layout.addWidget(test_btn, stretch=1)

            self.backends_list_layout.addWidget(card)

    @qasync.asyncSlot()
    async def test_backend_connection(self, backend_obj) -> None:
        self.notifications.notify("Testing Connection", f"Pinging {backend_obj.type.upper()}...", "info")
        try:
            if not getattr(backend_obj, "_connected", False):
                await backend_obj.connect()
                backend_obj._connected = True

            # Perform a quick latency check or simple call
            t0 = time.perf_counter()
            res = await backend_obj.health_check()
            latency = (time.perf_counter() - t0) * 1000

            if res.reachable:
                text = f"Successfully reached {backend_obj.type.upper()}!\nLatency: {latency:.1f} ms\nAvailable Space: {self._format_bytes(res.quota_remaining or 0)}"
                QTimer.singleShot(0, lambda: QMessageBox.information(self, "Connection Success", text))
            else:
                text = f"Reachable but reported issues: {res.error}"
                QTimer.singleShot(0, lambda: QMessageBox.warning(self, "Degraded Connection", text))
        except Exception as exc:
            text = f"Could not connect to {backend_obj.type.upper()}: {exc}"
            QTimer.singleShot(0, lambda: QMessageBox.critical(self, "Connection Failed", text))

    # ─── General Helpers ────────────────────────────────────────────────────────

    def _format_bytes(self, num_bytes: int) -> str:
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if num_bytes < 1024.0:
                return f"{num_bytes:.1f} {unit}"
            num_bytes /= 1024.0
        return f"{num_bytes:.1f} PB"

    def lock_and_logout(self) -> None:
        """Zero the keystore and drop back to Unlock Screen."""
        if hasattr(self, "vault") and self.vault:
            self.vault.lock()
            self.vault = None
        if hasattr(self, "secrets_panel") and self.secrets_panel:
            self.secrets_panel.lock()

        self.km.lock()
        if self.db:
            self.db.close()
        
        # Open Unlock View
        from ghostdrive.gui.unlock_view import UnlockView
        self.unlock_view = UnlockView(keystore_path=self.km.keystore_path)
        self.unlock_view.unlocked.connect(self._on_reunlocked)
        self.unlock_view.setStyleSheet(get_stylesheet(self.current_theme))
        self.unlock_view.show()
        
        # Hide self
        self.hide()

    def _on_reunlocked(self, unlocked_km) -> None:
        # Re-open DB
        self.km = unlocked_km
        # Derive database keys dynamically via HKDF from unlocked KeystoreManager
        from ghostdrive.crypto.hkdf import derive_index_mac_key
        ledger_key = derive_index_mac_key(unlocked_km.master_key, unlocked_km.hkdf_salt)
        genesis_seed = unlocked_km.genesis_seed
        # Re-initialize DB connection
        self.db = self.db.__class__(self.db._path, ledger_key, genesis_seed, master_key=unlocked_km.master_key)
        self.db.open()

        # Re-initialize vault
        from ghostdrive.crypto.secrets_vault import SecretsVault
        self.vault = SecretsVault(self.db, unlocked_km.master_key, unlocked_km.hkdf_salt)
        if hasattr(self, "secrets_panel") and self.secrets_panel:
            self.secrets_panel.set_vault(self.vault)

        # Update sharing engine
        if hasattr(self, "sharing_engine") and self.sharing_engine:
            self.sharing_engine.km = unlocked_km
        if hasattr(self, "shared_media_panel") and self.shared_media_panel:
            self.shared_media_panel.km = unlocked_km

        # Update telemetry view DB
        self.telemetry_view.set_db(self.db)

        # Show self
        self.show()
        self.refresh_files()
        self.refresh_trash()
        self.refresh_backends_ui()

        if self.unlock_view:
            self.unlock_view.hide()
            self.unlock_view = None

    def close_and_exit(self) -> None:
        """Trigger graceful shutdown."""
        self.km.lock()
        if self.db:
            self.db.close()
        self.close()

    def closeEvent(self, event) -> None:
        """Ensure background health daemon and healing queue stop cleanly on window close."""
        if hasattr(self, "minimize_to_tray_checkbox") and self.minimize_to_tray_checkbox.isChecked() and hasattr(self, "tray") and self.tray.isVisible():
            self.hide()
            event.ignore()
            self.notifications.notify("GhostDrive Minimized", "Application is still running in the system tray.", "info")
            return

        if hasattr(self, "health_daemon") and self.health_daemon:
            self.health_daemon.stop()
        if hasattr(self, "healing_queue") and self.healing_queue:
            self.healing_queue.stop()
        if hasattr(self, "tray") and self.tray:
            self.tray.hide()
            self.tray.deleteLater()
        super().closeEvent(event)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self.handle_resize_event()
        self.adjust_grid_layout()

    def adjust_grid_layout(self) -> None:
        if not hasattr(self, "files_grid_layout") or not self.files_grid_layout:
            return
        if not hasattr(self, "files_grid_scroll") or not self.files_grid_scroll:
            return
            
        scroll_width = self.files_grid_scroll.viewport().width()
        scale = getattr(self, "_scale_factor", 1.0)
        card_width = max(80, int(145 * scale))
        columns = max(1, scroll_width // card_width)
        
        # Scale each card and its contents
        from ghostdrive.gui.styles import (
            store_original_layout_metrics,
            store_original_widget_stylesheets,
            apply_layout_scaling,
            apply_widget_stylesheet_scaling,
        )
        for i in range(self.files_grid_layout.count()):
            item = self.files_grid_layout.itemAt(i)
            if item:
                card = item.widget()
                if card:
                    store_original_layout_metrics(card)
                    store_original_widget_stylesheets(card)
                    apply_widget_stylesheet_scaling(card, scale)
                    apply_layout_scaling(card, scale)
                    
                    item_type = card.property("item_type")
                    if item_type == "folder":
                        card.setFixedWidth(card_width)
                        card.setFixedHeight(max(90, int(100 * scale)))
                    elif item_type == "file":
                        card.setFixedWidth(card_width)
                        card.setFixedHeight(max(150, int(170 * scale)))
                    
                    for child in card.findChildren(QLabel):
                        if child.text() == "📁":
                            child.setStyleSheet(f"font-size: {int(32 * scale)}px;")
                    for thumb in card.findChildren(ThumbnailWidget):
                        thumb.resize_thumbnail(int(100 * scale))
                        
        if hasattr(self, "_current_grid_columns") and self._current_grid_columns == columns:
            return
        self._current_grid_columns = columns
        
        # Collect active widgets in grid layout in order
        widgets = []
        for i in range(self.files_grid_layout.count()):
            item = self.files_grid_layout.itemAt(i)
            if item:
                w = item.widget()
                if w:
                    widgets.append(w)
                    
        # Remove widgets from grid
        for w in widgets:
            self.files_grid_layout.removeWidget(w)
            
        # Re-add with new columns
        for idx, w in enumerate(widgets):
            grid_row = idx // columns
            grid_col = idx % columns
            self.files_grid_layout.addWidget(w, grid_row, grid_col)

    def show_about_dialog(self) -> None:
        from ghostdrive.gui.dialogs import AboutDialog
        dialog = AboutDialog(self)
        dialog.exec()

    def add_activity_log(self, text: str) -> None:
        time_str = datetime.now().strftime("%H:%M:%S")
        item = QListWidgetItem(f"[{time_str}] {text}")
        self.activity_list.addItem(item)
        if self.activity_list.count() > 100:
            self.activity_list.takeItem(0)
        self.activity_list.scrollToBottom()

    def show_crypto_properties(self) -> None:
        selected_ids = self.get_selected_file_ids()
        if len(selected_ids) != 1:
            return
        file_id = selected_ids[0]
        with self.db.transaction():
            row = self.db._conn.execute(
                "SELECT * FROM files WHERE id = ?", (file_id,)
            ).fetchone()
        if row:
            from ghostdrive.gui.dialogs import FileInspectorDialog
            dialog = FileInspectorDialog(row, self.db, self)
            dialog.exec()

    def on_delete_shortcut_activated(self) -> None:
        current_view = self.stacked_views.currentIndex()
        if current_view == 0:  # Files page
            selected_ids = self.get_selected_file_ids()
            if not selected_ids:
                return
            reply = QMessageBox.question(
                self, "Confirm Deletion", f"Are you sure you want to delete {len(selected_ids)} file(s)?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.Yes:
                try:
                    for file_id in selected_ids:
                        # Fetch file row for tier check
                        with self.db.transaction():
                            f_row = self.db._conn.execute("SELECT tier FROM files WHERE id = ?", (file_id,)).fetchone()
                        if f_row and f_row["tier"] == "DISPOSABLE":
                            asyncio.create_task(self._purge_file_permanent_no_prompt(file_id))
                        else:
                            with self.db.transaction():
                                self.db.tombstone_file(file_id)
                    self.notifications.notify("Files Deleted", "Selected files moved to trash.", "info")
                    self.refresh_files()
                    self.refresh_trash()
                except Exception as exc:
                    QMessageBox.critical(self, "Error", f"Failed to delete selected files: {exc}")
        elif current_view == 1:  # Trash page
            self.purge_selected_trash()

    def on_f5_shortcut_activated(self) -> None:
        import time
        now = time.monotonic()
        if hasattr(self, "_last_f5_time") and (now - self._last_f5_time) < 2.0:
            return
        self._last_f5_time = now
        self.refresh_files()
        self.refresh_trash()
        self.refresh_backends_ui()
        self.notifications.notify("Dashboard Refreshed", "Updated file list, trash state, and backend status.", "info")

    def on_ctrl_u_shortcut_activated(self) -> None:
        if self.stacked_views.currentIndex() == 0:  # Files page
            self.on_manual_upload_clicked()

    def check_and_trigger_weekly_digest(self) -> None:
        """Checks and triggers the weekly system health digest."""
        if hasattr(self, "notifications") and self.notifications:
            self.notifications.send_weekly_digest()

    @qasync.asyncSlot()
    async def sync_index_on_startup(self) -> None:
        """
        Runs the startup index synchronization.
        Pulls remote snapshots from remote backends on the asyncio loop,
        reconciles them on a background thread pool to prevent GUI freezes,
        and merges remote records row-by-row into the local database.
        """
        if not self.db or not self.km:
            return
            
        logger.info("Starting startup index synchronization...")
        
        master_key = self.km.master_key
        salt = self.km.hkdf_salt
        
        # Derive backup names
        from ghostdrive.crypto.hkdf import derive_index_backup_name
        index_backup_name_hex = derive_index_backup_name(master_key, salt).hex()
        db_remote_filename = f"{index_backup_name_hex}_9999.gdc"
        
        # Filter remote backends
        remote_backends = []
        for b_name, b_obj in self.active_backends.items():
            if b_obj.type not in ("local_fs", "external_drive"):
                remote_backends.append(b_obj)
                
        if not remote_backends:
            logger.info("No remote backends registered. Skipping startup sync.")
            return
            
        import io
        with self.db._lock:
            local_clock = self.db.current_clock()
            
        newest_clock = local_clock
        newest_temp_db_path = None
        newest_backend_name = None
        
        for b_obj in remote_backends:
            try:
                if not getattr(b_obj, "_connected", False):
                    await b_obj.connect()
                    b_obj._connected = True
                    
                logger.info("Checking remote snapshot on backend %s...", b_obj.type)
                buf = io.BytesIO()
                async for block in b_obj.download(db_remote_filename):
                    buf.write(block)
                encrypted_bytes = buf.getvalue()
                
                if len(encrypted_bytes) > 0:
                    # Offload decryption and clock check to background thread
                    clock, temp_db_path = await asyncio.to_thread(
                        _decrypt_and_get_remote_clock,
                        encrypted_bytes,
                        master_key,
                        salt
                    )
                    logger.info("Backend %s remote clock: %d (local: %d)", b_obj.type, clock, local_clock)
                    
                    if clock > newest_clock:
                        if newest_temp_db_path and newest_temp_db_path != temp_db_path:
                            try:
                                await asyncio.to_thread(os.unlink, newest_temp_db_path)
                            except Exception:
                                pass
                        newest_clock = clock
                        newest_temp_db_path = temp_db_path
                        newest_backend_name = b_obj.type.upper()
                    else:
                        try:
                            await asyncio.to_thread(os.unlink, temp_db_path)
                        except Exception:
                            pass
            except Exception as e:
                logger.debug("No valid snapshot or connection failed on %s: %s", b_obj.type, e)
                
        if newest_temp_db_path:
            logger.info("Newer snapshot found on %s with clock %d. Reconciling...", newest_backend_name, newest_clock)
            try:
                with self.db._lock:
                    await asyncio.to_thread(
                        _reconcile_db_sync,
                        self.db._path,
                        newest_temp_db_path,
                        master_key
                    )
                logger.info("Reconciliation complete.")
                self.notifications.notify(
                    "Sync Completed",
                    f"Successfully synchronized local metadata with remote changes from {newest_backend_name}.",
                    "success"
                )
                self.refresh_files()
                self.refresh_trash()
                self.refresh_backends_ui()
            except Exception as reconciliation_error:
                logger.error("Failed during database reconciliation: %s", reconciliation_error)
            finally:
                try:
                    await asyncio.to_thread(os.unlink, newest_temp_db_path)
                except Exception:
                    pass
        else:
            logger.info("Local index is up to date.")

    @qasync.asyncSlot()
    async def backup_index_and_credentials(self) -> None:
        """
        Securely backs up the local index database and OS keyring credentials.
        Uses SQLite Online Backup API to ensure consistency.
        Encrypts payloads and replicates to all healthy remote backends.
        """
        if not self.db or not self.km:
            return
            
        logger.info("Starting background index and credentials backup...")
        try:
            self.db.wal_checkpoint()
            
            import sqlite3 as py_sqlite3
            import tempfile
            from pathlib import Path
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            from ghostdrive.crypto.hkdf import (
                derive_index_backup_name,
                derive_index_backup_enc_key,
                derive_credentials_backup_name,
                derive_backend_credentials_key
            )
            
            master_key = self.km.master_key
            salt = self.km.hkdf_salt
            
            temp_dir = tempfile.gettempdir()
            tmp_path = Path(temp_dir) / f"backup_{uuid.uuid4().hex}.db"
            
            def perform_sqlite_backup(src_conn, dest_path):
                dest_conn = py_sqlite3.connect(dest_path)
                src_conn.backup(dest_conn)
                dest_conn.close()
                
            with self.db._lock:
                await asyncio.to_thread(perform_sqlite_backup, self.db._conn, tmp_path)
                
            db_bytes = await asyncio.to_thread(tmp_path.read_bytes)
            try:
                await asyncio.to_thread(tmp_path.unlink)
            except Exception:
                pass
                
            db_enc_key = derive_index_backup_enc_key(master_key, salt)
            aesgcm_db = AESGCM(db_enc_key)
            nonce_db = os.urandom(12)
            encrypted_db = nonce_db + aesgcm_db.encrypt(nonce_db, db_bytes, None)
            
            keys_to_backup = [
                "telegram_phone",
                "telegram_api_id",
                "telegram_api_hash",
                "telegram_session",
                "keyring:encrypted:nas_creds"
            ]
            creds_dict = {}
            from ghostdrive.crypto.credential_store import credential_store
            for k in keys_to_backup:
                val = credential_store.load(k)
                if val:
                    creds_dict[k] = val
                    
            creds_enc_key = derive_backend_credentials_key(master_key, salt)
            creds_json = json.dumps(creds_dict).encode("utf-8")
            aesgcm_creds = AESGCM(creds_enc_key)
            nonce_creds = os.urandom(12)
            encrypted_creds = nonce_creds + aesgcm_creds.encrypt(nonce_creds, creds_json, None)
            
            remote_backends = []
            for b_name, b_obj in self.active_backends.items():
                if b_obj.type not in ("local_fs", "external_drive"):
                    remote_backends.append(b_obj)
                    
            if not remote_backends:
                logger.warning("No remote backends available for backup.")
                return
                
            index_backup_name_hex = derive_index_backup_name(master_key, salt).hex()
            credentials_backup_name_hex = derive_credentials_backup_name(master_key, salt).hex()
            
            async def make_stream(data: bytes):
                yield data
                
            for b_obj in remote_backends:
                try:
                    if not getattr(b_obj, "_connected", False):
                        await b_obj.connect()
                        b_obj._connected = True
                        
                    await b_obj.upload(make_stream(encrypted_db), index_backup_name_hex, 9999)
                    await b_obj.upload(make_stream(encrypted_creds), credentials_backup_name_hex, 9998)
                    
                    logger.info("Backup successfully uploaded to remote backend: %s", b_obj.type)
                except Exception as b_exc:
                    logger.error("Failed to upload backup to backend %s: %s", b_obj.type, b_exc)
                    
            self.notifications.notify("Index Backup Completed", "Database and credentials securely backed up to remote channels.", "success")
        except Exception as exc:
            logger.error("Failed to perform background index and credentials backup: %s", exc)


def _decrypt_and_get_remote_clock(encrypted_db: bytes, master_key: bytes, salt: bytes) -> tuple[int, str]:
    """
    Decrypts the remote database backup, writes it to a temporary file,
    and queries its current Lamport logical clock.
    Returns (clock, temp_file_path).
    """
    import tempfile
    import uuid
    try:
        import sqlcipher3 as py_sqlite3
    except ImportError:
        import pysqlcipher3 as py_sqlite3  # type: ignore
    from pathlib import Path
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from ghostdrive.crypto.hkdf import derive_index_backup_enc_key
    
    db_enc_key = derive_index_backup_enc_key(master_key, salt)
    aesgcm_db = AESGCM(db_enc_key)
    
    nonce = encrypted_db[:12]
    ciphertext = encrypted_db[12:]
    decrypted_bytes = aesgcm_db.decrypt(nonce, ciphertext, None)
    
    temp_dir = tempfile.gettempdir()
    tmp_path = Path(temp_dir) / f"remote_sync_{uuid.uuid4().hex}.db"
    tmp_path.write_bytes(decrypted_bytes)
    
    conn = py_sqlite3.connect(str(tmp_path))
    conn.execute(f"PRAGMA key = \"x'{master_key.hex()}'\"")
    conn.row_factory = py_sqlite3.Row
    try:
        row = conn.execute("SELECT logical_clock FROM hmac_ledger WHERE id = 1").fetchone()
        clock = row["logical_clock"] if row else 0
    except Exception:
        clock = 0
    finally:
        conn.close()
        
    return clock, str(tmp_path)


def _reconcile_db_sync(local_db_path: str, remote_db_path: str, master_key: bytes) -> None:
    """
    Reconciles the local database with a remote database row-by-row.
    Compares Lamport clocks and merges records.
    """
    try:
        import sqlcipher3 as py_sqlite3
    except ImportError:
        import pysqlcipher3 as py_sqlite3  # type: ignore
    
    local_conn = py_sqlite3.connect(local_db_path)
    local_conn.execute(f"PRAGMA key = \"x'{master_key.hex()}'\"")
    local_conn.row_factory = py_sqlite3.Row
    
    remote_conn = py_sqlite3.connect(remote_db_path)
    remote_conn.execute(f"PRAGMA key = \"x'{master_key.hex()}'\"")
    remote_conn.row_factory = py_sqlite3.Row
    
    try:
        # Reconcile files table
        remote_files = remote_conn.execute("SELECT * FROM files").fetchall()
        for r_file in remote_files:
            l_file = local_conn.execute("SELECT * FROM files WHERE id = ?", (r_file["id"],)).fetchone()
            if not l_file:
                cols = r_file.keys()
                placeholders = ",".join(["?"] * len(cols))
                col_names = ",".join(cols)
                local_conn.execute(
                    f"INSERT INTO files ({col_names}) VALUES ({placeholders})",
                    [r_file[c] for c in cols]
                )
            else:
                r_clock = r_file.get("logical_clock", 0)
                l_clock = l_file.get("logical_clock", 0)
                r_modified = r_file.get("modified_at", "")
                l_modified = l_file.get("modified_at", "")
                if r_clock > l_clock or (r_clock == l_clock and r_modified > l_modified):
                    cols = [c for c in r_file.keys() if c != "id"]
                    set_clause = ",".join([f"{c} = ?" for c in cols])
                    local_conn.execute(
                        f"UPDATE files SET {set_clause} WHERE id = ?",
                        [r_file[c] for c in cols] + [r_file["id"]]
                    )
                    
        # Reconcile secrets_vault table
        remote_secrets = remote_conn.execute("SELECT * FROM secrets_vault").fetchall()
        for r_sec in remote_secrets:
            l_sec = local_conn.execute("SELECT * FROM secrets_vault WHERE id = ?", (r_sec["id"],)).fetchone()
            if not l_sec:
                cols = r_sec.keys()
                placeholders = ",".join(["?"] * len(cols))
                col_names = ",".join(cols)
                local_conn.execute(
                    f"INSERT INTO secrets_vault ({col_names}) VALUES ({placeholders})",
                    [r_sec[c] for c in cols]
                )
            else:
                r_clock = r_sec.get("logical_clock", 0)
                l_clock = l_sec.get("logical_clock", 0)
                r_modified = r_sec.get("modified_at", "")
                l_modified = l_sec.get("modified_at", "")
                if r_clock > l_clock or (r_clock == l_clock and r_modified > l_modified):
                    cols = [c for c in r_sec.keys() if c != "id"]
                    set_clause = ",".join([f"{c} = ?" for c in cols])
                    local_conn.execute(
                        f"UPDATE secrets_vault SET {set_clause} WHERE id = ?",
                        [r_sec[c] for c in cols] + [r_sec["id"]]
                    )

        # Reconcile chunks table (spec §12 Month 2 database schema sync)
        remote_chunks = remote_conn.execute("SELECT * FROM chunks").fetchall()
        for r_chunk in remote_chunks:
            l_chunk = local_conn.execute("SELECT * FROM chunks WHERE id = ?", (r_chunk["id"],)).fetchone()
            if not l_chunk:
                cols = r_chunk.keys()
                placeholders = ",".join(["?"] * len(cols))
                col_names = ",".join(cols)
                local_conn.execute(
                    f"INSERT INTO chunks ({col_names}) VALUES ({placeholders})",
                    [r_chunk[c] for c in cols]
                )
            else:
                r_ref = r_chunk.get("ref_count", 1)
                l_ref = l_chunk.get("ref_count", 1)
                if r_ref > l_ref:
                    local_conn.execute(
                        "UPDATE chunks SET ref_count = ? WHERE id = ?",
                        (r_ref, r_chunk["id"])
                    )

        # Reconcile chunk_locations table using its composite primary key fields
        remote_locs = remote_conn.execute("SELECT * FROM chunk_locations").fetchall()
        for r_loc in remote_locs:
            l_loc = local_conn.execute(
                "SELECT * FROM chunk_locations WHERE chunk_id = ? AND sub_block_index = ? AND backend_id = ?",
                (r_loc["chunk_id"], r_loc["sub_block_index"], r_loc["backend_id"])
            ).fetchone()
            if not l_loc:
                cols = r_loc.keys()
                placeholders = ",".join(["?"] * len(cols))
                col_names = ",".join(cols)
                local_conn.execute(
                    f"INSERT INTO chunk_locations ({col_names}) VALUES ({placeholders})",
                    [r_loc[c] for c in cols]
                )
            else:
                if r_loc["status"] == "confirmed" and l_loc["status"] != "confirmed":
                    local_conn.execute(
                        """UPDATE chunk_locations 
                           SET status = 'confirmed', reference_id = ?, quota_reserved = 0 
                           WHERE chunk_id = ? AND sub_block_index = ? AND backend_id = ?""",
                        (r_loc["reference_id"], r_loc["chunk_id"], r_loc["sub_block_index"], r_loc["backend_id"])
                    )
                    
        # Reconcile other tables: contacts, shares, backends
        for table in ["contacts", "shares", "backends"]:
            try:
                remote_rows = remote_conn.execute(f"SELECT * FROM {table}").fetchall()
            except Exception:
                continue
            for r_row in remote_rows:
                l_row = local_conn.execute(f"SELECT * FROM {table} WHERE id = ?", (r_row["id"],)).fetchone()
                if not l_row:
                    cols = r_row.keys()
                    placeholders = ",".join(["?"] * len(cols))
                    col_names = ",".join(cols)
                    local_conn.execute(
                        f"INSERT INTO {table} ({col_names}) VALUES ({placeholders})",
                        [r_row[c] for c in cols]
                    )
                else:
                    r_clock = r_row.get("logical_clock", 0)
                    l_clock = l_row.get("logical_clock", 0)
                    r_modified = r_row.get("modified_at", "")
                    l_modified = l_row.get("modified_at", "")
                    if r_clock > l_clock or (r_clock == l_clock and r_modified > l_modified):
                        cols = [c for c in r_row.keys() if c != "id"]
                        set_clause = ",".join([f"{c} = ?" for c in cols])
                        local_conn.execute(
                            f"UPDATE {table} SET {set_clause} WHERE id = ?",
                            [r_row[c] for c in cols] + [r_row["id"]]
                        )
                        
        local_conn.commit()
    finally:
        local_conn.close()
        remote_conn.close()
