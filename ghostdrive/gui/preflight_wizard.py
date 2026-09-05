"""
preflight_wizard.py -- Pre-flight connectivity and system checklist wizard dialog.
"""

import socket
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QProgressBar,
)

from ghostdrive.gui.widgets import StyledButton, GlassCard
from ghostdrive.gui.sys_checks import run_system_diagnostics
from ghostdrive.gui.styles import ResizingResilientMixin

# ─── Diagnostics Thread ────────────────────────────────────────────────────────

class DiagnosticsWorker(QThread):
    """Background thread performing network, database, and keyring reachability checks."""
    progress = pyqtSignal(int, str)
    check_completed = pyqtSignal(str, bool, str)
    finished_all = pyqtSignal(bool)

    def run(self) -> None:
        all_passed = True

        # 1. Keyring Access Check
        self.progress.emit(10, "Checking OS Keyring access...")
        keyring_ok = False
        keyring_msg = ""
        try:
            import keyring
            # Try a dummy write/read/delete cycle or basic get_keyring check
            kr = keyring.get_keyring()
            if kr is not None:
                keyring_ok = True
                keyring_msg = f"Keyring backend loaded: {kr.__class__.__name__}"
            else:
                keyring_msg = "No keyring backend found."
        except Exception as exc:
            keyring_msg = f"Keyring check failed: {exc}"
        
        self.check_completed.emit("keyring", keyring_ok, keyring_msg)
        if not keyring_ok:
            all_passed = False

        self.msleep(300)

        # 2. Database Write Access Check
        self.progress.emit(40, "Checking database write accessibility...")
        db_ok = True
        db_msg = "Database directories are writable."
        try:
            # Check write in current directory
            test_file = ".gd_write_test"
            with open(test_file, "w") as f:
                f.write("test")
            os_remove_ok = True
            try:
                import os
                os.remove(test_file)
            except Exception:
                os_remove_ok = False
            if not os_remove_ok:
                db_ok = False
                db_msg = "Could not delete test database files."
        except Exception as exc:
            db_ok = False
            db_msg = f"Write access check failed: {exc}"
            
        self.check_completed.emit("database", db_ok, db_msg)
        if not db_ok:
            all_passed = False

        self.msleep(300)

        # 3. Internet Connectivity Check
        self.progress.emit(70, "Checking internet reachability (DNS / Port)...")
        net_ok = False
        net_msg = ""
        
        # Test targets
        hosts = ["discord.com", "google.com", "api.telegram.org"]
        socket.setdefaulttimeout(3)
        
        for attempt in range(3):
            for host in hosts:
                try:
                    socket.gethostbyname(host)
                    net_ok = True
                    net_msg = f"Internet reachability verified via {host}."
                    break
                except Exception:
                    pass
            if net_ok:
                break
            self.msleep(200)

        if not net_ok:
            net_msg = "Local-Only Pipeline Active"

        self.check_completed.emit("network", net_ok, net_msg)
        # Network check is informational-only; do not fail diagnostics if offline.

        self.msleep(300)
        self.progress.emit(100, "Diagnostics complete.")
        self.finished_all.emit(all_passed)


# ─── Preflight Wizard Dialog ───────────────────────────────────────────────────

class PreflightWizard(QDialog, ResizingResilientMixin):
    """Initial pre-flight checks screen displaying diagnostics before main app open."""
    diagnostics_passed = pyqtSignal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("GhostDrive Diagnostics")
        self.setMinimumSize(450, 520)
        self.resize(450, 520)
        self.setWindowFlags(Qt.WindowType.CustomizeWindowHint | Qt.WindowType.WindowTitleHint)

        # Layouts
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # Title
        title = QLabel("Pre-Flight System Check", self)
        title.setObjectName("Heading")
        layout.addWidget(title)

        sub_title = QLabel("Verifying system and network prerequisites...", self)
        sub_title.setObjectName("SubHeading")
        layout.addWidget(sub_title)

        # Card container for results
        self.card = GlassCard(self)
        card_layout = QVBoxLayout(self.card)
        card_layout.setSpacing(12)
        
        # Checklist Labels
        self.keyring_label = QLabel("🔑 OS Keyring: Pending...", self)
        self.db_label      = QLabel("💽 Database Access: Pending...", self)
        self.net_label     = QLabel("🌐 Internet Connectivity: Pending...", self)
        
        card_layout.addWidget(self.keyring_label)
        card_layout.addWidget(self.db_label)
        card_layout.addWidget(self.net_label)
        layout.addWidget(self.card)

        # System checks section (Windows long path & inotify)
        self.sys_card = GlassCard(self)
        sys_layout = QVBoxLayout(self.sys_card)
        sys_layout.setSpacing(6)
        self.sys_title = QLabel("System Environment Details:", self)
        self.sys_title.setStyleSheet("font-weight: bold;")
        sys_layout.addWidget(self.sys_title)
        
        # Run local checks synchronously (fast)
        diag = run_system_diagnostics()
        self.lp_lbl = QLabel(f"• Long Paths: {'OK' if diag['long_paths'][0] else 'Warning'} - {diag['long_paths'][1]}", self)
        self.in_lbl = QLabel(f"• Linux inotify: {'OK' if diag['inotify_limits'][0] else 'Warning'} - {diag['inotify_limits'][1]}", self)
        sys_layout.addWidget(self.lp_lbl)
        sys_layout.addWidget(self.in_lbl)
        layout.addWidget(self.sys_card)

        # Progress bar
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)

        self.status_label = QLabel("Initializing...", self)
        self.status_label.setObjectName("MutedLabel")
        layout.addWidget(self.status_label)

        # Buttons
        btn_layout = QHBoxLayout()
        self.retry_btn = StyledButton("Retry Diagnostics", self, secondary=True)
        self.retry_btn.setEnabled(False)
        self.retry_btn.clicked.connect(self.start_diagnostics)
        
        self.skip_btn = StyledButton("Proceed Anyway", self)
        self.skip_btn.setEnabled(False)
        self.skip_btn.clicked.connect(self.accept_diagnostics)

        btn_layout.addWidget(self.retry_btn)
        btn_layout.addWidget(self.skip_btn)
        layout.addLayout(btn_layout)

        # Diagnostics worker
        self._worker = None

        # Auto start
        QTimer.singleShot(500, self.start_diagnostics)

        # Initialize resizing resiliency framework with saved UI preferences
        from PyQt6.QtCore import QSettings
        settings = QSettings("GhostDrive", "Preferences")
        theme = settings.value("theme", "dark", type=str)
        accent = settings.value("accent_color", "#8b5cf6", type=str)
        self.init_resizing_resiliency(450, 420, theme, accent)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self.handle_resize_event()

    def start_diagnostics(self) -> None:
        """Reset UI state and launch background diagnostics thread."""
        self.retry_btn.setEnabled(False)
        self.skip_btn.setEnabled(False)
        self.progress_bar.setValue(0)
        
        self.keyring_label.setText("🔑 OS Keyring: Checking...")
        self.db_label.setText("💽 Database Access: Checking...")
        self.net_label.setText("🌐 Internet Connectivity: Checking...")

        self._worker = DiagnosticsWorker()
        self._worker.progress.connect(self._on_progress)
        self._worker.check_completed.connect(self._on_check_completed)
        self._worker.finished_all.connect(self._on_finished)
        self._worker.start()

    def _on_progress(self, val: int, text: str) -> None:
        self.progress_bar.setValue(val)
        self.status_label.setText(text)

    def _on_check_completed(self, name: str, success: bool, msg: str) -> None:
        status_text = "✅ Passed" if success else "❌ Failed"
        if name == "keyring":
            self.keyring_label.setText(f"🔑 OS Keyring: {status_text} ({msg})")
        elif name == "database":
            self.db_label.setText(f"💽 Database Access: {status_text} ({msg})")
        elif name == "network":
            if success:
                self.net_label.setText(f"🌐 Internet Connectivity: ✅ Active ({msg})")
            else:
                self.net_label.setText("🌐 Internet Connectivity: ℹ️ Local Only")

    def _on_finished(self, all_passed: bool) -> None:
        self._worker.quit()
        self._worker.wait()
        self._worker = None

        if all_passed:
            self.status_label.setText("All diagnostic tests passed successfully! Launching app...")
            # Auto proceed after 1s delay
            QTimer.singleShot(1000, self.accept_diagnostics)
        else:
            self.status_label.setText("Some diagnostics checks failed. Verify network or access permissions.")
            self.retry_btn.setEnabled(True)
            self.skip_btn.setEnabled(True)

    def accept_diagnostics(self) -> None:
        self.diagnostics_passed.emit()
        self.accept()
