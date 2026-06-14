"""
notifications.py -- Premium desktop notification alerts and glassmorphic toast overlays.
"""

from PyQt6.QtCore import Qt, QTimer, QPoint, QPropertyAnimation, QEasingCurve
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QWidget,
    QLabel,
    QHBoxLayout,
    QGraphicsOpacityEffect,
    QSystemTrayIcon,
)
from ghostdrive.gui.widgets import GlassCard

class ToastNotification(GlassCard):
    """A floating, glassmorphic toast overlay that fades in and out."""
    def __init__(self, parent: QWidget, message: str, severity: str = "info") -> None:
        super().__init__(parent)
        self.setObjectName("GlassCard")
        
        # Styles based on severity
        border_color = "#06b6d4"  # Default: Cyan
        icon = "ℹ️"
        if severity == "critical":
            border_color = "#ef4444"  # Red
            icon = "🚨"
        elif severity == "important":
            border_color = "#f59e0b"  # Amber
            icon = "⚠️"
        elif severity == "success":
            border_color = "#10b981"  # Green
            icon = "✅"

        self.setStyleSheet(f"""
            QFrame#GlassCard {{
                background-color: rgba(26, 26, 30, 230);
                border: 1.5px solid {border_color};
                border-radius: 8px;
            }}
        """)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(10)

        self.icon_label = QLabel(icon, self)
        self.icon_label.setStyleSheet("font-size: 16px;")
        layout.addWidget(self.icon_label)

        self.msg_label = QLabel(message, self)
        self.msg_label.setWordWrap(True)
        self.msg_label.setStyleSheet("color: #f4f4f5; font-weight: 500;")
        layout.addWidget(self.msg_label)

        # Set transparency effect for fading
        self.opacity_effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self.opacity_effect)
        self.opacity_effect.setOpacity(0.0)

        # Setup animations
        self.anim = QPropertyAnimation(self.opacity_effect, b"opacity")
        self.anim.setDuration(300)
        self.anim.setEasingCurve(QEasingCurve.Type.InOutQuad)

        self.adjustSize()

    def show_toast(self) -> None:
        """Position toast at the top-right of the parent window and slide/fade in."""
        parent = self.parentWidget()
        if not parent:
            return

        # Position at the top right of the parent window, with a margin
        margin_x = 20
        margin_y = 20
        x = parent.width() - self.width() - margin_x
        y = margin_y
        self.move(QPoint(x, y))
        self.show()
        
        self.anim.setStartValue(0.0)
        self.anim.setEndValue(1.0)
        self.anim.start()

        # Timer to close/fade out
        QTimer.singleShot(3500, self.fade_out)

    def fade_out(self) -> None:
        self.anim.stop()
        self.anim.setStartValue(1.0)
        self.anim.setEndValue(0.0)
        self.anim.finished.connect(self.deleteLater)
        self.anim.start()


class NotificationManager:
    """Manages system tray and custom overlay toasts based on severity."""
    def __init__(self, main_window: QWidget = None, tray_icon: QSystemTrayIcon = None) -> None:
        self.main_window = main_window
        self.tray_icon = tray_icon

    def set_main_window(self, window: QWidget) -> None:
        self.main_window = window

    def set_tray_icon(self, tray_icon: QSystemTrayIcon) -> None:
        self.tray_icon = tray_icon

    def notify(self, title: str, message: str, severity: str = "info") -> None:
        """
        Send a notification. 
        Tries system tray first; falls back or overlays toast if main window is active.
        """
        # 1. Native tray notification if available
        if self.tray_icon and self.tray_icon.isVisible():
            icon_type = QSystemTrayIcon.MessageIcon.Information
            if severity == "critical":
                icon_type = QSystemTrayIcon.MessageIcon.Critical
            elif severity == "important":
                icon_type = QSystemTrayIcon.MessageIcon.Warning
            
            self.tray_icon.showMessage(title, message, icon_type, 3000)

        # 2. Glassmorphic overlay toast on the active UI window
        if self.main_window and self.main_window.isVisible():
            toast = ToastNotification(self.main_window, message, severity)
            toast.show_toast()
