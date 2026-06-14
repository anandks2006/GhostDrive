"""
telemetry_view.py -- Dashboard for real-time speed charting and storage quota allocation.
"""

from PyQt6.QtCore import Qt, QTimer, QPointF
from PyQt6.QtGui import QPainter, QPen, QColor, QLinearGradient
from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QProgressBar,
)
from ghostdrive.gui.widgets import GlassCard
import random

class SpeedChartWidget(QWidget):
    """
    Custom widget that draws a smooth, hardware-accelerated rolling speed graph
    using QPainter and a gradient-filled curve (no external plotting libraries).
    """
    def __init__(self, parent: QWidget = None) -> None:
        super().__init__(parent)
        self.setMinimumHeight(180)
        self._speed_history = [0.0] * 50  # Keep last 50 data points
        self._max_speed = 10.0            # Dynamic scale (MB/s)

    def add_speed_point(self, speed_mbs: float) -> None:
        """Add a new speed measurement and refresh the chart."""
        self._speed_history.pop(0)
        self._speed_history.append(speed_mbs)
        
        # Recalculate max speed for scaling
        current_max = max(self._speed_history)
        self._max_speed = max(10.0, current_max * 1.2)
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        w = self.width()
        h = self.height()
        margin_left = 40
        margin_bottom = 20
        margin_top = 10
        margin_right = 10
        
        graph_w = w - margin_left - margin_right
        graph_h = h - margin_top - margin_bottom

        # 1. Draw grid lines & axes labels
        grid_pen = QPen(QColor("#27272a"), 1, Qt.PenStyle.DashLine)
        painter.setPen(grid_pen)
        
        # Horizontal lines (speed levels)
        levels = 4
        text_pen = QPen(QColor("#9ca3af"), 1)
        for i in range(levels + 1):
            y = margin_top + graph_h - (i * graph_h // levels)
            painter.setPen(grid_pen)
            painter.drawLine(margin_left, y, w - margin_right, y)
            
            # Label
            val = (i * self._max_speed) / levels
            painter.setPen(text_pen)
            painter.drawText(5, y + 4, f"{val:.1f}")

        # 2. Plot the history line and filled area
        points = []
        n = len(self._speed_history)
        for idx, speed in enumerate(self._speed_history):
            x = margin_left + (idx * graph_w) / (n - 1)
            y = margin_top + graph_h - (speed / self._max_speed) * graph_h
            points.append(QPointF(x, y))

        if len(points) > 1:
            # Create the gradient path for filling
            gradient = QLinearGradient(0, margin_top, 0, h - margin_bottom)
            # Use neon violet and transparent cyan gradients
            gradient.setColorAt(0.0, QColor(139, 92, 246, 120))  # Violet
            gradient.setColorAt(1.0, QColor(6, 182, 212, 0))     # Cyan fading out
            
            # Fill path
            from PyQt6.QtGui import QPainterPath
            fill_path = QPainterPath()
            fill_path.moveTo(margin_left, h - margin_bottom)
            for pt in points:
                fill_path.lineTo(pt)
            fill_path.lineTo(w - margin_right, h - margin_bottom)
            fill_path.closeSubpath()
            
            painter.fillPath(fill_path, gradient)

            # Draw the top border line
            line_pen = QPen(QColor("#06b6d4"), 2, Qt.PenStyle.SolidLine)  # Cyan line
            painter.setPen(line_pen)
            line_path = QPainterPath()
            line_path.moveTo(points[0])
            for pt in points[1:]:
                line_path.lineTo(pt)
            painter.drawPath(line_path)


class TelemetryView(QWidget):
    """
    Main Telemetry View containing speed graph, storage quota allocations,
    and thermal throttling / backpressure alarms.
    """
    def __init__(self, parent: QWidget = None, db = None) -> None:
        super().__init__(parent)
        self._db = db

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        # Title
        title_lbl = QLabel("Telemetry & System Health", self)
        title_lbl.setObjectName("Heading")
        layout.addWidget(title_lbl)

        # Chart card
        chart_card = GlassCard(self)
        chart_layout = QVBoxLayout(chart_card)
        chart_layout.setContentsMargins(16, 16, 16, 16)
        
        chart_title = QLabel("Network Transfer Speed (MB/s)", chart_card)
        chart_title.setObjectName("SubHeading")
        chart_layout.addWidget(chart_title)

        self.chart = SpeedChartWidget(chart_card)
        chart_layout.addWidget(self.chart)
        layout.addWidget(chart_card)

        # Bottom section: Storage + Health
        bottom_layout = QHBoxLayout()
        bottom_layout.setSpacing(16)

        # Storage quotas card
        self.storage_card = GlassCard(self)
        self.storage_layout = QVBoxLayout(self.storage_card)
        self.storage_layout.setContentsMargins(16, 16, 16, 16)
        storage_title = QLabel("Active Backend Storage Quotas", self.storage_card)
        storage_title.setObjectName("SubHeading")
        self.storage_layout.addWidget(storage_title)
        
        self.backend_widgets = {}  # type: dict[str, tuple[QLabel, QProgressBar]]
        bottom_layout.addWidget(self.storage_card, stretch=3)

        # Health & backpressure alarms card
        self.health_card = GlassCard(self)
        health_layout = QVBoxLayout(self.health_card)
        health_layout.setContentsMargins(16, 16, 16, 16)
        health_title = QLabel("System Status Indicators", self.health_card)
        health_title.setObjectName("SubHeading")
        health_layout.addWidget(health_title)

        self.bp_label = QLabel("🟢 Thermal Backpressure: Healthy", self.health_card)
        self.bp_label.setStyleSheet("color: #10b981; font-weight: bold;")
        health_layout.addWidget(self.bp_label)

        self.disk_label = QLabel("🟢 File Locking System: Active", self.health_card)
        self.disk_label.setStyleSheet("color: #10b981;")
        health_layout.addWidget(self.disk_label)

        self.db_status_lbl = QLabel("🟢 Database Integrity: HMAC OK", self.health_card)
        self.db_status_lbl.setStyleSheet("color: #10b981;")
        health_layout.addWidget(self.db_status_lbl)

        self.healing_status_lbl = QLabel("🟢 Background Healing: Idle", self.health_card)
        self.healing_status_lbl.setStyleSheet("color: #10b981;")
        health_layout.addWidget(self.healing_status_lbl)

        # Warning/alert area
        self.alert_box = QLabel("No active alarms or CPU throttling detected.", self.health_card)
        self.alert_box.setWordWrap(True)
        self.alert_box.setObjectName("MutedLabel")
        health_layout.addWidget(self.alert_box)

        # Manual Verify button
        from ghostdrive.gui.widgets import StyledButton
        self.verify_btn = StyledButton("Verify Index Integrity", self.health_card, secondary=True)
        self.verify_btn.clicked.connect(self.trigger_manual_sweep)
        health_layout.addWidget(self.verify_btn)

        bottom_layout.addWidget(self.health_card, stretch=2)
        layout.addLayout(bottom_layout)

        # Poll database and speed updates
        self._update_timer = QTimer(self)
        self._update_timer.timeout.connect(self.update_telemetry)
        self._update_timer.start(1000)

        # For simulation when no active transfers are running
        self._current_sim_speed = 0.0

    def set_db(self, db) -> None:
        self._db = db
        self.update_telemetry()

    def set_current_speed(self, speed_mbs: float) -> None:
        """Called by main window when files are active to report real throughput."""
        self._current_sim_speed = speed_mbs

    def trigger_manual_sweep(self) -> None:
        """Manually trigger a full database integrity check (Health sweep)."""
        parent_window = self.window()
        if hasattr(parent_window, "health_daemon") and parent_window.health_daemon:
            import asyncio
            asyncio.create_task(parent_window.health_daemon.perform_health_sweep())
            if hasattr(parent_window, "notifications"):
                parent_window.notifications.notify(
                    "Integrity Scan",
                    "Manual health check and integrity scan started...",
                    "info"
                )

    def set_healing_status(self, text: str, color_hex: str = "#10b981") -> None:
        """Update healing status label."""
        self.healing_status_lbl.setText(text)
        self.healing_status_lbl.setStyleSheet(f"color: {color_hex};")

    def set_backpressure(self, high: bool) -> None:
        """Report thermal throttling backpressure status."""
        if high:
            self.bp_label.setText("🔴 Thermal Backpressure: High (Throttling)")
            self.bp_label.setStyleSheet("color: #ef4444; font-weight: bold;")
            self.alert_box.setText("WARNING: High CPU/network congestion. Throttling pipeline to safeguard hardware.")
        else:
            self.bp_label.setText("🟢 Thermal Backpressure: Healthy")
            self.bp_label.setStyleSheet("color: #10b981; font-weight: bold;")
            self.alert_box.setText("No active alarms or CPU throttling detected.")

    def update_telemetry(self) -> None:
        """Query DB and update backend quota progress bars and push next speed point."""
        # 1. Update speed graph
        # If speed isn't set, simulate a tiny idle fluctuation
        if self._current_sim_speed == 0.0:
            speed = 0.0
        else:
            speed = self._current_sim_speed
        self.chart.add_speed_point(speed)

        # 2. Update storage allocations
        if not self._db:
            return

        try:
            with self._db.transaction():
                # Query all backends
                backends = self._db._conn.execute(
                    "SELECT id, type, quota_used, quota_limit, quota_reserved, status FROM backends"
                ).fetchall()

            for row in backends:
                b_id = row["id"]
                b_type = row["type"]
                used = row["quota_used"]
                limit = row["quota_limit"]
                reserved = row["quota_reserved"]
                status = row["status"]

                total_allocated = used + reserved
                # Format sizes nicely
                used_str = self._format_bytes(total_allocated)
                limit_str = self._format_bytes(limit) if limit < 4000000000000000000 else "Unlimited"

                pct = 0
                if limit > 0 and limit < 4000000000000000000:
                    pct = int((total_allocated * 100) / limit)

                label_text = f"{b_type.upper()} ({status}): {used_str} / {limit_str}"

                if b_id not in self.backend_widgets:
                    lbl = QLabel(label_text, self.storage_card)
                    bar = QProgressBar(self.storage_card)
                    bar.setMaximum(100)
                    bar.setValue(pct)
                    self.storage_layout.addWidget(lbl)
                    self.storage_layout.addWidget(bar)
                    self.backend_widgets[b_id] = (lbl, bar)
                else:
                    lbl, bar = self.backend_widgets[b_id]
                    lbl.setText(label_text)
                    bar.setValue(pct)

        except Exception as exc:
            # Gracefully ignore if database is temporarily locked or not initialised
            print(f"[Telemetry Update Error] {exc}")

    def _format_bytes(self, num_bytes: int) -> str:
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if num_bytes < 1024.0:
                return f"{num_bytes:.1f} {unit}"
            num_bytes /= 1024.0
        return f"{num_bytes:.1f} PB"
