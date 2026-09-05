"""
storage_analytics.py -- Custom QPainter charts for GhostDrive.
"""

import logging
from PyQt6.QtCore import Qt, QRect
from PyQt6.QtGui import QPainter, QColor, QPen, QBrush, QFont, QLinearGradient
from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QGridLayout,
    QScrollArea,
)
from ghostdrive.gui.widgets import StyledButton

logger = logging.getLogger(__name__)

def format_bytes(b: int) -> str:
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 * 1024 * 1024:
        return f"{b / (1024 * 1024):.1f} MB"
    else:
        return f"{b / (1024 * 1024 * 1024):.1f} GB"

class BaseChartWidget(QWidget):
    """Abstract base class for drawing custom QPainter charts inside GlassCard."""
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setMinimumHeight(220)
        self.data = None

    def set_data(self, data) -> None:
        self.data = data
        self.update()


class BackendUsageChart(BaseChartWidget):
    """Draws a vertical bar chart representing storage used per active backend."""
    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        w, h = self.width(), self.height()
        
        # Background glass card styling
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(255, 255, 255, 4))
        painter.drawRoundedRect(0, 0, w, h, 12, 12)
        
        if not self.data:
            painter.setPen(QColor("#9ca3af"))
            painter.setFont(QFont("Outfit", 12))
            painter.drawText(QRect(0, 0, w, h), Qt.AlignmentFlag.AlignCenter, "No Backend Data Available")
            return

        # Title
        painter.setFont(QFont("Outfit", 11, QFont.Weight.Bold))
        painter.setPen(QColor("#a855f7"))  # Neon Violet
        painter.drawText(15, 25, "Storage Usage by Backend")
        
        # Filter zero-usage backends
        usable = [x for x in self.data if (x.get("quota_used") or 0) > 0]
        if not usable:
            painter.setPen(QColor("#9ca3af"))
            painter.setFont(QFont("Outfit", 10))
            painter.drawText(QRect(0, 40, w, h - 40), Qt.AlignmentFlag.AlignCenter, "No active files stored yet.")
            return
            
        max_used = max(x.get("quota_used", 0) for x in usable) or 1
        
        # Dimensions
        padding_left = 60
        chart_w = w - padding_left - 30
        chart_h = h - 80
        
        # Y-Axis labels
        painter.setFont(QFont("Outfit", 8))
        painter.setPen(QColor("#6b7280"))
        painter.drawText(5, 55, format_bytes(max_used))
        painter.drawText(5, 55 + chart_h // 2, format_bytes(max_used // 2))
        painter.drawText(5, 55 + chart_h, "0 B")
        
        # Axis lines
        pen = QPen(QColor(255, 255, 255, 20), 1)
        painter.setPen(pen)
        painter.drawLine(padding_left, 50, padding_left, 50 + chart_h)
        painter.drawLine(padding_left, 50 + chart_h, padding_left + chart_w, 50 + chart_h)
        
        # Draw bars
        bar_w = min(40, chart_w // (len(usable) * 2))
        gap = (chart_w - (bar_w * len(usable))) // (len(usable) + 1)
        
        for idx, item in enumerate(usable):
            used = item.get("quota_used", 0)
            b_type = item.get("type", "unknown").capitalize()
            
            bar_h = int((used / max_used) * chart_h)
            x = padding_left + gap + idx * (bar_w + gap)
            y = 50 + chart_h - bar_h
            
            # Gradient fill for bar
            grad = QLinearGradient(x, y, x, y + bar_h)
            grad.setColorAt(0, QColor("#a855f7"))  # Neon Violet
            grad.setColorAt(1, QColor("#6366f1"))  # Electric Indigo
            
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(grad))
            painter.drawRoundedRect(x, y, bar_w, bar_h, 4, 4)
            
            # Labels
            painter.setPen(QColor("#f4f4f5"))
            painter.setFont(QFont("Outfit", 8, QFont.Weight.Bold))
            painter.drawText(QRect(x - 10, y - 18, bar_w + 20, 15), Qt.AlignmentFlag.AlignCenter, format_bytes(used))
            
            painter.setPen(QColor("#9ca3af"))
            painter.setFont(QFont("Outfit", 8))
            painter.drawText(QRect(x - 20, 55 + chart_h, bar_w + 40, 20), Qt.AlignmentFlag.AlignCenter, b_type)


class TierUsageChart(BaseChartWidget):
    """Draws a horizontal stacked bar representing storage distribution by Tier."""
    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        w, h = self.width(), self.height()
        
        # Background glass card styling
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(255, 255, 255, 4))
        painter.drawRoundedRect(0, 0, w, h, 12, 12)
        
        if not self.data:
            painter.setPen(QColor("#9ca3af"))
            painter.setFont(QFont("Outfit", 12))
            painter.drawText(QRect(0, 0, w, h), Qt.AlignmentFlag.AlignCenter, "No Tier Data Available")
            return

        # Title
        painter.setFont(QFont("Outfit", 11, QFont.Weight.Bold))
        painter.setPen(QColor("#06b6d4"))  # Electric Cyan
        painter.drawText(15, 25, "Storage Tier Distribution")
        
        # Extract sizes
        sizes = {"CRITICAL": 0, "IMPORTANT": 0, "DISPOSABLE": 0}
        for item in self.data:
            tier = item.get("tier")
            if tier in sizes:
                sizes[tier] = item.get("total_size", 0) or 0
                
        total = sum(sizes.values())
        if total == 0:
            painter.setPen(QColor("#9ca3af"))
            painter.setFont(QFont("Outfit", 10))
            painter.drawText(QRect(0, 40, w, h - 40), Qt.AlignmentFlag.AlignCenter, "No files stored in tiers yet.")
            return

        # Stacked bar coordinates
        bar_x = 20
        bar_y = 60
        bar_w = w - 40
        bar_h = 30
        
        # Draw base bar background
        painter.setBrush(QColor(255, 255, 255, 10))
        painter.drawRoundedRect(bar_x, bar_y, bar_w, bar_h, 6, 6)
        
        # Tier Colors
        colors = {
            "CRITICAL": QColor("#8b5cf6"),    # Violet
            "IMPORTANT": QColor("#10b981"),   # Emerald Green
            "DISPOSABLE": QColor("#f59e0b"),  # Amber Orange
        }
        
        curr_x = bar_x
        for tier, size in sizes.items():
            if size == 0:
                continue
            frac_w = int((size / total) * bar_w)
            if frac_w < 1:
                continue
                
            painter.setBrush(colors[tier])
            painter.drawRoundedRect(curr_x, bar_y, frac_w, bar_h, 4, 4)
            curr_x += frac_w

        # Draw legends and numbers below
        leg_y = 115
        col_w = (w - 40) // 3
        
        for idx, (tier, size) in enumerate(sizes.items()):
            tx = 20 + idx * col_w
            
            # Color dot
            painter.setBrush(colors[tier])
            painter.drawEllipse(tx, leg_y + 3, 8, 8)
            
            # Label
            painter.setPen(QColor("#f4f4f5"))
            painter.setFont(QFont("Outfit", 9, QFont.Weight.Bold))
            painter.drawText(tx + 14, leg_y + 11, tier.capitalize())
            
            # Size
            pct = (size / total) * 100 if total > 0 else 0
            painter.setPen(QColor("#9ca3af"))
            painter.setFont(QFont("Outfit", 8))
            painter.drawText(tx + 14, leg_y + 26, f"{format_bytes(size)} ({pct:.1f}%)")


class TypeUsageChart(BaseChartWidget):
    """Draws a horizontal bar chart of file types."""
    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        w, h = self.width(), self.height()
        
        # Background glass card styling
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(255, 255, 255, 4))
        painter.drawRoundedRect(0, 0, w, h, 12, 12)
        
        if not self.data:
            painter.setPen(QColor("#9ca3af"))
            painter.setFont(QFont("Outfit", 12))
            painter.drawText(QRect(0, 0, w, h), Qt.AlignmentFlag.AlignCenter, "No File Type Data Available")
            return

        # Title
        painter.setFont(QFont("Outfit", 11, QFont.Weight.Bold))
        painter.setPen(QColor("#10b981"))  # Emerald Green
        painter.drawText(15, 25, "File Type Breakdown")
        
        total_sz = sum(self.data.values())
        if total_sz == 0:
            painter.setPen(QColor("#9ca3af"))
            painter.setFont(QFont("Outfit", 10))
            painter.drawText(QRect(0, 40, w, h - 40), Qt.AlignmentFlag.AlignCenter, "No files ingested yet.")
            return

        # Dimensions
        padding_left = 90
        chart_w = w - padding_left - 40
        row_h = 24
        start_y = 50
        
        max_sz = max(self.data.values()) or 1
        
        for idx, (label, size) in enumerate(self.data.items()):
            y = start_y + idx * (row_h + 8)
            
            # Label
            painter.setPen(QColor("#9ca3af"))
            painter.setFont(QFont("Outfit", 8, QFont.Weight.Bold))
            painter.drawText(15, y + 14, label)
            
            # Bar background
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(255, 255, 255, 8))
            painter.drawRoundedRect(padding_left, y, chart_w, 14, 3, 3)
            
            # Active bar
            bar_w = int((size / max_sz) * chart_w)
            if bar_w > 0:
                grad = QLinearGradient(padding_left, y, padding_left + bar_w, y)
                grad.setColorAt(0, QColor("#10b981"))  # Emerald
                grad.setColorAt(1, QColor("#059669"))
                
                painter.setBrush(grad)
                painter.drawRoundedRect(padding_left, y, bar_w, 14, 3, 3)
                
            # Right size text
            painter.setPen(QColor("#f4f4f5"))
            painter.setFont(QFont("Outfit", 8))
            painter.drawText(padding_left + bar_w + 6, y + 11, format_bytes(size))


class HistoryTrendChart(BaseChartWidget):
    """Draws a line graph showing monthly upload bytes for the last 6 months."""
    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        w, h = self.width(), self.height()
        
        # Background glass card styling
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(255, 255, 255, 4))
        painter.drawRoundedRect(0, 0, w, h, 12, 12)
        
        if not self.data:
            painter.setPen(QColor("#9ca3af"))
            painter.setFont(QFont("Outfit", 12))
            painter.drawText(QRect(0, 0, w, h), Qt.AlignmentFlag.AlignCenter, "No History Data Available")
            return

        # Title
        painter.setFont(QFont("Outfit", 11, QFont.Weight.Bold))
        painter.setPen(QColor("#f59e0b"))  # Amber Orange
        painter.drawText(15, 25, "Monthly Upload Volume Trend")
        
        if len(self.data) < 2:
            # Fallback to bar charts/text if there aren't enough months
            painter.setPen(QColor("#9ca3af"))
            painter.setFont(QFont("Outfit", 10))
            painter.drawText(QRect(0, 40, w, h - 40), Qt.AlignmentFlag.AlignCenter, "Insufficient data for trend graph.")
            return

        max_val = max(x.get("total_bytes", 0) for x in self.data) or 1
        
        # Dimensions
        padding_left = 60
        chart_w = w - padding_left - 30
        chart_h = h - 85
        
        # Draw Axes
        pen = QPen(QColor(255, 255, 255, 20), 1)
        painter.setPen(pen)
        painter.drawLine(padding_left, 50, padding_left, 50 + chart_h)
        painter.drawLine(padding_left, 50 + chart_h, padding_left + chart_w, 50 + chart_h)
        
        # Axis labels
        painter.setFont(QFont("Outfit", 8))
        painter.setPen(QColor("#6b7280"))
        painter.drawText(5, 55, format_bytes(max_val))
        painter.drawText(5, 55 + chart_h // 2, format_bytes(max_val // 2))
        painter.drawText(5, 55 + chart_h, "0 B")
        
        # Calculate points
        x_step = chart_w // (len(self.data) - 1)
        points = []
        
        for idx, item in enumerate(self.data):
            val = item.get("total_bytes", 0)
            month = item.get("month", "")
            
            px = padding_left + idx * x_step
            py = 50 + chart_h - int((val / max_val) * chart_h)
            points.append((px, py, month, val))

        # Draw line
        painter.setPen(QPen(QColor("#f59e0b"), 2, Qt.PenStyle.SolidLine))
        for i in range(len(points) - 1):
            painter.drawLine(points[i][0], points[i][1], points[i+1][0], points[i+1][1])
            
        # Draw data points & labels
        for px, py, label, val in points:
            # Circle marker
            painter.setPen(QPen(QColor("#ffffff"), 1))
            painter.setBrush(QColor("#f59e0b"))
            painter.drawEllipse(px - 3, py - 3, 6, 6)
            
            # Value tag on hover/top
            painter.setPen(QColor("#f4f4f5"))
            painter.setFont(QFont("Outfit", 7, QFont.Weight.Bold))
            painter.drawText(px - 15, py - 10, format_bytes(val))
            
            # X label
            month_abbr = label.split("-")[-1]
            months_map = {"01":"Jan","02":"Feb","03":"Mar","04":"Apr","05":"May","06":"Jun","07":"Jul","08":"Aug","09":"Sep","10":"Oct","11":"Nov","12":"Dec"}
            m_lbl = months_map.get(month_abbr, month_abbr)
            
            painter.setPen(QColor("#9ca3af"))
            painter.setFont(QFont("Outfit", 8))
            painter.drawText(px - 15, 60 + chart_h, m_lbl)


class StorageAnalyticsPanel(QWidget):
    """Main collapsible view widget containing all QPainter charts and totals."""
    def __init__(self, parent=None, db=None) -> None:
        super().__init__(parent)
        self.db = db
        
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(24, 24, 24, 24)
        self.layout.setSpacing(16)
        
        # Header Top Layout
        header_layout = QHBoxLayout()
        title_layout = QVBoxLayout()
        
        self.title_lbl = QLabel("📊 Storage Analytics & Metrics", self)
        self.title_lbl.setObjectName("Heading")
        title_layout.addWidget(self.title_lbl)
        
        self.subtitle_lbl = QLabel("Detailed metrics of storage utilization, tiering, and history.", self)
        self.subtitle_lbl.setObjectName("MutedLabel")
        title_layout.addWidget(self.subtitle_lbl)
        header_layout.addLayout(title_layout)
        
        self.refresh_btn = StyledButton("Refresh Metrics", self, secondary=True)
        self.refresh_btn.clicked.connect(self.load_analytics_data)
        header_layout.addWidget(self.refresh_btn, alignment=Qt.AlignmentFlag.AlignRight)
        self.layout.addLayout(header_layout)
        
        # Scroll Area for charts grid
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("background-color: transparent; border: none;")
        self.layout.addWidget(scroll)
        
        scroll_content = QWidget(scroll)
        scroll_content.setObjectName("ScrollContent")
        scroll_content.setStyleSheet("background-color: transparent;")
        scroll.setWidget(scroll_content)
        
        grid_layout = QGridLayout(scroll_content)
        grid_layout.setSpacing(16)
        grid_layout.setContentsMargins(0, 0, 0, 0)
        
        # Create Charts inside Cards
        self.backend_chart = BackendUsageChart(scroll_content)
        grid_layout.addWidget(self.backend_chart, 0, 0)
        
        self.tier_chart = TierUsageChart(scroll_content)
        grid_layout.addWidget(self.tier_chart, 0, 1)
        
        self.type_chart = TypeUsageChart(scroll_content)
        grid_layout.addWidget(self.type_chart, 1, 0)
        
        self.trend_chart = HistoryTrendChart(scroll_content)
        grid_layout.addWidget(self.trend_chart, 1, 1)
        
    def load_analytics_data(self) -> None:
        """Fetch updated aggregates from database and redraw charts."""
        if not self.db:
            return
            
        try:
            stats = self.db.get_storage_analytics()
            
            # Pass stats to charts
            self.backend_chart.set_data(stats["backend_usage"])
            self.tier_chart.set_data(stats["tier_usage"])
            self.type_chart.set_data(stats["type_groups"])
            self.trend_chart.set_data(stats["upload_history"])
            
            logger.info("Storage analytics metrics refreshed successfully.")
        except Exception as exc:
            logger.error("Failed to load storage analytics: %s", exc)
