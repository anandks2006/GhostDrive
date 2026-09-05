"""
smart_panel.py -- S.M.A.R.T. health monitoring dashboard panel for GhostDrive.
"""

import logging
import asyncio
import qasync
from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QMessageBox,
    QFrame,
)
from ghostdrive.gui.widgets import GlassCard, StyledButton
from ghostdrive.platform import get_smart_monitor

logger = logging.getLogger(__name__)

class SmartPanel(QWidget):
    """
    SmartPanel displays the drive health cards, S.M.A.R.T. attribute trends,
    and handles pre-emptive healing triggers for degraded physical disks.
    """
    healing_triggered = pyqtSignal(str) # Emits backend_id when healing is triggered

    def __init__(self, parent: QWidget = None, db = None) -> None:
        super().__init__(parent)
        self.db = db

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # Header
        header_layout = QHBoxLayout()
        title = QLabel("Physical Drive Health (S.M.A.R.T.)", self)
        title.setObjectName("Heading")
        header_layout.addWidget(title)
        
        self.refresh_btn = StyledButton("Scan Health", self, secondary=True)
        self.refresh_btn.clicked.connect(self.refresh)
        header_layout.addWidget(self.refresh_btn)
        layout.addLayout(header_layout)

        # Guidance text if tools unavailable
        self.guidance_card = GlassCard(self)
        guidance_layout = QVBoxLayout(self.guidance_card)
        self.guidance_lbl = QLabel(self.guidance_card)
        self.guidance_lbl.setWordWrap(True)
        self.guidance_lbl.setStyleSheet("color: #9ca3af; font-size: 12px;")
        guidance_layout.addWidget(self.guidance_lbl)
        layout.addWidget(self.guidance_card)
        self.guidance_card.setVisible(False)

        # Scroll Area for Health Cards
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("background-color: transparent;")
        
        self.scroll_content = QWidget(scroll)
        self.scroll_content.setStyleSheet("background-color: transparent;")
        self.cards_layout = QVBoxLayout(self.scroll_content)
        self.cards_layout.setSpacing(16)
        self.cards_layout.setContentsMargins(0, 0, 0, 0)
        self.cards_layout.addStretch()
        
        scroll.setWidget(self.scroll_content)
        layout.addWidget(scroll, stretch=1)

    @qasync.asyncSlot()
    async def refresh(self) -> None:
        """Query the database and local system status to render the health cards."""
        # 1. Clear previous cards
        while self.cards_layout.count() > 1:
            item = self.cards_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        # Check if platform SMART monitor is available
        try:
            monitor = get_smart_monitor()
            available = await asyncio.to_thread(monitor.is_available)
        except Exception:
            available = False

        if not available:
            self.guidance_lbl.setText(
                "⚠️ **S.M.A.R.T. monitoring utility (smartmontools) is not fully active.**\n\n"
                "To enable hardware health tracking, please ensure:\n"
                "1. `smartctl` is installed on your system (e.g., via `choco install smartmontools` on Windows, "
                "`apt install smartmontools` on Linux, or `brew install smartmontools` on macOS).\n"
                "2. The application is running with administrative elevation (UAC/sudo) to query raw block devices."
            )
            self.guidance_card.setVisible(True)
        else:
            self.guidance_card.setVisible(False)

        if not self.db:
            return

        try:
            # Fetch registered drives
            drives = await asyncio.to_thread(self.db.list_drive_registry)
        except Exception as exc:
            logger.error("Failed to list drives: %s", exc)
            return

        for d in drives:
            backend_id = d["backend_id"]
            
            # Fetch latest reading and last 5 history readings
            try:
                latest = await asyncio.to_thread(self.db.get_latest_smart_reading, backend_id)
                history = await asyncio.to_thread(self.db.get_smart_history, backend_id, limit=5)
            except Exception as exc:
                logger.error("Failed to read SMART history for %s: %s", backend_id, exc)
                latest = None
                history = []

            card = DriveHealthCard(self.scroll_content, d, latest, history)
            card.healing_requested.connect(self._on_healing_requested)
            self.cards_layout.insertWidget(self.cards_layout.count() - 1, card)

    def _on_healing_requested(self, backend_id: str) -> None:
        self.healing_triggered.emit(backend_id)


class DriveHealthCard(GlassCard):
    """Card representing a single drive's health status, metrics, and trends."""
    healing_requested = pyqtSignal(str)

    def __init__(self, parent: QWidget, drive: dict, latest: dict | None, history: list) -> None:
        super().__init__(parent)
        self.drive = drive
        self.backend_id = drive["backend_id"]

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        # Header: Name & Type
        header = QHBoxLayout()
        name_lbl = QLabel(f"{drive['drive_label']} ({drive['drive_type'].upper()})", self)
        name_lbl.setStyleSheet("font-weight: bold; font-size: 14px; color: #f4f4f5;")
        header.addWidget(name_lbl)
        
        # Health status badge
        status_text = "UNKNOWN"
        status_color = "#9ca3af"
        if latest:
            status_text = latest["overall_health"].upper()
            if status_text == "PASSED":
                status_color = "#10b981"
            elif status_text == "WARNING":
                status_color = "#f59e0b"
            else:
                status_color = "#ef4444"

        status_lbl = QLabel(status_text, self)
        status_lbl.setStyleSheet(f"font-weight: bold; color: {status_color}; border: 1px solid {status_color}; border-radius: 4px; padding: 2px 6px; font-size: 11px;")
        header.addWidget(status_lbl)
        layout.addLayout(header)

        # Sub-info: Serial and mount hint
        info_lbl = QLabel(f"Serial: {drive['drive_serial'] or 'N/A'} | Last Mount: {drive['mount_hint'] or 'N/A'}", self)
        info_lbl.setStyleSheet("color: #9ca3af; font-size: 11px;")
        layout.addWidget(info_lbl)

        # Divider
        line = QWidget(self)
        line.setFixedHeight(1)
        line.setStyleSheet("background-color: #27272a;")
        layout.addWidget(line)

        # Grid of SMART metrics
        metrics_layout = QHBoxLayout()
        metrics_layout.setSpacing(20)

        def add_metric(name, val, color="#f4f4f5"):
            vbox = QVBoxLayout()
            vbox.setSpacing(2)
            title = QLabel(name, self)
            title.setStyleSheet("color: #9ca3af; font-size: 11px;")
            value = QLabel(str(val), self)
            value.setStyleSheet(f"font-weight: bold; font-size: 14px; color: {color};")
            vbox.addWidget(title)
            vbox.addWidget(value)
            metrics_layout.addLayout(vbox)

        if latest:
            # SSD Life
            ssd_life = latest["ssd_life_pct"]
            life_val = f"{ssd_life}%" if ssd_life is not None else "N/A"
            life_color = "#10b981" if (ssd_life is None or ssd_life > 70) else ("#f59e0b" if ssd_life > 30 else "#ef4444")
            add_metric("SSD Life", life_val, life_color)

            # Temp
            temp = latest["temperature_c"]
            temp_val = f"{temp}°C" if temp is not None else "N/A"
            temp_color = "#10b981" if (temp is None or temp < 50) else ("#f59e0b" if temp < 65 else "#ef4444")
            add_metric("Temp", temp_val, temp_color)

            # Reallocated Sectors
            realloc = latest["reallocated_sectors"]
            realloc_val = str(realloc) if realloc is not None else "0"
            realloc_color = "#10b981" if (realloc is None or realloc == 0) else "#ef4444"
            add_metric("Realloc Sectors", realloc_val, realloc_color)

            # Pending Sectors
            pending = latest["pending_sectors"]
            pending_val = str(pending) if pending is not None else "0"
            pending_color = "#10b981" if (pending is None or pending == 0) else "#ef4444"
            add_metric("Pending Sectors", pending_val, pending_color)

            # Power-on hours
            poh = latest["power_on_hours"]
            poh_val = f"{poh}h" if poh is not None else "N/A"
            add_metric("Power-on Hours", poh_val)
        else:
            add_metric("SSD Life", "N/A")
            add_metric("Temp", "N/A")
            add_metric("Realloc Sectors", "N/A")
            add_metric("Pending Sectors", "N/A")

        layout.addLayout(metrics_layout)

        # Show trend if history is available
        if len(history) > 1:
            trend_lbl = QLabel(self)
            trend_lbl.setStyleSheet("color: #9ca3af; font-size: 11px;")
            
            # Simple assessment of temperature or reallocated sector trend
            newest_temp = history[0]["temperature_c"]
            oldest_temp = history[-1]["temperature_c"]
            
            newest_realloc = history[0]["reallocated_sectors"] or 0
            oldest_realloc = history[-1]["reallocated_sectors"] or 0

            trend_parts = []
            if newest_temp is not None and oldest_temp is not None:
                if newest_temp > oldest_temp:
                    trend_parts.append(f"Temperature rising: {oldest_temp}°C ↗ {newest_temp}°C")
                elif newest_temp < oldest_temp:
                    trend_parts.append(f"Temperature falling: {oldest_temp}°C ↘ {newest_temp}°C")

            if newest_realloc > oldest_realloc:
                trend_parts.append(f"⚠️ Reallocated sectors increasing: {oldest_realloc} ↗ {newest_realloc}")

            if trend_parts:
                trend_lbl.setText("Trends: " + " | ".join(trend_parts))
                layout.addWidget(trend_lbl)

        # --- Diagnostic Assessment & Recommendations ---
        realloc = latest["reallocated_sectors"] if latest else None
        pending = latest["pending_sectors"] if latest else None
        ssd_life = latest["ssd_life_pct"] if latest else None
        temp = latest["temperature_c"] if latest else None

        hazards = []  # List of (parameter_name, status_text, color)
        recommendations = []

        # 1. Reallocated Sectors (HDD/SSD)
        if realloc is not None:
            if realloc == 0:
                hazards.append(("Realloc", "Healthy", "#10b981"))
            elif 1 <= realloc <= 10:
                hazards.append(("Realloc", "Warning", "#f59e0b"))
                recommendations.append("Minor surface wear detected. Monitor reallocated sector count for increases.")
            else:
                hazards.append(("Realloc", "High Hazard", "#ef4444"))
                recommendations.append("Active physical hardware degradation detected. Pre-emptive healing/backup is strongly advised.")

        # 2. Current Pending Sectors (HDD)
        if pending is not None:
            if pending == 0:
                hazards.append(("Pending", "Healthy", "#10b981"))
            else:
                hazards.append(("Pending", "Extreme Hazard", "#ef4444"))
                recommendations.append("Active write/read failures detected (pending sectors > 0). Run pre-emptive healing immediately.")

        # 3. SSD Wear / Life Left
        if ssd_life is not None:
            if ssd_life > 70:
                hazards.append(("Wear/Life", f"Healthy ({ssd_life}%)", "#10b981"))
            elif 30 <= ssd_life <= 70:
                hazards.append(("Wear/Life", f"Warning ({ssd_life}%)", "#f59e0b"))
                recommendations.append("SSD is showing moderate age and wear. Normal operation, but monitor life remaining.")
            elif 10 < ssd_life < 30:
                hazards.append(("Wear/Life", f"High Hazard ({ssd_life}%)", "#ef4444"))
                recommendations.append("SSD nearing write endurance limits. Plan to replace the drive soon.")
            else:
                hazards.append(("Wear/Life", f"Extreme Hazard ({ssd_life}%)", "#ef4444"))
                recommendations.append("SSD is at end of life (<= 10% left) and may lock into read-only mode. Evacuate all data immediately.")

        # 4. Temperature
        if temp is not None:
            if temp < 45:
                hazards.append(("Temp", f"Healthy ({temp}°C)", "#10b981"))
            elif 45 <= temp <= 55:
                hazards.append(("Temp", f"Warning ({temp}°C)", "#f59e0b"))
                recommendations.append("Elevated operating temperature. Check device airflow or fan operation.")
            else:
                hazards.append(("Temp", f"High Hazard ({temp}°C)", "#ef4444"))
                recommendations.append("Thermal stress detected. Improve ventilation immediately to prevent hardware damage.")

        # Default recommendation
        if not recommendations:
            if latest:
                recommendations.append("All metrics are within normal parameters. Drive is operating healthy.")
            else:
                recommendations.append("No diagnostic data available. Run a health scan to evaluate drive status.")

        # Divider
        diag_divider = QWidget(self)
        diag_divider.setFixedHeight(1)
        diag_divider.setStyleSheet("background-color: #27272a;")
        layout.addWidget(diag_divider)

        # Diagnostic Section Card
        diag_card = GlassCard(self)
        diag_card.setStyleSheet("background-color: rgba(255, 255, 255, 0.02); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 8px;")
        diag_layout = QVBoxLayout(diag_card)
        diag_layout.setContentsMargins(12, 12, 12, 12)
        diag_layout.setSpacing(10)

        diag_title = QLabel("📋 Diagnostic Assessment & Recommendations", diag_card)
        diag_title.setStyleSheet("font-weight: bold; font-size: 11px; color: #a855f7;")
        diag_layout.addWidget(diag_title)

        # Badges layout
        badges_layout = QHBoxLayout()
        badges_layout.setSpacing(12)
        
        for param, status, color in hazards:
            badge_widget = QWidget(diag_card)
            badge_widget.setStyleSheet("background-color: rgba(255, 255, 255, 0.03); border-radius: 4px; border: 1px solid rgba(255, 255, 255, 0.06);")
            badge_lay = QVBoxLayout(badge_widget)
            badge_lay.setContentsMargins(8, 6, 8, 6)
            badge_lay.setSpacing(2)
            
            p_lbl = QLabel(param, badge_widget)
            p_lbl.setStyleSheet("color: #9ca3af; font-size: 9px;")
            s_lbl = QLabel(status, badge_widget)
            s_lbl.setStyleSheet(f"color: {color}; font-weight: bold; font-size: 11px;")
            
            badge_lay.addWidget(p_lbl)
            badge_lay.addWidget(s_lbl)
            badges_layout.addWidget(badge_widget)
            
        if not hazards:
            no_haz_lbl = QLabel("No diagnostic parameters retrieved yet.", diag_card)
            no_haz_lbl.setStyleSheet("color: #71717a; font-size: 11px; font-style: italic;")
            badges_layout.addWidget(no_haz_lbl)
            
        badges_layout.addStretch()
        diag_layout.addLayout(badges_layout)

        # Plain English recommendations
        rec_text = "• " + "\n• ".join(recommendations)
        rec_lbl = QLabel(rec_text, diag_card)
        rec_lbl.setWordWrap(True)
        rec_lbl.setStyleSheet("color: #e4e4e7; font-size: 11px; line-height: 14px;")
        diag_layout.addWidget(rec_lbl)

        layout.addWidget(diag_card)

        # If assessment is critical/failed, show immediate warning and trigger button
        is_critical = False
        if latest and latest["assessment"] in ("critical", "failing", "failed"):
            is_critical = True

        if is_critical:
            warn_box = QHBoxLayout()
            warn_lbl = QLabel("⚠️ CRITICAL HEALTH ALERT: Imminent disk failure detected! Evacuate files immediately.", self)
            warn_lbl.setStyleSheet("color: #ef4444; font-weight: bold; font-size: 12px;")
            warn_box.addWidget(warn_lbl, stretch=1)
            
            heal_btn = StyledButton("Pre-emptive Healing", self, danger=True)
            heal_btn.clicked.connect(self._trigger_healing)
            warn_box.addWidget(heal_btn)
            layout.addLayout(warn_box)

    def _trigger_healing(self) -> None:
        reply = QMessageBox.warning(
            self, "Confirm Pre-emptive Healing",
            "This will immediately trigger the healing daemon to replicate all chunks "
            "stored on this degraded drive to other healthy backends. Proceed?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.healing_requested.emit(self.backend_id)
