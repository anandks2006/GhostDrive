"""
resilience_panel.py -- PyQt6 widget to calculate and display physical independence and overall resilience score.
"""

import logging
from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QProgressBar,
)
from ghostdrive.gui.widgets import GlassCard

logger = logging.getLogger(__name__)

class ResiliencePanel(GlassCard):
    """
    ResiliencePanel displays the physical independence score and overall resilience rating.
    It analyzes the configured backends to warn the user about 'fake redundancy'
    (e.g., multiple backends pointing to the same physical disk).
    """

    def __init__(self, parent: QWidget = None, db = None) -> None:
        super().__init__(parent)
        self.db = db
        self.setObjectName("GlassCard")
        
        # UI Layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Title
        title_lbl = QLabel("Storage Resilience & Physical Independence", self)
        title_lbl.setStyleSheet("font-weight: bold; font-size: 14px; color: #f4f4f5;")
        layout.addWidget(title_lbl)

        # Score & Progress Bar
        score_layout = QHBoxLayout()
        self.score_lbl = QLabel("0%", self)
        self.score_lbl.setStyleSheet("font-size: 28px; font-weight: bold; color: #8b5cf6;")
        score_layout.addWidget(self.score_lbl)

        self.progress_bar = QProgressBar(self)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(12)
        self._progress_bar_style = """
            QProgressBar {{
                background-color: #24242a;
                border: 1px solid #27272a;
                border-radius: 6px;
            }}
            QProgressBar::chunk {{
                background-color: {color};
                border-radius: 5px;
            }}
        """
        self.progress_bar.setStyleSheet(self._progress_bar_style.format(color="#8b5cf6"))
        score_layout.addWidget(self.progress_bar, stretch=1)
        layout.addLayout(score_layout)

        # Plain English assessment & details
        self.assessment_lbl = QLabel("Assessment: Loading...", self)
        self.assessment_lbl.setStyleSheet("font-weight: 500; font-size: 13px;")
        layout.addWidget(self.assessment_lbl)

        self.details_lbl = QLabel("Add backends to distribute files and improve security.", self)
        self.details_lbl.setStyleSheet("color: #9ca3af; font-size: 12px;")
        self.details_lbl.setWordWrap(True)
        layout.addWidget(self.details_lbl)

        # Warning block for fake redundancy
        self.warning_lbl = QLabel(self)
        self.warning_lbl.setStyleSheet("color: #ef4444; font-weight: bold; font-size: 12px;")
        self.warning_lbl.setWordWrap(True)
        self.warning_lbl.setVisible(False)
        layout.addWidget(self.warning_lbl)

    def refresh(self) -> None:
        """Query the database to recalculate the resilience metrics."""
        if not self.db:
            return

        try:
            # Query backends
            backends = self.db._conn.execute(
                "SELECT id, type, status, credentials_ref FROM backends"
            ).fetchall()

            # Query drive registry details
            registry = self.db._conn.execute(
                "SELECT backend_id, drive_uuid, drive_type, drive_label FROM drive_registry"
            ).fetchall()
        except Exception as exc:
            logger.error("Failed to query backends for resilience calculations: %s", exc)
            return

        registry_map = {r["backend_id"]: r for r in registry}

        # Calculate scores
        # We assign points based on physical isolation of each healthy backend:
        # - Cloud (telegram, discord, nas SFTP/SMB): +25 points (fully isolated / remote)
        # - Local external USB drive (identified in drive_registry): +15 points
        # - Local directory: +5 points
        score = 0
        local_uuids = set()
        has_cloud = False
        has_external = False
        total_backends = 0

        for b in backends:
            if b["status"] != "healthy":
                continue

            total_backends += 1
            b_type = b["type"].lower()
            b_id = b["id"]

            if b_type in ("telegram", "discord", "sftp", "smb", "nas"):
                score += 25
                has_cloud = True
            elif b_id in registry_map:
                reg = registry_map[b_id]
                score += 15
                has_external = True
                if reg["drive_uuid"]:
                    local_uuids.add(reg["drive_uuid"])
            else:
                # Fallback to local directory
                score += 5
                local_uuids.add("local_fs")

        # Cap score at 100
        score = min(100, score)

        # Determine if we have fake redundancy (i.e. multiple local paths pointing to same disk / same machine)
        # If total_backends > 1, but we have no external or cloud backends, then all storage is local
        fake_redundancy = False
        if total_backends > 1 and not has_cloud and not has_external:
            fake_redundancy = True

        # Update UI
        self.score_lbl.setText(f"{score}%")
        self.progress_bar.setValue(score)

        # Color based on score
        if score < 25:
            color = "#ef4444"
            self.score_lbl.setStyleSheet("font-size: 28px; font-weight: bold; color: #ef4444;")
            self.assessment_lbl.setText("Assessment: Vulnerable (No physical isolation)")
            self.assessment_lbl.setStyleSheet("font-weight: 500; font-size: 13px; color: #ef4444;")
            self.details_lbl.setText("Your files reside on a single machine or have no active replication. A single hardware failure could cause permanent data loss.")
        elif score < 60:
            color = "#f59e0b"
            self.score_lbl.setStyleSheet("font-size: 28px; font-weight: bold; color: #f59e0b;")
            self.assessment_lbl.setText("Assessment: Basic (Local or external backup)")
            self.assessment_lbl.setStyleSheet("font-weight: 500; font-size: 13px; color: #f59e0b;")
            self.details_lbl.setText("You have local or external drive redundancy, protecting against individual drive failure. Consider adding off-site cloud replication.")
        else:
            color = "#10b981"
            self.score_lbl.setStyleSheet("font-size: 28px; font-weight: bold; color: #10b981;")
            self.assessment_lbl.setText("Assessment: Resilient (Distributed off-site)")
            self.assessment_lbl.setStyleSheet("font-weight: 500; font-size: 13px; color: #10b981;")
            self.details_lbl.setText("Excellent! Chunks are distributed across physically independent local disks and off-site cloud platforms.")
            
        self.progress_bar.setStyleSheet(self._progress_bar_style.format(color=color))

        # Show fake redundancy warning if applicable
        if fake_redundancy:
            self.warning_lbl.setText("⚠️ WARNING: Fake Redundancy Detected! All active storage paths reside on your local primary disk. Multiple copies here do not protect against hardware loss.")
            self.warning_lbl.setVisible(True)
        else:
            self.warning_lbl.setVisible(False)
