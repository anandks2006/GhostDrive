"""
smart_monitor.py -- Cross-platform S.M.A.R.T. drive health monitoring.

Abstract base class. Platform implementations:
  ghostdrive/platform/windows/smart_monitor.py  (UAC elevation)
  ghostdrive/platform/linux/smart_monitor.py    (pkexec elevation)
  ghostdrive/platform/macos/smart_monitor.py    (usually no elevation needed)

All implementations wrap smartctl (smartmontools). The platform layer handles
privilege elevation; the core logic (attribute parsing, trend analysis) is
shared in this module.

Privilege handling
------------------
1. Try smartctl without elevation.
2. If PermissionError: platform impl triggers appropriate elevation UI.
3. If elevation declined or smartmontools not installed: return
   SmartReport(available=False) -- all other GhostDrive features unaffected.

Trend analysis
--------------
Trend engine is implemented here (platform-agnostic). It reads the last
14 smart_history rows per backend and computes linear regression on each
critical attribute. Called by the platform impl after inserting a new reading.

Monitored attributes
--------------------
Attr  5: Reallocated Sectors Count    -- non-zero is a warning
Attr  9: Power-On Hours               -- for trend context
Attr 187: Reported Uncorrectable Errors
Attr 196: Reallocation Event Count
Attr 197: Current Pending Sector Count -- non-zero is critical
Attr 198: Uncorrectable Sector Count   -- non-zero is critical
Attr 231: SSD Life Left (%)            -- SSDs only; <= 10% is critical
"""

from __future__ import annotations

import dataclasses
import subprocess
from abc import ABC, abstractmethod
from typing import Optional


# ── S.M.A.R.T. report ─────────────────────────────────────────────────────────

@dataclasses.dataclass
class SmartReport:
    """
    S.M.A.R.T. health report for one drive.

    available: False if smartmontools is not installed, elevation was denied,
               or the drive does not support S.M.A.R.T.
               All other fields are None when available=False.

    assessment:
      "healthy"   -- all critical attributes zero, overall PASSED
      "degrading" -- one or more attributes non-zero but below critical threshold
      "critical"  -- pending/uncorrectable sectors > 0, or SSD life <= 10%,
                     or overall_health == "FAILED"
      "unknown"   -- S.M.A.R.T. data available but assessment inconclusive

    trend (computed from last 14 readings in smart_history):
      "stable"       -- no significant change in critical attributes
      "worsening"    -- positive slope on one or more critical attributes
      "accelerating" -- rate of increase is itself increasing (most urgent)
    """
    available:             bool
    backend_id:            Optional[str]        # UUIDv4 -> backends.id
    checked_at:            Optional[str]        # ISO-8601
    overall_health:        Optional[str]        # "PASSED" | "FAILED" | "UNKNOWN"
    reallocated_sectors:   Optional[int]        # Attr 5
    pending_sectors:       Optional[int]        # Attr 197
    uncorrectable_sectors: Optional[int]        # Attr 198
    ssd_life_pct:          Optional[int]        # Attr 231; None for HDDs
    power_on_hours:        Optional[int]        # Attr 9
    temperature_c:         Optional[int]
    assessment:            Optional[str]        # "healthy"|"degrading"|"critical"|"unknown"
    trend:                 Optional[str]        # "stable"|"worsening"|"accelerating"
    unavailable_reason:    Optional[str]        # human-readable reason when available=False

    @classmethod
    def unavailable(cls, reason: str) -> "SmartReport":
        """Create a SmartReport indicating monitoring is unavailable."""
        return cls(
            available=False,
            backend_id=None, checked_at=None, overall_health=None,
            reallocated_sectors=None, pending_sectors=None,
            uncorrectable_sectors=None, ssd_life_pct=None,
            power_on_hours=None, temperature_c=None,
            assessment=None, trend=None,
            unavailable_reason=reason,
        )


# ── Trend engine (platform-independent) ──────────────────────────────────────

def compute_trend(history_rows: list[dict]) -> str:
    """
    Compute trend from the last up to 14 S.M.A.R.T. readings.

    Args:
        history_rows: List of dicts with keys: reallocated_sectors,
                      pending_sectors, uncorrectable_sectors.
                      Ordered newest-first (as returned by get_smart_history).

    Returns:
        "stable" | "worsening" | "accelerating"

    Algorithm:
        For each critical attribute, compute the linear slope over the readings.
        If any slope > 0 for at least 3 consecutive readings: "worsening".
        If the slope itself is increasing: "accelerating".
        Otherwise: "stable".
    """
    if len(history_rows) < 3:
        return "stable"

    rows = list(reversed(history_rows[:14]))  # oldest first, max 14
    n = len(rows)

    def _slope(values: list[int]) -> float:
        """Simple linear regression slope (least squares)."""
        m = len(values)
        if m < 2:
            return 0.0
        x_mean = (m - 1) / 2
        y_mean = sum(values) / m
        numerator   = sum((i - x_mean) * (v - y_mean) for i, v in enumerate(values))
        denominator = sum((i - x_mean) ** 2 for i in range(m))
        return numerator / denominator if denominator != 0 else 0.0

    critical_attrs = [
        [r.get("reallocated_sectors", 0) for r in rows],
        [r.get("pending_sectors", 0)     for r in rows],
        [r.get("uncorrectable_sectors", 0) for r in rows],
    ]

    slopes = [_slope(attr) for attr in critical_attrs]
    max_slope = max(slopes)

    if max_slope <= 0:
        return "stable"

    # Check if slope itself is accelerating (compare first-half slope to second-half)
    if n >= 6:
        mid = n // 2
        for attr in critical_attrs:
            first_half_slope  = _slope(attr[:mid])
            second_half_slope = _slope(attr[mid:])
            if second_half_slope > first_half_slope > 0:
                return "accelerating"

    return "worsening"


def compute_assessment(report: "SmartReport") -> str:
    """
    Derive a plain-English assessment from a SmartReport's attribute values.

    Returns: "healthy" | "degrading" | "critical" | "unknown"
    """
    if not report.available:
        return "unknown"

    # Critical conditions
    if report.overall_health == "FAILED":
        return "critical"
    if (report.pending_sectors or 0) > 0:
        return "critical"
    if (report.uncorrectable_sectors or 0) > 0:
        return "critical"
    if report.ssd_life_pct is not None and report.ssd_life_pct <= 10:
        return "critical"

    # Degrading conditions
    if (report.reallocated_sectors or 0) > 0:
        return "degrading"
    if report.ssd_life_pct is not None and report.ssd_life_pct <= 25:
        return "degrading"

    if report.overall_health == "UNKNOWN":
        return "unknown"

    return "healthy"


# ── Smartctl availability check ───────────────────────────────────────────────

def smartctl_is_installed() -> bool:
    """
    Return True if smartctl is available in PATH.
    Does NOT require elevated privileges -- just checks for the binary.
    """
    try:
        result = subprocess.run(
            ["smartctl", "--version"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


# ── Abstract base class ────────────────────────────────────────────────────────

class SmartMonitorBase(ABC):
    """
    Abstract cross-platform S.M.A.R.T. monitor.

    Usage::

        monitor = get_smart_monitor()
        if not monitor.is_available():
            show_install_guide()
        elif monitor.requires_elevation():
            if monitor.request_elevation():
                report = monitor.get_report(drive)
        else:
            report = monitor.get_report(drive)
    """

    @abstractmethod
    def is_available(self) -> bool:
        """
        Return True if smartmontools is installed and accessible.
        Does NOT imply elevation has been granted -- check requires_elevation().
        """

    @abstractmethod
    def requires_elevation(self) -> bool:
        """
        Return True if the current user cannot run smartctl without elevation.
        False on macOS (usually), True on most Linux/Windows configurations.
        """

    @abstractmethod
    def request_elevation(self) -> bool:
        """
        Trigger the platform-appropriate elevation prompt.
        Windows: UAC dialog via ShellExecute runas.
        Linux:   pkexec dialog.
        macOS:   AuthorizationCreate (usually not needed).

        Returns True if elevation was granted (or not needed).
        Returns False if the user declined or elevation is impossible.
        """
    @abstractmethod
    def get_report(
        self,
        backend_id: str,
        device_path: str,
        background: bool = True,
    ) -> SmartReport:
        """
        Run smartctl on the specified device and return a SmartReport.

        Args:
            backend_id:  UUIDv4 of the backend (for SmartReport.backend_id).
            device_path: OS device path (e.g., /dev/sda, \\\\.\\PhysicalDrive0).

        Returns:
            SmartReport. If smartmontools is unavailable or elevation denied,
            returns SmartReport.unavailable(reason).
        """

    def parse_smartctl_json(self, data: dict, backend_id: str) -> SmartReport:
        """
        Common JSON parser for smartctl JSON output.
        Handles both ATA and NVMe data formats.
        """
        import datetime
        if not data:
            return SmartReport.unavailable("No SMART data returned")

        smart_status = data.get("smart_status", {})
        passed = smart_status.get("passed")
        overall_health = "UNKNOWN"
        if passed is True:
            overall_health = "PASSED"
        elif passed is False:
            overall_health = "FAILED"

        temp_c = data.get("temperature", {}).get("current")
        power_on_hours = data.get("power_on_time", {}).get("hours")

        reallocated_sectors = 0
        pending_sectors = 0
        uncorrectable_sectors = 0
        ssd_life_pct = None

        # Check for NVMe
        nvme_log = data.get("nvme_smart_health_information_log")
        if nvme_log:
            media_errors = nvme_log.get("media_and_data_integrity_errors", 0)
            pending_sectors = media_errors
            uncorrectable_sectors = media_errors

            pct_used = nvme_log.get("percentage_used")
            if pct_used is not None:
                ssd_life_pct = max(0, 100 - pct_used)

            if power_on_hours is None:
                power_on_hours = nvme_log.get("power_on_hours")

            if temp_c is None:
                temp_k = nvme_log.get("temperature")
                if temp_k is not None:
                    temp_c = temp_k - 273
        else:
            # ATA / SCSI
            ata_table = data.get("ata_smart_attributes", {}).get("table", [])
            for attr in ata_table:
                attr_id = attr.get("id")
                raw_val = attr.get("raw", {}).get("value", 0)
                if attr_id == 5:
                    reallocated_sectors = raw_val
                elif attr_id == 9:
                    if power_on_hours is None:
                        power_on_hours = raw_val
                elif attr_id == 187:
                    uncorrectable_sectors = raw_val
                elif attr_id == 197:
                    pending_sectors = raw_val
                elif attr_id == 198:
                    uncorrectable_sectors = max(uncorrectable_sectors or 0, raw_val)
                elif attr_id == 231:
                    ssd_life_pct = raw_val

        checked_at = datetime.datetime.now().isoformat()

        report = SmartReport(
            available=True,
            backend_id=backend_id,
            checked_at=checked_at,
            overall_health=overall_health,
            reallocated_sectors=reallocated_sectors,
            pending_sectors=pending_sectors,
            uncorrectable_sectors=uncorrectable_sectors,
            ssd_life_pct=ssd_life_pct,
            power_on_hours=power_on_hours,
            temperature_c=temp_c,
            assessment="unknown",
            trend="stable",
            unavailable_reason=None,
        )
        report.assessment = compute_assessment(report)
        return report

