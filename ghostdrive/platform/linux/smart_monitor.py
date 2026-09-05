"""
linux/smart_monitor.py -- Linux-native S.M.A.R.T. monitor.
"""

from __future__ import annotations

import os
import json
import subprocess
import logging

from ghostdrive.platform.smart_monitor import SmartMonitorBase, SmartReport, smartctl_is_installed

logger = logging.getLogger(__name__)


class LinuxSmartMonitor(SmartMonitorBase):
    """
    Linux implementation of S.M.A.R.T. monitoring using smartctl.
    Requires root privileges to query block devices (e.g. /dev/sda).
    Uses pkexec for GUI elevation.
    """

    def is_available(self) -> bool:
        return smartctl_is_installed()

    def requires_elevation(self) -> bool:
        try:
            return os.geteuid() != 0
        except Exception:
            return True

    def request_elevation(self) -> bool:
        # pkexec will handle elevation during execution
        return True

    def get_report(self, backend_id: str, device_path: str) -> SmartReport:
        if not self.is_available():
            return SmartReport.unavailable("smartctl is not installed or not in PATH")

        # Try running directly first (if already root or if it works without elevation)
        try:
            result = subprocess.run(
                ["smartctl", "--json", "-a", device_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0 or result.stdout:
                try:
                    data = json.loads(result.stdout)
                    if "error" not in data or not data["error"]:
                        return self.parse_smartctl_json(data, backend_id)
                except json.JSONDecodeError:
                    pass
        except Exception as exc:
            logger.debug("Direct smartctl execution failed on Linux: %s", exc)

        # If direct execution failed and we require elevation, use pkexec
        if self.requires_elevation():
            try:
                logger.info("Requesting pkexec elevation to run smartctl on %s", device_path)
                result = subprocess.run(
                    ["pkexec", "smartctl", "--json", "-a", device_path],
                    capture_output=True,
                    text=True,
                    timeout=20
                )
                if result.returncode == 0 and result.stdout:
                    data = json.loads(result.stdout)
                    return self.parse_smartctl_json(data, backend_id)
                else:
                    return SmartReport.unavailable(
                        f"pkexec elevation denied or smartctl failed: {result.stderr or 'unknown error'}"
                    )
            except Exception as exc:
                logger.warning("pkexec smartctl execution failed: %s", exc)
                return SmartReport.unavailable(f"Failed to run smartctl via pkexec: {exc}")

        return SmartReport.unavailable("Unable to query drive without root privileges")
