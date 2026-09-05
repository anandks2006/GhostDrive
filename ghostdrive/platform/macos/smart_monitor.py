"""
macos/smart_monitor.py -- macOS-native S.M.A.R.T. monitor.
"""

from __future__ import annotations

import os
import json
import subprocess
import logging

from ghostdrive.platform.smart_monitor import SmartMonitorBase, SmartReport, smartctl_is_installed

logger = logging.getLogger(__name__)


class MacOSSmartMonitor(SmartMonitorBase):
    """
    macOS implementation of S.M.A.R.T. monitoring using smartctl.
    Requires root privileges to query raw disk devices (e.g. /dev/disk0).
    Uses osascript (AppleScript) for GUI elevation.
    """

    def is_available(self) -> bool:
        return smartctl_is_installed()

    def requires_elevation(self) -> bool:
        try:
            return os.geteuid() != 0
        except Exception:
            return True

    def request_elevation(self) -> bool:
        # osascript will handle elevation during execution
        return True

    def get_report(self, backend_id: str, device_path: str, background: bool = True) -> SmartReport:
        if not self.is_available():
            return SmartReport.unavailable("smartctl is not installed or not in PATH")

        import shutil
        smartctl_bin = shutil.which("smartctl")
        if not smartctl_bin:
            for path in ["/opt/homebrew/bin/smartctl", "/usr/local/bin/smartctl", "/usr/bin/smartctl"]:
                if os.path.exists(path):
                    smartctl_bin = path
                    break
        if not smartctl_bin:
            smartctl_bin = "smartctl"

        # Try running directly first (if already root or if it works without elevation)
        try:
            result = subprocess.run(
                [smartctl_bin, "--json", "-a", device_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0 or result.stdout:
                try:
                    data = json.loads(result.stdout)
                    return self.parse_smartctl_json(data, backend_id)
                except json.JSONDecodeError:
                    pass
        except Exception as exc:
            logger.debug("Direct smartctl execution failed on macOS: %s", exc)

        # If direct execution failed and we require elevation, use osascript
        if self.requires_elevation():
            if background:
                logger.info("SMART monitor requires elevation, but background is True. Skipping macOS AppleScript elevation.")
                return SmartReport.unavailable("Requires elevation (AppleScript prompt skipped in background)")
            try:
                # Escape device path for AppleScript
                escaped_dev = device_path.replace('"', '\\"')
                
                logger.info("Requesting macOS AppleScript elevation to run smartctl on %s", device_path)
                
                # AppleScript command to run smartctl with admin privileges
                applescript = f'do shell script "{smartctl_bin} --json -a {escaped_dev}" with administrator privileges'
                result = subprocess.run(
                    ["osascript", "-e", applescript],
                    capture_output=True,
                    text=True,
                    timeout=20
                )
                if result.returncode == 0 and result.stdout:
                    data = json.loads(result.stdout)
                    return self.parse_smartctl_json(data, backend_id)
                else:
                    return SmartReport.unavailable(
                        f"macOS AppleScript elevation denied or smartctl failed: {result.stderr or 'unknown error'}"
                    )
            except Exception as exc:
                logger.warning("macOS AppleScript smartctl execution failed: %s", exc)
                return SmartReport.unavailable(f"Failed to run smartctl via AppleScript: {exc}")

        return SmartReport.unavailable("Unable to query drive without root privileges")
