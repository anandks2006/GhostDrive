"""
windows/smart_monitor.py -- Windows-native S.M.A.R.T. monitor.
"""

from __future__ import annotations

import os
import json
import ctypes
import tempfile
import subprocess
import logging
from pathlib import Path
from typing import Optional

from ghostdrive.platform.smart_monitor import SmartMonitorBase, SmartReport, smartctl_is_installed

logger = logging.getLogger(__name__)


class WindowsSmartMonitor(SmartMonitorBase):
    """
    Windows implementation of S.M.A.R.T. monitoring using smartctl.
    Requires admin privileges to access physical drive objects (\\\\.\\PhysicalDriveX).
    """

    def is_available(self) -> bool:
        return smartctl_is_installed()

    def requires_elevation(self) -> bool:
        try:
            return not ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return True

    def request_elevation(self) -> bool:
        # On Windows, we can trigger the UAC prompt per command execution.
        # This function returns True to indicate that we will prompt for UAC during execution.
        return True

    def get_report(self, backend_id: str, device_path: str, background: bool = True) -> SmartReport:
        if not self.is_available():
            return SmartReport.unavailable("smartctl is not installed or not in PATH")

        # Normalize device path for Windows (e.g. \\.\PhysicalDrive0)
        # If user passed "D:" or similar, we should resolve it to physical drive if possible.
        normalized_device = device_path
        if len(device_path) == 2 and device_path[1] == ":":
            resolved = self._resolve_drive_letter_to_physical_drive(device_path[0])
            if resolved:
                normalized_device = resolved

        # Try running directly first (if already elevated or if it works)
        try:
            result = subprocess.run(
                ["smartctl", "--json", "-a", normalized_device],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            )
            if result.returncode == 0 or result.stdout:
                try:
                    data = json.loads(result.stdout)
                    # If smartctl reports open/read errors, we might need elevation
                    if "error" not in data or not data["error"]:
                        return self.parse_smartctl_json(data, backend_id)
                except json.JSONDecodeError:
                    pass
        except Exception as exc:
            logger.debug("Direct smartctl execution failed: %s", exc)

        # If direct execution failed or returned errors, and we require elevation:
        if self.requires_elevation():
            if background:
                logger.info("SMART monitor requires elevation, but background is True. Skipping UAC prompt.")
                return SmartReport.unavailable("Requires elevation (UAC prompt skipped in background)")
            temp_fd, temp_path_str = tempfile.mkstemp(suffix=f"_smart_{backend_id}.json")
            os.close(temp_fd)
            temp_path = Path(temp_path_str)

            try:
                # Use powershell Start-Process with -Verb RunAs to execute smartctl elevated
                # and write the JSON output to our temp file.
                ps_script = (
                    f"Start-Process smartctl -ArgumentList '--json', '-a', '{normalized_device}' "
                    f"-RedirectStandardOutput '{temp_path}' -NoNewWindow -Verb RunAs -Wait"
                )
                
                logger.info("Requesting elevation (UAC) to run smartctl on %s", normalized_device)
                
                subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
                    timeout=20,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
                )

                if temp_path.exists() and temp_path.stat().st_size > 0:
                    with open(temp_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    return self.parse_smartctl_json(data, backend_id)
                else:
                    return SmartReport.unavailable("UAC elevation denied or smartctl failed to write output")
            except Exception as exc:
                logger.warning("Elevated smartctl execution failed: %s", exc)
                return SmartReport.unavailable(f"Failed to run smartctl with elevation: {exc}")
            finally:
                try:
                    if temp_path.exists():
                        temp_path.unlink()
                except Exception:
                    pass
        
        return SmartReport.unavailable("Unable to query drive without admin privileges")

    def _resolve_drive_letter_to_physical_drive(self, drive_letter: str) -> Optional[str]:
        """Resolve a drive letter like 'D' to WMI PhysicalDrive path like '\\\\.\\PhysicalDrive0'."""
        try:
            # Query WMI via powershell to associate drive letter with physical drive index
            cmd = (
                f"Get-Partition -DriveLetter {drive_letter} | "
                "Get-Disk | Select-Object -ExpandProperty Number"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            )
            if result.returncode == 0:
                disk_number = result.stdout.strip()
                if disk_number.isdigit():
                    return f"\\\\.\\PhysicalDrive{disk_number}"
        except Exception as exc:
            logger.debug("Failed to resolve drive letter %s via PowerShell: %s", drive_letter, exc)
        return None
