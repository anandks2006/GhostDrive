"""
sys_checks.py -- Pre-flight environment check (Windows Long Paths and Linux inotify limits).
"""

import os
import platform
from typing import Dict, Tuple

def check_windows_long_paths() -> Tuple[bool, str]:
    """
    Check if Windows Long Paths support is enabled.
    Returns (enabled, description).
    """
    if platform.system() != "Windows":
        return True, "N/A (Non-Windows platform)"

    try:
        import winreg
        key_path = r"SYSTEM\CurrentControlSet\Control\FileSystem"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            val, _ = winreg.QueryValueEx(key, "LongPathsEnabled")
            if val == 1:
                return True, "Windows Long Paths are enabled."
            else:
                return False, "Windows Long Paths are disabled (paths limited to 260 chars)."
    except Exception as exc:
        return False, f"Could not verify Windows Long Paths registry: {exc}"


def check_linux_inotify_limits() -> Tuple[bool, str]:
    """
    Check if Linux inotify user watches are sufficient (recommended >= 524288).
    Returns (sufficient, description).
    """
    if platform.system() != "Linux":
        return True, "N/A (Non-Linux platform)"

    path = "/proc/sys/fs/inotify/max_user_watches"
    if not os.path.exists(path):
        return True, "N/A (inotify file not found)"

    try:
        with open(path, "r") as f:
            limit = int(f.read().strip())
        if limit >= 524288:
            return True, f"inotify watches limit is sufficient ({limit})."
        else:
            return False, f"inotify watches limit is too low ({limit} < 524288). Run 'sysctl fs.inotify.max_user_watches=524288' to fix."
    except Exception as exc:
        return False, f"Could not verify Linux inotify watches limit: {exc}"


def run_system_diagnostics() -> Dict[str, Tuple[bool, str]]:
    """Run all OS-specific checks and return results."""
    return {
        "long_paths": check_windows_long_paths(),
        "inotify_limits": check_linux_inotify_limits(),
    }
