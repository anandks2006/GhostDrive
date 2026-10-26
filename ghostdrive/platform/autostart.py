"""
ghostdrive/platform/autostart.py -- Cross-platform startup configuration.
Configures application auto-start on boot for Windows, macOS, and Linux.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

APP_NAME = "GhostDrive"


def is_autostart_enabled() -> bool:
    """Check if autostart is currently enabled for the application."""
    if sys.platform == "win32":
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0,
                winreg.KEY_READ,
            )
            try:
                winreg.QueryValueEx(key, APP_NAME)
                return True
            except FileNotFoundError:
                return False
            finally:
                winreg.CloseKey(key)
        except Exception as exc:
            logger.debug("Failed to query Windows autostart: %s", exc)
            return False

    elif sys.platform == "darwin":
        plist_path = Path.home() / "Library/LaunchAgents" / f"com.ghostdrive.{APP_NAME.lower()}.plist"
        return plist_path.exists()

    elif sys.platform.startswith("linux"):
        desktop_path = Path.home() / ".config/autostart" / f"{APP_NAME.lower()}.desktop"
        return desktop_path.exists()

    return False


def set_autostart(enable: bool) -> bool:
    """
    Enable or disable application auto-start on boot.

    Args:
        enable: True to register autostart, False to remove.

    Returns:
        True if the action succeeded or was a no-op, False otherwise.
    """
    if sys.platform == "win32":
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0,
                winreg.KEY_SET_VALUE,
            )
            try:
                if enable:
                    # Point to current python executable and module
                    exe = sys.executable
                    cmd = f'"{exe}" -m ghostdrive'
                    winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, cmd)
                else:
                    try:
                        winreg.DeleteValue(key, APP_NAME)
                    except FileNotFoundError:
                        pass
                return True
            finally:
                winreg.CloseKey(key)
        except Exception as exc:
            logger.warning("Failed to update Windows autostart: %s", exc)
            return False

    elif sys.platform == "darwin":
        plist_dir = Path.home() / "Library/LaunchAgents"
        plist_path = plist_dir / f"com.ghostdrive.{APP_NAME.lower()}.plist"
        if enable:
            try:
                plist_dir.mkdir(parents=True, exist_ok=True)
                content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.ghostdrive.{APP_NAME.lower()}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{sys.executable}</string>
        <string>-m</string>
        <string>ghostdrive</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
"""
                plist_path.write_text(content, encoding="utf-8")
                return True
            except Exception as exc:
                logger.warning("Failed to create macOS LaunchAgent: %s", exc)
                return False
        else:
            try:
                if plist_path.exists():
                    plist_path.unlink()
                return True
            except Exception as exc:
                logger.warning("Failed to remove macOS LaunchAgent: %s", exc)
                return False

    elif sys.platform.startswith("linux"):
        autostart_dir = Path.home() / ".config/autostart"
        desktop_path = autostart_dir / f"{APP_NAME.lower()}.desktop"
        if enable:
            try:
                autostart_dir.mkdir(parents=True, exist_ok=True)
                content = f"""[Desktop Entry]
Type=Application
Exec={sys.executable} -m ghostdrive
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
Name={APP_NAME}
Comment=GhostDrive Encrypted Cloud Drive
"""
                desktop_path.write_text(content, encoding="utf-8")
                return True
            except Exception as exc:
                logger.warning("Failed to create Linux autostart desktop entry: %s", exc)
                return False
        else:
            try:
                if desktop_path.exists():
                    desktop_path.unlink()
                return True
            except Exception as exc:
                logger.warning("Failed to remove Linux autostart desktop entry: %s", exc)
                return False

    return False
