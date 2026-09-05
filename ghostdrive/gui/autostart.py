"""
autostart.py -- Platform-agnostic application auto-startup manager.
"""

import sys
import platform
import logging
from pathlib import Path

logger = logging.getLogger("ghostdrive.gui.autostart")

class AutoStartManager:
    """Manages application launch-on-boot configuration across OS platforms."""

    @staticmethod
    def _get_app_path() -> str:
        """Returns the executable command line for GhostDrive launcher."""
        # Use python executable + launcher main module path if running under python
        # or direct executable if compiled/packaged.
        if getattr(sys, "frozen", False):
            return sys.executable
        else:
            main_module = Path(sys.argv[0]).resolve()
            return f'"{sys.executable}" "{main_module}"'

    @classmethod
    def is_enabled(cls) -> bool:
        """Checks if auto-start is currently configured for the application."""
        system = platform.system()
        try:
            if system == "Windows":
                import winreg
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                try:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as key:
                        val, _ = winreg.QueryValueEx(key, "GhostDrive")
                        return bool(val)
                except FileNotFoundError:
                    return False

            elif system == "Darwin":  # macOS
                plist_path = Path.home() / "Library" / "LaunchAgents" / "com.ghostdrive.plist"
                return plist_path.exists()

            elif system == "Linux":
                desktop_path = Path.home() / ".config" / "autostart" / "ghostdrive.desktop"
                return desktop_path.exists()

        except Exception as exc:
            logger.error("Failed to check auto-start state: %s", exc)
        return False

    @classmethod
    def enable(cls) -> bool:
        """Enables auto-start for the current user session."""
        system = platform.system()
        app_path = cls._get_app_path()
        try:
            if system == "Windows":
                import winreg
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, "GhostDrive", 0, winreg.REG_SZ, app_path)
                logger.info("Auto-start enabled in registry (Windows).")
                return True

            elif system == "Darwin":  # macOS
                agents_dir = Path.home() / "Library" / "LaunchAgents"
                agents_dir.mkdir(parents=True, exist_ok=True)
                plist_path = agents_dir / "com.ghostdrive.plist"
                
                # Render standard launch agent plist
                # Using sys.executable wrapper to invoke launcher
                executable = sys.executable
                main_script = sys.argv[0]
                args_str = ""
                if not getattr(sys, "frozen", False):
                    args_str = f"        <string>{main_script}</string>\n"
                
                plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.ghostdrive</string>
    <key>ProgramArguments</key>
    <array>
        <string>{executable}</string>
{args_str}    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
"""
                plist_path.write_text(plist_content, encoding="utf-8")
                logger.info("Auto-start enabled via LaunchAgent plist (macOS).")
                return True

            elif system == "Linux":
                autostart_dir = Path.home() / ".config" / "autostart"
                autostart_dir.mkdir(parents=True, exist_ok=True)
                desktop_path = autostart_dir / "ghostdrive.desktop"
                
                desktop_content = f"""[Desktop Entry]
Type=Application
Version=1.0
Name=GhostDrive
Comment=Encrypted Personal Redundant Drive
Exec={app_path}
StartupNotify=false
Terminal=false
"""
                desktop_path.write_text(desktop_content, encoding="utf-8")
                logger.info("Auto-start enabled via desktop autostart entry (Linux).")
                return True

        except Exception as exc:
            logger.error("Failed to enable auto-start: %s", exc)
        return False

    @classmethod
    def disable(cls) -> bool:
        """Disables auto-start configuration."""
        system = platform.system()
        try:
            if system == "Windows":
                import winreg
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                try:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
                        winreg.DeleteValue(key, "GhostDrive")
                except FileNotFoundError:
                    pass
                logger.info("Auto-start disabled in registry (Windows).")
                return True

            elif system == "Darwin":  # macOS
                plist_path = Path.home() / "Library" / "LaunchAgents" / "com.ghostdrive.plist"
                if plist_path.exists():
                    plist_path.unlink()
                logger.info("Auto-start LaunchAgent plist removed (macOS).")
                return True

            elif system == "Linux":
                desktop_path = Path.home() / ".config" / "autostart" / "ghostdrive.desktop"
                if desktop_path.exists():
                    desktop_path.unlink()
                logger.info("Auto-start desktop autostart entry removed (Linux).")
                return True

        except Exception as exc:
            logger.error("Failed to disable auto-start: %s", exc)
        return False
