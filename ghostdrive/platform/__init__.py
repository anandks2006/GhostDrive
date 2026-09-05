"""
ghostdrive/platform/__init__.py -- Platform abstraction entry point.

Selects the appropriate platform implementation based on sys.platform.
Exposes factory functions for monitors, cleaners, and SMART health checkers.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ghostdrive.platform.drive_monitor import DriveMonitorBase, ScreenLockMonitorBase
    from ghostdrive.platform.artifact_cleaner import ArtifactCleanerBase
    from ghostdrive.platform.smart_monitor import SmartMonitorBase


def get_drive_monitor() -> DriveMonitorBase:
    """Return the platform-appropriate DriveMonitor implementation."""
    if sys.platform == "win32":
        from ghostdrive.platform.windows.drive_monitor import WindowsDriveMonitor
        return WindowsDriveMonitor()
    elif sys.platform == "linux":
        from ghostdrive.platform.linux.drive_monitor import LinuxDriveMonitor
        return LinuxDriveMonitor()
    elif sys.platform == "darwin":
        from ghostdrive.platform.macos.drive_monitor import MacOSDriveMonitor
        return MacOSDriveMonitor()
    else:
        # Fallback to polling for unsupported platforms
        from ghostdrive.platform._polling_fallback import PollingDriveMonitor
        return PollingDriveMonitor()


def get_screen_lock_monitor() -> ScreenLockMonitorBase:
    """Return the platform-appropriate ScreenLockMonitor implementation."""
    if sys.platform == "win32":
        from ghostdrive.platform.windows.drive_monitor import WindowsScreenLockMonitor
        return WindowsScreenLockMonitor()
    elif sys.platform == "linux":
        from ghostdrive.platform.linux.screen_lock import LinuxScreenLockMonitor
        return LinuxScreenLockMonitor()
    elif sys.platform == "darwin":
        from ghostdrive.platform.macos.screen_lock import MacOSScreenLockMonitor
        return MacOSScreenLockMonitor()
    else:
        # Return a dummy monitor that never fires but doesn't crash
        from ghostdrive.platform.drive_monitor import ScreenLockMonitorBase
        class DummyScreenLockMonitor(ScreenLockMonitorBase):
            def is_available(self) -> bool:
                return False
            def start(self, on_lock) -> None:
                pass
            def stop(self) -> None:
                pass
        return DummyScreenLockMonitor()


def get_artifact_cleaner() -> ArtifactCleanerBase:
    """Return the platform-appropriate ArtifactCleaner implementation."""
    if sys.platform == "win32":
        from ghostdrive.platform.windows.artifact_cleaner import WindowsArtifactCleaner
        return WindowsArtifactCleaner()
    elif sys.platform == "linux":
        from ghostdrive.platform.linux.artifact_cleaner import LinuxArtifactCleaner
        return LinuxArtifactCleaner()
    elif sys.platform == "darwin":
        from ghostdrive.platform.macos.artifact_cleaner import MacOSArtifactCleaner
        return MacOSArtifactCleaner()
    else:
        from ghostdrive.platform.artifact_cleaner import ArtifactCleanerBase, ArtifactReport, CleanResult
        class DummyArtifactCleaner(ArtifactCleanerBase):
            def is_available(self) -> bool:
                return False
            async def audit(self) -> ArtifactReport:
                return ArtifactReport(files_found=[], total_bytes=0, categories={})
            async def clean(self, categories=None) -> CleanResult:
                return CleanResult(success=True, files_cleaned=[], bytes_freed=0, errors={})
        return DummyArtifactCleaner()


def get_smart_monitor() -> SmartMonitorBase:
    """Return the platform-appropriate SmartMonitor implementation."""
    if sys.platform == "win32":
        from ghostdrive.platform.windows.smart_monitor import WindowsSmartMonitor
        return WindowsSmartMonitor()
    elif sys.platform == "linux":
        from ghostdrive.platform.linux.smart_monitor import LinuxSmartMonitor
        return LinuxSmartMonitor()
    elif sys.platform == "darwin":
        from ghostdrive.platform.macos.smart_monitor import MacOSSmartMonitor
        return MacOSSmartMonitor()
    else:
        from ghostdrive.platform.smart_monitor import SmartMonitorBase, SmartReport
        class DummySmartMonitor(SmartMonitorBase):
            def is_available(self) -> bool:
                return False
            async def query_drive(self, backend_id, drive_identity) -> SmartReport:
                from ghostdrive.exceptions import SMARTUnavailableError
                raise SMARTUnavailableError("SMART monitoring not supported on this platform")
        return DummySmartMonitor()
