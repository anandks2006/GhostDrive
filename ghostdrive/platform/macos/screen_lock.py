"""
macos/screen_lock.py -- macOS screen lock detection via NSDistributedNotificationCenter.
"""

from __future__ import annotations

import logging
import threading
from typing import Callable, Optional

from ghostdrive.platform.drive_monitor import ScreenLockMonitorBase

logger = logging.getLogger(__name__)


class MacOSScreenLockMonitor(ScreenLockMonitorBase):
    """
    macOS screen lock monitor.
    Uses NSDistributedNotificationCenter via PyObjC to observe screen lock/unlock.
    """

    def __init__(self) -> None:
        self._on_lock: Optional[Callable[[], None]] = None
        self._stop_evt = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def is_available(self) -> bool:
        return True

    def start(self, on_lock: Callable[[], None]) -> None:
        self._on_lock = on_lock
        self._stop_evt.clear()
        self._thread = threading.Thread(
            target=self._monitor_loop,
            name="gd-macos-screen-lock",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_evt.set()

    def _monitor_loop(self) -> None:
        try:
            self._notification_loop()
        except Exception as exc:
            logger.debug("macOS PyObjC screen lock monitor failed: %s. Using idle fallback.", exc)
            self._idle_timer_loop()

    def _notification_loop(self) -> None:
        from Foundation import NSDistributedNotificationCenter, NSObject, NSRunLoop, NSDate

        outer_self = self
        class LockObserver(NSObject):
            def screenLocked_(self, notification):
                logger.info("macOS Screen Locked detected")
                if outer_self._on_lock:
                    outer_self._on_lock()

        observer = LockObserver.alloc().init()
        dnc = NSDistributedNotificationCenter.defaultCenter()
        
        # Subscribe to Apple's system lock notifications
        dnc.addObserver_selector_name_object_(
            observer,
            "screenLocked:",
            "com.apple.screenIsLocked",
            None
        )

        run_loop = NSRunLoop.currentRunLoop()
        while not self._stop_evt.is_set():
            run_loop.runUntilDate_(NSDate.dateWithTimeIntervalSinceNow_(0.5))

        dnc.removeObserver_(observer)

    def _idle_timer_loop(self) -> None:
        """Fallback: poll CoreGraphics / CGSession lock state or check sleep state."""
        import subprocess
        # Check output of 'pmset -g powerstate' or CGSession lock state via command:
        # 'ioreg -n IODisplayWrangler | grep -i "iopowerstate"'
        # If display is asleep, screen is locked/off.
        
        while not self._stop_evt.wait(10.0):
            try:
                # Check for Apple loginwindow session state (e.g. CGSession)
                # or read user idle time using Quartz if pyobjc-framework-Quartz is installed
                try:
                    import Quartz
                    # Idle time in seconds
                    idle_secs = Quartz.CGEventSourceSecondsSinceLastEventType(
                        Quartz.kCGEventSourceStateCombinedSessionState,
                        Quartz.kCGAnyInputEventType
                    )
                    if idle_secs >= 5 * 60: # 5 minutes
                        logger.info("macOS Idle Lock triggered (Quartz idle: %s)", idle_secs)
                        if self._on_lock:
                            self._on_lock()
                except ImportError:
                    # Alternative command line check
                    result = subprocess.run(
                        ["ioreg", "-n", "IODisplayWrangler", "-r", "-d", "1"],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    # "IOPowerManagement" = {"DevicePowerState"=0} (0 is off)
                    if '"DevicePowerState"=0' in result.stdout.replace(" ", ""):
                        logger.info("macOS Display sleep lock detected")
                        if self._on_lock:
                            self._on_lock()
            except Exception:
                pass
