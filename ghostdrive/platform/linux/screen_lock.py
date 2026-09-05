"""
linux/screen_lock.py -- Linux screen lock detection via D-Bus.
"""

from __future__ import annotations

import logging
import threading
from typing import Callable, Optional

from ghostdrive.platform.drive_monitor import ScreenLockMonitorBase

logger = logging.getLogger(__name__)


class LinuxScreenLockMonitor(ScreenLockMonitorBase):
    """
    Linux screen lock monitor.
    Uses D-Bus signals (org.gnome.ScreenSaver or org.freedesktop.ScreenSaver) via jeepney.
    Falls back to a dummy/idle monitor if D-Bus libraries are missing.
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
        self._thread = threading.Event() # dummy/flag
        self._thread = threading.Thread(
            target=self._monitor_loop,
            name="gd-linux-screen-lock",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_evt.set()

    def _monitor_loop(self) -> None:
        try:
            self._dbus_loop()
        except Exception as exc:
            logger.debug("D-Bus screen lock monitor failed or unavailable: %s. Using fallback.", exc)
            self._fallback_loop()

    def _dbus_loop(self) -> None:
        # Import jeepney (standard Python D-Bus library)
        from jeepney import DBusAddress, new_method_call
        from jeepney.io.blocking import open_dbus_connection

        connection = open_dbus_connection(bus='SESSION')
        
        # Subscribe to GNOME Screensaver ActiveChanged signal
        # interface: org.gnome.ScreenSaver, member: ActiveChanged
        # signal is emitted when screen locks/unlocks
        # We also listen to org.freedesktop.ScreenSaver
        
        # Subscription rules
        # (For simplicity in blocking mode, we can issue a MatchRule or just poll the state via method calls)
        # GNOME ScreenSaver address
        gnome_addr = DBusAddress(
            '/org/gnome/ScreenSaver',
            bus_name='org.gnome.ScreenSaver',
            interface='org.gnome.ScreenSaver'
        )
        
        # ActiveChanged method call or state polling
        # Polling the active state every 5 seconds is extremely robust, simple, and works across both
        # GNOME and KDE with no complex asynchronous D-Bus signal subscription setup!
        # Let's poll GetActive():
        msg = new_method_call(gnome_addr, 'GetActive', '')
        
        last_state = False
        while not self._stop_evt.wait(5.0):
            try:
                reply = connection.send_message_and_wait(msg)
                # reply is a tuple, first element is boolean active state
                is_active = reply[0] if reply else False
                if is_active and not last_state:
                    logger.info("Linux Screen Lock detected via GNOME ScreenSaver")
                    if self._on_lock:
                        self._on_lock()
                last_state = is_active
            except Exception:
                # Try freedesktop.ScreenSaver (KDE/others)
                try:
                    kde_addr = DBusAddress(
                        '/ScreenSaver',
                        bus_name='org.freedesktop.ScreenSaver',
                        interface='org.freedesktop.ScreenSaver'
                    )
                    kde_msg = new_method_call(kde_addr, 'GetActive', '')
                    reply = connection.send_message_and_wait(kde_msg)
                    is_active = reply[0] if reply else False
                    if is_active and not last_state:
                        logger.info("Linux Screen Lock detected via freedesktop ScreenSaver")
                        if self._on_lock:
                            self._on_lock()
                    last_state = is_active
                except Exception:
                    pass

    def _fallback_loop(self) -> None:
        """Fallback: check if common screensaver or lock processes are running, or just wait."""
        # Linux desktops run lock processes: gnome-screensaver, kscreenlocker, light-locker, i3lock.
        # We check process names as a fallback.
        import psutil
        lock_names = {"light-locker", "i3lock", "swaylock", "slock"}
        
        while not self._stop_evt.wait(10.0):
            try:
                for proc in psutil.process_iter(["name"]):
                    if proc.info["name"] in lock_names:
                        logger.info("Linux Screen Lock detected via active lock process: %s", proc.info["name"])
                        if self._on_lock:
                            self._on_lock()
                        break
            except Exception:
                pass
