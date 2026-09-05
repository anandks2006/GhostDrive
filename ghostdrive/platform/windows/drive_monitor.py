"""
windows/drive_monitor.py -- Windows drive UUID + connect/disconnect events.

UUID resolution: win32api.GetVolumeInformation() for volume GUIDs.
Hardware serial: WMI Win32_DiskDrive query via subprocess (avoids win32com dep).
Events: WM_DEVICECHANGE via a hidden HWND in a background thread.

Falls back to PollingDriveMonitor if win32api is unavailable.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import logging
import subprocess
import threading
from typing import Callable, Optional

from ghostdrive.platform.drive_monitor import (
    DriveEvent,
    DriveIdentity,
    DriveMonitorBase,
    ScreenLockMonitorBase,
)
from ghostdrive.platform._polling_fallback import PollingDriveMonitor

logger = logging.getLogger(__name__)

# Windows API constants
_WM_DEVICECHANGE       = 0x0219
_DBT_DEVICEARRIVAL     = 0x8000
_DBT_DEVICEREMOVECOMPLETE = 0x8004
_WTS_SESSION_LOCK      = 0x7
_WTS_CONSOLE_CONNECT   = 0x1
_WM_WTSSESSION_CHANGE  = 0x02B1

# GetVolumeInformation flags
_MAX_PATH = 260


def _get_volume_uuid(mountpoint: str) -> Optional[str]:
    """
    Return the volume GUID for a Windows mountpoint (e.g. "D:\\").
    Returns None if unavailable (no UUID, access denied).
    """
    try:
        kernel32 = ctypes.windll.kernel32
        volume_name     = ctypes.create_unicode_buffer(_MAX_PATH + 1)
        volume_serial   = ctypes.wintypes.DWORD()
        fs_name         = ctypes.create_unicode_buffer(_MAX_PATH + 1)

        success = kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(mountpoint),
            volume_name, _MAX_PATH + 1,
            ctypes.byref(volume_serial),
            None, None,
            fs_name, _MAX_PATH + 1,
        )
        if not success:
            return None

        # Volume serial is a 32-bit integer -- format as 8-char hex UUID-like string
        serial_hex = f"{volume_serial.value:08X}"
        return f"{serial_hex[:4]}-{serial_hex[4:]}"   # e.g. "4A21-B3C9"
    except Exception as exc:
        logger.debug("GetVolumeInformation failed for %s: %s", mountpoint, exc)
        return None


def _get_drive_serial_wmic(drive_letter: str) -> Optional[str]:
    """
    Query hardware serial via WMIC. Requires no elevation on most systems.
    drive_letter: e.g. "D" (without colon or backslash)
    """
    try:
        result = subprocess.run(
            ["wmic", "logicaldisk", "where", f"DeviceID='{drive_letter}:'",
             "get", "VolumeSerialNumber", "/format:value"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            if line.startswith("VolumeSerialNumber="):
                serial = line.split("=", 1)[1].strip()
                return serial or None
    except Exception as exc:
        logger.debug("WMIC serial query failed: %s", exc)
    return None


def _detect_drive_type(drive_letter: str) -> str:
    """Heuristically detect SSD vs HDD via WMIC logical disk associations."""
    try:
        # Step 1: Map logical disk (e.g. "D:") to physical disk partition index
        target_device_id = f'DeviceID="{drive_letter.upper()}:"'
        result = subprocess.run(
            ["wmic", "path", "Win32_LogicalDiskToPartition", "get", "Antecedent,Dependent", "/format:value"],
            capture_output=True, text=True, timeout=5,
        )
        disk_index = None
        for line in result.stdout.splitlines():
            if target_device_id in line:
                import re
                match = re.search(r'Disk #(\d+)', line)
                if match:
                    disk_index = match.group(1)
                    break
        
        if disk_index is None:
            disk_index = "0"
            
        # Step 2: Get media type for the specific physical disk index
        result = subprocess.run(
            ["wmic", "diskdrive", "where", f"Index={disk_index}", "get", "MediaType,Model", "/format:value"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            if line.startswith("MediaType=") or line.startswith("Model="):
                val = line.split("=", 1)[1].upper()
                if "SSD" in val or "SOLID" in val:
                    return "ssd"
                if "HDD" in val or "FIXED" in val or "HARD" in val:
                    return "hdd"
    except Exception:
        pass
    return "unknown"


def _build_identity_from_mountpoint(mountpoint: str) -> Optional[DriveIdentity]:
    """Build a DriveIdentity for a Windows drive letter mountpoint."""
    import psutil
    try:
        usage   = psutil.disk_usage(mountpoint)
        parts   = psutil.disk_partitions(all=False)
        fstype  = next((p.fstype for p in parts if p.mountpoint.upper() == mountpoint.upper()), "unknown")
    except Exception:
        return None

    drive_letter = mountpoint.rstrip("\\:/").upper()
    uuid   = _get_volume_uuid(mountpoint)
    serial = _get_drive_serial_wmic(drive_letter)

    label = f"Drive ({drive_letter}:)"
    try:
        vol_buf = ctypes.create_unicode_buffer(_MAX_PATH + 1)
        ctypes.windll.kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(mountpoint),
            vol_buf, _MAX_PATH + 1,
            None, None, None, None, 0,
        )
        if vol_buf.value:
            label = vol_buf.value
    except Exception:
        pass

    if uuid:
        identity = DriveIdentity.from_uuid(
            uuid=uuid, label=label, mountpoint=mountpoint,
            capacity_bytes=usage.total,
            drive_type=_detect_drive_type(drive_letter),
            filesystem=fstype, serial=serial,
        )
    elif serial:
        identity = DriveIdentity.from_fingerprint(
            serial=serial, capacity_bytes=usage.total,
            label=label, mountpoint=mountpoint,
            drive_type=_detect_drive_type(drive_letter),
            filesystem=fstype,
        )
    else:
        return None

    return identity


class WindowsDriveMonitor(DriveMonitorBase):
    """
    Windows drive monitor using WM_DEVICECHANGE messages.

    Requires pywin32 for the hidden-window event loop. Falls back to
    PollingDriveMonitor if win32api is unavailable.
    """

    def __init__(self) -> None:
        self._fallback = PollingDriveMonitor()
        self._use_fallback = False
        self._callback: Optional[Callable[[DriveEvent], None]] = None
        self._stop_evt = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def is_available(self) -> bool:
        return True   # polling fallback always works on Windows

    def list_drives(self) -> list[DriveIdentity]:
        import psutil
        result = []
        for part in psutil.disk_partitions(all=False):
            if part.fstype.lower() in ("", "cdrom"):
                continue
            identity = _build_identity_from_mountpoint(part.mountpoint)
            if identity:
                result.append(identity)
        return result

    def get_uuid(self, mountpoint: str) -> Optional[str]:
        return _get_volume_uuid(mountpoint)

    def start_monitoring(self, callback: Callable[[DriveEvent], None]) -> None:
        self._callback = callback
        try:
            self._start_wm_devicechange(callback)
        except Exception as exc:
            logger.warning("WM_DEVICECHANGE unavailable, using polling fallback: %s", exc)
            self._use_fallback = True
            self._fallback.start_monitoring(callback)

    def stop_monitoring(self) -> None:
        if self._use_fallback:
            self._fallback.stop_monitoring()
        else:
            self._stop_evt.set()

    def _start_wm_devicechange(self, callback: Callable) -> None:
        """Start a hidden window message loop for WM_DEVICECHANGE events."""
        import win32gui   # type: ignore[import]

        known: dict[str, DriveIdentity] = {}

        def wnd_proc(hwnd: int, msg: int, wparam: int, lparam: int) -> int:
            if msg == _WM_DEVICECHANGE:
                if wparam in (_DBT_DEVICEARRIVAL, _DBT_DEVICEREMOVECOMPLETE):
                    import psutil
                    current_mounts = {
                        p.mountpoint
                        for p in psutil.disk_partitions(all=False)
                        if p.fstype.lower() not in ("", "cdrom")
                    }
                    known_mounts = set(known.keys())

                    for mp in current_mounts - known_mounts:
                        identity = _build_identity_from_mountpoint(mp)
                        if identity:
                            known[mp] = identity
                            callback(DriveEvent("connected", identity))

                    for mp in known_mounts - current_mounts:
                        identity = known.pop(mp)
                        callback(DriveEvent("disconnected", identity))

            return win32gui.DefWindowProc(hwnd, msg, wparam, lparam)

        def _loop() -> None:
            wc = win32gui.WNDCLASS()
            wc.lpfnWndProc = wnd_proc
            wc.lpszClassName = "GhostDriveDriveMonitor"
            try:
                win32gui.RegisterClass(wc)
            except Exception:
                pass
            hwnd = win32gui.CreateWindow(
                wc.lpszClassName, "GhostDrive Monitor",
                0, 0, 0, 0, 0, 0, 0, None, None,
            )
            # Snapshot initial state
            import psutil
            for p in psutil.disk_partitions(all=False):
                if p.fstype.lower() not in ("", "cdrom"):
                    identity = _build_identity_from_mountpoint(p.mountpoint)
                    if identity:
                        known[p.mountpoint] = identity
            # Message loop
            import time
            while not self._stop_evt.is_set():
                win32gui.PumpWaitingMessages()
                time.sleep(0.1)
            win32gui.DestroyWindow(hwnd)

        self._stop_evt.clear()
        self._thread = threading.Thread(target=_loop, name="gd-drv-monitor", daemon=True)
        self._thread.start()


class WindowsScreenLockMonitor(ScreenLockMonitorBase):
    """
    Windows screen lock detection via WTS session notifications.
    Fires on_lock() when WTS_SESSION_LOCK is received.
    Falls back to idle timer (30-second poll) if win32api unavailable.
    """

    _IDLE_POLL = 30   # seconds for fallback idle check

    def __init__(self) -> None:
        self._on_lock: Optional[Callable[[], None]] = None
        self._stop_evt = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def is_available(self) -> bool:
        return True   # fallback always available

    def start(self, on_lock: Callable[[], None]) -> None:
        self._on_lock = on_lock
        self._stop_evt.clear()
        self._thread = threading.Thread(
            target=self._monitor_loop,
            name="gd-screen-lock",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_evt.set()

    def _monitor_loop(self) -> None:
        try:
            self._wts_session_loop()
        except Exception as exc:
            logger.debug("WTS session monitor unavailable (%s); using idle timer", exc)
            self._idle_timer_loop()

    def _wts_session_loop(self) -> None:
        import win32gui       # type: ignore[import]
        import win32ts        # type: ignore[import]

        def wnd_proc(hwnd: int, msg: int, wparam: int, lparam: int) -> int:
            if msg == _WM_WTSSESSION_CHANGE and wparam == _WTS_SESSION_LOCK:
                if self._on_lock:
                    self._on_lock()
            return win32gui.DefWindowProc(hwnd, msg, wparam, lparam)

        wc = win32gui.WNDCLASS()
        wc.lpfnWndProc = wnd_proc
        wc.lpszClassName = "GhostDriveSessionMonitor"
        try:
            win32gui.RegisterClass(wc)
        except Exception:
            pass
        hwnd = win32gui.CreateWindow(wc.lpszClassName, "", 0, 0, 0, 0, 0, 0, 0, None, None)
        win32ts.WTSRegisterSessionNotification(hwnd, win32ts.NOTIFY_FOR_THIS_SESSION)

        import time
        while not self._stop_evt.is_set():
            win32gui.PumpWaitingMessages()
            time.sleep(0.1)

        win32ts.WTSUnRegisterSessionNotification(hwnd)
        win32gui.DestroyWindow(hwnd)

    def _idle_timer_loop(self) -> None:
        """Fallback: check GetLastInputInfo idle time every 30 seconds."""
        import ctypes

        class _LASTINPUTINFO(ctypes.Structure):
            _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]

        IDLE_THRESHOLD_MS = 5 * 60 * 1000   # 5 minutes
        locked = False

        while not self._stop_evt.wait(self._IDLE_POLL):
            lii = _LASTINPUTINFO()
            lii.cbSize = ctypes.sizeof(_LASTINPUTINFO)
            ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii))
            tick_now  = ctypes.windll.kernel32.GetTickCount()
            idle_ms   = tick_now - lii.dwTime

            if idle_ms >= IDLE_THRESHOLD_MS and not locked:
                locked = True
                if self._on_lock:
                    self._on_lock()
            elif idle_ms < IDLE_THRESHOLD_MS:
                locked = False
