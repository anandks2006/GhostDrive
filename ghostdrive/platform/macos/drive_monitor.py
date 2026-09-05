"""
macos/drive_monitor.py -- macOS drive UUID, serial, type detection and event monitoring.
"""

from __future__ import annotations

import logging
import plistlib
import subprocess
import threading
from pathlib import Path
from typing import Callable, Optional

from ghostdrive.platform.drive_monitor import DriveMonitorBase, DriveEvent, DriveIdentity
from ghostdrive.platform._polling_fallback import PollingDriveMonitor

logger = logging.getLogger(__name__)


def _get_diskutil_info(mountpoint_or_device: str) -> Optional[dict]:
    """Query diskutil info -plist for a volume or device."""
    try:
        result = subprocess.run(
            ["diskutil", "info", "-plist", mountpoint_or_device],
            capture_output=True,
            timeout=5
        )
        if result.returncode == 0 and result.stdout:
            return plistlib.loads(result.stdout)
    except Exception as exc:
        logger.debug("diskutil info failed for %s: %s", mountpoint_or_device, exc)
    return None


def _build_identity_from_mountpoint(mountpoint: str) -> Optional[DriveIdentity]:
    info = _get_diskutil_info(mountpoint)
    if not info:
        return None

    uuid = info.get("VolumeUUID")
    label = info.get("VolumeName") or info.get("MediaName") or Path(mountpoint).name
    capacity_bytes = info.get("TotalSize", 0)
    
    # filesystem
    filesystem = info.get("FilesystemType") or info.get("FilesystemName") or "unknown"
    
    # drive type: SolidState key is boolean
    is_ssd = info.get("SolidState", False)
    drive_type = "ssd" if is_ssd else "hdd"
    if "ssd" not in drive_type.lower() and info.get("VirtualOrPhysical") == "Virtual":
        drive_type = "unknown"

    # serial number
    serial = info.get("DeviceGUID") or info.get("OSInternalUUID")
    parent_id = info.get("ParentDiskIdentifier")
    if parent_id and not serial:
        # Try getting hardware serial from parent disk info
        parent_info = _get_diskutil_info(parent_id)
        if parent_info:
            serial = parent_info.get("DeviceGUID") or parent_info.get("OSInternalUUID")

    if uuid:
        return DriveIdentity.from_uuid(
            uuid=uuid, label=label, mountpoint=mountpoint,
            capacity_bytes=capacity_bytes, drive_type=drive_type,
            filesystem=filesystem, serial=serial
        )
    elif serial:
        return DriveIdentity.from_fingerprint(
            serial=serial, capacity_bytes=capacity_bytes,
            label=label, mountpoint=mountpoint,
            drive_type=drive_type, filesystem=filesystem
        )
    return None


class MacOSDriveMonitor(DriveMonitorBase):
    """
    macOS drive monitor using NSWorkspace notifications via PyObjC, with polling fallback.
    """

    def __init__(self) -> None:
        self._fallback = PollingDriveMonitor()
        self._use_fallback = False
        self._callback: Optional[Callable[[DriveEvent], None]] = None
        self._stop_evt = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def is_available(self) -> bool:
        return True

    def list_drives(self) -> list[DriveIdentity]:
        import psutil
        result = []
        for part in psutil.disk_partitions(all=False):
            # Exclude macOS special volumes / system / read-only firmwares
            if part.mountpoint.startswith(("/System", "/private", "/dev", "/Volumes/Recovery")):
                continue
            if part.fstype in ("devfs", "autofs", "sysfs"):
                continue
            identity = _build_identity_from_mountpoint(part.mountpoint)
            if identity:
                result.append(identity)
        return result

    def get_uuid(self, mountpoint: str) -> Optional[str]:
        info = _get_diskutil_info(mountpoint)
        return info.get("VolumeUUID") if info else None

    def start_monitoring(self, callback: Callable[[DriveEvent], None]) -> None:
        self._callback = callback
        try:
            self._start_ns_workspace_monitoring(callback)
        except Exception as exc:
            logger.warning("PyObjC NSWorkspace monitor unavailable, using polling fallback: %s", exc)
            self._use_fallback = True
            self._fallback.start_monitoring(callback)

    def stop_monitoring(self) -> None:
        if self._use_fallback:
            self._fallback.stop_monitoring()
        else:
            self._stop_evt.set()

    def _start_ns_workspace_monitoring(self, callback: Callable[[DriveEvent], None]) -> None:
        # Import PyObjC runtime elements
        from AppKit import NSWorkspace
        from Foundation import NSObject, NSRunLoop, NSDate

        known: dict[str, DriveIdentity] = {}
        for part in self.list_drives():
            known[part.mountpoint] = part

        class WorkspaceObserver(NSObject):
            def deviceDidMount_(self, notification):
                userInfo = notification.userInfo()
                # path to mountpoint is key NSWorkspaceVolumeURLKey
                url = userInfo.objectForKey_("NSWorkspaceVolumeURLKey")
                if url:
                    mp = url.path()
                    # wait a split second for mounting plist details to settle
                    threading.Thread(target=self._process_mount, args=(mp,), daemon=True).start()

            def _process_mount(self, mp: str):
                identity = _build_identity_from_mountpoint(mp)
                if identity:
                    known[mp] = identity
                    callback(DriveEvent("connected", identity))

            def deviceDidUnmount_(self, notification):
                userInfo = notification.userInfo()
                url = userInfo.objectForKey_("NSWorkspaceVolumeURLKey")
                if url:
                    mp = url.path()
                    identity = known.pop(mp, None)
                    if identity:
                        callback(DriveEvent("disconnected", identity))

        observer = WorkspaceObserver.alloc().init()
        nc = NSWorkspace.sharedWorkspace().notificationCenter()
        
        nc.addObserver_selector_name_object_(
            observer,
            "deviceDidMount:",
            "NSWorkspaceDidMountNotification",
            None
        )
        nc.addObserver_selector_name_object_(
            observer,
            "deviceDidUnmount:",
            "NSWorkspaceDidUnmountNotification",
            None
        )

        def _loop() -> None:
            run_loop = NSRunLoop.currentRunLoop()
            while not self._stop_evt.is_set():
                run_loop.runUntilDate_(NSDate.dateWithTimeIntervalSinceNow_(0.5))
            nc.removeObserver_(observer)

        self._stop_evt.clear()
        self._thread = threading.Thread(target=_loop, name="gd-macos-drv-monitor", daemon=True)
        self._thread.start()
