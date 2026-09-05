"""
linux/drive_monitor.py -- Linux drive UUID, serial, type detection and event monitoring.
"""

from __future__ import annotations

import re
import logging
import threading
from pathlib import Path
from typing import Callable, Optional

from ghostdrive.platform.drive_monitor import DriveMonitorBase, DriveEvent, DriveIdentity
from ghostdrive.platform._polling_fallback import PollingDriveMonitor

logger = logging.getLogger(__name__)


def _get_linux_volume_uuid(device_node: str) -> Optional[str]:
    """Resolve UUID via /dev/disk/by-uuid/ symlinks."""
    try:
        uuid_dir = Path("/dev/disk/by-uuid")
        if uuid_dir.exists():
            real_dev = Path(device_node).resolve()
            for link in uuid_dir.iterdir():
                if link.is_symlink() and link.resolve() == real_dev:
                    return link.name
    except Exception as exc:
        logger.debug("Failed to resolve Linux UUID for %s: %s", device_node, exc)
    return None


def _get_linux_drive_serial(device_node: str) -> Optional[str]:
    """Read hardware serial from sysfs."""
    try:
        dev_name = Path(device_node).name
        # Match sdX, nvmeXnX, mmcblkX
        disk_match = re.match(r"^([a-z]+|nvme\d+n\d+|mmcblk\d+)", dev_name)
        if disk_match:
            disk_name = disk_match.group(1)
            serial_path = Path("/sys/block") / disk_name / "device" / "serial"
            if serial_path.exists():
                return serial_path.read_text().strip()
            # Try alternate path
            serial_path = Path("/sys/class/block") / disk_name / "device" / "serial"
            if serial_path.exists():
                return serial_path.read_text().strip()
    except Exception as exc:
        logger.debug("Failed to read sysfs serial for %s: %s", device_node, exc)
    return None


def _detect_linux_drive_type(device_node: str) -> str:
    """Read rotational attribute from sysfs (0=SSD, 1=HDD)."""
    try:
        dev_name = Path(device_node).name
        disk_match = re.match(r"^([a-z]+|nvme\d+n\d+|mmcblk\d+)", dev_name)
        if disk_match:
            disk_name = disk_match.group(1)
            rot_path = Path("/sys/block") / disk_name / "queue" / "rotational"
            if rot_path.exists():
                rot = rot_path.read_text().strip()
                return "hdd" if rot == "1" else "ssd"
    except Exception:
        pass
    return "unknown"


def _build_identity_from_partition(mountpoint: str, device: str) -> Optional[DriveIdentity]:
    import psutil
    try:
        usage = psutil.disk_usage(mountpoint)
        parts = psutil.disk_partitions(all=False)
        fstype = next((p.fstype for p in parts if p.mountpoint == mountpoint), "unknown")
    except Exception:
        return None

    uuid = _get_linux_volume_uuid(device)
    serial = _get_linux_drive_serial(device)
    label = Path(mountpoint).name or f"Drive ({device})"
    
    # Try reading the volume label if filesystem tools allow, but fall back to directory name
    drive_type = _detect_linux_drive_type(device)

    if uuid:
        return DriveIdentity.from_uuid(
            uuid=uuid, label=label, mountpoint=mountpoint,
            capacity_bytes=usage.total, drive_type=drive_type,
            filesystem=fstype, serial=serial
        )
    elif serial:
        return DriveIdentity.from_fingerprint(
            serial=serial, capacity_bytes=usage.total,
            label=label, mountpoint=mountpoint,
            drive_type=drive_type, filesystem=fstype
        )
    return None


class LinuxDriveMonitor(DriveMonitorBase):
    """
    Linux drive monitor using pyudev for events, with psutil polling fallback.
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
            # Ignore root and virtual filesystems typical of Linux
            if part.fstype in ("tmpfs", "devtmpfs", "proc", "sysfs", "cgroup", "overlay"):
                continue
            if part.mountpoint.startswith(("/proc", "/sys", "/dev", "/run", "/boot")):
                continue
            identity = _build_identity_from_partition(part.mountpoint, part.device)
            if identity:
                result.append(identity)
        return result

    def get_uuid(self, mountpoint: str) -> Optional[str]:
        import psutil
        for part in psutil.disk_partitions(all=False):
            if part.mountpoint == mountpoint:
                return _get_linux_volume_uuid(part.device)
        return None

    def start_monitoring(self, callback: Callable[[DriveEvent], None]) -> None:
        self._callback = callback
        try:
            self._start_pyudev_monitoring(callback)
        except Exception as exc:
            logger.warning("pyudev monitor unavailable, using polling fallback: %s", exc)
            self._use_fallback = True
            self._fallback.start_monitoring(callback)

    def stop_monitoring(self) -> None:
        if self._use_fallback:
            self._fallback.stop_monitoring()
        else:
            self._stop_evt.set()

    def _start_pyudev_monitoring(self, callback: Callable[[DriveEvent], None]) -> None:
        import pyudev
        
        context = pyudev.Context()
        monitor = pyudev.Monitor.from_netlink(context)
        monitor.filter_by(subsystem='block')

        known: dict[str, DriveIdentity] = {}
        for dev in context.list_devices(subsystem='block', device_type='partition'):
            # Find if it is mounted
            mp = self._find_mountpoint(dev.device_node)
            if mp:
                identity = _build_identity_from_partition(mp, dev.device_node)
                if identity:
                    known[dev.device_node] = identity

        def _loop() -> None:
            # Poll monitor with timeout to check stop event
            while not self._stop_evt.is_set():
                dev = monitor.poll(timeout=0.5)
                if dev is None:
                    continue

                dev_node = dev.device_node
                if dev.action == 'add':
                    # Give it a moment to mount if automounted
                    self._stop_evt.wait(1.0)
                    mp = self._find_mountpoint(dev_node)
                    if mp:
                        identity = _build_identity_from_partition(mp, dev_node)
                        if identity:
                            known[dev_node] = identity
                            callback(DriveEvent("connected", identity))
                elif dev.action == 'remove':
                    identity = known.pop(dev_node, None)
                    if identity:
                        callback(DriveEvent("disconnected", identity))

        self._stop_evt.clear()
        self._thread = threading.Thread(target=_loop, name="gd-linux-drv-monitor", daemon=True)
        self._thread.start()

    def _find_mountpoint(self, device_node: str) -> Optional[str]:
        import psutil
        try:
            real_node = Path(device_node).resolve()
            for part in psutil.disk_partitions(all=False):
                if Path(part.device).resolve() == real_node:
                    return part.mountpoint
        except Exception:
            pass
        return None
