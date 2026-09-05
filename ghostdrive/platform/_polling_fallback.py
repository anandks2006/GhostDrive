"""
_polling_fallback.py -- psutil-based polling drive monitor (all platforms).

Used when the platform-native monitor (pyudev / WM_DEVICECHANGE / NSWorkspace)
is unavailable or fails to initialise. Polls psutil.disk_partitions() every
2 seconds and diffs against the previous state to detect connects/disconnects.

2-second detection latency is acceptable for drive connect/disconnect events.

This is also the UUID resolution path for any platform where the native UUID
lookup is unavailable -- falls back to a serial+capacity fingerprint.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Callable, Optional

import psutil

from ghostdrive.platform.drive_monitor import (
    DriveEvent,
    DriveIdentity,
    DriveMonitorBase,
)

logger = logging.getLogger(__name__)

_POLL_INTERVAL = 2.0   # seconds
_SYSTEM_FSTYPES = frozenset({
    "sysfs", "proc", "devtmpfs", "devpts", "tmpfs", "cgroup",
    "cgroup2", "pstore", "bpf", "tracefs", "fusectl", "hugetlbfs",
    "mqueue", "debugfs", "securityfs", "efivarfs", "configfs",
    "squashfs", "overlay",
})
_SYSTEM_MOUNTPOINTS = frozenset({"/", "/proc", "/sys", "/dev", "/run", "/boot"})


def _is_system_partition(part: psutil.sdiskpart) -> bool:
    """Return True for virtual/system partitions that should not be monitored."""
    if part.fstype in _SYSTEM_FSTYPES:
        return True
    mountpoint = part.mountpoint
    if any(mountpoint == sp or mountpoint.startswith(sp + "/")
           for sp in _SYSTEM_MOUNTPOINTS):
        return True
    # Windows: filter out drive C (OS drive) heuristically
    if mountpoint.upper() in ("C:\\", "C:/"):
        return True
    return False


def _partition_to_identity(part: psutil.sdiskpart) -> DriveIdentity:
    """
    Build a DriveIdentity from a psutil.sdiskpart.
    UUID is not available via psutil -- returns fingerprint identity.
    Platform-specific UUID lookup is layered on top by _PollingDriveMonitor.
    """
    try:
        usage = psutil.disk_usage(part.mountpoint)
        capacity = usage.total
    except (OSError, PermissionError):
        capacity = 0

    label = Path(part.mountpoint).name or part.mountpoint
    # Device node last component as a pseudo-serial (better than nothing)
    pseudo_serial = Path(part.device).name if part.device else "unknown"

    return DriveIdentity.from_fingerprint(
        serial         = pseudo_serial,
        capacity_bytes = capacity,
        label          = label,
        mountpoint     = part.mountpoint,
        drive_type     = "unknown",
        filesystem     = part.fstype,
    )


class PollingDriveMonitor(DriveMonitorBase):
    """
    psutil-based polling drive monitor.

    Works on all platforms without any platform-specific libraries.
    UUID resolution is best-effort (fingerprint only from this class;
    actual UUID is resolved by the platform-specific wrapper if available).
    """

    def __init__(self) -> None:
        self._callback: Optional[Callable[[DriveEvent], None]] = None
        self._thread:   Optional[threading.Thread] = None
        self._stop_evt  = threading.Event()
        self._known:    dict[str, DriveIdentity] = {}   # mountpoint -> identity

    def is_available(self) -> bool:
        try:
            psutil.disk_partitions()
            return True
        except Exception:
            return False

    def list_drives(self) -> list[DriveIdentity]:
        partitions = psutil.disk_partitions(all=False)
        return [
            _partition_to_identity(p)
            for p in partitions
            if not _is_system_partition(p)
        ]

    def get_uuid(self, mountpoint: str) -> Optional[str]:
        # psutil cannot provide UUIDs -- return None (caller uses fingerprint)
        return None

    def start_monitoring(self, callback: Callable[[DriveEvent], None]) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._callback  = callback
        self._stop_evt.clear()
        # Snapshot current state
        self._known = {
            p.mountpoint: _partition_to_identity(p)
            for p in psutil.disk_partitions(all=False)
            if not _is_system_partition(p)
        }
        self._thread = threading.Thread(
            target=self._poll_loop,
            name="ghostdrive-drive-monitor",
            daemon=True,
        )
        self._thread.start()
        logger.debug("PollingDriveMonitor started (interval=%.1fs)", _POLL_INTERVAL)

    def stop_monitoring(self) -> None:
        self._stop_evt.set()
        if self._thread:
            self._thread.join(timeout=_POLL_INTERVAL + 1)
        self._thread = None
        logger.debug("PollingDriveMonitor stopped.")

    def _poll_loop(self) -> None:
        while not self._stop_evt.wait(_POLL_INTERVAL):
            try:
                self._check_partitions()
            except Exception as exc:
                logger.warning("PollingDriveMonitor poll error: %s", exc)

    def _check_partitions(self) -> None:
        current_parts = {
            p.mountpoint: p
            for p in psutil.disk_partitions(all=False)
            if not _is_system_partition(p)
        }
        current_mounts = set(current_parts.keys())
        known_mounts   = set(self._known.keys())

        # Newly connected
        for mountpoint in current_mounts - known_mounts:
            identity = _partition_to_identity(current_parts[mountpoint])
            self._known[mountpoint] = identity
            if self._callback:
                self._callback(DriveEvent(kind="connected", identity=identity))
            logger.info("Drive connected: %s (%s)", identity.label, mountpoint)

        # Disconnected
        for mountpoint in known_mounts - current_mounts:
            identity = self._known.pop(mountpoint)
            if self._callback:
                self._callback(DriveEvent(kind="disconnected", identity=identity))
            logger.info("Drive disconnected: %s (%s)", identity.label, mountpoint)
