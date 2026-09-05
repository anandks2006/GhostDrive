"""
drive_monitor.py -- Cross-platform drive identity and connect/disconnect events.

Abstract base classes only. Platform implementations live in:
  ghostdrive/platform/windows/drive_monitor.py
  ghostdrive/platform/linux/drive_monitor.py
  ghostdrive/platform/macos/drive_monitor.py
  ghostdrive/platform/_polling_fallback.py  (psutil, works everywhere)

Identity contract
-----------------
Drive identity is always the filesystem UUID (or serial+capacity fingerprint
when UUID is unavailable). It is NEVER a mount path, drive letter, or device
node -- these change across reboots and OS reinstalls.

backend_identity column format:
  "uuid:<filesystem-uuid>"          -- preferred
  "fingerprint:<serial>:<capacity>" -- fallback for FAT32 drives without UUID
"""

from __future__ import annotations

import dataclasses
from abc import ABC, abstractmethod
from typing import Callable, Optional


# ── Drive identity ─────────────────────────────────────────────────────────────

@dataclasses.dataclass
class DriveIdentity:
    """
    Stable, reboot-persistent identity for a physical drive or NAS share.

    identity_key: use this as the canonical identifier everywhere.
        Format: "uuid:<filesystem-uuid>" or "fingerprint:<serial>:<capacity_bytes>"
    mountpoint: current OS mount path -- for display/hint ONLY.
        NEVER use as identity. Changes across reboots.
    drive_type: determined heuristically; may be "unknown" if detection fails.
    """
    identity_key:   str           # "uuid:<uuid>" or "fingerprint:<serial>:<cap>"
    drive_uuid:     Optional[str] # filesystem UUID; None if drive has no UUID
    drive_serial:   Optional[str] # hardware serial; None if elevation unavailable
    label:          str           # volume label or user-assigned label
    mountpoint:     str           # current mount path (hint only)
    capacity_bytes: int
    drive_type:     str           # "ssd" | "hdd" | "nas" | "unknown"
    filesystem:     str           # "ntfs" | "ext4" | "apfs" | "exfat" | etc.

    @classmethod
    def from_uuid(
        cls,
        uuid: str,
        label: str,
        mountpoint: str,
        capacity_bytes: int,
        drive_type: str = "unknown",
        filesystem: str = "unknown",
        serial: Optional[str] = None,
    ) -> "DriveIdentity":
        return cls(
            identity_key   = f"uuid:{uuid}",
            drive_uuid     = uuid,
            drive_serial   = serial,
            label          = label,
            mountpoint     = mountpoint,
            capacity_bytes = capacity_bytes,
            drive_type     = drive_type,
            filesystem     = filesystem,
        )

    @classmethod
    def from_fingerprint(
        cls,
        serial: str,
        capacity_bytes: int,
        label: str,
        mountpoint: str,
        drive_type: str = "unknown",
        filesystem: str = "unknown",
    ) -> "DriveIdentity":
        return cls(
            identity_key   = f"fingerprint:{serial}:{capacity_bytes}",
            drive_uuid     = None,
            drive_serial   = serial,
            label          = label,
            mountpoint     = mountpoint,
            capacity_bytes = capacity_bytes,
            drive_type     = drive_type,
            filesystem     = filesystem,
        )


# ── Drive events ──────────────────────────────────────────────────────────────

@dataclasses.dataclass
class DriveEvent:
    """
    Emitted by DriveMonitorBase when a drive connects or disconnects.

    kind: "connected" | "disconnected"
    identity: always populated for "connected" events.
              for "disconnected": identity_key is the key that was removed.
              Other fields may be None for disconnect events depending on platform.
    """
    kind:     str          # "connected" | "disconnected"
    identity: DriveIdentity


# ── Abstract base class ────────────────────────────────────────────────────────

class DriveMonitorBase(ABC):
    """
    Abstract cross-platform drive monitor.

    Usage::

        monitor = get_drive_monitor()
        if monitor.is_available():
            monitor.start_monitoring(lambda event: handle(event))
            drives = monitor.list_drives()
            uuid = monitor.get_uuid("/dev/sdb1")
            ...
            monitor.stop_monitoring()

    All methods must be safe to call from a background thread.
    Callbacks are invoked from the monitor's background thread --
    callers must dispatch to the UI thread if needed.
    """

    @abstractmethod
    def is_available(self) -> bool:
        """
        Return True if this monitor implementation is functional on this system.
        May return False if required libraries or system APIs are unavailable.
        Always check before calling any other method.
        """

    @abstractmethod
    def list_drives(self) -> list[DriveIdentity]:
        """
        Return all currently mounted drives (excluding virtual/system mounts).
        Raises DriveIdentityError if enumeration fails entirely.
        """

    @abstractmethod
    def get_uuid(self, mountpoint: str) -> Optional[str]:
        """
        Return the filesystem UUID for the given mountpoint.
        Returns None if the drive has no UUID (e.g., FAT32 without UUID).
        Raises DriveIdentityError if the mountpoint is invalid or inaccessible.
        """

    @abstractmethod
    def start_monitoring(self, callback: Callable[[DriveEvent], None]) -> None:
        """
        Start background monitoring for drive connect/disconnect events.
        Invokes callback from a background thread on each event.
        No-op if already monitoring.
        """

    @abstractmethod
    def stop_monitoring(self) -> None:
        """Stop background monitoring. No-op if not running."""


# ── Screen lock monitor ────────────────────────────────────────────────────────

class ScreenLockMonitorBase(ABC):
    """
    Abstract cross-platform screen lock / session idle detector.

    When screen locks or lid closes, GhostDrive should auto-lock its vault.
    Platform implementations use native OS APIs; the idle timer fallback
    applies when native detection is unavailable.

    Usage::

        monitor = get_screen_lock_monitor()
        monitor.start(on_lock=lambda: vault.lock())
        ...
        monitor.stop()
    """

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if this implementation can detect screen lock events."""

    @abstractmethod
    def start(self, on_lock: Callable[[], None]) -> None:
        """
        Start monitoring. Invokes on_lock() when screen locks.
        on_lock is called from a background thread.
        """

    @abstractmethod
    def stop(self) -> None:
        """Stop monitoring."""
