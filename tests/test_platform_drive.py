"""
tests/test_platform_drive.py -- Unit tests for the platform drive monitor layer.
"""

from __future__ import annotations

import sys

from ghostdrive.platform.drive_monitor import DriveIdentity
from ghostdrive.platform import get_drive_monitor, get_screen_lock_monitor
from ghostdrive.platform._polling_fallback import PollingDriveMonitor


def test_drive_identity_from_uuid():
    identity = DriveIdentity.from_uuid(
        uuid="1234-ABCD",
        label="TestUSB",
        mountpoint="/media/testusb" if sys.platform != "win32" else "E:\\",
        capacity_bytes=1024 * 1024 * 1024,
        drive_type="ssd",
        filesystem="exfat",
        serial="SN12345",
    )
    assert identity.identity_key == "uuid:1234-ABCD"
    assert identity.drive_uuid == "1234-ABCD"
    assert identity.drive_serial == "SN12345"
    assert identity.drive_type == "ssd"
    assert identity.capacity_bytes == 1024 * 1024 * 1024


def test_drive_identity_from_fingerprint():
    identity = DriveIdentity.from_fingerprint(
        serial="SN12345",
        capacity_bytes=512 * 1024 * 1024,
        label="TestFAT",
        mountpoint="/media/testfat" if sys.platform != "win32" else "F:\\",
        drive_type="hdd",
        filesystem="vfat",
    )
    assert identity.identity_key == "fingerprint:SN12345:536870912"
    assert identity.drive_uuid is None
    assert identity.drive_serial == "SN12345"
    assert identity.drive_type == "hdd"
    assert identity.capacity_bytes == 512 * 1024 * 1024


def test_get_drive_monitor_returns_available():
    monitor = get_drive_monitor()
    assert monitor is not None
    assert monitor.is_available() is True


def test_polling_fallback_drive_list():
    # Polling drive monitor should work and return a list of drive identities on all platforms
    monitor = PollingDriveMonitor()
    assert monitor.is_available() is True
    drives = monitor.list_drives()
    assert isinstance(drives, list)
    # Each item in the list must be a DriveIdentity
    for drive in drives:
        assert isinstance(drive, DriveIdentity)
        assert drive.identity_key.startswith(("uuid:", "fingerprint:"))
        assert drive.capacity_bytes > 0


def test_get_screen_lock_monitor():
    monitor = get_screen_lock_monitor()
    assert monitor is not None
    # Just verify we can call is_available without crashing
    assert isinstance(monitor.is_available(), bool)
