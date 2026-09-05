"""
tests/test_local_backends.py -- Unit tests for LocalFSBackend and ExternalDriveBackend.
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from ghostdrive.backends.local_fs_backend import LocalFSBackend
from ghostdrive.backends.external_drive_backend import ExternalDriveBackend
from ghostdrive.exceptions import (
    BackendConnectionError,
    BackendNotFoundError,
)
from ghostdrive.platform.drive_monitor import DriveIdentity


# --- LocalFSBackend Tests ---

@pytest.mark.asyncio
async def test_local_fs_backend_lifecycle(tmp_path):
    root = tmp_path / "local_backend_root"
    backend = LocalFSBackend(root_path=root)

    # Verify capability flags
    assert backend.supports_range_requests is True
    assert backend.supports_streaming is True
    assert backend.supports_deletion is True
    assert backend.tier == "IMPORTANT"

    # Test upload
    async def dummy_stream():
        yield b"chunk_data_block_1"
        yield b"chunk_data_block_2"

    ref_id = await backend.upload(dummy_stream(), "chunk-1", 0)
    assert ref_id.startswith("local:")
    
    # Target file should exist
    rel_path = ref_id.split("local:", 1)[1]
    target_file = root / rel_path
    assert target_file.exists()
    assert target_file.read_bytes() == b"chunk_data_block_1chunk_data_block_2"

    # Test download
    blocks = []
    async for block in backend.download(ref_id):
        blocks.append(block)
    assert b"".join(blocks) == b"chunk_data_block_1chunk_data_block_2"

    # Test health check
    health = await backend.health_check()
    assert health.reachable is True
    assert health.quota_remaining > 0
    assert health.latency_ms > 0

    # Test delete
    deleted = await backend.delete(ref_id)
    assert deleted is True
    assert not target_file.exists()

    # Deleting again should be idempotent and return False
    deleted_again = await backend.delete(ref_id)
    assert deleted_again is False


@pytest.mark.asyncio
async def test_local_fs_backend_not_found(tmp_path):
    root = tmp_path / "local_backend_root"
    backend = LocalFSBackend(root_path=root)

    with pytest.raises(BackendNotFoundError):
        async for _ in backend.download("local:nonexistent.gdc"):
            pass


# --- ExternalDriveBackend Tests ---

@pytest.mark.asyncio
async def test_external_drive_backend_lifecycle(tmp_path):
    drive_uuid = "usb-ssd-uuid-123"
    mount_dir = tmp_path / "mock_usb_mount"
    mount_dir.mkdir()

    # Mock DriveIdentity
    mock_drive = DriveIdentity.from_uuid(
        uuid=drive_uuid,
        label="My SSD",
        mountpoint=str(mount_dir),
        capacity_bytes=100_000_000,
        drive_type="ssd",
        filesystem="exfat",
    )

    # 1. Mock get_drive_monitor to return the connected drive
    mock_monitor = MagicMock()
    mock_monitor.list_drives.return_value = [mock_drive]

    with patch("ghostdrive.backends.external_drive_backend.get_drive_monitor", return_value=mock_monitor):
        backend = ExternalDriveBackend(drive_uuid=drive_uuid, relative_root="GhostDriveData")

        assert backend.is_available() is True
        assert backend.root_path == mount_dir / "GhostDriveData"

        # Upload check
        async def dummy_stream():
            yield b"external_chunk"

        ref_id = await backend.upload(dummy_stream(), "ext-chunk-1", 0)
        assert ref_id.startswith("local:")
        
        # Verify file written to mock mount folder
        target_file = mount_dir / "GhostDriveData" / ref_id.split("local:", 1)[1]
        assert target_file.exists()

        # Download check
        blocks = []
        async for block in backend.download(ref_id):
            blocks.append(block)
        assert b"".join(blocks) == b"external_chunk"

        # Health check check
        health = await backend.health_check()
        assert health.reachable is True
        assert health.quota_remaining > 0

        # Available space check
        space = await backend.available_space()
        assert space > 0

    # 2. Simulate unplugging the drive (monitor returns empty list)
    mock_monitor.list_drives.return_value = []

    with patch("ghostdrive.backends.external_drive_backend.get_drive_monitor", return_value=mock_monitor):
        # Resolve path should fail now
        assert backend.is_available() is False
        assert backend.root_path is None

        # Health check should return unreachable gracefully
        health = await backend.health_check()
        assert health.reachable is False
        assert health.error == "Drive not connected"

        # Space should return 0
        assert await backend.available_space() == 0

        # Upload and download should raise BackendConnectionError
        async def dummy_stream():
            yield b"error"
        with pytest.raises(BackendConnectionError, match="not connected"):
            await backend.upload(dummy_stream(), "ext-chunk-2", 0)

        with pytest.raises(BackendConnectionError, match="not connected"):
            async for _ in backend.download(ref_id):
                pass

        # Delete should return False and not crash
        deleted = await backend.delete(ref_id)
        assert deleted is False
