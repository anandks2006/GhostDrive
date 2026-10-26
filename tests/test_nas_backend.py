"""
tests/test_nas_backend.py -- Unit tests for NASBackend (SFTP and SMB protocols).
"""

from __future__ import annotations

from unittest.mock import MagicMock

# Mock paramiko, smbclient, and smbprotocol in sys.modules to allow testing
# without requiring the actual external libraries to be installed.
mock_paramiko = MagicMock()

import sys  # noqa: E402

sys.modules.setdefault('paramiko', mock_paramiko)
sys.modules.setdefault('smbclient', MagicMock())
sys.modules.setdefault('smbprotocol', MagicMock())

# Now we can safely import NASBackend
from ghostdrive.backends import nas_backend as _nas_module  # noqa: E402
from ghostdrive.backends.nas_backend import NASBackend  # noqa: E402
import pytest  # noqa: E402

mock_smbclient = MagicMock()


@pytest.fixture(autouse=True)
def _patch_nas_dependencies(monkeypatch):
    """
    NASBackend binds paramiko/smbclient at import time, so in a full-suite run
    an earlier test may have already imported the real libraries (the
    sys.modules mocks above then have no effect). Patch the module's own
    references so these tests are hermetic regardless of import order.
    """
    mock_paramiko.reset_mock()
    mock_smbclient.reset_mock()
    monkeypatch.setattr(_nas_module, "paramiko", mock_paramiko, raising=False)
    monkeypatch.setattr(_nas_module, "smbclient", mock_smbclient, raising=False)
    monkeypatch.setattr(_nas_module, "_PARAMIKO_AVAILABLE", True, raising=False)
    monkeypatch.setattr(_nas_module, "_SMB_AVAILABLE", True, raising=False)


# --- SFTP Protocol Tests ---

@pytest.mark.asyncio
async def test_sftp_backend_upload_download_lifecycle():
    host = "192.168.1.100"
    username = "nas_user"
    password = "secret_password"
    remote_dir = "GhostDriveData"

    # Reset mock
    mock_paramiko.reset_mock()

    # Mock SSH and SFTP clients
    mock_sftp = MagicMock()
    mock_ssh = MagicMock()
    mock_ssh.open_sftp.return_value = mock_sftp
    mock_paramiko.SSHClient.return_value = mock_ssh
    
    # Mock open_sftp file object
    mock_file = MagicMock()
    mock_sftp.open.return_value.__enter__.return_value = mock_file

    # Mock statvfs
    mock_stat = MagicMock()
    mock_stat.f_frsize = 4096
    mock_stat.f_bavail = 100_000
    mock_sftp.statvfs.return_value = mock_stat

    backend = NASBackend(
        protocol="sftp",
        host=host,
        username=username,
        password=password,
        remote_dir=remote_dir,
    )

    # 1. Connect
    await backend.connect()
    mock_ssh.connect.assert_called_once_with(
        hostname=host,
        port=22,
        username=username,
        password=password,
        pkey=None,
        timeout=10,
    )
    mock_ssh.open_sftp.assert_called_once()
    mock_sftp.mkdir.assert_called_once_with(remote_dir)

    # 2. Upload
    async def dummy_stream():
        yield b"sftp_chunk_bytes"

    ref_id = await backend.upload(dummy_stream(), "chunk-sftp", 0)
    assert ref_id == f"sftp:{remote_dir}/chunk-sftp_0000.gdc"
    mock_sftp.open.assert_called_once_with(f"{remote_dir}/chunk-sftp_0000.gdc", "wb")
    mock_file.write.assert_called_once_with(b"sftp_chunk_bytes")

    # 3. Download
    # Mock download open file
    mock_read_file = MagicMock()
    mock_read_file.read.return_value = b"sftp_chunk_bytes"
    mock_sftp.open.return_value.__enter__.return_value = mock_read_file

    blocks = []
    async for block in backend.download(ref_id):
        blocks.append(block)
    assert b"".join(blocks) == b"sftp_chunk_bytes"

    # 4. Health check
    health = await backend.health_check()
    assert health.reachable is True
    assert health.quota_remaining == 4096 * 100_000

    # 5. Delete
    await backend.delete(ref_id)
    mock_sftp.remove.assert_called_once_with(f"{remote_dir}/chunk-sftp_0000.gdc")

    # 6. Disconnect
    await backend.disconnect()
    mock_sftp.close.assert_called_once()
    mock_ssh.close.assert_called_once()


# --- SMB Protocol Tests ---

@pytest.mark.asyncio
async def test_smb_backend_upload_download_lifecycle():
    host = "192.168.1.200"
    username = "nas_user"
    password = "secret_password"
    share = "backups"
    remote_dir = "GhostDriveData"

    # Reset mock
    mock_smbclient.reset_mock()

    # Mock disk usage
    mock_usage = MagicMock()
    mock_usage.free = 500_000_000
    mock_smbclient.shutil.disk_usage.return_value = mock_usage

    # Mock file write
    mock_file = MagicMock()
    mock_smbclient.open_file.return_value.__enter__.return_value = mock_file

    backend = NASBackend(
        protocol="smb",
        host=host,
        username=username,
        password=password,
        share=share,
        remote_dir=remote_dir,
    )

    # 1. Connect
    await backend.connect()
    mock_smbclient.register_session.assert_called_once_with(
        server=host,
        username=username,
        password=password,
        port=445,
    )
    mock_smbclient.mkdir.assert_called_once_with(f"\\\\{host}\\{share}\\{remote_dir}")

    # 2. Upload
    async def dummy_stream():
        yield b"smb_chunk_bytes"

    ref_id = await backend.upload(dummy_stream(), "chunk-smb", 0)
    assert ref_id == f"smb://{host}/{share}/{remote_dir}/chunk-smb_0000.gdc"
    mock_smbclient.open_file.assert_called_once_with(f"\\\\{host}\\{share}\\{remote_dir}\\chunk-smb_0000.gdc", mode="wb")
    mock_file.write.assert_called_once_with(b"smb_chunk_bytes")

    # 3. Download
    # Mock download read
    mock_read_file = MagicMock()
    mock_read_file.read.return_value = b"smb_chunk_bytes"
    mock_smbclient.open_file.return_value.__enter__.return_value = mock_read_file

    blocks = []
    async for block in backend.download(ref_id):
        blocks.append(block)
    assert b"".join(blocks) == b"smb_chunk_bytes"

    # 4. Health check
    health = await backend.health_check()
    assert health.reachable is True
    assert health.quota_remaining == 500_000_000

    # 5. Delete
    await backend.delete(ref_id)
    mock_smbclient.remove.assert_called_once_with(f"\\\\{host}\\{share}\\{remote_dir}\\chunk-smb_0000.gdc")

    # 6. Disconnect
    await backend.disconnect()
    mock_smbclient.delete_session.assert_called_once_with(host)
