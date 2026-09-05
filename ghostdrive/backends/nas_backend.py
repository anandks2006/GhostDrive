"""
nas_backend.py -- NAS (SFTP/SMB) backend plugin for GhostDrive.
"""

from __future__ import annotations

import io
import time
import logging
import asyncio
from pathlib import Path
from typing import AsyncGenerator, Optional

from ghostdrive.backends.base import BackendBase, HealthResult
from ghostdrive.exceptions import (
    BackendError,
    BackendConnectionError,
    BackendNotFoundError,
    BackendAuthError,
)

logger = logging.getLogger(__name__)

# Gracefully import paramiko
try:
    import paramiko  # type: ignore
    _PARAMIKO_AVAILABLE = True
except ImportError:
    _PARAMIKO_AVAILABLE = False

# Gracefully import smbprotocol / smbclient
try:
    import smbclient  # type: ignore
    _SMB_AVAILABLE = True
except ImportError:
    _SMB_AVAILABLE = False



class NASBackend(BackendBase):
    """
    NAS Backend plugin supporting both SFTP (via Paramiko) and SMB/CIFS (via smbprotocol).
    Protocol is selected via the 'protocol' parameter ('sftp' or 'smb').
    """

    # ── Capability flags (Spec 6.1) ─────────────────────────────────────────
    supports_range_requests: bool = True
    supports_streaming:      bool = True
    supports_deletion:       bool = True
    is_cold_storage:         bool = False
    tier:                    str  = "IMPORTANT"

    def __init__(
        self,
        protocol: str,  # "sftp" | "smb"
        host: str,
        port: Optional[int] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        private_key_path: Optional[str] = None,
        share: Optional[str] = None,       # SMB share name
        remote_dir: str = "GhostDriveData",
        credentials_ref: Optional[str] = None,
    ) -> None:
        self.protocol = protocol.lower()
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.private_key_path = private_key_path
        self.share = share
        self.remote_dir = remote_dir

        if self.protocol not in ("sftp", "smb"):
            raise ValueError(f"Unsupported NAS protocol: {protocol}. Supported: 'sftp', 'smb'")

        if self.protocol == "sftp" and not _PARAMIKO_AVAILABLE:
            raise ImportError("paramiko is required for SFTP NAS backend. Install it or add to Poetry.")
        if self.protocol == "smb" and not _SMB_AVAILABLE:
            raise ImportError("smbprotocol is required for SMB NAS backend. Install it or add to Poetry.")

        # Load credentials from credential_store if credentials_ref is specified
        if credentials_ref:
            try:
                from ghostdrive.crypto.credential_store import credential_store
                cred_str = credential_store.load(credentials_ref)
            except Exception:
                cred_str = None
            if cred_str:
                # Expected format: "password" or "password|private_key_path"
                if "|" in cred_str:
                    parts = cred_str.split("|", 1)
                    if not self.password:
                        self.password = parts[0]
                    if not self.private_key_path:
                        self.private_key_path = parts[1]
                else:
                    if not self.password:
                        self.password = cred_str

        # Host and username are mandatory
        if not self.host:
            raise ValueError("NAS backend requires a host address.")
        if not self.username:
            raise ValueError("NAS backend requires a username.")

        # SMB requires share name
        if self.protocol == "smb" and not self.share:
            raise ValueError("SMB protocol requires a share name.")

        self._ssh_client: Optional[paramiko.SSHClient] = None
        self._sftp_client: Optional[paramiko.SFTPClient] = None
        self._smb_session_registered = False

    # ── Connection Management ──

    async def connect(self) -> None:
        """Establish connection in a background thread to prevent event loop blocking."""
        if self.protocol == "sftp":
            await asyncio.to_thread(self._connect_sftp)
        elif self.protocol == "smb":
            await asyncio.to_thread(self._connect_smb)

    def _connect_sftp(self) -> None:
        try:
            self._ssh_client = paramiko.SSHClient()
            try:
                self._ssh_client.load_system_host_keys()
            except Exception:
                pass
            self._ssh_client.set_missing_host_key_policy(paramiko.RejectPolicy())
            
            pkey = None
            if self.private_key_path:
                key_path = Path(self.private_key_path).expanduser()
                if key_path.exists():
                    # Try loading private key (RSA / Ed25519)
                    for key_class in (paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey):
                        try:
                            pkey = key_class.from_private_key_file(str(key_path), password=self.password)
                            break
                        except Exception:
                            continue

            port = self.port or 22
            logger.info("Connecting to SFTP NAS: %s:%d", self.host, port)
            self._ssh_client.connect(
                hostname=self.host,
                port=port,
                username=self.username,
                password=self.password if not pkey else None,
                pkey=pkey,
                timeout=10,
            )
            self._sftp_client = self._ssh_client.open_sftp()
            
            # Ensure remote directory exists
            try:
                self._sftp_client.mkdir(self.remote_dir)
            except OSError:
                pass  # Directory already exists or permission denied (checked on write)

        except paramiko.AuthenticationException as exc:
            raise BackendAuthError(f"SFTP Authentication failed: {exc}")
        except Exception as exc:
            raise BackendConnectionError(f"SFTP connection failed: {exc}")

    def _connect_smb(self) -> None:
        try:
            logger.info("Connecting to SMB NAS share: \\\\%s\\%s", self.host, self.share)
            # Register session with smbclient
            smbclient.register_session(
                server=self.host,
                username=self.username,
                password=self.password,
                port=self.port or 445,
            )
            self._smb_session_registered = True

            # Ensure remote directory exists
            smb_dir = f"\\\\{self.host}\\{self.share}\\{self.remote_dir}"
            try:
                smbclient.mkdir(smb_dir)
            except Exception:
                pass  # Directory already exists
        except Exception as exc:
            raise BackendConnectionError(f"SMB connection failed: {exc}")

    async def disconnect(self) -> None:
        await asyncio.to_thread(self._disconnect)

    def _disconnect(self) -> None:
        if self._sftp_client:
            self._sftp_client.close()
            self._sftp_client = None
        if self._ssh_client:
            self._ssh_client.close()
            self._ssh_client = None
        if self._smb_session_registered and _SMB_AVAILABLE:
            try:
                smbclient.delete_session(self.host)
            except Exception:
                pass
            self._smb_session_registered = False
        logger.debug("NAS Backend disconnected.")

    # ── BAL Interface ──

    async def upload(
        self,
        stream: AsyncGenerator[bytes, None],
        chunk_id: str,
        sub_block_index: int,
    ) -> str:
        # Collect stream to memory buffer (NAS sub-blocks are fast, fits comfortably in memory)
        buf = io.BytesIO()
        async for block in stream:
            buf.write(block)
        data = buf.getvalue()

        filename = f"{chunk_id}_{sub_block_index:04d}.gdc"

        if self.protocol == "sftp":
            remote_path = f"{self.remote_dir}/{filename}"
            await asyncio.to_thread(self._upload_sftp, data, remote_path)
            return f"sftp:{remote_path}"
        
        elif self.protocol == "smb":
            remote_path = f"\\\\{self.host}\\{self.share}\\{self.remote_dir}\\{filename}"
            await asyncio.to_thread(self._upload_smb, data, remote_path)
            return f"smb://{self.host}/{self.share}/{self.remote_dir}/{filename}"
        
        raise BackendError("Protocol mismatch.")

    def _upload_sftp(self, data: bytes, remote_path: str) -> None:
        if not self._sftp_client:
            raise BackendConnectionError("SFTP is not connected.")
        try:
            with self._sftp_client.open(remote_path, "wb") as f:
                f.write(data)
                f.flush()
        except Exception as exc:
            raise BackendConnectionError(f"SFTP write failed: {exc}")

    def _upload_smb(self, data: bytes, remote_path: str) -> None:
        if not self._smb_session_registered:
            raise BackendConnectionError("SMB is not connected.")
        try:
            with smbclient.open_file(remote_path, mode="wb") as f:
                f.write(data)
        except Exception as exc:
            raise BackendConnectionError(f"SMB write failed: {exc}")

    async def download(self, reference_id: str) -> AsyncGenerator[bytes, None]:
        if self.protocol == "sftp":
            if not reference_id.startswith("sftp:"):
                raise ValueError(f"Invalid reference ID for SFTP download: {reference_id}")
            remote_path = reference_id.split("sftp:", 1)[1]
            data = await asyncio.to_thread(self._download_sftp, remote_path)
        elif self.protocol == "smb":
            if not reference_id.startswith("smb://"):
                raise ValueError(f"Invalid reference ID for SMB download: {reference_id}")
            # Map smb://host/share/path -> \\host\share\path
            path_part = reference_id.split("smb://", 1)[1]
            remote_path = "\\\\" + path_part.replace("/", "\\")
            data = await asyncio.to_thread(self._download_smb, remote_path)
        else:
            raise BackendError("Protocol mismatch.")

        yield data

    def _download_sftp(self, remote_path: str) -> bytes:
        if not self._sftp_client:
            raise BackendConnectionError("SFTP is not connected.")
        try:
            with self._sftp_client.open(remote_path, "rb") as f:
                return f.read()
        except IOError as exc:
            if "no such file" in str(exc).lower() or exc.errno == 2:
                raise BackendNotFoundError(f"SFTP file not found: {remote_path}")
            raise BackendConnectionError(f"SFTP read failed: {exc}")
        except Exception as exc:
            raise BackendConnectionError(f"SFTP download failed: {exc}")

    def _download_smb(self, remote_path: str) -> bytes:
        if not self._smb_session_registered:
            raise BackendConnectionError("SMB is not connected.")
        try:
            with smbclient.open_file(remote_path, mode="rb") as f:
                return f.read()
        except Exception as exc:
            # Check for file not found
            if "STATUS_OBJECT_NAME_NOT_FOUND" in str(exc):
                raise BackendNotFoundError(f"SMB file not found: {remote_path}")
            raise BackendConnectionError(f"SMB download failed: {exc}")

    async def delete(self, reference_id: str) -> bool:
        if self.protocol == "sftp":
            if not reference_id.startswith("sftp:"):
                return False
            remote_path = reference_id.split("sftp:", 1)[1]
            return await asyncio.to_thread(self._delete_sftp, remote_path)
        elif self.protocol == "smb":
            if not reference_id.startswith("smb://"):
                return False
            path_part = reference_id.split("smb://", 1)[1]
            remote_path = "\\\\" + path_part.replace("/", "\\")
            return await asyncio.to_thread(self._delete_smb, remote_path)
        return False

    def _delete_sftp(self, remote_path: str) -> bool:
        if not self._sftp_client:
            raise BackendConnectionError("SFTP is not connected.")
        try:
            self._sftp_client.remove(remote_path)
            logger.info("SFTP removed chunk file: %s", remote_path)
            return True
        except IOError as exc:
            if exc.errno == 2:  # File not found
                return False
            raise BackendError(f"SFTP delete failed: {exc}")
        except Exception as exc:
            raise BackendError(f"SFTP delete failed: {exc}")

    def _delete_smb(self, remote_path: str) -> bool:
        if not self._smb_session_registered:
            raise BackendConnectionError("SMB is not connected.")
        try:
            smbclient.remove(remote_path)
            logger.info("SMB removed chunk file: %s", remote_path)
            return True
        except Exception as exc:
            if "STATUS_OBJECT_NAME_NOT_FOUND" in str(exc):
                return False
            raise BackendError(f"SMB delete failed: {exc}")

    async def health_check(self) -> HealthResult:
        if self.protocol == "sftp":
            if not self._sftp_client:
                return HealthResult(reachable=False, error="SFTP is not connected")
            return await asyncio.to_thread(self._health_check_sftp)
        elif self.protocol == "smb":
            if not self._smb_session_registered:
                return HealthResult(reachable=False, error="SMB is not connected")
            return await asyncio.to_thread(self._health_check_smb)
        return HealthResult(reachable=False, error="Invalid protocol")

    def _health_check_sftp(self) -> HealthResult:
        try:
            t0 = time.perf_counter()
            try:
                # Perform a light statvfs to check connectivity and space
                stat = self._sftp_client.statvfs(self.remote_dir)
                latency_ms = (time.perf_counter() - t0) * 1000
                free_bytes = stat.f_frsize * stat.f_bavail
                return HealthResult(reachable=True, quota_remaining=free_bytes, latency_ms=latency_ms)
            except Exception:
                # Fallback: check connectivity by listing directory (e.g. servers lacking OpenSSH extension)
                self._sftp_client.listdir(self.remote_dir)
                latency_ms = (time.perf_counter() - t0) * 1000
                return HealthResult(reachable=True, quota_remaining=100 * 1024 * 1024 * 1024, latency_ms=latency_ms)
        except Exception as exc:
            return HealthResult(reachable=False, error=str(exc))

    def _health_check_smb(self) -> HealthResult:
        try:
            t0 = time.perf_counter()
            smb_dir = f"\\\\{self.host}\\{self.share}\\{self.remote_dir}"
            usage = smbclient.shutil.disk_usage(smb_dir)
            latency_ms = (time.perf_counter() - t0) * 1000

            return HealthResult(reachable=True, quota_remaining=usage.free, latency_ms=latency_ms)
        except Exception as exc:
            return HealthResult(reachable=False, error=str(exc))

    async def available_space(self) -> int:
        res = await self.health_check()
        return res.quota_remaining if res.reachable and res.quota_remaining is not None else 0
