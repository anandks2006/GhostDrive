"""
local_fs_backend.py -- Local filesystem backend plugin for GhostDrive.
"""

from __future__ import annotations

import os
import time
import shutil
import logging
import uuid
from pathlib import Path
from typing import AsyncGenerator, Optional

import aiofiles

from ghostdrive.backends.base import BackendBase, HealthResult
from ghostdrive.exceptions import (
    BackendError,
    BackendConnectionError,
    BackendNotFoundError,
    BackendQuotaError,
)

logger = logging.getLogger(__name__)


class LocalFSBackend(BackendBase):
    """
    Local filesystem backend plugin.
    Stores chunk sub-blocks as files under a configured root directory.
    """

    # ── Capability flags (Spec 6.1) ─────────────────────────────────────────
    supports_range_requests: bool = True
    supports_streaming:      bool = True
    supports_deletion:       bool = True
    is_cold_storage:         bool = False
    tier:                    str  = "IMPORTANT"

    def _secure_and_hide_path(self, path: Path, is_dir: bool = False) -> None:
        """
        Mark a file or directory as hidden (cross-platform) and lock down permissions.
        - On Windows: Combines HIDDEN (2) and SYSTEM (4) to create a Protected OS File.
        - On macOS/Linux: Uses dot-prefixing for files. On macOS, applies chflags hidden on directories.
        - Permissions: Locks down directory to 0o700 (owner-only access).
        """
        try:
            import sys
            # 1. Access control lockdown: owner-only read/write/execute
            if is_dir:
                try:
                    os.chmod(path, 0o700)
                except Exception as exc:
                    logger.debug("Failed to set directory permissions to 0o700 on %s: %s", path, exc)

            # 2. Windows System/Hidden attribute
            if os.name == "nt":
                import ctypes
                # 2 (hidden) + 4 (system) = 6
                ctypes.windll.kernel32.SetFileAttributesW(str(path), 6)

            # 3. macOS Finder hidden flag
            elif sys.platform == "darwin" and is_dir:
                import subprocess
                subprocess.run(["chflags", "hidden", str(path)], check=False, capture_output=True)

        except Exception as exc:
            logger.debug("Failed to secure and hide path %s: %s", path, exc)

    def __init__(
        self,
        root_path: Optional[Path | str] = None,
        credentials_ref: Optional[str] = None,
    ) -> None:
        self.root_path: Optional[Path] = None

        if root_path:
            self.root_path = Path(root_path)
        elif credentials_ref:
            try:
                from ghostdrive.crypto.credential_store import credential_store
                path_str = credential_store.load(credentials_ref)
            except Exception:
                path_str = None
            if path_str:
                self.root_path = Path(path_str)

        # Fallback: if credentials_ref itself is a path-like string
        if not self.root_path and credentials_ref:
            self.root_path = Path(credentials_ref)

        if not self.root_path:
            raise ValueError("LocalFSBackend requires a root_path or a valid credentials_ref in keyring.")

        # Ensure the root directory exists and is secured
        try:
            self.root_path.mkdir(parents=True, exist_ok=True)
            self._secure_and_hide_path(self.root_path, is_dir=True)
        except Exception as exc:
            logger.error("Failed to create root directory %s: %s", self.root_path, exc)

    async def upload(
        self,
        stream: AsyncGenerator[bytes, None],
        chunk_id: str,
        sub_block_index: int,
    ) -> str:
        if not self.root_path:
            raise BackendError("Backend root path is not configured.")

        # Prefix filename with a dot to make it hidden on macOS/Linux
        filename = f".{chunk_id}_{sub_block_index:04d}.gdc"
        target_path = self.root_path / filename

        # Ensure parent directory exists
        target_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            # Check available space before writing
            await self.available_space()
            # If free space is less than some reasonable threshold, raise quota error
            # But standard streaming will raise OSError on disk full anyway.
            
            async with aiofiles.open(target_path, "wb") as f:
                async for block in stream:
                    await f.write(block)
                await f.flush()
                # fsync to guarantee durability
                os.fsync(f.fileno())

            # Apply OS-level hidden attributes
            self._secure_and_hide_path(target_path, is_dir=False)

            relative_path = target_path.relative_to(self.root_path)
            logger.info("LocalFS upload OK: chunk=%s sub_block=%d path=%s", chunk_id[:8], sub_block_index, relative_path)
            return f"local:{relative_path.as_posix()}"

        except OSError as exc:
            # Disk full or permission error
            if exc.errno == 28: # ENOSPC (No space left on device)
                raise BackendQuotaError(f"Local storage quota exhausted (disk full): {exc}")
            raise BackendConnectionError(f"Local write failed: {exc}")
        except Exception as exc:
            raise BackendError(f"Failed to upload to local filesystem: {exc}")

    async def download(self, reference_id: str) -> AsyncGenerator[bytes, None]:
        if not self.root_path:
            raise BackendError("Backend root path is not configured.")

        if not reference_id.startswith("local:"):
            raise ValueError(f"Invalid reference ID format for LocalFS: {reference_id}")

        rel_path_str = reference_id.split("local:", 1)[1]
        target_path = self.root_path / rel_path_str

        if not target_path.exists() or not target_path.is_file():
            raise BackendNotFoundError(f"Local chunk file not found: {target_path}")

        try:
            async with aiofiles.open(target_path, "rb") as f:
                while True:
                    block = await f.read(65536)  # 64 KB blocks
                    if not block:
                        break
                    yield block
        except OSError as exc:
            raise BackendConnectionError(f"Local read failed: {exc}")
        except Exception as exc:
            raise BackendError(f"Failed to download from local filesystem: {exc}")

    async def delete(self, reference_id: str) -> bool:
        if not self.root_path:
            raise BackendError("Backend root path is not configured.")

        if not reference_id.startswith("local:"):
            return False

        rel_path_str = reference_id.split("local:", 1)[1]
        target_path = self.root_path / rel_path_str

        if target_path.exists() and target_path.is_file():
            try:
                target_path.unlink()
                logger.info("LocalFS deleted chunk: %s", rel_path_str)
                return True
            except Exception as exc:
                logger.error("Failed to delete local chunk %s: %s", target_path, exc)
                raise BackendError(f"Failed to delete local chunk: {exc}")
        return False

    async def health_check(self) -> HealthResult:
        if not self.root_path or not self.root_path.exists():
            return HealthResult(reachable=False, error="Root directory does not exist")

        try:
            t0 = time.perf_counter()
            # Test write/delete latency
            test_file = self.root_path / f".health_check_{uuid.uuid4()}"
            async with aiofiles.open(test_file, "w") as f:
                await f.write("health")
            test_file.unlink()
            latency_ms = (time.perf_counter() - t0) * 1000

            free_bytes = await self.available_space()
            return HealthResult(reachable=True, quota_remaining=free_bytes, latency_ms=latency_ms)
        except Exception as exc:
            return HealthResult(reachable=False, error=str(exc))

    async def available_space(self) -> int:
        if not self.root_path or not self.root_path.exists():
            return 0
        try:
            usage = shutil.disk_usage(self.root_path)
            return usage.free
        except Exception as exc:
            logger.warning("Failed to query disk usage for %s: %s", self.root_path, exc)
            return 0
