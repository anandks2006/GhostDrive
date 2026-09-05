"""
external_drive_backend.py -- External USB drive backend plugin for GhostDrive.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import AsyncGenerator

from ghostdrive.backends.local_fs_backend import LocalFSBackend
from ghostdrive.backends.base import HealthResult
from ghostdrive.exceptions import (
    BackendConnectionError,
)
from ghostdrive.platform import get_drive_monitor

logger = logging.getLogger(__name__)


class ExternalDriveBackend(LocalFSBackend):
    """
    External USB drive backend.
    Inherits I/O logic from LocalFSBackend, but dynamically resolves the root path
    by scanning connected drives for a registered filesystem UUID.
    This ensures it works even if the drive letter or mount path changes across mounts.
    """

    def __init__(
        self,
        drive_uuid: str,
        relative_root: str = ".GhostDriveData",
    ) -> None:
        """
        Args:
            drive_uuid:    Stable volume UUID of the external drive.
            relative_root: Relative directory on the drive to store chunk files.
        """
        self.drive_uuid = drive_uuid
        self.relative_root = relative_root
        
        # Resolve the root path immediately if the drive is connected
        self._resolve_root_path()

    def _resolve_root_path(self) -> bool:
        """
        Scan connected drives via the platform drive monitor.
        If a drive matches self.drive_uuid, dynamically update self.root_path.
        Returns True if resolved successfully.
        """
        try:
            monitor = get_drive_monitor()
            for drive in monitor.list_drives():
                if drive.drive_uuid == self.drive_uuid:
                    self.root_path = Path(drive.mountpoint) / self.relative_root
                    try:
                        self.root_path.mkdir(parents=True, exist_ok=True)
                        self._secure_and_hide_path(self.root_path, is_dir=True)
                    except Exception:
                        pass  # Might be read-only at this moment, handle during I/O
                    return True
        except Exception as exc:
            logger.debug("Failed to resolve external drive root path: %s", exc)
        
        self.root_path = None
        return False

    async def _resolve_root_path_async(self) -> bool:
        """Asynchronously resolve root path in a worker thread."""
        import asyncio
        return await asyncio.to_thread(self._resolve_root_path)

    def is_available(self) -> bool:
        """Return True if the registered external drive is currently connected and mounted."""
        return self._resolve_root_path()

    async def upload(
        self,
        stream: AsyncGenerator[bytes, None],
        chunk_id: str,
        sub_block_index: int,
    ) -> str:
        if not await self._resolve_root_path_async():
            raise BackendConnectionError(f"External drive with UUID {self.drive_uuid} is not connected.")
        return await super().upload(stream, chunk_id, sub_block_index)

    async def download(self, reference_id: str) -> AsyncGenerator[bytes, None]:
        if not await self._resolve_root_path_async():
            raise BackendConnectionError(f"External drive with UUID {self.drive_uuid} is not connected.")
        async for block in super().download(reference_id):
            yield block

    async def delete(self, reference_id: str) -> bool:
        if not await self._resolve_root_path_async():
            # If the drive is unplugged, we can't delete right now. Return False.
            logger.warning("External drive not connected. Skipping chunk delete: %s", reference_id)
            return False
        return await super().delete(reference_id)

    async def health_check(self) -> HealthResult:
        if not await self._resolve_root_path_async():
            return HealthResult(
                reachable=False,
                error="Drive not connected",
            )
        return await super().health_check()

    async def available_space(self) -> int:
        if not await self._resolve_root_path_async():
            return 0
        return await super().available_space()

