"""
base.py -- Backend Abstraction Layer (BAL) interface.
"""

from __future__ import annotations

import dataclasses
from abc import ABC, abstractmethod
from typing import AsyncGenerator, Optional


@dataclasses.dataclass
class HealthResult:
    """
    Result of a backend health_check() call.

    Attributes:
        reachable:       True if the backend API responded successfully.
        quota_remaining: Remaining free bytes (after subtracting quota_reserved).
                         None if the backend does not report quotas.
        error:           Human-readable error message if not reachable.
        latency_ms:      Round-trip time of the health check in milliseconds.
    """
    reachable:       bool
    quota_remaining: Optional[int] = None
    error:           Optional[str]  = None
    latency_ms:      Optional[float] = None


class BackendBase(ABC):
    """
    Abstract base class for all GhostDrive backend plugins.
    """

    def __init_subclass__(cls, **kwargs) -> None:
        super().__init_subclass__(**kwargs)
        
        # Wrap upload method if defined in the subclass
        if "upload" in cls.__dict__:
            orig_upload = cls.upload
            async def wrapped_upload(self, stream, chunk_id, sub_block_index):
                from ghostdrive.utils.bandwidth_throttle import UPLOAD_LIMITER, throttle_generator
                throttled = throttle_generator(stream, UPLOAD_LIMITER)
                return await orig_upload(self, throttled, chunk_id, sub_block_index)
            cls.upload = wrapped_upload

        # Wrap download method if defined in the subclass
        if "download" in cls.__dict__:
            orig_download = cls.download
            def wrapped_download(self, reference_id):
                from ghostdrive.utils.bandwidth_throttle import DOWNLOAD_LIMITER, throttle_generator
                gen = orig_download(self, reference_id)
                return throttle_generator(gen, DOWNLOAD_LIMITER)
            cls.download = wrapped_download

    supports_range_requests: bool = False
    supports_streaming:      bool = True
    supports_deletion:       bool = True
    is_cold_storage:         bool = False
    is_ephemeral_url:        bool = False
    ml_artifacts_only:       bool = False
    cpu_intensive:           bool = False

    # WORM (write-once, read-many) / append-only marker. Like the flags above
    # this is a STATIC capability marker: plugin types that can operate
    # append-only set it True. The live per-backend toggle is the
    # backends.append_only DB column (default 0); the delete paths consult the
    # DB row via services/files.py (worm_backend_ids / assert_backend_writable),
    # not this class attribute, because only the DB knows which instance was
    # flagged. Enforcement is application-level, not hardware WORM.
    append_only:             bool = False

    tier: str = "IMPORTANT"

    logical_chunk_bytes: int = 50 * 1024 * 1024
    sub_block_bytes:     int = 50 * 1024 * 1024

    async def connect(self) -> None:
        """
        Establish connection to the backend.
        Default implementation is a no-op.
        """
        pass

    @abstractmethod
    async def upload(
        self,
        stream: AsyncGenerator[bytes, None],
        chunk_id: str,
        sub_block_index: int,
    ) -> str:
        """
        Upload one sub-block from an async bytes generator.

        The caller has already:
          1. Decremented quota_reserved atomically.
          2. Written a pending intent to chunk_locations and fsynced.

        Args:
            stream:          Async generator yielding encrypted bytes.
            chunk_id:        UUIDv4 chunk identifier (for naming/logging).
            sub_block_index: 0-based index of this sub-block within the chunk.

        Returns:
            reference_id: Opaque string the backend uses to locate this
                          sub-block on download (e.g. message_id for Telegram,
                          channel message reference for Discord).

        Raises:
            BackendConnectionError: Network unreachable.
            BackendAuthError:       Credentials invalid/expired.
            BackendRateLimitError:  Rate limited -- caller retries with backoff.
            BackendQuotaError:      Storage quota exhausted.
        """

    @abstractmethod
    async def download(self, reference_id: str) -> AsyncGenerator[bytes, None]:
        """
        Download a sub-block and yield raw bytes.

        For is_ephemeral_url backends (Discord): fetches a fresh CDN URL
        via the API before starting the download. Never yields bytes from
        a stale URL -- raises BackendEphemeralURLError and the caller
        retries from another backend.

        Args:
            reference_id: The reference_id returned by upload().

        Yields:
            Raw encrypted bytes (as uploaded -- do NOT decrypt here).

        Raises:
            BackendNotFoundError:     Sub-block not found (404 equivalent).
            BackendEphemeralURLError: CDN URL expired (Discord only).
            BackendConnectionError:   Network unreachable.
        """

    @abstractmethod
    async def delete(self, reference_id: str) -> bool:
        """
        Delete a sub-block from the backend.

        Called only after the 24 h tombstone window for CRITICAL/IMPORTANT.
        For DISPOSABLE: called immediately on file deletion.

        Returns:
            True if deleted, False if not found (idempotent -- not an error).
        """

    @abstractmethod
    async def health_check(self) -> HealthResult:
        """
        Check backend reachability and quota.

        MUST NOT be called on app startup (zero network calls on startup).
        Called only by the background health daemon (leaky bucket, 1% daily
        chunk sample per backend).

        Returns:
            HealthResult with reachable, quota_remaining, latency_ms.
        """

    @abstractmethod
    async def available_space(self) -> int:
        """
        Return available free space in bytes.

        Must subtract quota_reserved from the backend's reported value.

        Returns:
            Free bytes remaining (after quota_reserved subtraction).
        """
