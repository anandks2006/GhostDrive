"""
base.py -- Backend Abstraction Layer (BAL) interface.

Spec §6.1 -- Plugin Interface
==============================
Every backend plugin MUST implement this interface exactly.
The upload pipeline calls these methods only through this interface --
never directly against a backend's API library.

Method contracts
----------------
upload(stream, chunk_id, sub_block_index)
    Called AFTER:
      - quota_reserved decremented atomically in backends table
      - pending intent written to chunk_locations and fsynced
    Returns reference_id (str). Pipeline updates status -> confirmed.
    On exception: pipeline sets status -> failed, restores quota_reserved.

download(reference_id)
    Async bytes generator. Yields raw bytes sub-blocks.
    Discord: fetches fresh CDN URL via API before download.
    NEVER returns bytes before auth tag is verified (enforced by caller,
    not here -- but this method must not buffer and return partial data).

delete(reference_id)
    Returns bool. Soft-delete: the pipeline marks deletion-pending in
    the index for 24 h before calling this. Never called directly on
    user delete -- only after 24 h tombstone window for CRITICAL/IMPORTANT.
    DISPOSABLE: immediate deletion (no 24 h window).

health_check()
    Returns HealthResult. Called by the background health daemon only --
    NEVER on app startup (zero network calls on startup per spec §8.2).
    IPFS: must verify pin via pinning service API, not just gateway ping.

available_space()
    Returns int bytes remaining. Hard-capped for S3 backends at free tier
    limit. Must subtract quota_reserved from raw API value.

Capability flags (set as class attributes)
------------------------------------------
supports_range_requests : bool
supports_streaming       : bool
supports_deletion        : bool
is_cold_storage          : bool
is_ephemeral_url         : bool  -- Discord: store message_id+channel_id only
ml_artifacts_only        : bool  -- Hugging Face
cpu_intensive            : bool  -- Mega.nz: deprioritize above 70% CPU
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
        pin_verified:    For IPFS only: True if pin is confirmed active via
                         the pinning service API (not just gateway reachability).
                         None for non-IPFS backends.
        error:           Human-readable error message if not reachable.
        latency_ms:      Round-trip time of the health check in milliseconds.
    """
    reachable:       bool
    quota_remaining: Optional[int] = None
    pin_verified:    Optional[bool] = None
    error:           Optional[str]  = None
    latency_ms:      Optional[float] = None


class BackendBase(ABC):
    """
    Abstract base class for all GhostDrive backend plugins.

    Spec §6.1 -- all five methods are mandatory. Capability flags are
    class-level attributes with default values that subclasses override.
    """

    # ── Capability flags (defaults; override in subclass) ─────────────────────
    supports_range_requests: bool = False
    supports_streaming:      bool = True
    supports_deletion:       bool = True
    is_cold_storage:         bool = False
    is_ephemeral_url:        bool = False   # True for Discord
    ml_artifacts_only:       bool = False   # True for Hugging Face
    cpu_intensive:           bool = False   # True for Mega.nz

    # Tier: "CRITICAL", "IMPORTANT", or "DISPOSABLE"
    tier: str = "IMPORTANT"

    # Logical chunk and sub-block sizes for this backend (bytes)
    logical_chunk_bytes: int = 50 * 1024 * 1024   # 50 MB default
    sub_block_bytes:     int = 50 * 1024 * 1024   # 50 MB default

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
                          asset URL for GitHub, CIDv1 for IPFS).

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

        For IPFS: verifies pin via pinning service API -- not just gateway ping.

        Returns:
            HealthResult with reachable, quota_remaining, latency_ms.
        """

    @abstractmethod
    async def available_space(self) -> int:
        """
        Return available free space in bytes.

        For S3 backends (B2, R2, Storj): hard-capped at free tier limit.
        Must subtract quota_reserved from raw API value.

        Returns:
            Free bytes remaining (after quota_reserved subtraction).
        """
