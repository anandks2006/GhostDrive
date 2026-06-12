"""
dedup.py -- BLAKE3+size deduplication (pre-compression, spec §5.5).

Dedup key: BLAKE3_hash(original_file_bytes) + file_size
============================================================
- Hash computed on the ORIGINAL file bytes BEFORE zstd compression.
- Ensures the same file deduplicates regardless of compression level
  or settings used on different devices.
- Composite key (hash + size) guards against BLAKE3 collision false-positives
  (academic concern, but documented per spec §5.5).

Advisory lock (race condition fix, spec §5.5)
----------------------------------------------
Before starting an upload, an advisory lock is acquired per content hash:
an EXCLUSIVE SQLite transaction that reads the chunks table. A second
concurrent upload of the same file waits on the lock, then deduplicates
against the first upload's completed entry.

In the current implementation the advisory lock is the transaction isolation
itself -- SQLite serialises concurrent writers. A full distributed advisory
lock is added in Month 6 (multi-window scenario).

Reference counting (spec §5.8)
--------------------------------
When a dedup match is found:
  - A new FileRecord is created.
  - A new ChunkRecord is NOT created; instead ref_count is incremented.
  - No backend upload occurs.
  - The chunk's chunk_locations are shared across all referencing files.
  - Backend delete() is issued only when ref_count reaches 0.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Optional

import blake3

logger = logging.getLogger(__name__)


def compute_blake3(data: bytes) -> str:
    """
    Compute BLAKE3 hash of raw bytes. Returns lowercase hex string.
    Used on ORIGINAL bytes BEFORE compression (spec §5.5).
    """
    return blake3.blake3(data).hexdigest()


async def compute_blake3_async(data: bytes) -> str:
    """Async wrapper for compute_blake3 (runs in thread pool)."""
    return await asyncio.to_thread(compute_blake3, data)


def compute_blake3_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """
    Compute BLAKE3 hash of a file in streaming fashion.
    Reads in chunk_size blocks to avoid loading the full file into memory.

    Args:
        path:       Path to the file.
        chunk_size: Read block size in bytes (default: 1 MB).

    Returns:
        Lowercase hex BLAKE3 hash of the complete file.
    """
    hasher = blake3.blake3()
    with open(path, "rb") as f:
        while True:
            block = f.read(chunk_size)
            if not block:
                break
            hasher.update(block)
    return hasher.hexdigest()


async def compute_blake3_file_async(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """Async wrapper for compute_blake3_file (runs in thread pool)."""
    return await asyncio.to_thread(compute_blake3_file, path, chunk_size)


class DedupChecker:
    """
    Checks whether a file chunk already exists in ghostdrive.db by BLAKE3+size.

    Usage::

        checker = DedupChecker(db)
        result = checker.check(blake3_hash, size)
        if result.is_duplicate:
            db.increment_ref_count(result.existing_chunk_id)
        else:
            # proceed with full upload
    """

    def __init__(self, db) -> None:
        """
        Args:
            db: GhostDriveDB instance (open).
        """
        self._db = db

    def check(self, blake3_hash: str, size: int) -> "DedupResult":
        """
        Look up an existing chunk by BLAKE3+size (spec §5.5).

        This read is performed inside the caller's exclusive transaction
        to serve as the advisory lock -- no second concurrent upload can
        read the same state simultaneously.

        Args:
            blake3_hash: Hex BLAKE3 hash of original (pre-compression) bytes.
            size:        Original file size in bytes.

        Returns:
            DedupResult with is_duplicate=True and the existing chunk_id,
            or is_duplicate=False.
        """
        row = self._db.find_chunk_by_dedup_key(blake3_hash, size)
        if row is not None:
            logger.info(
                "Dedup hit: blake3=%s size=%d -> chunk_id=%s ref_count=%d",
                blake3_hash[:16], size, row["id"], row["ref_count"],
            )
            return DedupResult(is_duplicate=True, existing_chunk_id=row["id"])

        return DedupResult(is_duplicate=False, existing_chunk_id=None)


class DedupResult:
    """Result of a dedup check."""
    __slots__ = ("is_duplicate", "existing_chunk_id")

    def __init__(self, is_duplicate: bool, existing_chunk_id: Optional[str]) -> None:
        self.is_duplicate      = is_duplicate
        self.existing_chunk_id = existing_chunk_id

    def __repr__(self) -> str:
        if self.is_duplicate:
            return f"DedupResult(DUPLICATE, chunk_id={self.existing_chunk_id})"
        return "DedupResult(NEW)"
