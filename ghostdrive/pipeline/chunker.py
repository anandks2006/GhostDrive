"""
chunker.py -- File-to-logical-chunk splitter (spec §5.1, §5.4, §5.9).

Pipeline position
-----------------
    OS file lock acquired
    -> BLAKE3+size dedup check (pre-compression, on original)  <- dedup.py
    -> THIS MODULE: split file into logical chunks
    -> compressor.py, chunk_crypto.py, upload.py

What this does
--------------
Splits a file into logical chunks based on the backend's logical_chunk_bytes.
Yields (chunk_index, offset, size) descriptors -- NO data read here.
Data is read lazily during the encrypt+compress pipeline.

Edge cases (spec §5.9)
-----------------------
- Empty files: yields a single zero-size descriptor (zero-sub-block manifest entry).
- Symlinks: followed with depth limit (max 10) to prevent infinite loops.
- Unicode filenames: all paths handled via pathlib (explicit UTF-8 throughout).
- File modified during upload: OS lock prevents modification. If lock is
  unavailable and size changes post-upload, caller warns and re-uploads.
"""

from __future__ import annotations

import dataclasses
import logging
import os
from pathlib import Path
from typing import Generator, Optional

logger = logging.getLogger(__name__)

_SYMLINK_MAX_DEPTH = 10


@dataclasses.dataclass(frozen=True)
class ChunkDescriptor:
    """
    Describes one logical chunk of a file.

    No data is held here -- the pipeline reads the file lazily at upload time
    using offset + size.

    Attributes:
        chunk_index:  0-based index within the file.
        total_chunks: Total number of chunks for this file.
        offset:       Byte offset in the file where this chunk starts.
        size:         Number of bytes in this chunk (0 for empty file manifest).
        is_manifest:  True if this is the zero-size empty-file manifest entry.
    """
    chunk_index:  int
    total_chunks: int
    offset:       int
    size:         int
    is_manifest:  bool = False


def resolve_path(path: Path, max_depth: int = _SYMLINK_MAX_DEPTH) -> Path:
    """
    Resolve symlinks up to max_depth levels deep.

    Args:
        path:      Path to resolve.
        max_depth: Maximum symlink chain depth (spec §5.9: max 10).

    Returns:
        Resolved real path.

    Raises:
        RuntimeError: Symlink depth exceeded (loop detected).
        FileNotFoundError: Path does not exist after resolution.
    """
    # Walk the chain manually to enforce the depth limit.
    # Path.resolve() does not expose the depth -- we check it separately.
    current = Path(path)
    for _ in range(max_depth):
        if not current.is_symlink():
            break
        # Resolve one symlink step (handles relative and absolute targets)
        target = current.resolve()  # OS resolves one level
        if target == current:       # No progress (shouldn't happen, but guard)
            break
        current = target
    else:
        raise RuntimeError(
            f"Symlink depth exceeded {max_depth} levels for path: {path}. "
            "Possible symlink loop -- upload aborted."
        )

    # Final resolution to normalise Windows extended paths (//?/ prefix)
    resolved = current.resolve()

    if not resolved.exists():
        raise FileNotFoundError(f"Path does not exist after symlink resolution: {resolved}")

    return resolved


def split_file(
    path: Path,
    logical_chunk_bytes: int,
) -> Generator[ChunkDescriptor, None, None]:
    """
    Split a file into logical chunk descriptors.

    Does NOT read file data. Yields (chunk_index, offset, size) descriptors
    for the pipeline to consume lazily.

    Args:
        path:               Path to the file. Symlinks are resolved (depth <= 10).
        logical_chunk_bytes: Backend-specific logical chunk size in bytes.
                            e.g. 1.5 GB for Telegram, 1.9 GB for GitHub.

    Yields:
        ChunkDescriptor for each logical chunk.

    Special cases:
        - Empty file: yields one ChunkDescriptor with size=0, is_manifest=True.
        - Symlinks: resolved with depth <= 10.
    """
    resolved = resolve_path(path)
    file_size = resolved.stat().st_size

    if file_size == 0:
        # Empty file: zero-sub-block manifest entry (spec §5.9)
        logger.debug("split_file: empty file %s -> manifest entry", path)
        yield ChunkDescriptor(
            chunk_index=0,
            total_chunks=1,
            offset=0,
            size=0,
            is_manifest=True,
        )
        return

    # Calculate total number of chunks
    total = (file_size + logical_chunk_bytes - 1) // logical_chunk_bytes

    offset = 0
    for idx in range(total):
        remaining = file_size - offset
        size      = min(logical_chunk_bytes, remaining)
        yield ChunkDescriptor(
            chunk_index=idx,
            total_chunks=total,
            offset=offset,
            size=size,
            is_manifest=False,
        )
        offset += size

    logger.debug(
        "split_file: %s (%d bytes) -> %d chunk(s) of up to %d bytes",
        path.name, file_size, total, logical_chunk_bytes,
    )


async def read_chunk_async(
    path: Path,
    offset: int,
    size: int,
    block_size: int = 65_536,
) -> "AsyncGenerator[bytes, None]":
    """
    Async generator that reads one logical chunk from a file in 64 KB blocks.

    The OS file lock MUST be held by the caller for the duration of this call.

    Args:
        path:       Path to the file.
        offset:     Byte offset to start reading from.
        size:       Number of bytes to read.
        block_size: Read block size (default: 64 KB, spec §5.1 hard constraint).

    Yields:
        64 KB (or smaller final) blocks of raw bytes.
    """
    import aiofiles

    async with aiofiles.open(path, "rb") as f:
        await f.seek(offset)
        bytes_remaining = size
        while bytes_remaining > 0:
            to_read = min(block_size, bytes_remaining)
            block   = await f.read(to_read)
            if not block:
                break
            yield block
            bytes_remaining -= len(block)


# Make read_chunk_async an actual async generator (annotate properly)
from typing import AsyncGenerator  # noqa: E402 (after function def)
read_chunk_async.__annotations__["return"] = "AsyncGenerator[bytes, None]"
