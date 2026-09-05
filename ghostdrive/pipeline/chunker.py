"""
chunker.py -- File-to-logical-chunk splitter.
"""

from __future__ import annotations

import dataclasses
import logging
import os
from pathlib import Path
from typing import AsyncGenerator, Generator

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
    # Step one symlink level at a time using os.readlink() so the depth limit
    # is actually enforced. Path.resolve() calls the OS realpath(2) which
    # follows the *entire* chain in one shot and would bypass our limit.
    #
    # We use os.path.normpath (not Path.resolve) for intermediate steps to
    # avoid the //?/ extended-path UNC prefix that Path.resolve() can produce
    # on Windows for paths in certain directories (e.g., %TEMP%).
    current = os.path.abspath(str(path))
    for _ in range(max_depth):
        if not os.path.islink(current):
            break
        # Read exactly ONE symlink level
        link_target = os.readlink(current)
        if not os.path.isabs(link_target):
            # Relative symlink — resolve relative to the symlink's parent dir
            link_target = os.path.join(os.path.dirname(current), link_target)
        # Normalise (.., . etc) without following further symlinks
        current = os.path.normpath(link_target)
    else:
        raise RuntimeError(
            f"Symlink depth exceeded {max_depth} levels for path: {path}. "
            "Possible symlink loop -- upload aborted."
        )

    resolved = Path(current)
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
                            e.g. 1.5 GB for Telegram, 2 GB for Discord.

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
) -> AsyncGenerator[bytes, None]:
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
