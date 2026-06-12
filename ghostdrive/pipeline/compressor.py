"""
compressor.py -- zstd compression for the upload pipeline.

Spec §5.1, §5.9
================
- Compression level: 3 (FIXED CONSTANT -- NEVER user-configurable).
  Dedup hash is computed on the original bytes BEFORE compression.
  Changing the level on different devices would NOT break dedup (hash is
  pre-compression), but a fixed level ensures consistent size estimates.
- Pre-compressed MIME types are SKIPPED (compressing them wastes CPU and
  usually increases size slightly).
- Streaming: yields compressed blocks without buffering the full chunk.
"""

from __future__ import annotations

import asyncio
from typing import AsyncGenerator

import zstandard as zstd

# ── Fixed constant -- NEVER change, NEVER expose to users (spec §5.9) ─────────
ZSTD_LEVEL = 3

# MIME type prefixes and exact types that are already compressed.
# zstd would increase size or waste CPU on these.
_SKIP_COMPRESSION_PREFIXES = (
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
    "image/avif",
    "image/heic",
    "image/heif",
    "video/",
    "audio/",
)

_SKIP_COMPRESSION_EXACT = frozenset({
    "application/zip",
    "application/gzip",
    "application/x-bzip2",
    "application/x-xz",
    "application/x-7z-compressed",
    "application/x-rar-compressed",
    "application/zstd",
    "application/x-zstd",
    "application/vnd.rar",
    "application/pdf",           # Usually already compressed internally
    "application/epub+zip",
    "application/x-tar",         # Uncompressed tar -- DO compress
    # ^ intentionally NOT in skip list; tar alone is uncompressed
})


def should_skip_compression(mime_type: str) -> bool:
    """
    Return True if the MIME type indicates pre-compressed content.
    zstd is skipped for these (spec §5.9: 'skipped for pre-compressed formats').

    Args:
        mime_type: MIME type string e.g. 'image/jpeg', 'video/mp4'.

    Returns:
        True -> skip compression, False -> compress with zstd level 3.
    """
    mime = mime_type.lower().split(";")[0].strip()  # strip charset params
    if mime in _SKIP_COMPRESSION_EXACT:
        return True
    for prefix in _SKIP_COMPRESSION_PREFIXES:
        if mime.startswith(prefix):
            return True
    return False


async def compress_stream(
    data_stream: AsyncGenerator[bytes, None],
    mime_type: str = "application/octet-stream",
) -> AsyncGenerator[bytes, None]:
    """
    Async generator: compress blocks from data_stream with zstd level 3.

    If the MIME type is pre-compressed, yields blocks unmodified.
    Uses zstd streaming compressor -- no full-chunk buffering.

    Args:
        data_stream: Async generator yielding raw bytes blocks.
        mime_type:   MIME type of the file being compressed.

    Yields:
        Compressed (or passthrough) bytes blocks.
    """
    skip = should_skip_compression(mime_type)

    if skip:
        async for block in data_stream:
            yield block
        return

    # zstd streaming compressor (synchronous C extension, run in thread)
    compressor = zstd.ZstdCompressor(level=ZSTD_LEVEL)
    comp_obj   = compressor.compressobj()

    async for block in data_stream:
        compressed = await asyncio.to_thread(comp_obj.compress, block)
        if compressed:
            yield compressed

    # Flush final frame
    tail = await asyncio.to_thread(comp_obj.flush)
    if tail:
        yield tail


async def decompress_stream(
    data_stream: AsyncGenerator[bytes, None],
    mime_type: str = "application/octet-stream",
) -> AsyncGenerator[bytes, None]:
    """
    Async generator: decompress zstd-compressed blocks.

    If the MIME type was pre-compressed (and therefore not compressed by us),
    yields blocks unmodified.

    Args:
        data_stream: Async generator yielding compressed bytes blocks.
        mime_type:   MIME type of the original file.

    Yields:
        Decompressed bytes blocks.
    """
    skip = should_skip_compression(mime_type)

    if skip:
        async for block in data_stream:
            yield block
        return

    decompressor = zstd.ZstdDecompressor()
    decomp_obj   = decompressor.decompressobj()

    async for block in data_stream:
        decompressed = await asyncio.to_thread(decomp_obj.decompress, block)
        if decompressed:
            yield decompressed


def compress_bytes(data: bytes, mime_type: str = "application/octet-stream") -> bytes:
    """
    Synchronous single-call compression. Used in tests and small structs.
    Production pipeline uses compress_stream().
    """
    if should_skip_compression(mime_type):
        return data
    return zstd.ZstdCompressor(level=ZSTD_LEVEL).compress(data)


def decompress_bytes(data: bytes, mime_type: str = "application/octet-stream") -> bytes:
    """Synchronous single-call decompression. Counterpart to compress_bytes()."""
    if should_skip_compression(mime_type):
        return data
    return zstd.ZstdDecompressor().decompress(data)
