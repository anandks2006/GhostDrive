"""
secure_erase.py -- L1 file-level secure overwrite.

This module implements software overwrite for individual files (L1 operations).
L3 (whole-drive) erase is NOT implemented -- users are directed to
manufacturer tools (Samsung Magician, WD Dashboard, macOS Disk Utility, etc.)

Erase levels
------------
PASS_1: Single zero-pass. Defeats casual forensic recovery on HDDs.
        Best-effort on SSDs (wear leveling means old pages may persist
        until garbage collection -- see UI disclosure).
PASS_3: Three-pass (zeros -> ones -> random). DoD 5220.22-M pattern.
        More thorough on HDDs; same SSD caveats as PASS_1.

SSD disclosure
--------------
The caller (SecureEraseDialog) is responsible for showing the SSD disclosure
when the target drive is an SSD. This module does not show UI.

The overwrite uses the same 64 KB streaming block pattern as the upload
pipeline (aiofiles, async generator) to avoid loading the entire file into
RAM. fsync() is called after each pass.

Integration with DestructiveOperationGuard
------------------------------------------
This module is called ONLY from pipeline/secure_erase.py after the
10-step guard pipeline has already validated and logged the operation.
Do not call _overwrite_file() directly -- always go through the guard.
"""

from __future__ import annotations

import asyncio
import enum
import logging
import os
from pathlib import Path
from typing import Optional

import aiofiles

logger = logging.getLogger(__name__)

_BLOCK_SIZE = 65_536  # 64 KB -- matches upload pipeline


class SecureEraseLevel(enum.Enum):
    """
    Software-level overwrite patterns for L1 secure erase.

    PASS_1: Single zero-pass. Fast; sufficient against casual recovery.
    PASS_3: Three-pass DoD pattern. Thorough on HDDs.

    Note: Neither level guarantees erasure on SSDs due to wear leveling.
    The UI (SecureEraseDialog) discloses this when the drive is an SSD.
    """
    PASS_1 = 1   # zeros only
    PASS_3 = 3   # zeros -> ones -> random


async def overwrite_file(
    path: Path,
    level: SecureEraseLevel = SecureEraseLevel.PASS_3,
) -> None:
    """
    Securely overwrite a file's content in-place, then unlink it.

    This function is ONLY called from pipeline/secure_erase.py after the
    DestructiveOperationGuard has approved and logged the operation.

    Args:
        path:  Resolved absolute path to the file. Must be a regular file.
               No symlinks, no device nodes (guard validates this).
        level: PASS_1 (fast) or PASS_3 (thorough). Defaults to PASS_3.

    Raises:
        OSError:    If the file cannot be opened, written, or fsynced.
        ValueError: If path does not resolve to a regular file.
    """
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"overwrite_file: path must be a regular file: {path}")

    file_size = path.stat().st_size

    # Build pass patterns
    patterns: list[Optional[bytes]] = []
    if level == SecureEraseLevel.PASS_1:
        patterns = [b"\x00"]
    else:  # PASS_3
        patterns = [b"\x00", b"\xFF", None]  # None = os.urandom per block

    logger.debug(
        "Secure overwrite started: %s  size=%d  passes=%d",
        path.name, file_size, len(patterns),
    )

    async with aiofiles.open(path, "r+b") as f:
        for pass_idx, pattern in enumerate(patterns):
            await f.seek(0)
            written = 0

            while written < file_size:
                remaining = file_size - written
                block_size = min(_BLOCK_SIZE, remaining)

                if pattern is None:
                    block = os.urandom(block_size)
                else:
                    # Repeat the single-byte pattern to fill the block
                    block = (pattern * block_size)[:block_size]

                await f.write(block)
                written += block_size

            # fsync after every pass -- ensures data hits physical media
            # before moving to the next pass.
            raw_fd = f.fileno()
            await asyncio.to_thread(os.fsync, raw_fd)
            logger.debug("Pass %d/%d complete: %s", pass_idx + 1, len(patterns), path.name)

    # Unlink after all passes complete
    path.unlink()
    logger.info("Secure erase complete: %s (%d bytes, %d passes)", path.name, file_size, len(patterns))
