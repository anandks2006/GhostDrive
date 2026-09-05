"""
file_lock.py — Cross-platform OS file locking abstraction.

Spec §5.2 — OS File Locking
=============================
The pre-hash double-read (BLAKE3 before upload, then re-read for encryption)
is eliminated. A single streaming pass reads the file once. File integrity
during upload is guaranteed by OS-level file locking:

  Linux/macOS: fcntl.flock(fd, LOCK_EX | LOCK_NB)
  Windows:     msvcrt.locking() via a cross-platform abstraction wrapper

Lock acquisition failure (permission error, read-only filesystem, another
process holds lock):
  → Warn user (logged as WARNING)
  → Proceed WITHOUT lock
  → Flag file as 'uploaded-without-integrity-lock' in the index record
  → Upload is NOT aborted (spec requirement)

The lock is held for the ENTIRE upload duration and released on:
  - Completion
  - Cancellation
  - Failure / exception

Note on Windows ``msvcrt.locking()``
--------------------------------------
``msvcrt.locking()`` only locks a contiguous byte range, not the whole file.
We lock bytes from offset 0 to ``min(file_size, MAX_LOCK_BYTES)`` as an
advisory lock. This is the best available mechanism on Windows without the
Win32 LockFile API. The spec acknowledges this limitation.
"""

import logging
import os
import sys
from pathlib import Path
from typing import Optional


logger = logging.getLogger(__name__)

# Maximum byte range to lock on Windows (1 GB to avoid overflow)
_MAX_LOCK_BYTES = 2 ** 30  # 1 GB

# Platform detection
if sys.platform == "win32":
    import msvcrt
    _PLATFORM = "windows"
elif sys.platform in ("linux", "darwin") or sys.platform.startswith("freebsd"):
    import fcntl
    _PLATFORM = "posix"
else:
    _PLATFORM = "unsupported"


class FileLock:
    """
    Cross-platform exclusive file lock.

    Usage as a context manager (recommended)
    ----------------------------------------
        with FileLock(path) as lock:
            if lock.lock_skipped:
                logger.warning("Upload proceeding without integrity lock")
            # ... upload

    Usage with manual acquire/release
    -----------------------------------
        lock = FileLock(path)
        lock.acquire()
        try:
            # ... upload
        finally:
            lock.release()

    The ``lock_skipped`` attribute is ``True`` if acquisition failed. Callers
    MUST check this and flag the file record in the index accordingly.
    """

    def __init__(self, path: Path) -> None:
        self.path        = Path(path)
        self.lock_skipped = False   # True if lock could not be acquired
        self._fd: Optional[int]    = None
        self._acquired             = False
        self._windows_lock_bytes   = 0

    # ── Public API ────────────────────────────────────────────────────────────

    def acquire(self) -> bool:
        """
        Attempt to acquire an exclusive non-blocking file lock.

        Returns:
            ``True`` if lock acquired successfully.
            ``False`` if the lock was skipped (with a logged warning).

        Never raises. Acquisition failures are handled gracefully.
        """
        try:
            self._fd = os.open(self.path, os.O_RDONLY)
        except (OSError, PermissionError) as exc:
            self._warn_and_skip(f"Could not open file descriptor: {exc}")
            return False

        try:
            if _PLATFORM == "posix":
                self._acquire_posix()
            elif _PLATFORM == "windows":
                self._acquire_windows()
            else:
                self._warn_and_skip(
                    f"File locking not supported on platform {sys.platform!r}"
                )
                return False

            self._acquired = True
            logger.debug("Acquired exclusive file lock: %s", self.path)
            return True

        except (OSError, PermissionError) as exc:
            self._warn_and_skip(
                f"Lock acquisition failed (another process holds it, "
                f"or read-only filesystem): {exc}"
            )
            self._close_fd()
            return False

    def release(self) -> None:
        """
        Release the file lock and close the file descriptor.
        Safe to call even if ``acquire()`` was never called or returned ``False``.
        """
        if self._fd is None:
            return

        try:
            if self._acquired:
                if _PLATFORM == "posix":
                    fcntl.flock(self._fd, fcntl.LOCK_UN)
                elif _PLATFORM == "windows" and self._windows_lock_bytes > 0:
                    os.lseek(self._fd, 0, os.SEEK_SET)
                    msvcrt.locking(self._fd, msvcrt.LK_UNLCK, self._windows_lock_bytes)
        except OSError as exc:
            logger.warning("Error releasing file lock for %s: %s", self.path, exc)
        finally:
            self._close_fd()
            self._acquired = False

    # ── Context manager ───────────────────────────────────────────────────────

    def __enter__(self) -> "FileLock":
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        self.release()
        return False  # Never suppress exceptions

    # ── Private ───────────────────────────────────────────────────────────────

    def _acquire_posix(self) -> None:
        """Non-blocking exclusive lock via ``fcntl.flock`` (Linux/macOS)."""
        fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _acquire_windows(self) -> None:
        """
        Byte-range advisory lock via ``msvcrt.locking`` (Windows).

        Locks from byte 0 to min(file_size, MAX_LOCK_BYTES).
        Empty files get no lock (no bytes to lock).
        """
        try:
            file_size = self.path.stat().st_size
        except OSError:
            file_size = 0

        if file_size == 0:
            # No bytes to lock; return without error
            return

        lock_bytes = min(file_size, _MAX_LOCK_BYTES)
        os.lseek(self._fd, 0, os.SEEK_SET)
        msvcrt.locking(self._fd, msvcrt.LK_NBLCK, lock_bytes)
        self._windows_lock_bytes = lock_bytes

    def _warn_and_skip(self, reason: str) -> None:
        """Log a warning and set lock_skipped = True."""
        logger.warning(
            "File lock skipped for %s: %s. "
            "File will be flagged as 'uploaded-without-integrity-lock' in the index.",
            self.path,
            reason,
        )
        self.lock_skipped = True

    def _close_fd(self) -> None:
        """Close the file descriptor if it's open."""
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            finally:
                self._fd = None
