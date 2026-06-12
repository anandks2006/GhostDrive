"""
fsync.py — Atomic file writes with fsync for all critical GhostDrive state.

Spec §5.1 / §9.5 — "fsync on critical writes"
===============================================
Critical files (keystore.json, nonce_counter.json, WAL checkpoint marker,
index snapshot) MUST be written atomically with fsync so that a power loss or
OS crash never leaves a partial write.

``atomic_write()`` implements the write-to-temp-fsync-rename pattern:
  1. Write to a temporary file in the SAME directory (same filesystem ⇒ atomic rename).
  2. ``fsync()`` the temporary file's file descriptor.
  3. ``os.replace()`` / ``Path.replace()`` the temp file onto the target path.
  4. ``fsync()`` the parent directory to make the rename durable.

On Windows, Step 4 fails silently (directory fsync is not supported) but the
rename is still the best available atomic write on NTFS/ReFS.
"""

import os
import tempfile
from pathlib import Path


def fsync_file(path: Path) -> None:
    """
    Open an existing file and call ``fsync()`` to flush it to durable storage.

    Args:
        path: File to fsync.

    Raises:
        OSError: If the file cannot be opened or fsync fails.
    """
    with open(path, "rb") as fh:
        os.fsync(fh.fileno())


def fsync_dir(directory: Path) -> None:
    """
    Call ``fsync()`` on a directory file descriptor to make a preceding rename
    durable on POSIX systems.

    On Windows this raises ``OSError`` and is silently skipped by callers.

    Args:
        directory: Directory to fsync.
    """
    dir_fd = os.open(str(directory), os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def atomic_write(path: Path, data: bytes) -> None:
    """
    Write ``data`` to ``path`` atomically with fsync.

    Algorithm
    ---------
    1. Create a temporary file in the same directory (guarantees same filesystem
       so that the rename at step 3 is truly atomic on POSIX).
    2. Write ``data`` to the temp file and flush Python's I/O buffer.
    3. Call ``fsync()`` on the temp file's file descriptor to push bytes to
       durable storage before we commit to the rename.
    4. Use ``Path.replace()`` to atomically rename temp → target.
       On POSIX this is a single ``rename(2)`` syscall; on Windows it uses
       ``MoveFileEx`` with MOVEFILE_REPLACE_EXISTING.
    5. Attempt to ``fsync()`` the parent directory so the directory entry
       (the rename) is also durable. Silently ignored on Windows.

    If any step fails, the temporary file is cleaned up and the original
    ``path`` is left untouched.

    Args:
        path: Target file path.
        data: Bytes to write.

    Raises:
        FsyncError: If writing or fsyncing the temp file fails (re-raised after cleanup).
        OSError:    Propagated for unexpected I/O errors.
    """
    from ghostdrive.exceptions import FsyncError

    path   = Path(path)
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)

    # Step 1: Create temp file in same directory
    tmp_fd, tmp_str = tempfile.mkstemp(dir=parent, prefix=f".{path.name}.tmp.")
    tmp_path = Path(tmp_str)

    try:
        # Step 2: Write data
        with os.fdopen(tmp_fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            # Step 3: fsync the temp file
            os.fsync(fh.fileno())
        tmp_fd = None  # os.fdopen took ownership

        # Step 4: Atomic rename
        tmp_path.replace(path)

        # Step 5: fsync the directory (makes rename durable on POSIX)
        try:
            fsync_dir(parent)
        except OSError:
            # Not supported on Windows — acceptable
            pass

    except Exception as exc:
        # Clean up the temp file if anything went wrong
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise FsyncError(
            f"atomic_write failed for {path}: {exc}"
        ) from exc
