"""
test_file_lock.py — Tests for the cross-platform OS file locking abstraction.

Spec §5.2: Lock acquisition failure warns but NEVER aborts the upload.
"""

import sys
from pathlib import Path

import pytest

from ghostdrive.pipeline.file_lock import FileLock


class TestFileLock:

    @pytest.fixture
    def test_file(self, tmp_path) -> Path:
        f = tmp_path / "upload_target.bin"
        f.write_bytes(b"test file content for locking tests " * 100)
        return f

    @pytest.fixture
    def empty_file(self, tmp_path) -> Path:
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        return f

    # ── Basic acquire / release ───────────────────────────────────────────────

    def test_acquire_returns_true_on_supported_platform(self, test_file):
        lock   = FileLock(test_file)
        result = lock.acquire()
        lock.release()

        if sys.platform in ("win32", "linux", "darwin"):
            assert result is True
            assert not lock.lock_skipped
        # On unsupported platforms result is False (tested separately)

    def test_lock_skipped_is_false_on_success(self, test_file):
        with FileLock(test_file) as lock:
            if sys.platform in ("win32", "linux", "darwin"):
                assert not lock.lock_skipped

    def test_context_manager_releases_on_exit(self, test_file):
        with FileLock(test_file) as lock:
            acquired = lock._acquired

        assert not lock._acquired  # Released after context exit
        assert lock._fd is None

    def test_release_without_acquire_is_safe(self, test_file):
        """Should not raise — guards against cleanup code calling release()
        unconditionally even when acquire() was never called."""
        lock = FileLock(test_file)
        lock.release()  # Must not raise

    def test_context_manager_does_not_suppress_exceptions(self, test_file):
        """Exceptions inside the 'with' block must propagate."""
        with pytest.raises(ValueError):
            with FileLock(test_file):
                raise ValueError("deliberate test exception")

    # ── Failure / graceful degradation ────────────────────────────────────────

    def test_nonexistent_file_skips_gracefully(self, tmp_path):
        """Spec §5.2: lock acquisition failure warns, does NOT abort."""
        lock = FileLock(tmp_path / "does_not_exist.bin")
        result = lock.acquire()
        assert result is False
        assert lock.lock_skipped is True

    def test_empty_file_does_not_crash(self, empty_file):
        """Empty files have no bytes to lock — should not raise."""
        with FileLock(empty_file):
            pass  # Should complete without error

    # ── lock_skipped flag ─────────────────────────────────────────────────────

    def test_lock_skipped_starts_false(self, test_file):
        lock = FileLock(test_file)
        assert lock.lock_skipped is False

    def test_lock_skipped_true_on_nonexistent_file(self, tmp_path):
        lock = FileLock(tmp_path / "missing.bin")
        lock.acquire()
        assert lock.lock_skipped is True

    # ── Attributes ────────────────────────────────────────────────────────────

    def test_path_stored_correctly(self, test_file):
        lock = FileLock(test_file)
        assert lock.path == test_file

    def test_fd_is_none_before_acquire(self, test_file):
        lock = FileLock(test_file)
        assert lock._fd is None

    def test_fd_is_none_after_release(self, test_file):
        lock = FileLock(test_file)
        lock.acquire()
        lock.release()
        assert lock._fd is None


class TestFileLockFsync:
    """Tests for utils.fsync atomic write behaviour (also exercises file I/O paths)."""

    def test_atomic_write_creates_file(self, tmp_path):
        from ghostdrive.utils.fsync import atomic_write
        target = tmp_path / "output.json"
        atomic_write(target, b'{"key": "value"}')
        assert target.exists()
        assert target.read_bytes() == b'{"key": "value"}'

    def test_atomic_write_is_idempotent(self, tmp_path):
        from ghostdrive.utils.fsync import atomic_write
        target = tmp_path / "idempotent.json"
        atomic_write(target, b"first write")
        atomic_write(target, b"second write")
        assert target.read_bytes() == b"second write"

    def test_atomic_write_creates_parent_dirs(self, tmp_path):
        from ghostdrive.utils.fsync import atomic_write
        deep = tmp_path / "a" / "b" / "c" / "file.json"
        atomic_write(deep, b"deep content")
        assert deep.exists()

    def test_atomic_write_leaves_no_temp_files_on_success(self, tmp_path):
        from ghostdrive.utils.fsync import atomic_write
        target = tmp_path / "clean.json"
        atomic_write(target, b"clean")
        # Only the target file should exist, no .tmp. files
        temp_files = list(tmp_path.glob("*.tmp.*"))
        assert len(temp_files) == 0
