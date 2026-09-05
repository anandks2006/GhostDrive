"""
artifact_cleaner.py -- Cross-platform OS artifact audit and removal.

Abstract base class. Platform implementations:
  ghostdrive/platform/windows/artifact_cleaner.py
  ghostdrive/platform/linux/artifact_cleaner.py
  ghostdrive/platform/macos/artifact_cleaner.py

What are "artifacts"?
---------------------
OS features (thumbnail cache, recent files, search indexes) silently record
metadata about files a user opens. This metadata persists after the file is
deleted, potentially leaking that the user accessed a specific file.

GhostDrive's vault data is always encrypted -- artifacts of accessing the
vault *container* are irrelevant. This cleaner targets plaintext files
*outside* the vault that the user explicitly marks for secure erasure,
plus optionally the GhostDrive data directory itself.

Setup-time vs on-demand
-----------------------
SETUP TIME (called once at first launch):
  exclude_directory_from_indexing() -- prevent future indexing
  write_nomedia_markers()           -- .metadata_never_index + .nomedia files

ON DEMAND (before or after sensitive session):
  audit()  -- find existing artifacts for given file paths
  clean()  -- remove found artifacts

Platform behaviour
------------------
Linux:   Most surgical -- thumbnail filenames are MD5(file:// URI), so we
         can delete exactly the right cache file. recently-used.xbel is XML.
Windows: Deletes entire thumbcache_*.db (Windows rebuilds for other files).
         RecentDocs registry keys pruned surgically.
macOS:   qlmanage -r cache (clears all QL cache). NSRecentDocuments cleared
         via defaults command. mdutil excludes the data directory.
"""

from __future__ import annotations

import dataclasses
from abc import ABC, abstractmethod
from pathlib import Path


@dataclasses.dataclass
class ArtifactReport:
    """
    Result of an artifact audit for a list of file paths.

    thumbnail_entries:    Paths of thumbnail cache files found for our files.
    recent_file_entries:  MRU/recent-file entries that reference our files.
    search_index_hits:    Best-effort list of search index hits (may be empty
                          if index is inaccessible without elevated privileges).
    skipped_components:   Names of components that could not be audited
                          (e.g., "search_index: tracker not running").
    total_found:          Sum of all found entries across all components.
    """
    thumbnail_entries:   list[Path]
    recent_file_entries: list[str]
    search_index_hits:   list[str]
    skipped_components:  list[str]
    total_found:         int


@dataclasses.dataclass
class CleanResult:
    """Result of a clean operation."""
    thumbnails_removed:    int
    recent_entries_removed: int
    errors:                list[str]  # non-fatal: logged, clean continues
    total_removed:         int


class ArtifactCleanerBase(ABC):
    """
    Abstract cross-platform OS artifact cleaner.

    All methods must be safe to call from the pipeline thread.
    Methods that invoke external processes (qlmanage, tracker3, defaults)
    do so via subprocess with a short timeout; failures are non-fatal.

    Usage::

        cleaner = get_artifact_cleaner()
        if cleaner.is_available():
            report = cleaner.audit([path1, path2])
            result = cleaner.clean([path1, path2])
    """

    @abstractmethod
    def is_available(self) -> bool:
        """
        Return True if artifact cleaning is possible on this platform.
        Always True for the base implementation; may be False if required
        system tools are missing.
        """

    @abstractmethod
    def audit(self, file_paths: list[Path]) -> ArtifactReport:
        """
        Find OS artifacts that reference the given file paths.
        Read-only -- does not modify any files.

        Args:
            file_paths: Absolute paths of files to check. Must be resolved
                        (no symlinks, no ../ components).

        Returns:
            ArtifactReport detailing found artifacts.
        """

    @abstractmethod
    def clean(self, file_paths: list[Path]) -> CleanResult:
        """
        Remove OS artifacts for the given file paths.

        Args:
            file_paths: Absolute paths of files to clean. Must be resolved.

        Returns:
            CleanResult with counts and any non-fatal errors.
        """

    @abstractmethod
    def exclude_directory_from_indexing(self, directory: Path) -> bool:
        """
        Configure the OS search indexer to permanently exclude `directory`.
        Called once at first launch for the GhostDrive data directory.

        Returns:
            True if exclusion was applied successfully.
            False if the OS indexer is not available or exclusion failed
            (non-fatal: GhostDrive continues, logs a warning).
        """

    def write_nomedia_markers(self, directory: Path) -> None:
        """
        Write .metadata_never_index and .nomedia marker files into `directory`.
        These files signal to Spotlight (macOS), Tracker (Linux), and media
        scanners that the directory should not be indexed.
        Safe to call multiple times (idempotent).
        """
        for marker in (".metadata_never_index", ".nomedia"):
            marker_path = directory / marker
            if not marker_path.exists():
                try:
                    marker_path.touch()
                except OSError:
                    pass  # non-fatal: directory may be read-only or not yet created
