"""
linux/artifact_cleaner.py -- Linux-native OS artifact search and removal.
"""

from __future__ import annotations

import os
import xml.etree.ElementTree as ET
import hashlib
import subprocess
import logging
from pathlib import Path

from ghostdrive.platform.artifact_cleaner import ArtifactCleanerBase, ArtifactReport, CleanResult

logger = logging.getLogger(__name__)


class LinuxArtifactCleaner(ArtifactCleanerBase):
    """
    Linux-native implementation of artifact cleaner.
    Cleans:
      - Freedesktop.org thumbnail cache (surgically matches MD5 of file:// URIs)
      - recently-used.xbel entries (surgically removes XML bookmarks)
    """

    def is_available(self) -> bool:
        return True

    def _get_thumbnail_paths(self, file_path: Path) -> list[Path]:
        """Get possible Freedesktop thumbnail paths for the file."""
        paths: list[Path] = []
        try:
            # Freedesktop standard: MD5 hash of absolute file:// URI
            uri = f"file://{file_path.resolve()}"
            md5_hex = hashlib.md5(uri.encode("utf-8")).hexdigest()
            thumb_name = f"{md5_hex}.png"

            # Check in standard locations
            cache_dir = Path(os.environ.get("XDG_CACHE_HOME", "~/.cache")).expanduser()
            thumb_base = cache_dir / "thumbnails"
            
            for size in ("normal", "large", "fail", "high-mem", "xlarge", "xxlarge"):
                paths.append(thumb_base / size / thumb_name)
        except Exception as exc:
            logger.debug("Failed to calculate thumbnail paths: %s", exc)
        return paths

    def _get_xbel_path(self) -> Path:
        data_dir = Path(os.environ.get("XDG_DATA_HOME", "~/.local/share")).expanduser()
        return data_dir / "recently-used.xbel"

    def audit(self, file_paths: list[Path]) -> ArtifactReport:
        thumbnail_entries: list[Path] = []
        recent_file_entries: list[str] = []
        search_index_hits: list[str] = []
        skipped_components: list[str] = []

        # 1. Audit Thumbnail Cache
        for p in file_paths:
            for t_path in self._get_thumbnail_paths(p):
                if t_path.exists():
                    thumbnail_entries.append(t_path)

        # 2. Audit recently-used.xbel
        xbel_path = self._get_xbel_path()
        if xbel_path.exists() and xbel_path.is_file():
            try:
                target_uris = {f"file://{p.resolve()}" for p in file_paths}
                tree = ET.parse(xbel_path)
                root = tree.getroot()
                # Bookmark nodes have href attribute
                for bookmark in root.findall("bookmark"):
                    href = bookmark.get("href")
                    if href in target_uris:
                        recent_file_entries.append(f"XBEL Bookmark: {href}")
            except Exception as exc:
                logger.debug("Failed to parse recently-used.xbel: %s", exc)
                skipped_components.append("recently_used_xbel")
        else:
            skipped_components.append("recently_used_xbel")

        # 3. Search Index hits (Tracker / Baloo)
        # Usually requires dbus or CLI queries. Since it is best-effort, we skip for now.
        skipped_components.append("search_index")

        total_found = len(thumbnail_entries) + len(recent_file_entries)
        return ArtifactReport(
            thumbnail_entries=thumbnail_entries,
            recent_file_entries=recent_file_entries,
            search_index_hits=search_index_hits,
            skipped_components=skipped_components,
            total_found=total_found,
        )

    def clean(self, file_paths: list[Path]) -> CleanResult:
        thumbnails_removed = 0
        recent_entries_removed = 0
        errors: list[str] = []

        # 1. Clean Thumbnails
        for p in file_paths:
            for t_path in self._get_thumbnail_paths(p):
                if t_path.exists():
                    try:
                        t_path.unlink()
                        thumbnails_removed += 1
                    except Exception as exc:
                        errors.append(f"Failed to delete thumbnail {t_path}: {exc}")

        # 2. Clean recently-used.xbel
        xbel_path = self._get_xbel_path()
        if xbel_path.exists() and xbel_path.is_file():
            try:
                target_uris = {f"file://{p.resolve()}" for p in file_paths}
                tree = ET.parse(xbel_path)
                root = tree.getroot()
                
                bookmarks_to_remove = []
                for bookmark in root.findall("bookmark"):
                    href = bookmark.get("href")
                    if href in target_uris:
                        bookmarks_to_remove.append(bookmark)

                if bookmarks_to_remove:
                    for bookmark in bookmarks_to_remove:
                        root.remove(bookmark)
                        recent_entries_removed += 1
                    tree.write(xbel_path, encoding="utf-8", xml_declaration=True)
            except Exception as exc:
                errors.append(f"Failed to clean recently-used.xbel: {exc}")

        return CleanResult(
            thumbnails_removed=thumbnails_removed,
            recent_entries_removed=recent_entries_removed,
            errors=errors,
            total_removed=thumbnails_removed + recent_entries_removed,
        )

    def exclude_directory_from_indexing(self, directory: Path) -> bool:
        """
        Exclude directory from indexing by writing .metadata_never_index
        and using Baloo exclude settings if available.
        """
        # Writing .metadata_never_index is done by write_nomedia_markers in the base class,
        # but let's make sure it's called or handled. We return True as writing markers
        # is the primary way on Linux.
        self.write_nomedia_markers(directory)
        
        # Best effort: run balooctl if available
        import shutil
        if shutil.which("balooctl"):
            try:
                subprocess.run(
                    ["balooctl", "config", "add", "excludeFolders", str(directory.resolve())],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5
                )
            except Exception:
                pass
        return True
