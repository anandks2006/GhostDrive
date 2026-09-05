"""
macos/artifact_cleaner.py -- macOS-native OS artifact search and removal.
"""

from __future__ import annotations

import plistlib
import subprocess
import logging
from pathlib import Path

from ghostdrive.platform.artifact_cleaner import ArtifactCleanerBase, ArtifactReport, CleanResult

logger = logging.getLogger(__name__)


class MacOSArtifactCleaner(ArtifactCleanerBase):
    """
    macOS-native implementation of artifact cleaner.
    Cleans:
      - QuickLook cache (via qlmanage -r cache)
      - Spotlight index exclusions (via mdutil -i off)
      - Recent documents (audits and clears com.apple.LSSharedFileList.RecentDocuments plist)
    """

    def is_available(self) -> bool:
        return True

    def _get_recent_items_plist(self) -> Path:
        return Path("~/Library/Preferences/com.apple.LSSharedFileList.RecentDocuments.plist").expanduser()

    def audit(self, file_paths: list[Path]) -> ArtifactReport:
        thumbnail_entries: list[Path] = []
        recent_file_entries: list[str] = []
        search_index_hits: list[str] = []
        skipped_components: list[str] = []

        # 1. QuickLook Cache Audit
        # macOS holds QuickLook caches centrally. We can't surgically list individual QuickLook entries easily,
        # but we know they exist when files have been previewed. We list the quicklook cache directory as a candidate.
        ql_dir = Path("~/Library/Caches/com.apple.QuickLookDaemon.attributes").expanduser()
        if ql_dir.exists():
            thumbnail_entries.append(ql_dir)

        # 2. Recent Documents Plist Audit
        plist_path = self._get_recent_items_plist()
        if plist_path.exists():
            try:
                with open(plist_path, "rb") as f:
                    data = plistlib.load(f)
                
                # com.apple.LSSharedFileList.RecentDocuments usually stores items in a 'CustomListItems' array
                items = data.get("CustomListItems", [])
                target_names = {p.name.lower() for p in file_paths}

                for item in items:
                    name = item.get("Name", "")
                    if name.lower() in target_names:
                        recent_file_entries.append(f"RecentDocs Plist: {name}")
            except Exception as exc:
                logger.debug("Failed to audit macOS RecentDocuments plist: %s", exc)
                skipped_components.append("recent_documents_plist")
        else:
            skipped_components.append("recent_documents_plist")

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

        # 1. Clean QuickLook Cache
        # Run qlmanage -r cache to discard all QuickLook cache database/thumbnails
        try:
            subprocess.run(
                ["qlmanage", "-r", "cache"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5
            )
            thumbnails_removed += 1
        except Exception as exc:
            errors.append(f"Failed to clear macOS QuickLook cache: {exc}")

        # 2. Clean Recent Documents Plist
        plist_path = self._get_recent_items_plist()
        if plist_path.exists():
            try:
                # We can try to clear system-wide recents using the defaults command
                subprocess.run(
                    ["defaults", "delete", "com.apple.LSSharedFileList.RecentDocuments"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5
                )
                
                # Force-reload sharedfilelist daemon to apply changes
                subprocess.run(
                    ["killall", "sharedfilelistd"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5
                )
                recent_entries_removed += 1
            except Exception as exc:
                errors.append(f"Failed to clear com.apple.LSSharedFileList.RecentDocuments: {exc}")
        
        try:
            # Clear global navigation recent places
            subprocess.run(
                ["defaults", "delete", "-g", "NSNavRecentPlaces"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5
            )
        except Exception:
            pass

        return CleanResult(
            thumbnails_removed=thumbnails_removed,
            recent_entries_removed=recent_entries_removed,
            errors=errors,
            total_removed=thumbnails_removed + recent_entries_removed,
        )

    def exclude_directory_from_indexing(self, directory: Path) -> bool:
        """
        Exclude directory from Spotlight indexing by writing .metadata_never_index
        and executing mdutil -i off.
        """
        # First write markers
        self.write_nomedia_markers(directory)

        # Run mdutil -i off <directory>
        try:
            subprocess.run(
                ["mdutil", "-i", "off", str(directory.resolve())],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5
            )
            return True
        except Exception as exc:
            logger.warning("Failed to exclude directory %s from Spotlight indexing: %s", directory, exc)
            return False
