"""
windows/artifact_cleaner.py -- Windows-native OS artifact search and removal.
"""

from __future__ import annotations

import os
import ctypes
import winreg
import logging
from pathlib import Path

from ghostdrive.platform.artifact_cleaner import ArtifactCleanerBase, ArtifactReport, CleanResult

logger = logging.getLogger(__name__)

# Windows Constants
FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x2000


class WindowsArtifactCleaner(ArtifactCleanerBase):
    """
    Windows-native implementation of artifact cleaner.
    Cleans:
      - Recent files shortcuts (.lnk) in %APPDATA%\\Microsoft\\Windows\\Recent
      - RecentDocs registry entries (HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs)
      - Explorer Thumbcache files (identifies thumbcache_*.db in %LOCALAPPDATA%\\Microsoft\\Windows\\Explorer)
    """

    def is_available(self) -> bool:
        return True

    def _get_recent_folder(self) -> Path:
        """Get the shell Recent path, default to environment path if lookup fails."""
        try:
            buf = ctypes.create_unicode_buffer(ctypes.wintypes.MAX_PATH)
            # CSIDL_RECENT is 0x0008
            ctypes.windll.shell32.SHGetFolderPathW(None, 0x0008, None, 0, buf)
            if buf.value:
                return Path(buf.value)
        except Exception as exc:
            logger.debug("SHGetFolderPathW for CSIDL_RECENT failed: %s", exc)
        return Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Recent"

    def _get_thumbcache_folder(self) -> Path:
        return Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "Windows" / "Explorer"

    def audit(self, file_paths: list[Path]) -> ArtifactReport:
        thumbnail_entries: list[Path] = []
        recent_file_entries: list[str] = []
        search_index_hits: list[str] = []
        skipped_components: list[str] = []

        # 1. Audit Recent LNK Files
        recent_dir = self._get_recent_folder()
        if recent_dir.exists() and recent_dir.is_dir():
            try:
                # Compile target names for quick lookup
                target_names = {p.name.lower() for p in file_paths}
                for entry in recent_dir.iterdir():
                    if entry.is_file() and entry.suffix.lower() == ".lnk":
                        # We can match on name: e.g. "my_file.txt.lnk" or "my_file.lnk"
                        lnk_name = entry.name.lower()
                        # Strip .lnk
                        base_lnk = lnk_name[:-4]
                        for target in target_names:
                            if target == base_lnk or base_lnk.endswith(target):
                                recent_file_entries.append(str(entry))
                                break
            except Exception as exc:
                logger.debug("Error auditing recent folder: %s", exc)
                skipped_components.append("recent_shortcuts_folder")
        else:
            skipped_components.append("recent_shortcuts_folder")

        # 2. Audit RecentDocs Registry
        try:
            reg_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
            target_basenames_bytes = []
            for p in file_paths:
                # UTF-16LE is how Windows Registry stores file/folder names in RecentDocs
                target_basenames_bytes.append(p.name.encode("utf-16-le"))
                # Also check full path if it got stored there
                target_basenames_bytes.append(str(p).encode("utf-16-le"))

            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_READ) as key:
                # The root RecentDocs key and extensions subkeys
                subkeys = [""]
                try:
                    i = 0
                    while True:
                        subkey_name = winreg.EnumKey(key, i)
                        subkeys.append(subkey_name)
                        i += 1
                except OSError:
                    pass

                for subkey in subkeys:
                    sub_path = f"{reg_path}\\{subkey}" if subkey else reg_path
                    try:
                        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub_path, 0, winreg.KEY_READ) as skey:
                            val_idx = 0
                            while True:
                                val_name, val_data, val_type = winreg.EnumValue(skey, val_idx)
                                if val_name != "MRUListEx" and isinstance(val_data, bytes):
                                    # Search for any target file name byte patterns in the binary entry
                                    for t_bytes in target_basenames_bytes:
                                        if t_bytes in val_data:
                                            recent_file_entries.append(f"Registry: {sub_path}\\{val_name}")
                                            break
                                val_idx += 1
                    except OSError:
                        pass
        except Exception as exc:
            logger.debug("Error auditing RecentDocs registry: %s", exc)
            skipped_components.append("recentdocs_registry")

        # 3. Audit Thumbcache Files
        # On Windows, we can't surgically search within thumbcache db files easily,
        # but if the user has opened the file and generated thumbnails, the entire
        # thumbcache db files under Microsoft\Windows\Explorer are affected.
        # We list the thumbcache db files as the candidate thumbnail entries.
        thumb_dir = self._get_thumbcache_folder()
        if thumb_dir.exists() and thumb_dir.is_dir():
            try:
                for entry in thumb_dir.iterdir():
                    if entry.is_file() and entry.name.startswith("thumbcache_") and entry.suffix.lower() == ".db":
                        thumbnail_entries.append(entry)
            except Exception as exc:
                logger.debug("Error auditing thumbcache folder: %s", exc)
                skipped_components.append("thumbcache_folder")
        else:
            skipped_components.append("thumbcache_folder")

        total_found = len(thumbnail_entries) + len(recent_file_entries) + len(search_index_hits)
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

        # 1. Clean Recent Shortcuts
        recent_dir = self._get_recent_folder()
        if recent_dir.exists() and recent_dir.is_dir():
            try:
                target_names = {p.name.lower() for p in file_paths}
                for entry in list(recent_dir.iterdir()):
                    if entry.is_file() and entry.suffix.lower() == ".lnk":
                        lnk_name = entry.name.lower()
                        base_lnk = lnk_name[:-4]
                        for target in target_names:
                            if target == base_lnk or base_lnk.endswith(target):
                                try:
                                    entry.unlink()
                                    recent_entries_removed += 1
                                except Exception as exc:
                                    errors.append(f"Failed to delete shortcut {entry.name}: {exc}")
                                break
            except Exception as exc:
                errors.append(f"Failed to scan recent directory for clean: {exc}")

        # 2. Clean RecentDocs Registry
        try:
            reg_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
            target_basenames_bytes = []
            for p in file_paths:
                target_basenames_bytes.append(p.name.encode("utf-16-le"))
                target_basenames_bytes.append(str(p).encode("utf-16-le"))

            # Open with write access
            subkeys = [""]
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_READ) as key:
                    i = 0
                    while True:
                        subkey_name = winreg.EnumKey(key, i)
                        subkeys.append(subkey_name)
                        i += 1
            except OSError:
                pass

            for subkey in subkeys:
                sub_path = f"{reg_path}\\{subkey}" if subkey else reg_path
                try:
                    # Open key with read/write permission to modify it
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub_path, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as skey:
                        values_to_delete = []
                        val_idx = 0
                        while True:
                            try:
                                val_name, val_data, val_type = winreg.EnumValue(skey, val_idx)
                                if val_name != "MRUListEx" and isinstance(val_data, bytes):
                                    for t_bytes in target_basenames_bytes:
                                        if t_bytes in val_data:
                                            values_to_delete.append(val_name)
                                            break
                                val_idx += 1
                            except OSError:
                                break

                        for val_name in values_to_delete:
                            try:
                                winreg.DeleteValue(skey, val_name)
                                recent_entries_removed += 1
                            except Exception as exc:
                                errors.append(f"Failed to delete registry value {sub_path}\\{val_name}: {exc}")
                except OSError:
                    pass
        except Exception as exc:
            errors.append(f"Failed to prune RecentDocs registry: {exc}")

        # 3. Clean Thumbcache
        # Thumbcache databases are active and held locked by Explorer.
        # Direct deletion of files will fail. The typical way is to let Windows know
        # or clear them if possible. Since we can't reliably delete the files themselves
        # without killing Explorer, we can attempt deletion of any we can, but otherwise
        # we log errors or skip gracefully.
        thumb_dir = self._get_thumbcache_folder()
        if thumb_dir.exists() and thumb_dir.is_dir():
            try:
                for entry in thumb_dir.iterdir():
                    if entry.is_file() and entry.name.startswith("thumbcache_") and entry.suffix.lower() == ".db":
                        try:
                            # Try to delete -- it will likely raise PermissionError if locked
                            entry.unlink()
                            thumbnails_removed += 1
                        except PermissionError:
                            # Locked, this is expected behavior on Windows.
                            # We can register to delete on reboot, or notify user.
                            pass
                        except Exception as exc:
                            errors.append(f"Failed to delete thumbcache file {entry.name}: {exc}")
            except Exception as exc:
                errors.append(f"Failed to clear thumbcache directory: {exc}")

        return CleanResult(
            thumbnails_removed=thumbnails_removed,
            recent_entries_removed=recent_entries_removed,
            errors=errors,
            total_removed=thumbnails_removed + recent_entries_removed,
        )

    def exclude_directory_from_indexing(self, directory: Path) -> bool:
        """
        Configure Windows Search indexer to exclude `directory` using standard
        FILE_ATTRIBUTE_NOT_CONTENT_INDEXED attribute.
        """
        if not directory.exists():
            try:
                directory.mkdir(parents=True, exist_ok=True)
            except Exception as exc:
                logger.warning("Could not create directory for indexing exclusion: %s", exc)
                return False

        try:
            path_str = str(directory)
            kernel32 = ctypes.windll.kernel32
            attrs = kernel32.GetFileAttributesW(path_str)
            if attrs == -1:
                return False
            # Add the flag if it's not set
            if not (attrs & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED):
                success = kernel32.SetFileAttributesW(path_str, attrs | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)
                return bool(success)
            return True
        except Exception as exc:
            logger.warning("Failed to exclude directory %s from content indexing: %s", directory, exc)
            return False
