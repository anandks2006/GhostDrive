"""
factory_reset.py -- Full local factory reset: erase credentials and vault data.

Use case: the user lost their passphrase and has no recovery phrase, so the
existing vault is unrecoverable. This service returns the machine to the
first-run state (no keystore, no index, no local ciphertext, no keyring
entries) so a brand-new vault can be created.

The wipe deliberately needs NO passphrase: a forgotten passphrase cannot
decrypt anything anyway, and the web UI binds to 127.0.0.1 only. Accidental
execution is prevented by a typed confirmation phrase at the route/UI layer
(``CONFIRM_PHRASE``), not by authentication.

What is erased:
  1. Background schedulers (sync, drills, alerts, protection watcher) so no
     task races the wipe or re-creates files afterwards.
  2. Every known-name file in the app data dir: keystore.json, the database
     and its WAL/SHM sidecars, nonce_counter.json, the local vault folder
     (local backend ciphertext), staged updates, and the log file.
     A known-name allowlist is used instead of nuking the whole directory so
     a user-configured GHOSTDRIVE_DATA_DIR that happens to contain unrelated
     files does not lose them.
  3. OS keyring entries under the "ghostdrive" service: refs recorded in the
     backends table (read BEFORE the database is closed), the static backend
     keys, and -- on Windows -- an enumeration sweep that also removes
     orphaned entries while the vault is locked (the DB is unreadable then).
  4. In-memory preferences, so no stale settings leak into the new vault.
"""

from __future__ import annotations

import logging
import shutil
import sys
from pathlib import Path
from typing import Any, Iterable, Optional

from ghostdrive.crypto.credential_store import _KEYRING_SERVICE, credential_store
from ghostdrive.web.state import DEFAULT_SETTINGS, state

logger = logging.getLogger("ghostdrive_web.factory_reset")

#: Typed-confirmation phrase required by the route/UI before wiping.
CONFIRM_PHRASE = "ERASE EVERYTHING"

#: Keyring keys that are not derived from backend rows (fixed names used by
#: the Telegram/Discord backends and by backend registration). Deleted even
#: when the database is locked and its backends table cannot be read.
STATIC_KEYRING_KEYS: tuple[str, ...] = (
    "telegram_api_id",
    "telegram_api_hash",
    "telegram_session",
    "discord_bot_token",
    "discord_channel_id",
)

#: Known-name allowlist of app-data files a factory reset removes. Anything
#: else in the directory is left alone (defensive: GHOSTDRIVE_DATA_DIR may be
#: user-configured and could contain unrelated files).
_WIPE_FILE_NAMES: tuple[str, ...] = (
    "keystore.json",
    "ghostdrive.db",
    "ghostdrive.db-wal",
    "ghostdrive.db-shm",
    "ghostdrive.db-journal",
    "nonce_counter.json",
    "ghostdrive.log",
)
_WIPE_DIR_NAMES: tuple[str, ...] = (
    "vault",     # local backend ciphertext root (services/context.py)
    "updates",   # staged updater downloads (platform/updater.py)
)

#: Cap for the Windows credential sweep -- a healthy install has fewer than a
#: dozen entries; this only bounds pathological stores.
_MAX_ENUM_CREDENTIALS = 512


# ── Keyring ───────────────────────────────────────────────────────────────────

def collect_keyring_refs(db: Any = None) -> set[str]:
    """
    Return every keyring key name GhostDrive may have stored.

    Combines the fixed backend keys with per-backend refs (``credentials_ref``
    and ``local_root_{id}``) read from the backends table. ``db`` may be None
    (locked vault) -- the static keys are still returned.
    """
    refs: set[str] = set(STATIC_KEYRING_KEYS)
    if db is not None and getattr(db, "_conn", None) is not None:
        try:
            rows = db._conn.execute("SELECT id, credentials_ref FROM backends").fetchall()
            for row in rows:
                refs.add(row["credentials_ref"])
                refs.add(f"local_root_{row['id']}")
        except Exception as exc:
            # Reading refs is best-effort: the Windows sweep below still
            # catches everything under the service name.
            logger.warning("factory_reset: could not read backend keyring refs: %s", exc)
    return refs


def _wipe_keyring_keys(keys: Iterable[str]) -> list[str]:
    """Delete known keys via the keyring API. Returns the deleted key names."""
    import keyring

    deleted: list[str] = []
    for key in sorted(set(keys)):
        try:
            keyring.delete_password(_KEYRING_SERVICE, key)
            deleted.append(key)
        except Exception:
            # delete_password raises when the entry does not exist on some
            # backends; an absent entry is already the desired state.
            pass
    return deleted


def _wipe_windows_keyring_enum(service: str = _KEYRING_SERVICE) -> list[str]:
    """
    Windows-only: enumerate Credential Manager and delete every credential
    belonging to GhostDrive's service.

    keyring has no cross-platform enumeration API, and while the vault is
    locked the database (which records per-backend key names) is unreadable.
    WinVaultKeyring stores targets as ``service`` for the first entry and
    ``{username}@{service}`` for collisions, so we sweep both shapes and
    delete by exact target name. Returns deleted target names.
    """
    if sys.platform != "win32":
        return []
    import ctypes
    from ctypes import wintypes

    credential_struct = type(
        "CREDENTIALW",
        (ctypes.Structure,),
        {
            "_fields_": [
                ("Flags", wintypes.DWORD),
                ("Type", wintypes.DWORD),
                ("TargetName", wintypes.LPWSTR),
                ("Comment", wintypes.LPWSTR),
                ("LastWritten", wintypes.FILETIME),
                ("CredentialBlobSize", wintypes.DWORD),
                ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
                ("Persist", wintypes.DWORD),
                ("AttributeCount", wintypes.DWORD),
                ("Attributes", ctypes.c_void_p),
                ("TargetAlias", wintypes.LPWSTR),
                ("UserName", wintypes.LPWSTR),
            ],
        },
    )
    advapi32 = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
    advapi32.CredEnumerateW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(ctypes.POINTER(ctypes.POINTER(credential_struct))),
    ]
    advapi32.CredEnumerateW.restype = wintypes.BOOL
    advapi32.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
    advapi32.CredDeleteW.restype = wintypes.BOOL
    advapi32.CredFree.argtypes = [ctypes.c_void_p]
    advapi32.CredFree.restype = None

    count = wintypes.DWORD()
    pointer = ctypes.POINTER(ctypes.POINTER(credential_struct))()
    # Filter None enumerates every generic credential on the machine; we only
    # *inspect* targets belonging to our service and delete those (bounded by
    # _MAX_ENUM_CREDENTIALS). No other credential is read or modified.
    if not advapi32.CredEnumerateW(None, 0, ctypes.byref(count), ctypes.byref(pointer)):
        return []
    deleted: list[str] = []
    try:
        for i in range(min(count.value, _MAX_ENUM_CREDENTIALS)):
            cred = pointer[i].contents
            target = cred.TargetName or ""
            if target != service and not target.endswith(f"@{service}"):
                continue
            if advapi32.CredDeleteW(target, cred.Type, 0):
                deleted.append(target)
                logger.info("factory_reset: deleted keyring credential '%s'.", target)
    finally:
        advapi32.CredFree(pointer)
    return deleted


def wipe_keyring(refs: Iterable[str]) -> list[str]:
    """
    Remove GhostDrive keyring entries by known key name and, on Windows, by
    Credential Manager enumeration (catches orphans while the vault is
    locked). Returns a combined, de-duplicated list of removed names.
    """
    removed = _wipe_keyring_keys(refs)
    try:
        removed.extend(_wipe_windows_keyring_enum())
    except Exception as exc:
        # Enumeration is a best-effort completeness step; known-name deletion
        # above already ran.
        logger.warning("factory_reset: keyring enumeration sweep failed: %s", exc)
    return sorted(set(removed))


# ── Filesystem ────────────────────────────────────────────────────────────────

def wipe_app_data(app_data_dir: Path) -> list[str]:
    """Delete known-name vault files/dirs under ``app_data_dir``. Returns paths removed."""
    removed: list[str] = []
    app_data_dir = Path(app_data_dir)
    if not app_data_dir.is_dir():
        return removed
    for name in _WIPE_FILE_NAMES:
        path = app_data_dir / name
        if path.exists():
            path.unlink()
            removed.append(str(path))
    for name in _WIPE_DIR_NAMES:
        path = app_data_dir / name
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)
            removed.append(str(path))
        elif path.exists():
            path.unlink()
            removed.append(str(path))
    return removed


def _stop_background_jobs() -> None:
    """Stop schedulers/watchers so nothing races the wipe or re-creates files.

    Every stop is defensive: the reset must succeed even when a subsystem is
    missing, already stopped, or mid-refactor.
    """
    stops = (
        ("ghostdrive.services.sync", "stop_sync_scheduler"),
        ("ghostdrive.services.restore_drills", "stop_drill_scheduler"),
        ("ghostdrive.services.alerts", "stop_alerts_scheduler"),
        ("ghostdrive.services.protection", "stop_watcher"),
        ("ghostdrive.services.canary", "stop_canary_scheduler"),
        ("ghostdrive.services.mass_alarm", "stop_mass_alarm_scheduler"),
        ("ghostdrive.services.inheritance", "stop_inheritance_scheduler"),
        ("ghostdrive.services.health_report", "stop_health_report_scheduler"),
        ("ghostdrive.services.airgap", "stop_airgap_scheduler"),
    )
    for module_name, func_name in stops:
        try:
            module = __import__(module_name, fromlist=[func_name])
            getattr(module, func_name)()
        except Exception as exc:
            logger.debug("factory_reset: %s.%s not stopped: %s", module_name, func_name, exc)


# ── Entry point ───────────────────────────────────────────────────────────────

def perform_factory_reset(
    app_state: Any = None,
    keyring_refs: Optional[set[str]] = None,
) -> dict:
    """
    Erase all local GhostDrive credentials and vault data.

    Works whether the vault is locked or unlocked (no passphrase required).
    The caller (route/UI) is responsible for checking CONFIRM_PHRASE.

    Args:
        app_state: GlobalState-like object; defaults to the process singleton.
        keyring_refs: Optional pre-collected refs (tests); otherwise read from
            the open database before it is closed.

    Returns:
        {"status": "success", "keyring_entries": [...], "deleted_paths": [...]}
    """
    app_state = app_state if app_state is not None else state

    # 1. Stop background jobs first -- a sync pass racing the wipe could
    #    re-create the database after it was deleted.
    _stop_background_jobs()

    # 2. Collect keyring refs while the DB may still be readable, then close
    #    everything and zero key material in memory.
    if keyring_refs is None:
        keyring_refs = collect_keyring_refs(getattr(app_state, "db", None))
    app_state.clean_shutdown()
    # Belt-and-braces: clean_shutdown clears the credential key, but make the
    # post-reset state explicit for callers that use a custom app_state.
    credential_store.clear_active_key()

    # 3. Wipe files, then keyring.
    deleted_paths = wipe_app_data(app_state.app_data_dir)
    keyring_entries = wipe_keyring(keyring_refs)

    # 4. Reset in-memory preferences so nothing from the old vault leaks into
    #    the new one (the persisted copies died with the database).
    app_state.settings = dict(DEFAULT_SETTINGS)
    app_state._settings_loaded = False

    logger.warning(
        "factory_reset: wiped %d path(s) under %s and %d keyring entry/entries.",
        len(deleted_paths), app_state.app_data_dir, len(keyring_entries),
    )
    return {
        "status": "success",
        "keyring_entries": keyring_entries,
        "deleted_paths": deleted_paths,
        "message": "Vault erased. The app is back in first-run state.",
    }
