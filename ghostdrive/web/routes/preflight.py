"""
preflight.py -- Pre-flight system and connectivity diagnostics endpoint.
"""

import socket
import os
import keyring
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Dict, Any

router = APIRouter(prefix="/api/preflight", tags=["preflight"])

class DiagnosticsResponse(BaseModel):
    all_passed: bool
    keyring_ok: bool
    keyring_msg: str
    database_ok: bool
    database_msg: str
    network_ok: bool
    network_msg: str
    long_paths_ok: bool
    long_paths_msg: str
    inotify_ok: bool
    inotify_msg: str

@router.get("/run", response_model=DiagnosticsResponse)
def run_diagnostics() -> DiagnosticsResponse:
    """Runs pre-flight system diagnostics."""
    all_passed = True

    # 1. Keyring Access Check
    keyring_ok = False
    keyring_msg = ""
    try:
        kr = keyring.get_keyring()
        if kr is not None:
            keyring_ok = True
            keyring_msg = f"Keyring backend loaded: {kr.__class__.__name__}"
        else:
            keyring_msg = "No keyring backend found."
    except Exception as exc:
        keyring_msg = f"Keyring check failed: {exc}"
    
    if not keyring_ok:
        all_passed = False

    # 2. Database Write Access Check
    db_ok = True
    db_msg = "Application data directory is writable."
    try:
        import tempfile
        from ghostdrive.web.state import state
        state.app_data_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=state.app_data_dir, prefix=".gd_write_", delete=True) as handle:
            handle.write(b"test")
            handle.flush()
    except Exception as exc:
        db_ok = False
        db_msg = f"Write access check failed: {exc}"
        all_passed = False

    # 3. Internet Reachability Check
    net_ok = False
    net_msg = ""
    hosts = ["discord.com", "google.com", "api.telegram.org"]
    socket.setdefaulttimeout(3)
    for host in hosts:
        try:
            socket.gethostbyname(host)
            net_ok = True
            net_msg = f"Internet reachability verified via {host}."
            break
        except Exception:
            pass
    if not net_ok:
        net_msg = "Local-Only Pipeline Active"

    # 4. System Checks (Long paths & inotify)
    long_paths_ok = True
    long_paths_msg = "Windows long paths support enabled or non-Windows OS."
    if os.name == "nt":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\FileSystem") as key:
                val, _ = winreg.QueryValueEx(key, "LongPathsEnabled")
                if val != 1:
                    long_paths_ok = False
                    long_paths_msg = "Windows Long Paths are disabled in registry (Max 260 chars limit)."
        except Exception:
            long_paths_ok = True
            long_paths_msg = "Registry query skipped."

    inotify_ok = True
    inotify_msg = "inotify user watches OK."
    if os.name == "posix" and os.path.exists("/proc/sys/fs/inotify/max_user_watches"):
        try:
            with open("/proc/sys/fs/inotify/max_user_watches", "r") as f:
                watches = int(f.read().strip())
                if watches < 524288:
                    inotify_ok = False
                    inotify_msg = f"inotify watches low ({watches} < 524288)."
        except Exception:
            pass

    return DiagnosticsResponse(
        all_passed=all_passed,
        keyring_ok=keyring_ok,
        keyring_msg=keyring_msg,
        database_ok=db_ok,
        database_msg=db_msg,
        network_ok=net_ok,
        network_msg=net_msg,
        long_paths_ok=long_paths_ok,
        long_paths_msg=long_paths_msg,
        inotify_ok=inotify_ok,
        inotify_msg=inotify_msg,
    )
