"""
remote_access.py -- Reach GhostDrive from your own phone, safely.

GhostDrive's web server binds ``127.0.0.1`` only (``web/server.py::main``):
nothing listens on the LAN or the internet unless the operator deliberately
opens a path. This module is the honest helper for that deliberate step:

* ``detect_tailscale`` finds a locally installed Tailscale CLI and asks it for
  this machine's Tailscale IPv4 (``tailscale ip -4``, 5 s timeout). It never
  raises -- detection is best-effort and every failure lands in ``error``.
* ``local_urls`` / ``remote_urls`` build the operator-facing URLs; the remote
  one exists only when Tailscale is actually running, i.e. when a phone on the
  same tailnet could reach this machine.
* ``resolve_port`` surfaces the *configured* HTTP port (settings key
  ``http_port`` -> env ``GHOSTDRIVE_PORT`` -> 8000). The port the process
  actually binds is chosen by the launcher (``server.py::find_available_port``
  scans upward from 8000); from another context we cannot observe the socket,
  so this reports configured intent, not a bound-port fact.
* ``access_status`` combines all of the above into the JSON shape served by
  the ``/api/pairing`` and ``/api/remote`` routes.

What this module deliberately does NOT do: open firewall holes, bind to
``0.0.0.0``, start/reconfigure Tailscale, or proxy any traffic. Remote access
is operator-owned; we only report what we can see. See docs/REMOTE_ACCESS.md.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from typing import Any, Callable, Optional

logger = logging.getLogger("ghostdrive.services.remote_access")

#: Settings key for the operator-declared HTTP port (see resolve_port).
SETTING_HTTP_PORT = "http_port"

#: Environment fallback for the HTTP port, read when the setting is unset.
ENV_PORT = "GHOSTDRIVE_PORT"

#: Last-resort default; matches server.py's find_available_port start value.
DEFAULT_PORT = 8000

#: Subprocess budget for one ``tailscale ip -4`` call.
TAILSCALE_TIMEOUT_SECONDS = 5.0

# Loose IPv4 shape check -- "is this plausibly an address", not full validation.
_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# Windows default install location, used when `tailscale` is not on PATH.
_WINDOWS_FALLBACK = os.path.join(
    os.environ.get("ProgramFiles") or r"C:\Program Files",
    "Tailscale",
    "tailscale.exe",
)

#: Extra binary locations checked after shutil.which (patched in tests).
_FALLBACK_PATHS: tuple[str, ...] = (_WINDOWS_FALLBACK,)


def _find_tailscale_binary() -> Optional[str]:
    """Locate the tailscale CLI: PATH first, then known install locations."""
    found = shutil.which("tailscale")
    if found:
        return found
    for candidate in _FALLBACK_PATHS:
        if candidate and os.path.isfile(candidate):
            return candidate
    return None


def _run_command(cmd: list[str], timeout: float) -> Any:
    """Default command runner: subprocess.run with captured text output."""
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, check=False
    )


def detect_tailscale(command_runner: Optional[Callable] = None) -> dict:
    """Best-effort Tailscale detection. Never raises.

    Returns ``{"installed", "running", "ip", "method", "error"}``. ``method``
    is ``"cli"`` when the address came from ``tailscale ip -4``. The
    ``command_runner`` hook (``cmd, timeout -> CompletedProcess-like``) exists
    so tests never spawn a real subprocess.
    """
    result: dict[str, Any] = {
        "installed": False,
        "running": False,
        "ip": None,
        "method": None,
        "error": None,
    }
    try:
        binary = _find_tailscale_binary()
        if not binary:
            result["error"] = "Tailscale CLI not found on PATH."
            return result
        result["installed"] = True

        runner = command_runner or _run_command
        completed = runner(
            [binary, "ip", "-4"],
            TAILSCALE_TIMEOUT_SECONDS,
        )
        returncode = getattr(completed, "returncode", 1)
        stdout = str(getattr(completed, "stdout", "") or "")
        if returncode != 0:
            stderr = str(getattr(completed, "stderr", "") or "").strip()
            detail = f": {stderr[:200]}" if stderr else "."
            result["error"] = f"tailscale ip -4 exited {returncode}{detail}"
            return result

        for line in stdout.splitlines():
            line = line.strip()
            if _IPV4_RE.match(line):
                result["running"] = True
                result["ip"] = line
                result["method"] = "cli"
                return result
        result["error"] = "tailscale ip -4 returned no IPv4 address."
    except Exception as exc:  # noqa: BLE001 -- detection must never propagate
        result["running"] = False
        result["ip"] = None
        result["error"] = f"{type(exc).__name__}: {exc}"
        logger.debug("Tailscale detection failed: %s", exc)
    return result


def local_urls(port: int) -> list[str]:
    """Loopback URLs for this machine (both spellings of localhost)."""
    return [f"http://127.0.0.1:{port}/", f"http://localhost:{port}/"]


def remote_urls(port: int, tailscale: dict) -> list[str]:
    """Tailscale URL for the phone, or [] when no address is usable."""
    if not isinstance(tailscale, dict) or not tailscale.get("running"):
        return []
    ip = str(tailscale.get("ip") or "")
    if not _IPV4_RE.match(ip):
        return []
    return [f"http://{ip}:{port}/"]


def resolve_port(db: Any = None, default: int = DEFAULT_PORT) -> int:
    """Configured HTTP port: settings ``http_port`` -> env -> default.

    Reads the settings table only when an open ``db`` is handed in; a locked
    vault (no db) still answers from the environment. Only values in
    1..65535 are honored; anything else falls through to the next source.
    """
    if db is not None:
        try:
            raw = str(db.get_setting(SETTING_HTTP_PORT, "") or "").strip()
            port = int(raw)
            if 1 <= port <= 65535:
                return port
        except Exception as exc:
            logger.debug("http_port setting unreadable: %s", exc)

    raw_env = str(os.environ.get(ENV_PORT, "") or "").strip()
    try:
        port = int(raw_env)
        if 1 <= port <= 65535:
            return port
    except ValueError:
        pass
    return int(default)


def access_status(db: Any = None, port: Optional[int] = None) -> dict:
    """One JSON blob describing how (and whether) a phone can reach this app.

    ``db`` may be ``None`` (vault locked): the shape is identical either way,
    ``vault_unlocked`` flips to False and the only DB-dependent field -- the
    ``http_port`` setting -- falls back to env/default. The ``steps`` list is
    deterministic: the first step is a server-side fact (we are answering the
    request), the Tailscale steps come from ``detect_tailscale``, and the final
    "scan the QR / open the URL" step is always ``done: false`` because the
    server cannot observe the phone.
    """
    resolved_port = int(port) if port else resolve_port(db)
    tailscale = detect_tailscale()
    ready = bool(tailscale.get("running") and tailscale.get("ip"))
    return {
        "bind": "127.0.0.1",
        "port": resolved_port,
        "vault_unlocked": db is not None,
        "local_urls": local_urls(resolved_port),
        "tailscale": tailscale,
        "remote_urls": remote_urls(resolved_port, tailscale),
        "ready_for_phone": ready,
        "safety": [
            "The server listens on 127.0.0.1 only; nothing is reachable "
            "from the network without a tunnel you set up yourself.",
            "Remote URLs are reachable only inside your own Tailscale "
            "network (WireGuard-encrypted on the wire).",
            "HTTP itself is plain (no TLS): the tunnel encrypts the "
            "transport, not the application layer.",
            "The vault still requires the passphrase after the phone "
            "connects; pairing never unlocks anything.",
        ],
        "steps": [
            {
                "id": "app_running",
                "label": "GhostDrive web server is running",
                "done": True,
            },
            {
                "id": "tailscale_installed",
                "label": "Tailscale is installed on this machine",
                "done": bool(tailscale.get("installed")),
            },
            {
                "id": "tailscale_running",
                "label": "Tailscale is connected (signed in and up)",
                "done": bool(tailscale.get("running")),
            },
            {
                "id": "phone_scan_qr",
                "label": "Scan the QR code or open the remote URL on your phone",
                "done": False,
            },
        ],
    }
