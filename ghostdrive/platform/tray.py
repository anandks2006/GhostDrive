"""
tray.py -- Cross-platform system tray daemon for GhostDrive.

Runs the web server on a background thread and exposes a tray menu:

    Open GhostDrive      open the web UI in the browser
    Start with system    toggle autostart (reuses platform/autostart.py)
    Server status        live port + vault state (radio items, non-actionable)
    Quit                 stop the server and exit

``pystray`` + ``Pillow`` are OPTIONAL dependencies (``poetry install --with tray``):
the tray is imported lazily so servers/CLI/tests never need them, and
:func:`tray_available` reports why when they are missing.

Everything except the actual ``pystray.Icon.run()`` loop is pure logic and is
unit-tested headlessly: menu construction, server lifecycle, autostart toggle.
"""

from __future__ import annotations

import logging
import threading
import webbrowser
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

APP_NAME = "GhostDrive"

# ─── Optional dependency probe ────────────────────────────────────────────────


def tray_available() -> tuple[bool, str]:
    """Return (available, reason-if-not) for the tray's optional deps."""
    try:
        import pystray  # noqa: F401
    except ImportError:
        return False, "pystray is not installed (poetry install --with tray)."
    try:
        from PIL import Image  # noqa: F401
    except ImportError:
        return False, "Pillow is not installed (poetry install --with tray)."
    return True, ""


# ─── Icon ─────────────────────────────────────────────────────────────────────


def build_icon_image(size: int = 64):
    """
    Draw the GhostDrive glyph (rounded dark square + cyan 'G') with Pillow.

    Returns a ``PIL.Image.Image`` in RGBA. Falls back to a generated
    monochrome image if the bundled SVG asset can't be rasterized.
    """
    from PIL import Image, ImageDraw

    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    pad = max(1, size // 16)
    draw.rounded_rectangle(
        [pad, pad, size - pad - 1, size - pad - 1],
        radius=size // 5,
        fill=(18, 22, 30, 255),
        outline=(0, 229, 255, 255),
        width=max(1, size // 32),
    )
    # Letter "G" as an arc + bar (keeps us dependency-free of fonts).
    bbox = [size * 0.24, size * 0.24, size * 0.76, size * 0.76]
    arc_w = max(2, size // 10)
    draw.arc(bbox, start=-60, end=300, fill=(0, 229, 255, 255), width=arc_w)
    cy = size * 0.5
    draw.line(
        [size * 0.5, cy, size * 0.76, cy],
        fill=(0, 229, 255, 255),
        width=arc_w,
    )
    return img


# ─── Server lifecycle ─────────────────────────────────────────────────────────


class TrayServer:
    """
    Owns the uvicorn server thread for the tray.

    The server is started with ``port=0``-style discovery via
    ``web.server.find_available_port`` and stopped by calling
    ``uvicorn.Server.should_exit`` — the same mechanism Ctrl+C uses, so
    lifespan hooks (protection watcher, WAL checkpoint) still run.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0, log_level: str = "warning"):
        self.host = host
        self.port = port
        self.log_level = log_level
        self._server: Any = None
        self._thread: Optional[threading.Thread] = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def url(self) -> str:
        port = self.port or (getattr(self._server, "port", None) or 0)
        return f"http://{self.host}:{port}"

    def start(self, timeout: float = 20.0) -> str:
        """Start the server on a daemon thread; block until uvicorn accepts."""
        if self.running:
            return self.url

        import time as _time
        import uvicorn

        from ghostdrive.web.server import app, find_available_port

        if not self.port:
            self.port = find_available_port(8000)

        config = uvicorn.Config(
            app,
            host=self.host,
            port=self.port,
            log_level=self.log_level,
            lifespan="on",
        )
        self._server = uvicorn.Server(config)
        # uvicorn installs signal handlers only on the main thread; we run in
        # a worker, so replace the installer with a no-op.
        self._server.install_signal_handlers = lambda: None  # type: ignore[method-assign]

        def _run() -> None:
            self._server.run()

        self._thread = threading.Thread(target=_run, name="ghostdrive-tray-server", daemon=True)
        self._thread.start()

        deadline = _time.monotonic() + timeout
        while not self._server.started:
            if not self._thread.is_alive():
                raise RuntimeError("Tray server thread exited before starting.")
            if _time.monotonic() > deadline:
                raise TimeoutError("Tray server did not start within the timeout.")
            _time.sleep(0.05)
        return self.url

    def stop(self, timeout: float = 10.0) -> None:
        """Ask the server to exit and wait for the thread to finish."""
        server, self._server = self._server, None
        thread, self._thread = self._thread, None
        if server is not None:
            server.should_exit = True
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)
            if thread.is_alive():
                logger.warning("Tray server thread did not stop within %ss.", timeout)

    def open_browser(self) -> None:
        webbrowser.open(self.url)


# ─── Menu logic (pure, testable) ─────────────────────────────────────────────


class TrayController:
    """
    Menu state + handlers for the tray, independent of any icon library.

    ``notifier`` is an optional callable ``(level, message)`` used by tests;
    the real tray wires it to toast/log output.
    """

    def __init__(
        self,
        server: Optional[TrayServer] = None,
        autostart_fn: Optional[Callable[[bool], bool]] = None,
        autostart_status_fn: Optional[Callable[[], bool]] = None,
        notifier: Optional[Callable[[str, str], None]] = None,
    ):
        self.server = server or TrayServer()
        self._set_autostart = autostart_fn
        self._get_autostart = autostart_status_fn
        self._notify = notifier
        self.started = False
        self.quit_requested = False

    # -- state helpers ------------------------------------------------------

    def autostart_enabled(self) -> bool:
        if self._get_autostart is not None:
            return bool(self._get_autostart())
        from ghostdrive.platform.autostart import is_autostart_enabled

        return is_autostart_enabled()

    def status_text(self) -> str:
        if not self.server.running:
            return "Server: stopped"
        try:
            from ghostdrive.web.state import state

            unlocked = state.km is not None and state.km.is_unlocked
            vault = "unlocked" if unlocked else "locked"
        except Exception:
            vault = "unknown"
        return f"Server: running on {self.server.url} ({vault})"

    # -- menu handlers ------------------------------------------------------

    def on_open(self) -> None:
        self.ensure_running()
        self.server.open_browser()

    def on_toggle_autostart(self) -> None:
        enable = not self.autostart_enabled()
        if self._set_autostart is not None:
            ok = self._set_autostart(enable)
        else:
            from ghostdrive.platform.autostart import set_autostart

            ok = set_autostart(enable)
        self._emit("info" if ok else "error",
                   f"Autostart {'enabled' if ok and enable else 'disabled' if ok else 'change failed'}.")

    def ensure_running(self) -> str:
        if not self.server.running:
            url = self.server.start()
            self.started = True
            self._emit("info", f"GhostDrive server started at {url}")
            return url
        return self.server.url

    def on_quit(self) -> None:
        self.quit_requested = True
        if self.server.running:
            self.server.stop()
        self._emit("info", "GhostDrive tray stopped.")

    def _emit(self, level: str, message: str) -> None:
        logger.info("%s", message)
        if self._notify is not None:
            try:
                self._notify(level, message)
            except Exception:
                logger.debug("Tray notifier failed", exc_info=True)

    # -- menu description ---------------------------------------------------

    def menu_spec(self) -> list:
        """
        Declarative menu description consumed by :func:`run_tray`.

        Returns a list of entries: ``("item", label, handler)``,
        ``("checked", label, checked, handler)``, ``("separator",)``,
        ``("radio", label, selected, handler)``.
        """
        status = self.status_text()
        return [
            ("item", "Open GhostDrive", self.on_open),
            ("checked", "Start with system", self.autostart_enabled(), self.on_toggle_autostart),
            ("separator",),
            ("radio", status, self.server.running, lambda: None),
            ("separator",),
            ("item", "Quit", self.on_quit),
        ]


# ─── Entry point ─────────────────────────────────────────────────────────────


def run_tray(argv: Optional[list[str]] = None) -> int:
    """
    Console-script entry: start the tray (and with it the server).

    Returns a nonzero exit code with a clear message when the optional
    dependencies are missing.
    """
    import argparse

    parser = argparse.ArgumentParser(prog="ghostdrive-tray", description="GhostDrive system tray daemon.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--no-autostart-server", action="store_true",
                        help="Do not start the web server until 'Open GhostDrive' is clicked.")
    args = parser.parse_args(argv)

    ok, reason = tray_available()
    if not ok:
        print(f"Tray unavailable: {reason}")
        return 3

    import pystray

    controller = TrayController(server=TrayServer(host=args.host, port=args.port))
    if not args.no_autostart_server:
        try:
            controller.ensure_running()
        except Exception as exc:
            print(f"Failed to start server: {exc}")
            return 1

    def to_pystray(spec: list) -> "pystray.Menu":
        """
        Translate ``menu_spec()`` into a pystray.Menu.

        Labels/checked/state are bound as callables where pystray supports it,
        so the status line and autostart tick re-evaluate on every open instead
        of freezing at construction time.
        """
        items = []
        for entry in spec:
            kind = entry[0]
            if kind == "item":
                _, label, handler = entry
                items.append(pystray.MenuItem(
                    label, lambda icon, i=handler: _invoke(i)
                ))
            elif kind == "checked":
                _, label, _initial, handler = entry
                items.append(pystray.MenuItem(
                    label,
                    lambda icon, i=handler: _invoke(i),
                    checked=lambda item: controller.autostart_enabled(),
                ))
            elif kind == "radio":
                _, label, _selected, handler = entry
                items.append(pystray.MenuItem(
                    lambda item: controller.status_text(),
                    lambda icon, i=handler: _invoke(i),
                    radio=True,
                    default=lambda item: controller.server.running,
                ))
            elif kind == "separator":
                items.append(pystray.Menu.SEPARATOR)
        return pystray.Menu(*items)

    def _invoke(handler: Callable[[], None]) -> None:
        try:
            handler()
            icon.update_menu()
        except Exception:
            logger.exception("Tray menu action failed")

    icon = pystray.Icon(APP_NAME, build_icon_image(), APP_NAME, menu=to_pystray(controller.menu_spec()))

    try:
        icon.run()
    finally:
        controller.on_quit()
    return 0


if __name__ == "__main__":
    raise SystemExit(run_tray())
