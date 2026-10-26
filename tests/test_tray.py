"""
test_tray.py -- Tray daemon logic: availability probe, controller/menu spec,
server lifecycle, autostart wiring. GUI/pystray never imported (lazy by design).
"""

import threading

import pytest

from ghostdrive.platform.tray import (
    TrayController,
    TrayServer,
    tray_available,
)


class FakeServer:
    """Stand-in for TrayServer with observable lifecycle (no sockets)."""

    def __init__(self):
        self.running = False
        self.started_count = 0
        self.stopped_count = 0
        self.opened = 0
        self.url = "http://127.0.0.1:8000"

    def start(self, timeout: float = 20.0) -> str:
        self.running = True
        self.started_count += 1
        return self.url

    def stop(self, timeout: float = 10.0) -> None:
        self.running = False
        self.stopped_count += 1

    def open_browser(self) -> None:
        self.opened += 1


class TestAvailability:
    def test_tray_available_returns_shape(self):
        ok, reason = tray_available()
        assert isinstance(ok, bool)
        assert isinstance(reason, str)
        if not ok:
            # Reason must name the missing dependency, not a stack trace.
            assert "pystray" in reason or "Pillow" in reason
        else:
            assert reason == ""


class TestController:
    def _controller(self, autostart=False):
        notes = []
        server = FakeServer()
        ctl = TrayController(
            server=server,
            autostart_fn=lambda enable: notes.append(("set", enable)) or True,
            autostart_status_fn=lambda: autostart,
            notifier=lambda level, msg: notes.append((level, msg)),
        )
        return ctl, server, notes

    def test_menu_spec_structure(self):
        ctl, server, _ = self._controller()
        spec = ctl.menu_spec()
        kinds = [entry[0] for entry in spec]
        assert kinds == ["item", "checked", "separator", "radio", "separator", "item"]
        labels = [entry[1] for entry in spec if entry[0] in ("item", "checked")]
        assert "Open GhostDrive" in labels
        assert "Quit" in labels
        assert "Start with system" in labels

    def test_menu_reflects_autostart_state(self):
        on_ctl, _, _ = self._controller(autostart=True)
        off_ctl, _, _ = self._controller(autostart=False)
        checked_on = [e[2] for e in on_ctl.menu_spec() if e[0] == "checked"][0]
        checked_off = [e[2] for e in off_ctl.menu_spec() if e[0] == "checked"][0]
        assert checked_on is True
        assert checked_off is False

    def test_open_starts_server_then_opens_browser(self):
        ctl, server, notes = self._controller()
        assert server.started_count == 0

        ctl.on_open()
        assert server.started_count == 1
        assert server.opened == 1
        assert any("started at" in str(m) for lvl, m in notes)

        # Second click must NOT restart the server.
        ctl.on_open()
        assert server.started_count == 1
        assert server.opened == 2

    def test_toggle_autostart_flips(self):
        state = {"enabled": False}

        notes = []
        ctl = TrayController(
            server=FakeServer(),
            autostart_fn=lambda enable: state.update(enabled=enable) or True,
            autostart_status_fn=lambda: state["enabled"],
            notifier=lambda level, msg: notes.append(msg),
        )
        assert ctl.autostart_enabled() is False
        ctl.on_toggle_autostart()
        assert state["enabled"] is True
        assert any("enabled" in m for m in notes)

        ctl.on_toggle_autostart()
        assert state["enabled"] is False
        assert any("disabled" in m for m in notes)

    def test_toggle_autostart_reports_failure(self):
        notes = []
        ctl = TrayController(
            server=FakeServer(),
            autostart_fn=lambda enable: False,  # underlying call fails
            autostart_status_fn=lambda: False,
            notifier=lambda level, msg: notes.append((level, msg)),
        )
        ctl.on_toggle_autostart()
        assert any(level == "error" for level, _ in notes)

    def test_quit_stops_running_server(self):
        ctl, server, _ = self._controller()
        ctl.ensure_running()
        ctl.on_quit()
        assert ctl.quit_requested is True
        assert server.stopped_count == 1
        assert server.running is False

    def test_quit_without_server_is_safe(self):
        ctl, server, _ = self._controller()
        ctl.on_quit()
        assert server.stopped_count == 0

    def test_status_text_stopped_and_running(self):
        ctl, server, _ = self._controller()
        assert "stopped" in ctl.status_text()
        server.running = True
        assert ctl.status_text().startswith("Server: running")
        assert server.url in ctl.status_text()

    def test_status_text_includes_vault_state(self):
        ctl, server, _ = self._controller()
        server.running = True
        # state.km is None in a fresh test process → "locked"/"unknown"
        text = ctl.status_text()
        assert "locked" in text or "unknown" in text


class TestTrayServer:
    def test_initial_state(self):
        s = TrayServer(host="127.0.0.1", port=8123)
        assert s.running is False
        assert s.url == "http://127.0.0.1:8123"

    def test_start_real_server_and_stop(self):
        """Full lifecycle against a real uvicorn thread on an ephemeral port."""
        s = TrayServer(host="127.0.0.1", port=0)
        url = s.start(timeout=30.0)
        try:
            assert s.running is True
            assert "http://127.0.0.1:" in url

            # The server must actually serve the index page.
            import urllib.request

            with urllib.request.urlopen(url + "/", timeout=10) as resp:
                body = resp.read()
            assert resp.status == 200
            assert b"GhostDrive" in body or b"<!doctype" in body.lower() or len(body) > 0
        finally:
            s.stop(timeout=15.0)
        assert s.running is False

    def test_start_is_idempotent_while_running(self):
        s = TrayServer(host="127.0.0.1", port=0)
        try:
            first = s.start(timeout=30.0)
            second = s.start(timeout=5.0)
            assert first == second
        finally:
            s.stop(timeout=15.0)
