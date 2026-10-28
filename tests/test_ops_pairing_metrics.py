"""
tests/test_ops_pairing_metrics.py -- QR pairing, remote-access status, and the
Prometheus /metrics endpoint.

Covers detect_tailscale with an injected command runner (running / nonzero
exit / runner raising / PATH miss / Windows fallback path), access_status
shape with a mocked Tailscale, the /api/pairing and /api/remote routes on an
unlocked vault, QR URL validation (http/https only, no credentials), the
/metrics exposition on unlocked and locked vaults (line-format regex, file
counts after a real upload), the metrics_enabled kill switch, and the
existence of docs/REMOTE_ACCESS.md.

No real network and no real tailscale binary: every subprocess touchpoint
goes through the injectable runner or a monkeypatch. The local test app
carries only the three ops routers.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ghostdrive.services import files as files_service
from ghostdrive.services import remote_access
from ghostdrive.web.routes import ops as ops_routes
from ghostdrive.web.server import app as server_app
from ghostdrive.web.state import state

PASSPHRASE = "correct horse battery staple"
REPO_ROOT = Path(__file__).resolve().parents[1]

# Prometheus sample line format (comments stripped by the parser).
_METRIC_LINE_RE = re.compile(
    r"^[a-zA-Z_:][a-zA-Z0-9_:]*(\{[^}]*\})? -?[0-9.]+([eE][+-]?[0-9]+)?$"
)

_TS_OFF = {
    "installed": False, "running": False, "ip": None,
    "method": None, "error": "Tailscale CLI not found on PATH.",
}
_TS_ON = {
    "installed": True, "running": True, "ip": "100.64.0.5",
    "method": "cli", "error": None,
}


# ── Fixtures (vault pattern copied from tests/test_sync.py) ──────────────────

@pytest.fixture(scope="module")
def vault(tmp_path_factory):
    """Module-scoped unlocked vault, created via the real server app."""
    data_dir = tmp_path_factory.mktemp("ghostdrive_ops")
    state.clean_shutdown()
    state.app_data_dir = data_dir
    state.keystore_path = data_dir / "keystore.json"
    state.db_path = data_dir / "ghostdrive.db"

    client = TestClient(server_app)
    response = client.post("/api/auth/setup", json={"passphrase": PASSPHRASE})
    assert response.status_code == 200, response.text

    yield

    state.clean_shutdown()


def _local_ops_app() -> FastAPI:
    """Scheduler-free app carrying only the three ops routers."""
    local_app = FastAPI()
    local_app.include_router(ops_routes.pairing_router)
    local_app.include_router(ops_routes.remote_router)
    local_app.include_router(ops_routes.metrics_router)
    return local_app


@pytest.fixture
def ops_client(vault, monkeypatch):
    """TestClient over the ops-only app with Tailscale faked as running."""
    monkeypatch.setattr(
        remote_access, "detect_tailscale",
        lambda command_runner=None: dict(_TS_ON),
    )
    with TestClient(_local_ops_app()) as client:
        yield client


@pytest.fixture
def locked_ops_client(vault, monkeypatch):
    """Vault locked, then an ops client; re-unlocks on teardown.

    The teardown unlock keeps the module-scoped vault usable by tests that
    run after the locked-vault test (pytest executes in file order).
    """
    monkeypatch.setattr(
        remote_access, "detect_tailscale",
        lambda command_runner=None: dict(_TS_OFF),
    )
    state.clean_shutdown()
    with TestClient(_local_ops_app()) as client:
        try:
            yield client
        finally:
            admin = TestClient(server_app)
            response = admin.post(
                "/api/auth/unlock", json={"passphrase": PASSPHRASE}
            )
            assert response.status_code == 200, response.text
            assert response.json()["status"] == "success"


def _db():
    from ghostdrive.services.context import require_db

    return require_db()


def _patch_tailscale(monkeypatch, result: dict) -> None:
    monkeypatch.setattr(
        remote_access, "detect_tailscale",
        lambda command_runner=None: dict(result),
    )


def _metric_samples(text: str) -> dict[str, float]:
    """Parse non-comment lines; every line must match the exposition regex."""
    samples: dict[str, float] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        assert _METRIC_LINE_RE.match(line), f"bad metric line: {line!r}"
        name, value = line.rsplit(" ", 1)
        samples[name] = float(value)
    return samples


# ── detect_tailscale ─────────────────────────────────────────────────────────

def test_detect_tailscale_running_parses_first_ip(monkeypatch):
    monkeypatch.setattr(remote_access.shutil, "which", lambda name: "C:/bin/tailscale.exe")
    calls = []

    def runner(cmd, timeout):
        calls.append((list(cmd), timeout))
        return SimpleNamespace(stdout="100.64.0.5\n", returncode=0, stderr="")

    result = remote_access.detect_tailscale(command_runner=runner)
    assert result == {
        "installed": True, "running": True, "ip": "100.64.0.5",
        "method": "cli", "error": None,
    }
    assert calls == [(["C:/bin/tailscale.exe", "ip", "-4"], 5.0)]


def test_detect_tailscale_nonzero_exit_is_not_running(monkeypatch):
    monkeypatch.setattr(remote_access.shutil, "which", lambda name: "/usr/bin/tailscale")

    def runner(cmd, timeout):
        return SimpleNamespace(stdout="", returncode=1, stderr="Logged out.")

    result = remote_access.detect_tailscale(command_runner=runner)
    assert result["installed"] is True
    assert result["running"] is False and result["ip"] is None
    assert "exited 1" in result["error"] and "Logged out." in result["error"]


def test_detect_tailscale_runner_exception_is_captured(monkeypatch):
    monkeypatch.setattr(remote_access.shutil, "which", lambda name: "/usr/bin/tailscale")

    def runner(cmd, timeout):
        raise RuntimeError("boom")

    result = remote_access.detect_tailscale(command_runner=runner)  # must not raise
    assert result["installed"] is True
    assert result["running"] is False and result["ip"] is None
    assert "boom" in result["error"]


def test_detect_tailscale_not_installed_skips_runner(monkeypatch):
    monkeypatch.setattr(remote_access.shutil, "which", lambda name: None)
    monkeypatch.setattr(remote_access, "_FALLBACK_PATHS", ())
    invoked = []

    def runner(cmd, timeout):
        invoked.append(cmd)
        return SimpleNamespace(stdout="", returncode=0, stderr="")

    result = remote_access.detect_tailscale(command_runner=runner)
    assert result == {
        "installed": False, "running": False, "ip": None,
        "method": None, "error": "Tailscale CLI not found on PATH.",
    }
    assert invoked == []  # no binary, no subprocess


def test_detect_tailscale_windows_fallback_path(tmp_path, monkeypatch):
    monkeypatch.setattr(remote_access.shutil, "which", lambda name: None)
    fake_exe = tmp_path / "tailscale.exe"
    fake_exe.write_bytes(b"not a real binary")
    monkeypatch.setattr(remote_access, "_FALLBACK_PATHS", (str(fake_exe),))

    def runner(cmd, timeout):
        return SimpleNamespace(stdout="\n100.101.102.103\n", returncode=0, stderr="")

    result = remote_access.detect_tailscale(command_runner=runner)
    assert result["installed"] is True
    assert result["running"] is True and result["ip"] == "100.101.102.103"


def test_detect_tailscale_zero_exit_without_ip_is_not_running(monkeypatch):
    monkeypatch.setattr(remote_access.shutil, "which", lambda name: "/usr/bin/tailscale")

    def runner(cmd, timeout):
        return SimpleNamespace(stdout="no address here\n", returncode=0, stderr="")

    result = remote_access.detect_tailscale(command_runner=runner)
    assert result["running"] is False and result["ip"] is None
    assert "no IPv4" in result["error"]


# ── access_status / resolve_port ─────────────────────────────────────────────

def test_access_status_shape_ready_with_tailscale(monkeypatch):
    _patch_tailscale(monkeypatch, _TS_ON)
    status = remote_access.access_status(None, port=8123)
    assert set(status) == {
        "bind", "port", "vault_unlocked", "local_urls", "tailscale",
        "remote_urls", "ready_for_phone", "safety", "steps",
    }
    assert status["bind"] == "127.0.0.1" and status["port"] == 8123
    assert status["vault_unlocked"] is False
    assert status["local_urls"] == [
        "http://127.0.0.1:8123/", "http://localhost:8123/",
    ]
    assert status["remote_urls"] == ["http://100.64.0.5:8123/"]
    assert status["ready_for_phone"] is True
    assert all(isinstance(item, str) and item for item in status["safety"])

    steps = {step["id"]: step for step in status["steps"]}
    assert steps["app_running"]["done"] is True
    assert steps["tailscale_installed"]["done"] is True
    assert steps["tailscale_running"]["done"] is True
    assert steps["phone_scan_qr"]["done"] is False  # server cannot see the phone
    for step in status["steps"]:
        assert set(step) == {"id", "label", "done"}


def test_access_status_without_tailscale(monkeypatch):
    _patch_tailscale(monkeypatch, _TS_OFF)
    status = remote_access.access_status(None, port=8000)
    assert status["ready_for_phone"] is False
    assert status["remote_urls"] == []
    assert status["local_urls"][0] == "http://127.0.0.1:8000/"
    steps = {step["id"]: step["done"] for step in status["steps"]}
    assert steps["tailscale_installed"] is False
    assert steps["tailscale_running"] is False


def test_resolve_port_setting_env_default(monkeypatch, vault):
    db = _db()
    monkeypatch.delenv(remote_access.ENV_PORT, raising=False)

    db.set_setting(remote_access.SETTING_HTTP_PORT, "9001")
    assert remote_access.resolve_port(db) == 9001

    db.set_setting(remote_access.SETTING_HTTP_PORT, "not-a-port")
    assert remote_access.resolve_port(db) == remote_access.DEFAULT_PORT

    monkeypatch.setenv(remote_access.ENV_PORT, "9002")
    assert remote_access.resolve_port(db) == 9002
    assert remote_access.resolve_port(None) == 9002  # locked path: env only

    monkeypatch.delenv(remote_access.ENV_PORT, raising=False)
    db.set_setting(remote_access.SETTING_HTTP_PORT, "")
    assert remote_access.resolve_port(db) == remote_access.DEFAULT_PORT


# ── Router contracts ─────────────────────────────────────────────────────────

def test_router_names_prefixes_and_paths():
    assert ops_routes.pairing_router.prefix == "/api/pairing"
    assert ops_routes.remote_router.prefix == "/api/remote"
    assert ops_routes.metrics_router.prefix == ""

    pairing_paths = {route.path for route in ops_routes.pairing_router.routes}
    assert {"/api/pairing/status", "/api/pairing/qr.png"} <= pairing_paths
    remote_paths = {route.path for route in ops_routes.remote_router.routes}
    assert {"/api/remote/status", "/api/remote/rescan"} <= remote_paths
    metrics_paths = {route.path for route in ops_routes.metrics_router.routes}
    assert "/metrics" in metrics_paths


# ── /api/pairing ─────────────────────────────────────────────────────────────

def test_pairing_status_unlocked_vault(ops_client):
    res = ops_client.get("/api/pairing/status")
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["vault_unlocked"] is True
    assert data["bind"] == "127.0.0.1"
    assert data["ready_for_phone"] is True
    assert data["remote_urls"] == ["http://100.64.0.5:8000/"]
    assert isinstance(data["port"], int)
    assert isinstance(data["safety"], list) and data["safety"]
    assert isinstance(data["steps"], list) and data["steps"]


def test_pairing_qr_png_valid_urls(ops_client):
    res = ops_client.get(
        "/api/pairing/qr.png", params={"url": "http://example.test/x"}
    )
    assert res.status_code == 200, res.text
    assert res.headers["content-type"] == "image/png"
    assert res.headers["cache-control"] == "no-store"
    assert res.content.startswith(b"\x89PNG")

    # Default (no url): remote URL preferred while Tailscale is "running".
    default = ops_client.get("/api/pairing/qr.png")
    assert default.status_code == 200
    assert default.content.startswith(b"\x89PNG")


@pytest.mark.parametrize("url", [
    "javascript:alert(1)",
    "ftp://example.test/x",
    "data:text/plain,hello",
    "http://user:pass@example.test/",
    "http://",
    "",
])
def test_pairing_qr_rejects_unsafe_urls(ops_client, url):
    res = ops_client.get("/api/pairing/qr.png", params={"url": url})
    assert res.status_code == 400, res.text


# ── /api/remote ──────────────────────────────────────────────────────────────

def test_remote_status_and_rescan(ops_client):
    for path, method in (("/api/remote/status", "get"),
                         ("/api/remote/rescan", "post")):
        res = getattr(ops_client, method)(path)
        assert res.status_code == 200, res.text
        data = res.json()
        assert set(data) == {
            "bind", "port", "vault_unlocked", "local_urls", "tailscale",
            "remote_urls", "ready_for_phone", "safety", "steps",
        }
        assert data["tailscale"]["running"] is True
        assert data["remote_urls"][0].startswith("http://100.64.0.5:")


# ── /metrics ─────────────────────────────────────────────────────────────────

def test_metrics_unlocked_counts_uploaded_file(ops_client, tmp_path):
    payload = b"metrics probe payload"
    src = tmp_path / "metrics_probe.txt"
    src.write_bytes(payload)
    asyncio.run(
        files_service.upload_stream(src, "metrics_probe.txt", None, "IMPORTANT", "/")
    )

    res = ops_client.get("/metrics")
    assert res.status_code == 200, res.text
    assert res.headers["content-type"].startswith("text/plain; version=0.0.4")

    samples = _metric_samples(res.text)
    assert samples["ghostdrive_up"] == 1
    assert samples["ghostdrive_vault_unlocked"] == 1

    row = _db()._conn.execute(
        "SELECT COUNT(*) AS n, COALESCE(SUM(size), 0) AS b "
        "FROM files WHERE tombstone = 0"
    ).fetchone()
    assert samples["ghostdrive_files_total"] == int(row["n"]) == 1
    assert samples["ghostdrive_files_bytes"] == int(row["b"]) == len(payload)

    assert "ghostdrive_trash_total" in samples
    assert "ghostdrive_backends_total" in samples
    assert "ghostdrive_backends_healthy" in samples
    assert "ghostdrive_alerts_active" in samples
    assert "ghostdrive_alerts_critical" in samples
    assert "ghostdrive_last_drill_success" in samples
    assert "ghostdrive_drill_last_run_timestamp_seconds" in samples
    assert "ghostdrive_sync_enabled" in samples
    assert "ghostdrive_sync_roots" in samples
    assert "ghostdrive_uptime_seconds" in samples

    # Durability is emitted as exactly four one-hot series.
    durability_states = {
        name: value
        for name, value in samples.items()
        if name.startswith("ghostdrive_durability_state{")
    }
    assert len(durability_states) == 4
    assert sum(durability_states.values()) == 1  # exactly one state is current


def test_metrics_kill_switch_404(ops_client):
    db = _db()
    try:
        db.set_setting(ops_routes.SETTING_METRICS_ENABLED, "false")
        res = ops_client.get("/metrics")
        assert res.status_code == 404
        assert "metrics_enabled" in res.json()["detail"]
    finally:
        db.set_setting(ops_routes.SETTING_METRICS_ENABLED, "true")
    assert ops_client.get("/metrics").status_code == 200


def test_metrics_locked_vault_serves_minimal_set(locked_ops_client):
    # Pairing still answers while locked...
    res = locked_ops_client.get("/api/pairing/status")
    assert res.status_code == 200, res.text
    assert res.json()["vault_unlocked"] is False

    # ...and /metrics degrades to the minimal set instead of erroring.
    res = locked_ops_client.get("/metrics")
    assert res.status_code == 200, res.text
    assert res.headers["content-type"].startswith("text/plain")
    samples = _metric_samples(res.text)
    assert samples["ghostdrive_up"] == 1
    assert samples["ghostdrive_vault_unlocked"] == 0
    assert "ghostdrive_uptime_seconds" in samples
    assert "ghostdrive_files_total" not in samples  # no DB metrics when locked


# ── Documentation ────────────────────────────────────────────────────────────

def test_remote_access_doc_exists_and_mentions_key_facts():
    doc = (REPO_ROOT / "docs" / "REMOTE_ACCESS.md").read_text(encoding="utf-8")
    for needle in ("127.0.0.1", "tailscale", "/metrics"):
        assert needle in doc, f"docs/REMOTE_ACCESS.md must mention {needle!r}"
