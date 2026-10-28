"""
tests/test_health_report.py -- Weekly vault-health report service and routes.

Covers build_report on an empty vault (every top-level key present, badge in
{green,amber,red}, storage zeroed, lazy waste source degrading to
{"unavailable": True} when absent), run_health_report persistence + webhook
delivery (success and failure, report persisted either way), route behavior
(null-safe GET /report before first run, POST /run, clamped settings with the
webhook URL hidden), a real upload showing up in storage.active_files, and
the scheduler start/stop lifecycle.  No real network: urllib is monkeypatched.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ghostdrive.services import files as files_service
from ghostdrive.services import health_report as health_service
from ghostdrive.web.routes import health as health_routes
from ghostdrive.web.server import app as server_app
from ghostdrive.web.state import state

PASSPHRASE = "correct horse battery staple"
T0 = datetime(2026, 2, 2, 8, 0, 0, tzinfo=timezone.utc)

try:  # optional service owned by a later wave
    import ghostdrive.services.waste  # noqa: F401

    WASTE_PRESENT = True
except ImportError:
    WASTE_PRESENT = False


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def vault(tmp_path_factory):
    """Module-scoped unlocked vault (same pattern as tests/test_sync.py)."""
    data_dir = tmp_path_factory.mktemp("ghostdrive_health")
    state.clean_shutdown()
    state.app_data_dir = data_dir
    state.keystore_path = data_dir / "keystore.json"
    state.db_path = data_dir / "ghostdrive.db"

    client = TestClient(server_app)
    response = client.post("/api/auth/setup", json={"passphrase": PASSPHRASE})
    assert response.status_code == 200, response.text

    yield

    health_service.stop_health_report_scheduler()
    state.clean_shutdown()


@pytest.fixture
def db(vault):
    """Unlocked DB with every health-report setting reset for one test."""
    from ghostdrive.services.context import require_db

    database = require_db()
    with database.transaction():
        database.set_setting(health_service.KEY_ENABLED, "true")
        database.set_setting(health_service.KEY_INTERVAL_HOURS, "168")
        database.set_setting(health_service.KEY_LAST_RUN, "")
        database.set_setting(health_service.KEY_LAST_REPORT, "")
        database.set_setting(health_service.KEY_WEBHOOK_URL, "")
    return database


@pytest.fixture
def client(db):
    """App carrying ONLY the health router (context manager: one loop)."""
    local_app = FastAPI()
    local_app.include_router(health_routes.router)
    with TestClient(local_app) as local:
        yield local


class _FakeResponse:
    def read(self) -> bytes:
        return b"ok"

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


@pytest.fixture
def transport(monkeypatch):
    """Capture every urllib POST instead of hitting the network."""
    calls: list[dict] = []

    def fake_urlopen(request, timeout=10):
        calls.append(
            {
                "url": request.full_url,
                "body": request.data.decode("utf-8"),
                "timeout": timeout,
            }
        )
        return _FakeResponse()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    return calls


# ── build_report ──────────────────────────────────────────────────────────────


def test_build_report_on_empty_vault(db):
    report = asyncio.run(health_service.build_report(db, now=T0))

    for key in (
        "generated_at",
        "badge",
        "drills",
        "alerts",
        "durability",
        "sync",
        "storage",
        "waste",
        "inheritance",
    ):
        assert key in report, f"missing report key: {key}"
    assert report["generated_at"] == T0.isoformat()

    assert report["badge"]["overall"] in {"green", "amber", "red"}
    assert isinstance(report["badge"]["label"], str) and report["badge"]["label"]

    if not WASTE_PRESENT:
        # Lazy source absent -> consistently marked unavailable, never a crash.
        assert report["waste"] == {"unavailable": True}

    storage = report["storage"]
    assert storage["active_files"] == 0
    assert storage["active_bytes"] == 0
    assert storage["trash_bytes"] == 0

    assert report["sync"]["enabled"] is False
    assert report["sync"]["roots"] == []

    assert set(report["alerts"]) >= {"active_count", "critical", "warning"}
    assert set(report["durability"]) >= {"state", "total_chunks", "at_risk_chunks", "summary"}
    assert set(report["drills"]) >= {"last", "passed", "failed", "stale"}
    assert report["inheritance"] == {
        "enabled": False,
        "overdue": False,
        "days_remaining": None,
    }


# ── run_health_report: persistence + delivery ─────────────────────────────────


def test_run_persists_and_delivers(db, transport, monkeypatch):
    # No webhook configured: report persisted, delivery skipped (None).
    out = asyncio.run(health_service.run_health_report(db, now=T0))
    assert out["delivered"] is None and out["delivery_error"] is None
    stored = json.loads(db.get_setting(health_service.KEY_LAST_REPORT, ""))
    assert stored["generated_at"] == T0.isoformat()
    assert db.get_setting(health_service.KEY_LAST_RUN, "") == T0.isoformat()
    assert not transport

    # Webhook configured: delivered True, the JSON body IS the report.
    db.set_setting(health_service.KEY_WEBHOOK_URL, "https://hooks.example.test/health")
    second = T0 + timedelta(hours=1)
    out = asyncio.run(health_service.run_health_report(db, now=second))
    assert out["delivered"] is True and out["delivery_error"] is None
    assert len(transport) == 1
    assert transport[0]["url"] == "https://hooks.example.test/health"
    assert transport[0]["timeout"] == 10
    assert json.loads(transport[0]["body"])["generated_at"] == second.isoformat()

    # Failing webhook: delivered False + error, report STILL persisted.
    def failing_urlopen(request, timeout=10):
        raise OSError("boom")

    monkeypatch.setattr("urllib.request.urlopen", failing_urlopen)
    third = T0 + timedelta(hours=2)
    out = asyncio.run(health_service.run_health_report(db, now=third))
    assert out["delivered"] is False
    assert "boom" in out["delivery_error"]
    assert (
        json.loads(db.get_setting(health_service.KEY_LAST_REPORT, ""))[
            "generated_at"
        ]
        == third.isoformat()
    )
    assert db.get_setting(health_service.KEY_LAST_RUN, "") == third.isoformat()

    # deliver=False never sends even with a URL configured.
    calls_before = len(transport)
    out = asyncio.run(
        health_service.run_health_report(db, now=third + timedelta(hours=1), deliver=False)
    )
    assert out["delivered"] is None
    assert len(transport) == calls_before  # no request was attempted


def test_get_health_report_meta(db):
    meta = health_service.get_health_report(db)
    assert meta["report"] is None  # null-safe before the first run
    assert meta["last_run"] is None
    assert meta["enabled"] is True
    assert meta["interval_hours"] == 168.0


# ── Routes ────────────────────────────────────────────────────────────────────


def test_routes_report_and_run(client, db, transport):
    # GET /report before first run: 200 with a null report.
    resp = client.get("/api/health/report")
    assert resp.status_code == 200
    assert resp.json() == {"last_run": None, "report": None}

    resp = client.post("/api/health/run")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["report"]["storage"]["active_files"] >= 0
    assert body["delivered"] is None  # no webhook configured in this test

    # Now GET /report returns what /run persisted.
    resp = client.get("/api/health/report")
    assert resp.status_code == 200
    assert resp.json()["report"] is not None


def test_routes_settings_clamp_and_hide_webhook(client, db):
    resp = client.post(
        "/api/health/settings",
        json={"enabled": True, "interval_hours": 0.5, "webhook_url": "https://hooks.example.test/x"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["interval_hours"] == 1.0  # clamped from 0.5
    assert body["enabled"] is True
    assert body["webhook_configured"] is True
    assert "webhook_url" not in body  # the URL itself is never echoed

    # Partial update: nulls leave everything else alone.
    resp = client.post("/api/health/settings", json={"enabled": False})
    body = resp.json()
    assert body["enabled"] is False
    assert body["interval_hours"] == 1.0
    assert body["webhook_configured"] is True

    # Clearing the webhook flips only the flag.
    resp = client.post("/api/health/settings", json={"webhook_url": ""})
    assert resp.json()["webhook_configured"] is False


def test_routes_status(client, db):
    resp = client.get("/api/health/status")
    assert resp.status_code == 200
    body = resp.json()
    assert body["running"] is False
    assert body["enabled"] is True
    assert body["interval_hours"] == 168.0
    assert body["last_run"] is None
    assert body["webhook_configured"] is False


# ── Real DB reads ─────────────────────────────────────────────────────────────


def test_report_counts_uploaded_file(db, tmp_path):
    source = tmp_path / "hello.txt"
    content = b"hello health report"
    source.write_bytes(content)
    asyncio.run(
        files_service.upload_stream(source, "hello.txt", None, "IMPORTANT", "/")
    )

    report = asyncio.run(health_service.build_report(db))
    assert report["storage"]["active_files"] >= 1
    assert report["storage"]["active_bytes"] >= len(content)


# ── Scheduler lifecycle ───────────────────────────────────────────────────────


async def test_scheduler_lifecycle(db):
    task = health_service.start_health_report_scheduler(db=db)
    assert task is not None and not task.done()
    # Idempotent: double-start returns the same task.
    assert health_service.start_health_report_scheduler(db=db) is task
    assert health_service.health_report_status(db)["running"] is True

    stopped = health_service.stop_health_report_scheduler()
    assert stopped is task
    await asyncio.sleep(0)  # let the cancellation propagate
    assert health_service._health_task is None
    with pytest.raises(asyncio.CancelledError):
        await stopped
    # Stop again: no task, nothing to cancel.
    assert health_service.stop_health_report_scheduler() is None
