"""
tests/test_inheritance.py -- Inheritance / dead-man's switch service and routes.

Covers enable (validation, sealing round-trip, passphrase never persisted or
echoed), check-in timer reset, frozen-datetime overdue detection (alert
recorded exactly once via alerts.alert_state, release with mocked transport,
no-op after release), all-deliveries-fail retry semantics, manual release_now
(confirm gate), disable (package wiped, contacts/interval kept), scheduler
start/stop lifecycle, and the router endpoints.  No real network: the
transport is always monkeypatched urllib.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ghostdrive.crypto.shamir import combine_shares, secret_commitment, text_to_share
from ghostdrive.services import alerts as alerts_service
from ghostdrive.services import inheritance as inheritance_service
from ghostdrive.web.routes import inheritance as inheritance_routes
from ghostdrive.web.server import app as server_app
from ghostdrive.web.state import state

PASSPHRASE = "correct horse battery staple"
RELEASE_PASSPHRASE = "release the vault please"
CONTACTS = [
    {"name": "Ada", "webhook_url": "https://hooks.example.test/ada"},
    {"name": "Grace", "webhook_url": "https://hooks.example.test/grace"},
]
T0 = datetime(2026, 1, 5, 12, 0, 0, tzinfo=timezone.utc)


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def vault(tmp_path_factory):
    """Module-scoped unlocked vault (same pattern as tests/test_sync.py)."""
    data_dir = tmp_path_factory.mktemp("ghostdrive_inheritance")
    state.clean_shutdown()
    state.app_data_dir = data_dir
    state.keystore_path = data_dir / "keystore.json"
    state.db_path = data_dir / "ghostdrive.db"

    client = TestClient(server_app)
    response = client.post("/api/auth/setup", json={"passphrase": PASSPHRASE})
    assert response.status_code == 200, response.text

    yield

    inheritance_service.stop_inheritance_scheduler()
    state.clean_shutdown()


@pytest.fixture
def db(vault):
    """Unlocked DB with every inheritance setting reset for one test."""
    from ghostdrive.services.context import require_db

    database = require_db()
    with database.transaction():
        database.set_setting(inheritance_service.KEY_ENABLED, "false")
        database.set_setting(inheritance_service.KEY_INTERVAL_DAYS, "90")
        database.set_setting(inheritance_service.KEY_LAST_CHECK_IN, "")
        database.set_setting(inheritance_service.KEY_CONTACTS, "[]")
        database.set_setting(inheritance_service.KEY_PACKAGE, "")
        database.set_setting(inheritance_service.KEY_STATE, "{}")
        # Reset alert dedupe so the overdue alert is "new" deterministically.
        database.set_setting("alerts_state", "")
        database.set_setting("alert_webhook_url", "")
    return database


@pytest.fixture
def client(db):
    """App carrying ONLY the inheritance router (context manager: one loop)."""
    local_app = FastAPI()
    local_app.include_router(inheritance_routes.router)
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


def _enable(db, interval_days=7, now=T0, **kwargs):
    return asyncio.run(
        inheritance_service.enable_inheritance(
            db, interval_days, RELEASE_PASSPHRASE, CONTACTS, now=now, **kwargs
        )
    )


# ── Enable ────────────────────────────────────────────────────────────────────


def test_enable_seals_package_and_reports_status(db):
    status = _enable(db, interval_days=30)

    assert status["enabled"] is True
    assert status["package_sealed"] is True
    assert status["days_remaining"] == 30
    assert status["last_check_in"] == T0.isoformat()
    assert status["due_at"] == (T0 + timedelta(days=30)).isoformat()
    assert status["overdue"] is False
    assert status["released_at"] is None
    assert {c["name"] for c in status["contacts"]} == {"Ada", "Grace"}

    # The passphrase never reaches any persisted or returned JSON.
    package_raw = db.get_setting(inheritance_service.KEY_PACKAGE, "")
    assert RELEASE_PASSPHRASE not in package_raw
    assert RELEASE_PASSPHRASE not in json.dumps(status)
    assert RELEASE_PASSPHRASE not in db.get_setting(inheritance_service.KEY_STATE, "")

    # Round-trip: the sealed package really holds 3-of-5 shares that
    # reconstruct the CURRENT master key under the release passphrase.
    package = json.loads(package_raw)
    assert package["v"] == 1
    assert package["threshold"] == 3 and package["total"] == 5
    wrap_key = hashlib.pbkdf2_hmac(
        "sha256",
        RELEASE_PASSPHRASE.encode("utf-8"),
        base64.b64decode(package["salt"]),
        600_000,
    )
    plaintext = AESGCM(wrap_key).decrypt(
        base64.b64decode(package["nonce"]),
        base64.b64decode(package["ct"]),
        b"ghostdrive-inheritance-v1",
    )
    share_texts = json.loads(plaintext.decode("utf-8"))
    assert len(share_texts) == 5
    from ghostdrive.services.context import get_master_key

    master_key = combine_shares([text_to_share(text) for text in share_texts])
    assert master_key == get_master_key()
    assert secret_commitment(master_key) == package["commitment"]


def test_enable_validation_returns_400(client):
    good_url = [{"name": "Ada", "webhook_url": "https://hooks.example.test/ada"}]

    # Too-short passphrase.
    resp = client.post(
        "/api/inheritance/enable",
        json={"interval_days": 30, "release_passphrase": "short", "contacts": good_url},
    )
    assert resp.status_code == 400

    # Interval below 7 days.
    resp = client.post(
        "/api/inheritance/enable",
        json={
            "interval_days": 6,
            "release_passphrase": RELEASE_PASSPHRASE,
            "contacts": good_url,
        },
    )
    assert resp.status_code == 400

    # Empty contact list.
    resp = client.post(
        "/api/inheritance/enable",
        json={
            "interval_days": 30,
            "release_passphrase": RELEASE_PASSPHRASE,
            "contacts": [],
        },
    )
    assert resp.status_code == 400

    # Non-http webhook URL.
    resp = client.post(
        "/api/inheritance/enable",
        json={
            "interval_days": 30,
            "release_passphrase": RELEASE_PASSPHRASE,
            "contacts": [{"name": "Ada", "webhook_url": "ftp://nope"}],
        },
    )
    assert resp.status_code == 400

    # Valid enable succeeds and never echoes the passphrase.
    resp = client.post(
        "/api/inheritance/enable",
        json={
            "interval_days": 30,
            "release_passphrase": RELEASE_PASSPHRASE,
            "contacts": good_url,
        },
    )
    assert resp.status_code == 200, resp.text
    assert RELEASE_PASSPHRASE not in resp.text
    assert resp.json()["package_sealed"] is True

    # Second enable without force -> 400 (documents the re-seal trade).
    resp = client.post(
        "/api/inheritance/enable",
        json={
            "interval_days": 30,
            "release_passphrase": RELEASE_PASSPHRASE,
            "contacts": good_url,
        },
    )
    assert resp.status_code == 400
    assert "re-seals" in resp.json()["detail"]


# ── Check-in ──────────────────────────────────────────────────────────────────


def test_check_in_resets_timer(db):
    _enable(db, interval_days=7, now=T0)

    five_days = T0 + timedelta(days=5)
    status = inheritance_service.inheritance_status(db, now=five_days)
    assert status["overdue"] is False
    assert status["days_remaining"] == 2

    status = inheritance_service.check_in(db, now=five_days)
    assert status["last_check_in"] == five_days.isoformat()

    almost_due = five_days + timedelta(days=7, hours=-1)
    assert inheritance_service.inheritance_status(db, now=almost_due)["overdue"] is False
    due = five_days + timedelta(days=7)
    assert inheritance_service.inheritance_status(db, now=due)["overdue"] is True


# ── Overdue: alert once, then release ─────────────────────────────────────────


def test_overdue_alert_then_release(db, transport):
    _enable(db, interval_days=7, now=T0)

    # Not yet due: nothing happens at all.
    out = asyncio.run(
        inheritance_service.check_inheritance(
            db, now=T0 + timedelta(days=6), deliver=False
        )
    )
    assert out == {"overdue": False, "released": False, "results": [], "alerted": False}
    assert not transport

    # Due: the critical alert is recorded and dispatched once.
    overdue_at = T0 + timedelta(days=7, hours=1)
    out = asyncio.run(
        inheritance_service.check_inheritance(db, now=overdue_at, deliver=False)
    )
    assert out["overdue"] is True
    assert out["released"] is False
    assert out["alerted"] is True

    state_view = alerts_service.alert_state(db)
    alert_key = alerts_service.alert_id("inheritance_overdue", "inheritance")
    assert alert_key in state_view["seen"]

    # Second run the next minute: no duplicate alert.
    out = asyncio.run(
        inheritance_service.check_inheritance(
            db, now=overdue_at + timedelta(minutes=1), deliver=False
        )
    )
    assert out["alerted"] is False and out["released"] is False

    # Delivery with the mocked transport: both contacts succeed, release marks.
    out = asyncio.run(
        inheritance_service.check_inheritance(
            db, now=overdue_at + timedelta(minutes=2), deliver=True
        )
    )
    assert out["released"] is True
    assert [r["name"] for r in out["results"]] == ["Ada", "Grace"]
    assert all(r["ok"] for r in out["results"])
    assert len(transport) == 2
    assert {call["url"] for call in transport} == {
        "https://hooks.example.test/ada",
        "https://hooks.example.test/grace",
    }
    for call in transport:
        payload = json.loads(call["body"])
        assert "content" in payload  # Discord/Slack-compatible shape
        assert "Sealed package" in payload["content"]
        assert RELEASE_PASSPHRASE not in call["body"]
        assert call["timeout"] == 10

    status = inheritance_service.inheritance_status(db, now=overdue_at)
    assert status["released_at"] == (overdue_at + timedelta(minutes=2)).isoformat()

    # Repeated check after release: no-op, no re-sends.
    out = asyncio.run(
        inheritance_service.check_inheritance(
            db, now=overdue_at + timedelta(days=1), deliver=True
        )
    )
    assert out["released"] is True
    assert len(transport) == 2  # unchanged


def test_all_deliveries_fail_not_released(db, monkeypatch):
    _enable(db, interval_days=7, now=T0)

    def failing_urlopen(request, timeout=10):
        raise OSError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", failing_urlopen)

    out = asyncio.run(
        inheritance_service.check_inheritance(
            db, now=T0 + timedelta(days=8), deliver=True
        )
    )
    assert out["overdue"] is True
    assert out["released"] is False  # retry semantics: all failed -> not released
    assert len(out["results"]) == 2
    assert all(r["ok"] is False and r["error"] for r in out["results"])
    assert inheritance_service.inheritance_status(db)["released_at"] is None


# ── Manual release ────────────────────────────────────────────────────────────


def test_release_now_requires_confirm_and_delivers(db, client, transport):
    _enable(db, interval_days=7, now=T0)

    with pytest.raises(ValueError):
        asyncio.run(inheritance_service.release_now(db, confirm=False))
    resp = client.post("/api/inheritance/release", json={"confirm": False})
    assert resp.status_code == 400

    # Manual release works even though NOT overdue (planned-absence use case).
    out = asyncio.run(
        inheritance_service.release_now(db, now=T0 + timedelta(days=1), confirm=True)
    )
    assert out["released"] is True
    assert out["delivered_to"] == ["Ada", "Grace"]
    assert len(transport) == 2
    status = inheritance_service.inheritance_status(db, now=T0 + timedelta(days=1))
    assert status["overdue"] is False
    assert status["released_at"] is not None


# ── Disable ───────────────────────────────────────────────────────────────────


def test_disable_wipes_package(db):
    _enable(db, interval_days=30, now=T0)
    assert db.get_setting(inheritance_service.KEY_PACKAGE, "")

    inheritance_service.disable_inheritance(db)
    status = inheritance_service.inheritance_status(db)
    assert status["enabled"] is False
    assert status["package_sealed"] is False
    assert status["days_remaining"] is None
    assert status["overdue"] is False
    assert db.get_setting(inheritance_service.KEY_PACKAGE, "") == ""
    # Contacts and interval survive for an easy re-enable.
    assert status["contact_count"] == 2
    assert status["interval_days"] == 30


# ── Scheduler lifecycle ───────────────────────────────────────────────────────


async def test_scheduler_lifecycle(db):
    task = inheritance_service.start_inheritance_scheduler(db=db)
    assert task is not None and not task.done()
    # Idempotent: double-start returns the same task.
    assert inheritance_service.start_inheritance_scheduler(db=db) is task

    stopped = inheritance_service.stop_inheritance_scheduler()
    assert stopped is task
    await asyncio.sleep(0)  # let the cancellation propagate
    assert inheritance_service._inheritance_task is None
    with pytest.raises(asyncio.CancelledError):
        await stopped
    # Stop again: no task, nothing to cancel.
    assert inheritance_service.stop_inheritance_scheduler() is None


# ── Routes smoke ──────────────────────────────────────────────────────────────


def test_routes_smoke(client, db, transport):
    resp = client.get("/api/inheritance/status")
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False

    resp = client.post("/api/inheritance/check-in")
    assert resp.status_code == 200
    assert resp.json()["last_check_in"]

    # Check before enabling: honest no-op.
    resp = client.post("/api/inheritance/check")
    assert resp.status_code == 200
    assert resp.json() == {
        "overdue": False,
        "released": False,
        "results": [],
        "alerted": False,
    }

    resp = client.post(
        "/api/inheritance/enable",
        json={
            "interval_days": 7,
            "release_passphrase": RELEASE_PASSPHRASE,
            "contacts": CONTACTS,
        },
    )
    assert resp.status_code == 200, resp.text
    resp = client.post("/api/inheritance/check")
    assert resp.status_code == 200
    assert resp.json()["overdue"] is False

    resp = client.post("/api/inheritance/disable", json={})
    assert resp.status_code == 200
    body = resp.json()
    assert body["enabled"] is False and body["package_sealed"] is False
