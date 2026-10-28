"""
tests/test_security_tripwire.py -- Canary tripwire and mass-modification alarm.

Covers the canary lifecycle (plant -> clean check -> modify triggers one
critical alert with a generation-bearing subject id -> re-arm means no repeat
-> a second tamper yields a fresh alert id; delete triggers "missing", stays
missing without re-alerting, and re-planting works), route validation (400
for app-data overlap/empty, 409 for duplicates and for planting over a real
file, plant=false registering an existing file untouched, marker-guarded
delete), the mass alarm (settings persist + clamp, scan counts only files
inside the window, below threshold is silent, at/above threshold alerts once
per burst-minute via stable-id dedupe, snapshot failure degrades to a note,
disabled reports enabled False without walking the filesystem), scheduler
lifecycles for both loops, and the /api/security route shapes.  Alert
dispatch is monkeypatched throughout so no real HTTP can fire.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ghostdrive.services import alerts as alerts_service
from ghostdrive.services import canary as canary_service
from ghostdrive.services import mass_alarm as mass_alarm_service
from ghostdrive.services import snapshots as snapshots_service
from ghostdrive.web.routes import security as security_routes
from ghostdrive.web.server import app as server_app
from ghostdrive.web.state import state

PASSPHRASE = "correct horse battery staple"


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def vault(tmp_path_factory):
    """Module-scoped unlocked vault (copied from tests/test_sync.py)."""
    data_dir = tmp_path_factory.mktemp("ghostdrive_security")
    state.clean_shutdown()
    state.app_data_dir = data_dir
    state.keystore_path = data_dir / "keystore.json"
    state.db_path = data_dir / "ghostdrive.db"

    client = TestClient(server_app)
    response = client.post("/api/auth/setup", json={"passphrase": PASSPHRASE})
    assert response.status_code == 200, response.text

    yield

    canary_service.stop_canary_scheduler()
    mass_alarm_service.stop_mass_alarm_scheduler()
    state.clean_shutdown()


@pytest.fixture(autouse=True)
def no_real_dispatch(monkeypatch):
    """Replace alerts.dispatch so tests can never hit a webhook/network.

    Returns the recorded batches so tests can assert delivery attempts.
    """
    calls: list[list[dict]] = []

    async def _fake_dispatch(db, alerts, deliver=None):
        calls.append(list(alerts))
        return {"delivered": len(alerts), "errors": 0}

    monkeypatch.setattr(alerts_service, "dispatch", _fake_dispatch)
    return calls


@pytest.fixture
def security_client(vault):
    """Local app carrying ONLY the security router (TestClient context is
    mandatory so scheduler tasks share one event loop)."""
    local_app = FastAPI()
    local_app.include_router(security_routes.router)
    with TestClient(local_app) as client:
        _reset_security_settings(_db())
        try:
            yield client
        finally:
            canary_service.stop_canary_scheduler()
            mass_alarm_service.stop_mass_alarm_scheduler()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _db():
    from ghostdrive.services.context import require_db

    return require_db()


def _reset_security_settings(db) -> None:
    """Deterministic settings + empty states for one test."""
    db.set_setting(canary_service.SETTING_ENABLED, "false")
    db.set_setting(canary_service.SETTING_INTERVAL, "60")
    db.set_setting(canary_service.SETTING_STATE, "")
    db.set_setting(mass_alarm_service.SETTING_ENABLED, "true")
    db.set_setting(mass_alarm_service.SETTING_THRESHOLD, "50")
    db.set_setting(mass_alarm_service.SETTING_WINDOW, "5")
    db.set_setting(mass_alarm_service.SETTING_STATE, "")
    db.set_setting("alerts_state", "")


# ── Contracts ─────────────────────────────────────────────────────────────────

def test_settings_keys_and_router_contract():
    assert canary_service.SETTING_ENABLED == "canary_enabled"
    assert canary_service.SETTING_INTERVAL == "canary_interval_seconds"
    assert canary_service.SETTING_STATE == "canary_state"
    assert mass_alarm_service.SETTING_ENABLED == "mass_alarm_enabled"
    assert mass_alarm_service.SETTING_THRESHOLD == "mass_alarm_threshold"
    assert mass_alarm_service.SETTING_WINDOW == "mass_alarm_window_minutes"
    assert mass_alarm_service.SETTING_STATE == "mass_alarm_state"

    assert security_routes.router.prefix == "/api/security"
    paths = {route.path for route in security_routes.router.routes}
    assert {
        "/api/security/canaries",
        "/api/security/canary/add",
        "/api/security/canary",
        "/api/security/canary/check",
        "/api/security/canary/settings",
        "/api/security/mass-change",
        "/api/security/mass-change/settings",
        "/api/security/mass-change/check",
    } <= paths


# ── Canary: modify / re-arm ──────────────────────────────────────────────────

async def test_canary_plant_modify_trigger_and_rearm(vault):
    db = _db()
    _reset_security_settings(db)
    decoy = Path(state.app_data_dir).parent / "canary_mod" / "notes.txt"

    entry = await canary_service.plant_canary(db, str(decoy))
    assert entry["generation"] == 0 and entry["missing"] is False
    assert decoy.exists()
    # Planting must not flip the enable flag (the loop honors it).
    assert db.get_setting(canary_service.SETTING_ENABLED, "false") == "false"

    # Clean state: zero triggers, nothing dispatched.
    result = await canary_service.check_canaries(db)
    assert result["checked"] == 1 and result["triggers"] == 0
    assert result["dispatched"] == 0
    assert result["results"][0]["status"] == "ok"

    # Tamper: modify the decoy.
    decoy.write_bytes(b"encrypted by something -- all your files")
    result = await canary_service.check_canaries(db)
    assert result["triggers"] == 1 and result["dispatched"] == 1
    alert = result["alerts"][0]
    resolved = str(decoy.resolve())
    assert alert["kind"] == "canary_tampered"
    assert alert["severity"] == "critical"
    assert alert["subject_id"] == f"{resolved}#0"
    assert "modified" in alert["detail"] and resolved in alert["detail"]
    assert result["results"][0]["status"] == "tampered"
    assert alert["id"] in alerts_service.alert_state(db)["seen"]
    first_id = alert["id"]

    # Re-armed: the already-reported state never re-fires.
    result = await canary_service.check_canaries(db)
    assert result["triggers"] == 0

    # A second tamper is a fresh event: generation bumped, fresh alert id.
    decoy.write_bytes(b"second wave of ransomware -- worse this time")
    result = await canary_service.check_canaries(db)
    assert result["triggers"] == 1
    second = result["alerts"][0]
    assert second["subject_id"] == f"{resolved}#1"
    assert second["id"] != first_id
    assert second["id"] in alerts_service.alert_state(db)["seen"]
    # Re-armed again after the second tamper: stored generation is now 2.
    assert canary_service.canary_list(db)[0]["generation"] == 2


# ── Canary: deletion / missing / re-plant ────────────────────────────────────

async def test_canary_delete_missing_no_repeat_then_replant(vault, tmp_path):
    db = _db()
    _reset_security_settings(db)
    decoy = tmp_path / "canary_del.txt"

    await canary_service.plant_canary(db, str(decoy))
    decoy.unlink()

    result = await canary_service.check_canaries(db)
    assert result["triggers"] == 1
    assert result["results"][0]["status"] == "missing"
    assert "deleted" in result["results"][0]["detail"]
    assert "deleted" in result["alerts"][0]["detail"]

    # Still missing: no repeat trigger (already reported and re-armed).
    result = await canary_service.check_canaries(db)
    assert result["triggers"] == 0
    assert result["results"][0]["status"] == "missing"
    assert "already reported" in result["results"][0]["detail"]

    # Re-plant: unregister (file is gone; delete_file stays marker-safe) and
    # plant again -- a fresh, clean generation 0.
    canary_service.unregister_canary(db, str(decoy), delete_file=True)
    entry = await canary_service.plant_canary(db, str(decoy))
    assert entry["generation"] == 0 and decoy.exists()
    result = await canary_service.check_canaries(db)
    assert result["triggers"] == 0 and result["results"][0]["status"] == "ok"


# ── Route validation: 400 / 409 / marker-guarded delete ──────────────────────

def test_canary_add_routes_validation(security_client, tmp_path):
    # App-data overlap -> 400.
    overlap = str(Path(state.app_data_dir) / "decoy.txt")
    res = security_client.post("/api/security/canary/add", json={"path": overlap})
    assert res.status_code == 400, res.text

    # Empty path -> 400.
    res = security_client.post("/api/security/canary/add", json={"path": "   "})
    assert res.status_code == 400, res.text

    # A real user file: planting over it is refused (409), never overwritten.
    user_file = tmp_path / "real_notes.txt"
    original = b"definitely the user's own file"
    user_file.write_bytes(original)
    res = security_client.post(
        "/api/security/canary/add", json={"path": str(user_file)}
    )
    assert res.status_code == 409, res.text
    assert user_file.read_bytes() == original

    # plant=false registers the existing file WITHOUT modifying it.
    res = security_client.post(
        "/api/security/canary/add", json={"path": str(user_file), "plant": False}
    )
    assert res.status_code == 200, res.text
    assert user_file.read_bytes() == original
    assert len(res.json()["canaries"]) == 1

    # Duplicate registration -> 409.
    res = security_client.post(
        "/api/security/canary/add", json={"path": str(user_file), "plant": False}
    )
    assert res.status_code == 409, res.text

    # Unregistering with delete_file=true must NOT unlink a file GhostDrive
    # did not plant (no canary marker).
    res = security_client.delete(
        "/api/security/canary",
        params={"path": str(user_file), "delete_file": "true"},
    )
    assert res.status_code == 200, res.text
    assert res.json()["canaries"] == []
    assert user_file.exists() and user_file.read_bytes() == original

    # Unknown path -> 404.
    res = security_client.delete(
        "/api/security/canary", params={"path": str(tmp_path / "nope.txt")}
    )
    assert res.status_code == 404, res.text


def test_canary_settings_route_clamps(security_client):
    res = security_client.post(
        "/api/security/canary/settings",
        json={"enabled": True, "interval_seconds": 5},
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["enabled"] is True
    assert data["interval_seconds"] == 15  # clamped up to the floor

    res = security_client.post(
        "/api/security/canary/settings", json={"interval_seconds": 300}
    )
    assert res.json()["interval_seconds"] == 300
    assert res.json()["enabled"] is True  # untouched fields stay put

    res = security_client.post("/api/security/canary/settings", json={"enabled": False})
    assert res.json()["enabled"] is False

    # Status shape of GET /canaries.
    res = security_client.get("/api/security/canaries")
    assert res.status_code == 200, res.text
    assert set(res.json()) == {"enabled", "interval_seconds", "canaries"}
    assert res.json()["canaries"] == []


def test_canary_check_route_shape(security_client):
    res = security_client.post("/api/security/canary/check")
    assert res.status_code == 200, res.text
    assert res.json() == {
        "checked": 0, "triggers": 0, "alerts": [], "results": [], "dispatched": 0,
    }


# ── Mass alarm: scan window ──────────────────────────────────────────────────

def test_scan_recent_changes_counts_only_files_inside_window(tmp_path):
    root = tmp_path / "root"
    (root / "__pycache__").mkdir(parents=True)
    now = datetime.now(timezone.utc)

    (root / "fresh1.txt").write_bytes(b"a")
    (root / "fresh2.txt").write_bytes(b"b")
    (root / "__pycache__" / "junk.txt").write_bytes(b"noise")  # skipped dir
    old = root / "old.txt"
    old.write_bytes(b"c")
    backdated = (now - timedelta(minutes=10)).timestamp()
    os.utime(old, (backdated, backdated))

    count = mass_alarm_service.scan_recent_changes(
        [str(root)], now=now, window_minutes=5
    )
    assert count == 2  # fresh1 + fresh2; old.txt and __pycache__ excluded

    # max_files stops the walk early.
    assert (
        mass_alarm_service.scan_recent_changes(
            [str(root)], now=now, window_minutes=5, max_files=1
        )
        == 1
    )


# ── Mass alarm: threshold behavior ───────────────────────────────────────────

def _seed_root(db, root: Path, files: int) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for i in range(files):
        (root / f"file_{i}.txt").write_bytes(f"content {i}".encode())
    db.set_setting("sync_roots", json.dumps([str(root)]))


async def test_mass_alarm_below_threshold_is_silent(vault, tmp_path):
    db = _db()
    _reset_security_settings(db)
    root = tmp_path / "watched_low"
    _seed_root(db, root, files=2)
    db.set_setting(mass_alarm_service.SETTING_THRESHOLD, "5")

    now = datetime.now(timezone.utc)
    result = await mass_alarm_service.check_mass_change(db, now=now)
    assert result["count"] == 2 and result["threshold"] == 5
    assert result["triggered"] is False and result["alerted"] is False
    assert result["snapshot"] is None
    # The rolling window still recorded the observation.
    status = mass_alarm_service.mass_alarm_status(db)
    assert status["window"] == [{"at": now.isoformat(), "count": 2}]
    assert status["last"]["count"] == 2


async def test_mass_alarm_trigger_dedupe_and_snapshot_failure(
    vault, tmp_path, monkeypatch
):
    db = _db()
    _reset_security_settings(db)
    root = tmp_path / "watched_hot"
    _seed_root(db, root, files=3)
    db.set_setting(mass_alarm_service.SETTING_THRESHOLD, "3")

    async def _boom(db=None, objects=None, master_key=None, salt=None):
        raise RuntimeError("master key locked")

    monkeypatch.setattr(snapshots_service, "create_snapshot", _boom)

    now = datetime.now(timezone.utc)
    result = await mass_alarm_service.check_mass_change(db, now=now)
    assert result["triggered"] is True and result["alerted"] is True
    assert result["snapshot"].startswith("failed:")  # degrade, never raise
    alert_id = alerts_service.alert_id(
        "mass_modification", now.strftime("%Y-%m-%dT%H:%M")
    )
    seen = alerts_service.alert_state(db)["seen"]
    assert alert_id in seen

    # Second check in the same burst-minute: still triggered, but the stable
    # alert id dedupes -- nothing new to alert on.
    result = await mass_alarm_service.check_mass_change(db, now=now)
    assert result["triggered"] is True and result["alerted"] is False


async def test_mass_alarm_disabled_reports_and_skips(vault, tmp_path):
    db = _db()
    _reset_security_settings(db)
    root = tmp_path / "watched_off"
    _seed_root(db, root, files=5)
    db.set_setting(mass_alarm_service.SETTING_ENABLED, "false")

    result = await mass_alarm_service.check_mass_change(db)
    assert result["enabled"] is False
    # Disabled = the filesystem is not walked at all (count stays 0).
    assert result["count"] == 0
    assert result["triggered"] is False and result["alerted"] is False


def test_mass_change_settings_and_status_routes(security_client, tmp_path):
    res = security_client.get("/api/security/mass-change")
    assert res.status_code == 200, res.text
    assert set(res.json()) == {
        "enabled", "threshold", "window_minutes", "window", "last",
    }

    # Clamping: threshold floor 1, window 1..1440.
    res = security_client.post(
        "/api/security/mass-change/settings",
        json={"threshold": 0, "window_minutes": 0},
    )
    assert res.status_code == 200, res.text
    assert res.json()["threshold"] == 1 and res.json()["window_minutes"] == 1

    res = security_client.post(
        "/api/security/mass-change/settings", json={"window_minutes": 99999}
    )
    assert res.json()["window_minutes"] == 1440

    res = security_client.post(
        "/api/security/mass-change/settings", json={"enabled": False}
    )
    assert res.json()["enabled"] is False

    # On-demand check honors the disabled flag and reports the full shape.
    res = security_client.post("/api/security/mass-change/check")
    assert res.status_code == 200, res.text
    data = res.json()
    assert set(data) == {
        "count", "threshold", "window_minutes", "triggered", "alerted",
        "enabled", "roots", "snapshot",
    }
    assert data["enabled"] is False and data["triggered"] is False


# ── Scheduler lifecycles ─────────────────────────────────────────────────────

async def test_canary_scheduler_start_stop_and_double_start(vault):
    db = _db()
    _reset_security_settings(db)
    assert canary_service.stop_canary_scheduler() is None  # nothing running yet

    try:
        task = canary_service.start_canary_scheduler(db=db)
        assert task is not None and not task.done()
        assert canary_service._scheduler_task is task
        # Double start is a no-op returning the same task.
        assert canary_service.start_canary_scheduler(db=db) is task

        canary_service.stop_canary_scheduler()
        assert canary_service._scheduler_task is None
        with contextlib.suppress(asyncio.CancelledError):
            await task  # reap the cancelled loop (no pending-task warning)
        assert task.cancelled()
        assert canary_service._scheduler_task is None
    finally:
        canary_service.stop_canary_scheduler()


async def test_mass_alarm_scheduler_start_stop_and_double_start(vault):
    db = _db()
    _reset_security_settings(db)
    assert mass_alarm_service.stop_mass_alarm_scheduler() is None

    try:
        task = mass_alarm_service.start_mass_alarm_scheduler(db=db)
        assert task is not None and not task.done()
        assert mass_alarm_service._scheduler_task is task
        assert mass_alarm_service.start_mass_alarm_scheduler(db=db) is task

        mass_alarm_service.stop_mass_alarm_scheduler()
        assert mass_alarm_service._scheduler_task is None
        with contextlib.suppress(asyncio.CancelledError):
            await task
        assert task.cancelled()
        assert mass_alarm_service._scheduler_task is None
    finally:
        mass_alarm_service.stop_mass_alarm_scheduler()
