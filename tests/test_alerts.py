"""Tests for resilience alert evaluation, dedupe/dismiss state, and delivery."""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ghostdrive.database.db import GhostDriveDB
from ghostdrive.pipeline.coding import TOTAL_SHARDS
from ghostdrive.services import alerts
from ghostdrive.web.routes import monitoring
from ghostdrive.web.state import state

PASSPHRASE = "correct horse battery staple"


# ─── DB helpers: copied from tests/test_durability.py ────────────────────────


def _make_db(tmp_path: Path) -> GhostDriveDB:
    db = GhostDriveDB(
        path=tmp_path / "durability.db",
        ledger_key=bytes(range(32)),
        genesis_seed=bytes(range(32, 64)),
        master_key=bytes(range(32)),
    )
    db.open()
    return db


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _backend(db, backend_type: str, credentials_ref: str = "ref:test", **overrides) -> str:
    backend_id = str(uuid.uuid4())
    values = {
        "id": backend_id,
        "type": backend_type,
        "credentials_ref": credentials_ref,
        "status": "healthy",
        "priority": 100,
        "quota_used": 0,
        "quota_limit": 1024 ** 3,
        "quota_reserved": 0,
    }
    values.update(overrides)
    columns = ", ".join(values)
    marks = ", ".join("?" for _ in values)
    db._conn.execute("BEGIN")
    db._conn.execute(
        f"INSERT INTO backends ({columns}) VALUES ({marks})", tuple(values.values())
    )
    db._conn.execute("COMMIT")
    return backend_id


def _file(db, tier: str = "CRITICAL") -> str:
    file_id = str(uuid.uuid4())
    now = _now()
    db._conn.execute("BEGIN")
    db._conn.execute(
        """INSERT INTO files (id, name, path, size, mime_type, tier, created_at, modified_at)
           VALUES (?, 'test.bin', '/tmp/test.bin', 128, 'application/octet-stream', ?, ?, ?)""",
        (file_id, tier, now, now),
    )
    db._conn.execute("COMMIT")
    return file_id


def _chunk(db, file_id: str, sub_block_count: int = TOTAL_SHARDS) -> str:
    chunk_id = str(uuid.uuid4())
    db._conn.execute("BEGIN")
    db._conn.execute(
        """INSERT INTO chunks
           (id, file_id, chunk_index, total_chunks, blake3_hash, size,
            nonce_counter, sub_block_count)
           VALUES (?, ?, 0, 1, ?, 128, 1, ?)""",
        (chunk_id, file_id, "0" * 64, sub_block_count),
    )
    db._conn.execute("COMMIT")
    return chunk_id


def _location(db, chunk_id: str, backend_id: str, sub_block_index: int, status: str = "confirmed") -> None:
    db._conn.execute("BEGIN")
    db._conn.execute(
        """INSERT INTO chunk_locations
           (chunk_id, sub_block_index, backend_id, reference_id, upload_date, status)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (chunk_id, sub_block_index, backend_id, f"ref-{sub_block_index}", _now(), status),
    )
    db._conn.execute("COMMIT")


def _insert_drill(db, result: str, at: datetime, detail: str = "") -> str:
    drill_id = str(uuid.uuid4())
    stamp = at.isoformat()
    db._conn.execute("BEGIN")
    db._conn.execute(
        """INSERT INTO restore_drills
           (id, started_at, completed_at, snapshot_id, file_id, chunk_id,
            shards_used, domains_used, bytes_restored, duration_ms, result, detail)
           VALUES (?, ?, ?, NULL, NULL, NULL, 0, 0, 0, 0, ?, ?)""",
        (drill_id, stamp, stamp, result, detail),
    )
    db._conn.execute("COMMIT")
    return drill_id


def _by_kind(alert_list) -> dict:
    return {alert["kind"]: alert for alert in alert_list}


# ─── evaluate: every kind fires from seeded data ─────────────────────────────


def test_evaluate_fires_drill_alerts(tmp_path):
    db = _make_db(tmp_path)
    now = datetime.now(timezone.utc)

    assert alerts.evaluate(db) == []  # fresh DB: nothing to say, no noise

    _insert_drill(db, "passed", now - timedelta(days=20))
    fired = _by_kind(alerts.evaluate(db))
    assert "drill_stale" in fired
    assert fired["drill_stale"]["severity"] == "warning"

    _insert_drill(db, "failed", now, detail="shard unavailable")
    fired = _by_kind(alerts.evaluate(db))
    assert fired["drill_failed"]["severity"] == "critical"
    assert "shard unavailable" in fired["drill_failed"]["detail"]


def test_evaluate_backend_status_alerts(tmp_path):
    db = _make_db(tmp_path)
    degraded = _backend(db, "local", status="degraded")
    unreachable = _backend(db, "local", status="unreachable")

    fired = _by_kind(alerts.evaluate(db))

    assert fired["backend_degraded"]["severity"] == "warning"
    assert fired["backend_degraded"]["subject_id"] == degraded
    assert fired["backend_unreachable"]["severity"] == "critical"
    assert fired["backend_unreachable"]["subject_id"] == unreachable


def test_evaluate_hostility_alerts_from_canned_verdicts(tmp_path, monkeypatch):
    db = _make_db(tmp_path)
    withholder = _backend(db, "telegram")
    corrupter = _backend(db, "discord")

    # Keep it cheap: no integrity_log re-seeding, patch the detector instead.
    monkeypatch.setattr(
        alerts.hostility,
        "detect_withholding",
        lambda _db, **kwargs: {
            "flagged": [
                {"backend_id": withholder, "verdict": "withholding"},
                {"backend_id": corrupter, "verdict": "corrupting"},
            ]
        },
    )

    fired = _by_kind(alerts.evaluate(db))

    assert fired["backend_withholding"]["subject_id"] == withholder
    assert fired["backend_withholding"]["severity"] == "critical"
    assert fired["backend_corrupting"]["subject_id"] == corrupter
    assert fired["backend_corrupting"]["severity"] == "critical"


def test_evaluate_tolerates_hostility_failure(tmp_path, monkeypatch):
    """One broken subsystem must never silence the whole alert feed."""
    db = _make_db(tmp_path)
    _backend(db, "local", status="degraded")

    def _boom(_db, **kwargs):
        raise RuntimeError("hostility subsystem down")

    monkeypatch.setattr(alerts.hostility, "detect_withholding", _boom)

    kinds = {alert["kind"] for alert in alerts.evaluate(db)}
    assert "backend_degraded" in kinds


def test_evaluate_contract_alerts_and_at_risk_aggregation(tmp_path):
    db = _make_db(tmp_path)
    backend_id = _backend(db, "local")
    # Two erasure chunks, every shard on ONE failure domain: survivable
    # domain losses = 0, below the default contract of 2.
    chunk_ids = [_chunk(db, _file(db)) for _ in range(2)]
    for chunk_id in chunk_ids:
        for sub_index in range(TOTAL_SHARDS):
            _location(db, chunk_id, backend_id, sub_index)

    fired_list = alerts.evaluate(db)
    kinds = [alert["kind"] for alert in fired_list]

    assert "durability_below_contract" in kinds
    below = next(a for a in fired_list if a["kind"] == "durability_below_contract")
    assert "Guaranteed survivable domain losses: 0" in below["detail"]
    assert "contract requires 2" in below["detail"]

    # ONE aggregated alert with a count -- not one alert per chunk.
    at_risk = [a for a in fired_list if a["kind"] == "at_risk_chunks"]
    assert len(at_risk) == 1
    assert "2 chunk(s)" in at_risk[0]["detail"]
    assert kinds.count("at_risk_chunks") == 1


def test_evaluate_quota_low(tmp_path):
    db = _make_db(tmp_path)
    full = _backend(db, "local", quota_used=95, quota_limit=100)

    fired = _by_kind(alerts.evaluate(db))

    assert "quota_low" in fired
    assert fired["quota_low"]["subject_id"] == full
    assert fired["quota_low"]["severity"] == "warning"
    assert "95%" in fired["quota_low"]["detail"]


# ─── record_alerts: dedupe, dismiss, id stability ────────────────────────────


def test_record_alerts_dedupes_and_persists_dismissal(tmp_path):
    db = _make_db(tmp_path)
    _backend(db, "local", status="degraded")
    first_at = datetime.now(timezone.utc)

    first = alerts.evaluate(db, now=first_at)
    assert first
    new_one = alerts.record_alerts(db, first, now=first_at)
    assert {a["id"] for a in new_one} == {a["id"] for a in first}

    # Same conditions five minutes later: zero new alerts (stable-id dedupe).
    second_at = first_at + timedelta(minutes=5)
    second = alerts.evaluate(db, now=second_at)
    assert alerts.record_alerts(db, second, now=second_at) == []

    state_now = alerts.alert_state(db)
    degraded = next(a for a in state_now["alerts"] if a["kind"] == "backend_degraded")
    assert degraded["first_seen_at"] == first_at.isoformat()
    assert degraded["dismissed"] is False
    assert state_now["active_count"] == len(state_now["alerts"])

    result = alerts.dismiss_alert(db, degraded["id"])
    assert result["alert_id"] == degraded["id"]

    after = alerts.alert_state(db)
    assert after["dismissed"][degraded["id"]]
    assert degraded["id"] not in after["seen"]  # moved out of seen, into dismissed
    still_there = next(a for a in after["alerts"] if a["kind"] == "backend_degraded")
    assert still_there["dismissed"] is True
    assert after["active_count"] == 0

    # A dismissed id is never re-announced as "new".
    third = alerts.evaluate(db, now=first_at + timedelta(minutes=10))
    assert alerts.record_alerts(db, third, now=first_at + timedelta(minutes=10)) == []

    with pytest.raises(FileNotFoundError):
        alerts.dismiss_alert(db, "does-not-exist")


def test_alert_ids_stable_across_now_injection(tmp_path):
    db = _make_db(tmp_path)
    _backend(db, "local", status="unreachable")

    early = alerts.evaluate(db, now=datetime(2026, 1, 1, tzinfo=timezone.utc))
    late = alerts.evaluate(db, now=datetime(2026, 6, 1, tzinfo=timezone.utc))

    assert [a["id"] for a in early] == [a["id"] for a in late]
    assert early[0]["detected_at"] != late[0]["detected_at"]
    assert len(early[0]["id"]) == 16


# ─── dispatch: registered deliverers + webhook ───────────────────────────────


def _sample_alert(alert_id: str = "feedfacefeedface") -> dict:
    return {
        "id": alert_id,
        "kind": "backend_degraded",
        "severity": "warning",
        "subject_id": "backend-1",
        "title": "Backend degraded",
        "detail": "Test alert.",
        "detected_at": datetime.now(timezone.utc).isoformat(),
    }


def test_dispatch_counts_registered_deliverer(tmp_path, monkeypatch):
    db = _make_db(tmp_path)
    monkeypatch.setattr(alerts, "_DELIVERERS", [])  # hermetic channel list
    seen: list[str] = []

    async def _capture(alert: dict) -> None:
        seen.append(alert["id"])

    alerts.register_deliverer(_capture)
    result = asyncio.run(alerts.dispatch(db, [_sample_alert()]))

    assert result == {"delivered": 1, "errors": 0}
    assert seen == ["feedfacefeedface"]

    # A failing deliverer is counted, never raised.
    async def _boom(alert: dict) -> None:
        raise RuntimeError("toast backend down")

    alerts.register_deliverer(_boom)
    result = asyncio.run(alerts.dispatch(db, [_sample_alert()]))
    assert result == {"delivered": 1, "errors": 1}


def test_dispatch_posts_to_configured_webhook(tmp_path, monkeypatch):
    db = _make_db(tmp_path)
    monkeypatch.setattr(alerts, "_DELIVERERS", [])
    with db.transaction():
        db.set_setting(alerts.ALERT_WEBHOOK_URL_KEY, "https://hooks.example.test/gd")
    calls: list[tuple[str, dict]] = []

    async def _fake_post(url: str, payload: dict) -> None:
        calls.append((url, payload))

    monkeypatch.setattr(alerts, "_post_webhook", _fake_post)
    result = asyncio.run(alerts.dispatch(db, [_sample_alert("aaaabbbbcccceeee")]))

    assert result == {"delivered": 1, "errors": 0}
    assert calls[0][0] == "https://hooks.example.test/gd"
    assert calls[0][1]["id"] == "aaaabbbbcccceeee"

    # Failures are logged and counted, never raised.
    async def _fail(url: str, payload: dict) -> None:
        raise OSError("connection refused")

    monkeypatch.setattr(alerts, "_post_webhook", _fail)
    result = asyncio.run(alerts.dispatch(db, [_sample_alert()]))
    assert result == {"delivered": 0, "errors": 1}


def test_alerts_scheduler_start_is_idempotent_and_stop_clears(tmp_path):
    db = _make_db(tmp_path)

    async def scenario():
        task = alerts.start_alerts_scheduler(interval_minutes=1e-3, db=db)
        assert task is not None
        assert not task.done()

        again = alerts.start_alerts_scheduler(interval_minutes=1e-3, db=db)
        assert again is task  # double-start is a no-op

        await asyncio.sleep(0.05)  # tiny sleep: never stall the suite

        alerts.stop_alerts_scheduler()
        assert alerts._alerts_task is None
        await asyncio.sleep(0.01)

    asyncio.run(scenario())


# ─── Routes (hermetic local app, no server.py import) ────────────────────────


@pytest.fixture
def monitor(tmp_path):
    from ghostdrive.crypto.credential_store import credential_store
    from ghostdrive.crypto.hkdf import derive_index_mac_key
    from ghostdrive.crypto.keystore import KeystoreManager

    state.clean_shutdown()
    state.app_data_dir = tmp_path
    state.keystore_path = tmp_path / "keystore.json"
    state.db_path = tmp_path / "ghostdrive.db"

    km = KeystoreManager(state.keystore_path)
    seed_phrase = km.create_new(PASSPHRASE.encode("utf-8"), calibrate=False)
    km.verify_and_save(seed_phrase)
    state.km = km

    master_key = km._master_key_buf.key
    db = GhostDriveDB(
        state.db_path,
        derive_index_mac_key(master_key, km._hkdf_salt),
        km._genesis_seed,
        master_key,
    )
    db.open()
    state.db = db
    credential_store.set_active_key(bytes(master_key), bytes(km._hkdf_salt))
    state.load_persisted_settings()

    app = FastAPI()
    app.include_router(monitoring.router)
    client = TestClient(app)
    yield client
    state.clean_shutdown()


def test_alert_routes_evaluate_and_dismiss(monitor):
    res = monitor.get("/api/monitoring/alerts")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["alerts"] == []
    assert body["active_count"] == 0
    assert body["dismissed"] == {}

    res = monitor.post("/api/monitoring/alerts/evaluate")
    assert res.status_code == 200, res.text
    evaluated = res.json()
    assert evaluated["new_alerts"] == []
    assert evaluated["total"] == 0
    assert evaluated["dispatch"] == {"delivered": 0, "errors": 0}

    # Unknown id -> 404 via the local _http_error mapping.
    res = monitor.delete("/api/monitoring/alerts/not-a-real-id")
    assert res.status_code == 404

    # A live alert can be dismissed straight from the GET list.
    state.db._conn.execute("BEGIN")
    state.db._conn.execute(
        """INSERT INTO backends
           (id, type, credentials_ref, status, priority, quota_used, quota_limit, quota_reserved)
           VALUES ('route-degraded-1', 'local', 'ref:route', 'degraded', 100, 0, 1024, 0)"""
    )
    state.db._conn.execute("COMMIT")

    res = monitor.get("/api/monitoring/alerts")
    assert res.status_code == 200
    live = res.json()["alerts"]
    degraded = next(a for a in live if a["kind"] == "backend_degraded")
    assert degraded["dismissed"] is False

    res = monitor.delete(f"/api/monitoring/alerts/{degraded['id']}")
    assert res.status_code == 200, res.text
    assert res.json()["alert_id"] == degraded["id"]

    res = monitor.get("/api/monitoring/alerts")
    after = res.json()
    assert after["active_count"] == 0
    remaining = next(a for a in after["alerts"] if a["kind"] == "backend_degraded")
    assert remaining["dismissed"] is True
    assert degraded["id"] in after["dismissed"]

    # Dismissing the same id again is still fine (already in dismissed).
    res = monitor.delete(f"/api/monitoring/alerts/{degraded['id']}")
    assert res.status_code == 200
