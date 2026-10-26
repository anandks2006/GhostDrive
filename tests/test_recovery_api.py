"""
test_recovery_api.py -- /api/recovery endpoints: status, kit export, preview,
and combine (full restore-from-shares web flow).
"""

import pytest
from fastapi.testclient import TestClient

from ghostdrive.web.server import app
from ghostdrive.web.state import state

PASSPHRASE = "correct horse battery staple"


@pytest.fixture
def recovery_client(tmp_path):
    """Fresh unlocked vault in a temp dir (function-scoped: these tests lock it)."""
    state.clean_shutdown()
    state.app_data_dir = tmp_path
    state.keystore_path = tmp_path / "keystore.json"
    state.db_path = tmp_path / "ghostdrive.db"

    client = TestClient(app)
    res = client.post("/api/auth/setup", json={"passphrase": PASSPHRASE})
    assert res.status_code == 200, res.text

    yield client

    state.clean_shutdown()


def test_recovery_status(recovery_client):
    res = recovery_client.get("/api/recovery/status")
    assert res.status_code == 200
    data = res.json()
    assert data["available"] is True
    assert data["unlocked"] is True
    assert data["threshold"] == 3
    assert data["total"] == 5
    assert "offline_tool" in data


def test_kit_export_returns_five_distinct_shares(recovery_client):
    res = recovery_client.post("/api/recovery/kit/export", json={"threshold": 3, "total": 5})
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["status"] == "success"
    assert len(data["shares"]) == 5
    assert len(set(data["shares"])) == 5
    assert all(s.startswith("GDSHARE1:") for s in data["shares"])
    assert len(data["filenames"]) == 5
    assert data["manifest"]["threshold"] == 3
    assert data["manifest"]["total"] == 5
    # The raw key must never appear in the response payload.
    from ghostdrive.crypto.keystore import entropy_to_mnemonic

    master = bytes(state.km.master_key)
    blob = str(data)
    assert entropy_to_mnemonic(master) not in blob
    assert master.hex() not in blob


def test_kit_export_validation(recovery_client):
    res = recovery_client.post("/api/recovery/kit/export", json={"threshold": 6, "total": 5})
    assert res.status_code in (400, 422)


def test_kit_preview_progress(recovery_client):
    exported = recovery_client.post(
        "/api/recovery/kit/export", json={"threshold": 3, "total": 5}
    ).json()["shares"]

    res = recovery_client.post("/api/recovery/kit/preview", json={"shares": exported[:2]})
    assert res.status_code == 200
    data = res.json()
    assert data["valid"] is True
    assert data["ready"] is False
    assert data["missing"] == 1

    res = recovery_client.post("/api/recovery/kit/preview", json={"shares": exported[:3]})
    data = res.json()
    assert data["ready"] is True
    assert data["missing"] == 0


def test_kit_preview_reports_bad_share(recovery_client):
    res = recovery_client.post(
        "/api/recovery/kit/preview", json={"shares": ["GDSHARE1:not-a-real-share"]}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["valid"] is False
    assert data["ready"] is False
    assert data["errors"]


def test_kit_combine_refused_while_unlocked(recovery_client):
    res = recovery_client.post("/api/recovery/kit/combine", json={
        "shares": ["GDSHARE1:x"], "passphrase": "new",
    })
    assert res.status_code == 409


def test_kit_combine_restores_vault(recovery_client):
    """Full flow: export → lock → combine with new passphrase → unlocked again."""
    exported = recovery_client.post(
        "/api/recovery/kit/export", json={"threshold": 3, "total": 5}
    ).json()

    # Lock the vault (combine is only for a locked/lost passphrase scenario).
    locked = recovery_client.post("/api/auth/lock")
    assert locked.status_code == 200

    # Wrong count fails closed with 400.
    short = recovery_client.post("/api/recovery/kit/combine", json={
        "shares": exported["shares"][:2],
        "passphrase": "brand new pass",
    })
    assert short.status_code == 400

    # Corrupted share fails closed with 400.
    corrupted = list(exported["shares"][:3])
    idx = corrupted[0].index("A") if "A" in corrupted[0] else corrupted[0].index("B") + 1
    corrupted[0] = corrupted[0][:idx] + ("B" if corrupted[0][idx] == "A" else "A") + corrupted[0][idx + 1:]
    bad = recovery_client.post("/api/recovery/kit/combine", json={
        "shares": corrupted, "passphrase": "brand new pass",
    })
    assert bad.status_code == 400

    # 3 valid shares + new passphrase restores and unlocks.
    res = recovery_client.post("/api/recovery/kit/combine", json={
        "shares": exported["shares"][:3],
        "passphrase": "brand new pass",
    })
    assert res.status_code == 200, res.text
    assert res.json()["status"] == "success"

    status = recovery_client.get("/api/auth/status").json()
    assert status["is_unlocked"] is True
    assert status["db_opened"] is True

    # The rebuilt keystore opens with the NEW passphrase and holds the same key.
    from ghostdrive.crypto.keystore import KeystoreManager

    km = KeystoreManager(state.keystore_path)
    km.unlock(b"brand new pass")
    assert bytes(km.master_key) == bytes(state.km.master_key)

    # Old passphrase must no longer work.
    from ghostdrive.exceptions import AuthenticationError

    km2 = KeystoreManager(state.keystore_path)
    with pytest.raises(AuthenticationError):
        km2.unlock(PASSPHRASE.encode())
