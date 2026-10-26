"""
test_portable_api.py -- /api/portable endpoints: status, export download,
inspect, and import (with index restore).
"""

import io
import zipfile

import pytest
from fastapi.testclient import TestClient

from ghostdrive.web.server import app
from ghostdrive.web.state import state

PASSPHRASE = "correct horse battery staple"


@pytest.fixture
def portable_client(tmp_path):
    """Fresh unlocked vault in a temp dir (function-scoped: import replaces it)."""
    state.clean_shutdown()
    state.app_data_dir = tmp_path
    state.keystore_path = tmp_path / "keystore.json"
    state.db_path = tmp_path / "ghostdrive.db"

    client = TestClient(app)
    res = client.post("/api/auth/setup", json={"passphrase": PASSPHRASE})
    assert res.status_code == 200, res.text

    yield client

    state.clean_shutdown()


def test_portable_status(portable_client):
    res = portable_client.get("/api/portable/status")
    assert res.status_code == 200
    data = res.json()
    assert data["available"] is True
    assert data["unlocked"] is True
    assert data["extension"] == ".gdvault"


def test_export_downloads_encrypted_blob(portable_client):
    res = portable_client.post(
        "/api/portable/export",
        json={"passphrase": PASSPHRASE, "include_index": True, "label": "move"},
    )
    assert res.status_code == 200, res.text
    assert res.headers["content-type"] == "application/octet-stream"
    assert "ghostdrive-vault.gdvault" in res.headers["content-disposition"]
    blob = res.content
    assert blob[:8] == b"GDVAULT1"
    # No keystore/plaintext leakage in the transported bytes.
    assert b"argon2_salt" not in blob
    assert b"ciphertext" not in blob
    assert res.headers["X-GhostDrive-Blake3"]


def test_export_requires_unlock_and_passphrase(portable_client):
    res = portable_client.post("/api/portable/export", json={"passphrase": ""})
    assert res.status_code == 400

    assert portable_client.post("/api/auth/lock").status_code == 200
    res = portable_client.post(
        "/api/portable/export", json={"passphrase": PASSPHRASE}
    )
    assert res.status_code == 401


def test_export_import_roundtrip_with_index(portable_client):
    """Export → lock → import (keystore + index) → unlocked and same key."""
    exported = portable_client.post(
        "/api/portable/export",
        json={"passphrase": PASSPHRASE, "include_index": True},
    )
    assert exported.status_code == 200
    vault_blob = exported.content

    original_key = bytes(state.km.master_key)
    assert portable_client.post("/api/auth/lock").status_code == 200

    res = portable_client.post(
        "/api/portable/import?passphrase=" + PASSPHRASE.replace(" ", "%20") +
        "&restore_index=true&overwrite=true",
        files={"file": ("ghostdrive-vault.gdvault", io.BytesIO(vault_blob), "application/octet-stream")},
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["status"] == "success"
    assert data["index_restored"] is True

    status = portable_client.get("/api/auth/status").json()
    assert status["is_unlocked"] is True
    assert status["db_opened"] is True
    assert bytes(state.km.master_key) == original_key

    # The restored index is usable: the list endpoint reads the imported DB
    # without error and reports the snapshot's root directory.
    files = portable_client.get("/api/files/list").json()
    assert files["current_directory"] == "/"
    assert "files" in files

    # And the HMAC ledger still validates on the imported index.
    status = portable_client.get("/api/resilience/status")
    assert status.status_code == 200


def test_import_bad_passphrase_rejected(portable_client):
    exported = portable_client.post(
        "/api/portable/export",
        json={"passphrase": PASSPHRASE, "include_index": False},
    )
    blob = exported.content
    assert portable_client.post("/api/auth/lock").status_code == 200

    # The outer envelope is passphrase-sealed, so a wrong passphrase fails
    # closed at decryption (400) before any keystore is touched.
    res = portable_client.post(
        "/api/portable/import?passphrase=wrong%20pass",
        files={"file": ("v.gdvault", io.BytesIO(blob), "application/octet-stream")},
    )
    assert res.status_code == 400
    assert "passphrase" in res.json()["detail"].lower()


def test_inspect_uploaded_vault(portable_client):
    exported = portable_client.post(
        "/api/portable/export",
        json={"passphrase": PASSPHRASE, "include_index": True, "label": "inspect me"},
    )
    res = portable_client.post(
        "/api/portable/inspect?passphrase=" + PASSPHRASE.replace(" ", "%20"),
        files={"file": ("v.gdvault", io.BytesIO(exported.content), "application/octet-stream")},
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["label"] == "inspect me"
    assert data["has_snapshot"] is True
    assert "keystore.json" in data["members"]


def test_inspect_wrong_passphrase(portable_client):
    exported = portable_client.post(
        "/api/portable/export",
        json={"passphrase": PASSPHRASE, "include_index": False},
    )
    res = portable_client.post(
        "/api/portable/inspect?passphrase=nope",
        files={"file": ("v.gdvault", io.BytesIO(exported.content), "application/octet-stream")},
    )
    assert res.status_code == 400


def test_import_garbage_rejected(portable_client):
    res = portable_client.post(
        "/api/portable/import?passphrase=x",
        files={"file": ("junk.bin", io.BytesIO(b"not a vault at all"), "application/octet-stream")},
    )
    assert res.status_code == 400
