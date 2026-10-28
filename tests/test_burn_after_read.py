"""
test_burn_after_read.py -- Burn-after-read envelope links (/e/{token}).

Covers the opt-in burn semantics: the ciphertext blob is destroyed on the
backend after the FIRST completed fetch of /api/public/envelope/{token}/blob
(a BackgroundTask starlette runs after the body is fully sent — TestClient
runs it synchronously before its get() returns, which is the test-visible
ordering).  Later access answers 410 Gone with "burned" in the detail, the
settings meta entry is RETAINED and rewritten as burned (so burned (410) is
distinguishable from unknown (404)), the share row is revoked, the backend
object is really gone, and burn wins over max_downloads.  A non-burn envelope
must keep working exactly as before (fetchable twice, no burn markers).
"""

from __future__ import annotations

import asyncio
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ghostdrive.exceptions import BackendError
from ghostdrive.services import sharing as sharing_service
from ghostdrive.services.context import build_backend
from ghostdrive.web.routes import sharing as sharing_routes
from ghostdrive.web.state import state

PASSPHRASE = "correct horse battery staple"
MAGIC = b"GDSHARE1"


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def client(tmp_path):
    """Fresh unlocked vault + a local app with only the sharing routers."""
    state.clean_shutdown()
    state.app_data_dir = tmp_path
    state.keystore_path = tmp_path / "keystore.json"
    state.db_path = tmp_path / "ghostdrive.db"

    from ghostdrive.web.routes.auth import router as auth_router
    from ghostdrive.web.routes.files import router as files_router

    app = FastAPI()
    app.include_router(auth_router)
    app.include_router(files_router)
    app.include_router(sharing_routes.router)
    app.include_router(sharing_routes.public_router)

    client = TestClient(app)
    res = client.post("/api/auth/setup", json={"passphrase": PASSPHRASE})
    assert res.status_code == 200, res.text

    yield client

    state.clean_shutdown()


# ── Helpers ──────────────────────────────────────────────────────────────────

def _seed(client, payload: bytes = b"burn me", name: str = "note.txt") -> str:
    res = client.post(
        "/api/files/upload",
        files={"file": (name, payload, "text/plain")},
        data={"tier": "DISPOSABLE", "destination_path": "/"},
    )
    assert res.status_code == 200, res.text
    return res.json()["file_id"]


def _envelope_meta(token: str) -> dict:
    """The retained settings entry for a token ({} when unknown)."""
    raw = state.db.get_setting(sharing_service.ENVELOPE_SETTINGS_KEY, "{}") or "{}"
    return json.loads(raw).get(token) or {}


def _backend_object(backend_id: str):
    row = state.db.get_backend(backend_id)
    assert row is not None
    return build_backend(row)


def _try_backend_download(backend_id: str, reference_id: str) -> bytes:
    obj = _backend_object(backend_id)

    async def _run() -> bytes:
        parts: list[bytes] = []
        async for block in obj.download(reference_id):
            parts.append(block)
        return b"".join(parts)

    return asyncio.run(_run())


# ── Burn flow ────────────────────────────────────────────────────────────────

def test_burn_after_read_destroys_blob_after_first_fetch(client):
    file_id = _seed(client, b"one time secret")
    res = client.post(
        "/api/sharing/envelope",
        json={"file_id": file_id, "burn_after_read": True},
    )
    assert res.status_code == 200, res.text
    token = res.json()["token"]
    assert res.json()["burn_after_read"] is True

    # At creation: opt-in marker persisted, NOT yet burned.
    meta = _envelope_meta(token)
    assert meta["burn"] is True
    assert not meta.get("burned")

    # First (and only) fetch serves the ciphertext.
    blob = client.get(f"/api/public/envelope/{token}/blob")
    assert blob.status_code == 200, blob.text
    assert blob.content.startswith(MAGIC)

    # TestClient consumed the full body, so the post-stream burn task has run:
    # the meta entry is RETAINED but rewritten as burned.
    meta = _envelope_meta(token)
    assert meta["burned"] is True
    assert meta["burned_at"]
    # Backend location kept for forensics; "destroyed" records the deletion.
    assert meta["backend_id"] and meta["reference_id"]
    assert meta["destroyed"] is True
    # The share row is tombstoned/revoked.
    assert state.db.get_share_link(token)["revoked"] == 1

    # Every later access is 410 Gone with the "burned" message.
    for path in (
        f"/api/public/envelope/{token}",
        f"/api/public/envelope/{token}/blob",
        f"/e/{token}",
    ):
        later = client.get(path)
        assert later.status_code == 410, f"{path}: {later.status_code}"
        assert "burned" in later.json()["detail"].lower()

    # The backend object itself is gone: a raw backend download raises.
    with pytest.raises(BackendError):
        _try_backend_download(meta["backend_id"], meta["reference_id"])


def test_burn_marker_persisted_at_creation_via_service(client):
    """The service helper records the opt-in marker before any fetch."""
    file_id = _seed(client, b"service level burn")
    link = asyncio.run(
        sharing_service.create_envelope_link(
            file_id, burn_after_read=True, passphrase=PASSPHRASE
        )
    )
    meta = _envelope_meta(link["token"])
    assert meta["burn"] is True
    assert not meta.get("burned")
    # Still fully usable until the first completed blob fetch.
    assert client.get(f"/api/public/envelope/{link['token']}").status_code == 200


def test_non_burn_envelope_fetchable_twice_no_burn_marker(client):
    file_id = _seed(client, b"regular link payload")
    res = client.post("/api/sharing/envelope", json={"file_id": file_id})
    assert res.status_code == 200, res.text
    token = res.json()["token"]
    assert res.json()["burn_after_read"] is False

    first = client.get(f"/api/public/envelope/{token}/blob")
    second = client.get(f"/api/public/envelope/{token}/blob")
    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert first.content.startswith(MAGIC)
    assert first.content == second.content  # identical ciphertext, no burn

    meta = _envelope_meta(token)
    assert not meta.get("burn")
    assert not meta.get("burned")
    assert client.get(f"/api/public/envelope/{token}").status_code == 200
    assert client.get(f"/e/{token}").status_code == 200


def test_burned_is_410_unknown_is_404(client):
    # Unknown token: 404, never 410 (nothing was ever burned).
    missing = client.get("/api/public/envelope/not-a-real-token")
    assert missing.status_code == 404
    assert client.get("/api/public/envelope/not-a-real-token/blob").status_code == 404

    # Burned token: 410 on header, blob and page.
    file_id = _seed(client, b"burn distinguishes itself")
    res = client.post(
        "/api/sharing/envelope",
        json={"file_id": file_id, "burn_after_read": True},
    )
    token = res.json()["token"]
    assert (
        client.get(f"/api/public/envelope/{token}/blob").status_code == 200
    )
    for path in (
        f"/api/public/envelope/{token}",
        f"/api/public/envelope/{token}/blob",
        f"/e/{token}",
    ):
        burned = client.get(path)
        assert burned.status_code == 410
        assert "burned" in burned.json()["detail"].lower()


def test_burn_wins_over_max_downloads(client):
    """max_downloads=5 still dies after ONE fetch — burn is terminal."""
    file_id = _seed(client, b"budget vs burn")
    res = client.post(
        "/api/sharing/envelope",
        json={"file_id": file_id, "burn_after_read": True, "max_downloads": 5},
    )
    assert res.status_code == 200, res.text
    token = res.json()["token"]

    assert client.get(f"/api/public/envelope/{token}/blob").status_code == 200
    # Not 403 ("download limit"/"revoked") — 410, the burn is what ended it.
    second = client.get(f"/api/public/envelope/{token}/blob")
    assert second.status_code == 410
    assert "burned" in second.json()["detail"].lower()


def test_burn_envelope_service_refuses_second_serve(client):
    """After burn_envelope, even a direct load_envelope_blob cannot serve."""
    file_id = _seed(client, b"direct service burn")
    link = asyncio.run(
        sharing_service.create_envelope_link(
            file_id, burn_after_read=True, passphrase=PASSPHRASE
        )
    )
    token = link["token"]
    info = sharing_service.verify_envelope_access(token)
    envelope = asyncio.run(sharing_service.load_envelope_blob(info))
    assert envelope.startswith(MAGIC)

    burn = asyncio.run(sharing_service.burn_envelope(token))
    assert burn["status"] == "burned"
    assert burn["already_burned"] is False
    assert burn["ciphertext_destroyed"] is True

    # The burned state is terminal at the service level too.
    with pytest.raises(sharing_service.EnvelopeBurnedError):
        sharing_service.verify_envelope_access(token)
    meta = _envelope_meta(token)
    with pytest.raises(BackendError):
        _try_backend_download(meta["backend_id"], meta["reference_id"])

    # Idempotent: burning again reports already_burned, storage untouched.
    again = asyncio.run(sharing_service.burn_envelope(token))
    assert again["already_burned"] is True
