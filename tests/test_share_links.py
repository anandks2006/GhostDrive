"""
test_share_links.py -- Zero-knowledge envelope share links (/e/{token}).

Covers create_envelope_link, the GDSHARE1 byte layout (including a tiny
Python mirror of receive.js that decrypts the envelope end-to-end), the
access checks (expiry / revocation / max downloads), the public routes, and
a regression check that the classic /s/{token} flow still behaves.
"""

import asyncio
import base64
import hashlib
import json
import struct
from datetime import datetime, timezone

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ghostdrive.services import sharing as sharing_service
from ghostdrive.web.routes import sharing as sharing_routes
from ghostdrive.web.state import state

PASSPHRASE = "correct horse battery staple"
MAGIC = b"GDSHARE1"


@pytest.fixture
def share_client(tmp_path):
    """Fresh unlocked vault + a local app with only the sharing routers.

    Built locally (instead of ghostdrive.web.server) so the share routers are
    tested in isolation; auth/files routers are mounted only to unlock the
    vault and seed fixture files the same way the other route tests do.
    """
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


def _seed_file(client, payload: bytes, name: str = "note.txt") -> str:
    """Upload a real encrypted file, mirroring the other route tests."""
    res = client.post(
        "/api/files/upload",
        files={"file": (name, payload, "text/plain")},
        data={"tier": "DISPOSABLE", "destination_path": "/"},
    )
    assert res.status_code == 200, res.text
    return res.json()["file_id"]


def _create_envelope(file_id: str, **kwargs) -> dict:
    """Run the async service helper from sync tests."""
    return asyncio.run(sharing_service.create_envelope_link(file_id, **kwargs))


def _decrypt_envelope(envelope: bytes, passphrase: str) -> bytes:
    """Tiny Python mirror of receive.js — proves the byte layout self-consistent.

    Same steps: PBKDF2(600k) -> AES-GCM unwrap (AAD = magic) -> per-segment
    AES-256-GCM with nonce = prefix || index and AAD = index.
    """
    assert envelope[:8] == MAGIC
    (header_len,) = struct.unpack(">I", envelope[8:12])
    header = json.loads(envelope[12:12 + header_len].decode("utf-8"))
    body = envelope[12 + header_len:]

    wrap_key = hashlib.pbkdf2_hmac(
        "sha256",
        passphrase.encode("utf-8"),
        base64.b64decode(header["wrap_salt"]),
        header["iterations"],
    )
    envelope_key = AESGCM(wrap_key).decrypt(
        base64.b64decode(header["wrap_nonce"]),
        base64.b64decode(header["wrapped_key"]),
        MAGIC,  # AAD — same as the JS reader
    )

    prefix = base64.b64decode(header["nonce_prefix"])
    out = bytearray()
    offset = 0
    for index in range(header["segments"]):
        if index == header["segments"] - 1:
            plain_len = header["size"] - index * header["seg_size"]
        else:
            plain_len = header["seg_size"]
        piece = body[offset:offset + plain_len + 16]  # ciphertext || 16-byte tag
        offset += plain_len + 16
        nonce = prefix + index.to_bytes(8, "big")
        aad = index.to_bytes(8, "big")
        out += AESGCM(envelope_key).decrypt(nonce, piece, aad)
    assert offset == len(body)
    assert len(out) == header["size"]
    return bytes(out)


# ─── Service level ───────────────────────────────────────────────────────────

def test_create_envelope_link_returns_token_and_passphrase(share_client):
    file_id = _seed_file(share_client, b"secret bytes")
    link = _create_envelope(file_id, ttl_hours=24)

    assert link["status"] == "success"
    assert link["token"]
    assert link["url"] == f"/e/{link['token']}"
    # Generated passphrase: 5 words, shown once, never stored.
    assert len(link["passphrase"].split()) == 5
    assert link["expires_at"]
    assert link["size"] == len(b"secret bytes")
    assert link["envelope_size"] > link["size"]  # header + tags on top

    # A caller-supplied passphrase is respected, not regenerated.
    mine = _create_envelope(file_id, passphrase="my own phrase")
    assert mine["passphrase"] == "my own phrase"
    assert mine["token"] != link["token"]


def test_envelope_header_and_blob_layout(share_client):
    payload = b"layout probe"
    file_id = _seed_file(share_client, payload, "probe.bin")
    link = _create_envelope(file_id)
    token = link["token"]

    res = share_client.get(f"/api/public/envelope/{token}")
    assert res.status_code == 200, res.text
    header = res.json()
    for field in (
        "v", "alg", "kdf", "iterations", "wrap_salt", "wrap_nonce",
        "wrapped_key", "segments", "seg_size", "size", "nonce_prefix",
        "mime_type", "filename", "envelope_url",
    ):
        assert field in header, field
    assert header["v"] == 1
    assert header["alg"] == "A256GCM"
    assert header["kdf"] == "PBKDF2-SHA256"
    assert header["iterations"] == 600_000  # OWASP 2023 PBKDF2-SHA256
    assert header["seg_size"] == 65536
    assert header["size"] == len(payload)
    assert header["filename"] == "probe.bin"
    assert header["envelope_url"] == f"/api/public/envelope/{token}/blob"

    blob = share_client.get(header["envelope_url"])
    assert blob.status_code == 200, blob.text
    raw = blob.content
    assert raw[:8] == MAGIC
    assert int(blob.headers["content-length"]) == len(raw)
    assert "attachment" in blob.headers["content-disposition"]

    # The JSON header served to the browser equals the one embedded in the blob.
    (hlen,) = struct.unpack(">I", raw[8:12])
    embedded = json.loads(raw[12:12 + hlen].decode("utf-8"))
    served = {k: v for k, v in header.items() if k != "envelope_url"}
    assert embedded == served
    assert embedded["segments"] == (
        (len(payload) + embedded["seg_size"] - 1) // embedded["seg_size"]
    )

    # The route streams exactly what the service stores on the backend.
    stored = asyncio.run(
        sharing_service.load_envelope_blob(
            sharing_service.verify_envelope_access(token)
        )
    )
    assert stored == raw


def test_roundtrip_python_decryptor_matches_plaintext(share_client):
    """Decrypt the envelope the way receive.js does and compare plaintext.

    A payload spanning several 64 KiB segments exercises the per-segment
    nonce/AAD derivation (a wrong index or order would fail the GCM tag).
    """
    payload = b"zero-knowledge envelope payload;" * 7000  # ~217 KB, 4 segments
    file_id = _seed_file(share_client, payload, "multi.bin")
    link = _create_envelope(file_id, passphrase=PASSPHRASE)

    raw = share_client.get(f"/api/public/envelope/{link['token']}/blob").content
    assert raw[:8] == MAGIC
    header = json.loads(
        raw[12:12 + struct.unpack(">I", raw[8:12])[0]].decode("utf-8")
    )
    assert header["segments"] >= 3

    assert _decrypt_envelope(raw, PASSPHRASE) == payload

    # Wrong passphrase fails closed with an authentication error.
    with pytest.raises(InvalidTag):
        _decrypt_envelope(raw, "not the passphrase")

    # Tampering with one ciphertext byte also fails (per-segment GCM).
    tampered = bytearray(raw)
    tampered[-1] ^= 0x01
    with pytest.raises(InvalidTag):
        _decrypt_envelope(bytes(tampered), PASSPHRASE)


# ─── Access checks ───────────────────────────────────────────────────────────

def test_expired_envelope_blocks_header_and_blob(share_client):
    file_id = _seed_file(share_client, b"expires soon")
    link = _create_envelope(file_id, ttl_hours=1)
    token = link["token"]
    assert share_client.get(f"/api/public/envelope/{token}").status_code == 200

    # Pin the stored expiry into the past (same row open_link() reads).
    with state.db.transaction():
        state.db._conn.execute(
            "UPDATE share_links SET expires_at = ? WHERE token = ?",
            ("2000-01-01T00:00:00+00:00", token),
        )

    assert share_client.get(f"/api/public/envelope/{token}").status_code == 403
    assert (
        share_client.get(f"/api/public/envelope/{token}/blob").status_code == 403
    )
    # The page renders the expiry message instead of the decrypt form.
    page = share_client.get(f"/e/{token}")
    assert page.status_code == 200
    assert b"expired" in page.content.lower()
    assert b"receive.js" not in page.content


def test_verify_envelope_access_honours_pinned_clock(share_client):
    file_id = _seed_file(share_client, b"clock check")
    link = _create_envelope(file_id, ttl_hours=1)
    token = link["token"]

    info = sharing_service.verify_envelope_access(token)
    assert info["header"]["v"] == 1
    # Same call with a far-future clock reports the link as expired.
    with pytest.raises(PermissionError, match="expired"):
        sharing_service.verify_envelope_access(
            token, now=datetime(2100, 1, 1, tzinfo=timezone.utc)
        )


def test_max_downloads_blocks_blob_after_register_download(share_client):
    file_id = _seed_file(share_client, b"limited")
    link = _create_envelope(file_id, max_downloads=1)
    token = link["token"]

    # First fetch serves the ciphertext and registers the download.
    assert (
        share_client.get(f"/api/public/envelope/{token}/blob").status_code == 200
    )
    assert share_client.get(f"/api/public/envelope/{token}/blob").status_code == 403
    # Once the limit is reached the header is refused too (open_link check).
    assert share_client.get(f"/api/public/envelope/{token}").status_code == 403

    # The service-level register_download enforces the same limit directly.
    link2 = _create_envelope(file_id, max_downloads=1)
    sharing_service.register_download(link2["token"])
    assert (
        share_client.get(f"/api/public/envelope/{link2['token']}/blob").status_code
        == 403
    )


def test_revoked_envelope_blocks_endpoints(share_client):
    file_id = _seed_file(share_client, b"revoke me")
    link = _create_envelope(file_id)
    token = link["token"]
    assert share_client.get(f"/api/public/envelope/{token}").status_code == 200

    assert sharing_service.revoke_link(token)["status"] == "success"

    assert share_client.get(f"/api/public/envelope/{token}").status_code == 403
    assert (
        share_client.get(f"/api/public/envelope/{token}/blob").status_code == 403
    )
    page = share_client.get(f"/e/{token}")
    assert page.status_code == 200
    assert b"revoked" in page.content.lower()


def test_classic_share_token_has_no_envelope(share_client):
    """A regular /s/ token must 404 on the envelope endpoints."""
    file_id = _seed_file(share_client, b"classic")
    res = share_client.post(
        "/api/sharing/create", json={"file_id": file_id, "ttl_hours": 24}
    )
    assert res.status_code == 200, res.text
    token = res.json()["token"]

    assert share_client.get(f"/api/public/envelope/{token}").status_code == 404
    assert (
        share_client.get(f"/api/public/envelope/{token}/blob").status_code == 404
    )
    assert share_client.get("/api/public/envelope/nope").status_code == 404


# ─── Routes ──────────────────────────────────────────────────────────────────

def test_envelope_page_loads_receive_js(share_client):
    file_id = _seed_file(share_client, b"page probe")
    link = _create_envelope(file_id)

    page = share_client.get(f"/e/{link['token']}")
    assert page.status_code == 200
    assert b"receive.js" in page.content
    assert b"gd-passphrase" in page.content
    # No server-side secrets in the HTML: the passphrase is never embedded.
    assert link["passphrase"].encode() not in page.content

    missing = share_client.get("/e/not-a-real-token")
    assert missing.status_code == 200
    assert b"does not exist" in missing.content
    assert b"receive.js" not in missing.content


def test_create_envelope_route(share_client):
    payload = b"created through the route"
    file_id = _seed_file(share_client, payload)
    res = share_client.post(
        "/api/sharing/envelope",
        json={"file_id": file_id, "ttl_hours": 12, "max_downloads": 3},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["token"]
    assert body["url"].endswith(f"/e/{body['token']}")
    assert len(body["passphrase"].split()) == 5
    assert body["max_downloads"] == 3
    assert body["size"] == len(payload)

    # The returned URL renders and the returned passphrase decrypts.
    page = share_client.get(f"/e/{body['token']}")
    assert page.status_code == 200
    assert b"receive.js" in page.content
    raw = share_client.get(
        f"/api/public/envelope/{body['token']}/blob"
    ).content
    assert _decrypt_envelope(raw, body["passphrase"]) == payload

    # Unknown file fails closed with 404.
    missing = share_client.post(
        "/api/sharing/envelope", json={"file_id": "does-not-exist"}
    )
    assert missing.status_code == 404


# ─── Regression: classic share flow ──────────────────────────────────────────

def test_existing_share_flow_still_works(share_client):
    """List/create/passcode/revoke behaviour of the original /s/ links."""
    payload = b"shareable content"
    file_id = _seed_file(share_client, payload, "share.txt")

    res_create = share_client.post("/api/sharing/create", json={
        "file_id": file_id,
        "ttl_hours": 48,
        "require_passcode": True,
        "passcode": "open-sesame",
    })
    assert res_create.status_code == 200, res_create.text
    token = res_create.json()["token"]
    assert res_create.json()["url"].endswith(f"/s/{token}")

    res_links = share_client.get("/api/sharing/links")
    assert res_links.status_code == 200
    assert any(link["token"] == token for link in res_links.json()["shared_links"])

    public = share_client.get(f"/s/{token}?passcode=open-sesame")
    assert public.status_code == 200
    assert public.content == payload

    denied = share_client.get(f"/s/{token}?passcode=wrong")
    assert denied.status_code == 200
    assert b"Incorrect share passcode" in denied.content

    revoke = share_client.delete(f"/api/sharing/revoke/{token}")
    assert revoke.status_code == 200

    after_revoke = share_client.get(f"/s/{token}?passcode=open-sesame")
    assert b"revoked" in after_revoke.content.lower()
