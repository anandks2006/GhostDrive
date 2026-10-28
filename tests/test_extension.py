"""
tests/test_extension.py -- /api/extension routes and the packaged browser extension.

Covers the lock-tolerant status probe (before and after a real lock), the
in-memory zip download (content type, expected members, MV3 manifest shape),
the raw-body upload contract the extension sends (round-trip through
files_service.iter_file, empty body 400, path validation, locked vault 401),
and two cheap hygiene guards: the icon PNGs on disk and a URL scan of the
extension's JS (loopback-only, no remote code).
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import re
import zipfile
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ghostdrive.services import files as files_service
from ghostdrive.web.routes import extension as extension_routes
from ghostdrive.web.server import app as server_app
from ghostdrive.web.state import state

PASSPHRASE = "correct horse battery staple"
EXTENSION_DIR = Path(__file__).resolve().parents[1] / "packaging" / "extension"
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def vault(tmp_path_factory):
    """Module-scoped unlocked vault.

    Uploads run through the real files service, which needs an open database
    and a local backend -- unlocked once here via the real server app, same
    pattern as tests/test_sync.py.
    """
    data_dir = tmp_path_factory.mktemp("ghostdrive_extension")
    state.clean_shutdown()
    state.app_data_dir = data_dir
    state.keystore_path = data_dir / "keystore.json"
    state.db_path = data_dir / "ghostdrive.db"

    client = TestClient(server_app)
    response = client.post("/api/auth/setup", json={"passphrase": PASSPHRASE})
    assert response.status_code == 200, response.text

    yield

    state.clean_shutdown()


@pytest.fixture
def client(vault):
    """Local app carrying only the extension router."""
    local_app = FastAPI()
    local_app.include_router(extension_routes.router)
    with TestClient(local_app) as test_client:
        yield test_client


@contextlib.contextmanager
def locked_vault():
    """Lock the shared vault for one test, then unlock it again for the next."""
    state.clean_shutdown()
    try:
        yield
    finally:
        client = TestClient(server_app)
        response = client.post("/api/auth/unlock", json={"passphrase": PASSPHRASE})
        assert response.status_code == 200, response.text


# ── Helpers ──────────────────────────────────────────────────────────────────

async def _read_file(file_id: str) -> bytes:
    return b"".join([chunk async for chunk in files_service.iter_file(file_id)])


def _download_zip(client) -> zipfile.ZipFile:
    response = client.get("/api/extension/download")
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/zip")
    return zipfile.ZipFile(io.BytesIO(response.content))


# ── Status ───────────────────────────────────────────────────────────────────

def test_status_ok(client):
    response = client.get("/api/extension/status")
    assert response.status_code == 200
    payload = response.json()
    assert payload["installed_hint"] is True  # manifest.json exists on disk
    assert payload["app_url"].startswith("http://127.0.0.1:")
    assert payload["docs"]


def test_status_survives_locked_vault(client):
    with locked_vault():
        response = client.get("/api/extension/status")
        assert response.status_code == 200
        assert response.json()["installed_hint"] is True


# ── Download ─────────────────────────────────────────────────────────────────

def test_download_zips_the_extension_pack(client):
    with _download_zip(client) as bundle:
        names = set(bundle.namelist())
    for expected in (
        "manifest.json",
        "background.js",
        "popup.html",
        "popup.js",
        "options.html",
        "options.js",
        "icons/icon16.png",
        "icons/icon48.png",
        "icons/icon128.png",
    ):
        assert expected in names, f"{expected} missing from {sorted(names)}"


def test_manifest_in_zip_is_valid_mv3(client):
    with _download_zip(client) as bundle:
        manifest = bundle.read("manifest.json")
    parsed = json.loads(manifest)
    assert parsed["manifest_version"] == 3
    assert parsed["background"]["service_worker"] == "background.js"
    assert "contextMenus" in parsed["permissions"]
    assert "storage" in parsed["permissions"]
    assert "notifications" in parsed["permissions"]
    assert "http://127.0.0.1/*" in parsed["host_permissions"]
    assert "http://localhost/*" in parsed["host_permissions"]


# ── Upload ───────────────────────────────────────────────────────────────────

def test_upload_roundtrip(client):
    payload = b"hello from the browser"
    response = client.post(
        "/api/extension/upload",
        params={"path": "extension/test.txt"},
        content=payload,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "success"
    assert body["filename"] == "test.txt"
    assert body["size"] == len(payload)
    assert body["file"]["path"] == "/extension/test.txt"

    # Visible in the vault listing and byte-identical after decryption.
    listing = files_service.list_files("/extension")
    assert any(item["name"] == "test.txt" for item in listing["files"])
    assert asyncio.run(_read_file(body["file_id"])) == payload


def test_upload_empty_body_is_400(client):
    response = client.post(
        "/api/extension/upload",
        params={"path": "extension/empty.txt"},
        content=b"",
    )
    assert response.status_code == 400


def test_upload_path_must_end_with_filename(client):
    response = client.post(
        "/api/extension/upload",
        params={"path": "extension/"},
        content=b"x",
    )
    assert response.status_code == 400


def test_upload_rejects_locked_vault(client):
    with locked_vault():
        response = client.post(
            "/api/extension/upload",
            params={"path": "extension/locked.txt"},
            content=b"should not land",
        )
        assert response.status_code == 401
        assert "locked" in response.json()["detail"].lower()


# ── Hygiene guards ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("size", [16, 48, 128])
def test_icons_are_pngs_on_disk(size):
    icon = EXTENSION_DIR / "icons" / f"icon{size}.png"
    assert icon.is_file(), f"{icon} missing"
    assert icon.read_bytes().startswith(PNG_MAGIC)


def test_extension_js_references_only_loopback_urls():
    """Supply-chain guard: no remote hosts, no remote code, in the client JS."""
    url_pattern = re.compile(r"https?://[^\s\"'`)]+")
    for script in ("background.js", "popup.js", "options.js"):
        text = (EXTENSION_DIR / script).read_text(encoding="utf-8")
        for url in url_pattern.findall(text):
            assert url.startswith(
                ("http://127.0.0.1", "http://localhost")
            ), f"{script} references non-loopback URL: {url}"
