"""
tests/test_cloud_import.py -- Cloud import service (services/cloud_import.py)
and the /api/cloud routes (web/routes/cloud.py).

Covers: bring-your-own-token connect (cheap validated probe against the real
provider list endpoint shape, token stored encrypted in the (faked) OS
credential store, masked hint everywhere, raw token absent from every response
and from the settings table), remote listing, importing through the SAME
encrypting pipeline as a local upload (round-trip via iter_file/download_bytes
AND ciphertext-at-rest: the plaintext must not appear in any .gdc chunk file),
partial batch failure (imported 1 / failed 1, error carried per file, batch
never aborts), not-connected / invalid-provider / rejected-token 400s,
disconnect + import history in settings, destination path validation
('..' traversal and empty dest_dir rejected), and provider pagination.

NO real network: every provider HTTP call goes through the module-level
``cloud_import._http`` seam, which is replaced by a FakeTransport that records
calls, serves canned responses keyed by (method, url), asserts every URL
starts with a known provider API prefix (a regression to real urllib or an
unknown host fails loudly), and additionally poisons urllib.request.urlopen.
The OS keyring is likewise faked in-memory so no token ever touches the
machine keyring and tests stay hermetic.
"""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path

import keyring
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ghostdrive.services import cloud_import
from ghostdrive.services import files as files_service
from ghostdrive.web.routes import cloud as cloud_routes
from ghostdrive.web.server import app as server_app
from ghostdrive.web.state import state

PASSPHRASE = "correct horse battery staple"
TOKEN = "fket-AABBCCDD-12345678-ZZ"

DROPBOX_LIST_URL = "https://api.dropboxapi.com/2/files/list_folder"
DROPBOX_CONTINUE_URL = "https://api.dropboxapi.com/2/files/list_folder_continue"
DROPBOX_DOWNLOAD_URL = "https://content.dropboxapi.com/2/files/download"

# Realistic list_folder response shape (folders skipped by the importer).
DROPBOX_LIST_BODY = json.dumps({
    "entries": [
        {".tag": "folder", "name": "Docs", "id": "id:folder-docs", "path_display": "/Docs"},
        {".tag": "file", "name": "hello.txt", "id": "id:hello",
         "path_lower": "/hello.txt", "path_display": "/hello.txt",
         "server_modified": "2026-01-02T03:04:05Z", "size": 11},
        {".tag": "file", "name": "broken.txt", "id": "id:broken",
         "path_lower": "/broken.txt", "path_display": "/broken.txt",
         "server_modified": "2026-01-02T03:04:06Z", "size": 9},
    ],
    "has_more": False,
    "cursor": "cur-dropbox-1",
}).encode()


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def vault(tmp_path_factory):
    """Module-scoped unlocked vault (same pattern as tests/test_sync.py).

    The cloud import pipeline runs through the real files service, which needs
    an open database and a local backend -- unlocked once here via the real
    server app.
    """
    data_dir = tmp_path_factory.mktemp("ghostdrive_cloud_import")
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
def fake_keyring(monkeypatch):
    """In-memory stand-in for the OS keyring: token storage stays hermetic."""
    store: dict[str, str] = {}
    monkeypatch.setattr(keyring, "set_password", lambda service, user, password: store.__setitem__(user, password))
    monkeypatch.setattr(keyring, "get_password", lambda service, user: store.get(user))
    monkeypatch.setattr(keyring, "delete_password", lambda service, user: store.pop(user, None))
    return store


@pytest.fixture(autouse=True)
def clean_cloud_state(vault, fake_keyring):
    """Every test starts unconnected with an empty import history."""
    db = _db()
    with db.transaction():
        db.set_setting(cloud_import.SETTING_HISTORY, "[]")
    yield


class FakeTransport:
    """Replaces cloud_import._http: canned responses keyed by (method, url).

    Responses queue per key so repeated calls to the same endpoint (e.g. two
    downloads hitting the same URL) can return different bodies; a queue with
    a single entry is sticky. Any URL outside the known provider API prefixes
    raises AssertionError immediately, so a regression to real network code
    fails loudly instead of silently hitting the internet.
    """

    ALLOWED_PREFIXES = (
        "https://api.dropboxapi.com",
        "https://content.dropboxapi.com",
        "https://www.googleapis.com/drive/v3",
        "https://graph.microsoft.com/v1.0",
    )

    def __init__(self):
        self.calls: list[dict] = []
        self._responses: dict[tuple[str, str], list[tuple[int, bytes]]] = {}

    def add(self, method: str, url: str, status: int = 200, body: bytes = b"{}") -> None:
        self._responses.setdefault((method.upper(), url), []).append((status, body))

    def __call__(self, method, url, headers=None, body=None, timeout=30):
        assert any(url.startswith(prefix) for prefix in self.ALLOWED_PREFIXES), (
            f"fake transport saw a request to an unexpected host: {url}"
        )
        self.calls.append({
            "method": method.upper(), "url": url,
            "headers": dict(headers or {}), "body": body,
        })
        queue = self._responses.get((method.upper(), url))
        if not queue:
            raise AssertionError(f"fake transport received an unmocked request: {(method.upper(), url)}")
        return queue.pop(0) if len(queue) > 1 else queue[0]


@pytest.fixture
def fake_http(monkeypatch):
    transport = FakeTransport()
    monkeypatch.setattr(cloud_import, "_http", transport)

    def _poisoned_urlopen(*args, **kwargs):
        raise AssertionError("real network access is forbidden in cloud import tests")

    monkeypatch.setattr(urllib.request, "urlopen", _poisoned_urlopen)
    return transport


@pytest.fixture
def cloud_client(vault, fake_keyring):
    """Local app carrying ONLY the cloud router."""
    local_app = FastAPI()
    local_app.include_router(cloud_routes.router)
    return TestClient(local_app)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _db():
    from ghostdrive.services.context import require_db

    return require_db()


def _connect_dropbox(client: TestClient) -> None:
    """Connect dropbox through the route against the standard canned listing."""
    res = client.post("/api/cloud/connect", json={"provider": "dropbox", "token": TOKEN})
    assert res.status_code == 200, res.text


# ── Router contract ───────────────────────────────────────────────────────────

def test_router_contract():
    assert cloud_routes.router.prefix == "/api/cloud"
    paths = {route.path for route in cloud_routes.router.routes}
    assert {
        "/api/cloud/status",
        "/api/cloud/connect",
        "/api/cloud/disconnect",
        "/api/cloud/list",
        "/api/cloud/import",
        "/api/cloud/history",
    } <= paths
    assert set(cloud_import.PROVIDERS) == {"dropbox", "gdrive", "onedrive"}
    assert cloud_import.SETTING_HISTORY == "cloud_import_history"
    assert cloud_import.MAX_IMPORT_BYTES == 100 * 1024 * 1024


# ── Connect / status / masking ───────────────────────────────────────────────

def test_connect_dropbox_validates_masks_and_stores(cloud_client, fake_http, fake_keyring):
    fake_http.add("POST", DROPBOX_LIST_URL, 200, DROPBOX_LIST_BODY)

    res = cloud_client.post("/api/cloud/connect", json={"provider": "dropbox", "token": TOKEN})
    assert res.status_code == 200, res.text

    # Validation hit the real list endpoint shape with the Bearer token.
    call = fake_http.calls[0]
    assert call["url"] == DROPBOX_LIST_URL
    assert call["headers"]["Authorization"] == f"Bearer {TOKEN}"

    # Status: connected, token hint masked to first4…last4, NEVER the raw token.
    data = res.json()
    dropbox = data["dropbox"]
    assert dropbox["connected"] is True
    assert dropbox["token_hint"] == f"{TOKEN[:4]}…{TOKEN[-4:]}"
    assert TOKEN not in res.text
    assert set(data) == {"dropbox", "gdrive", "onedrive"}

    status_text = cloud_client.get("/api/cloud/status").text
    assert TOKEN not in status_text
    assert "fket" in status_text and "8-ZZ" in status_text  # the masked hint still identifies the account

    # The token landed in the (faked) OS credential store, encrypted -- the
    # stored blob is not the token itself.
    assert "cloud_dropbox_token" in fake_keyring
    assert TOKEN not in fake_keyring["cloud_dropbox_token"]

    # And it never lands in plaintext in the SQL settings table.
    for row in _db()._conn.execute("SELECT key, value FROM settings").fetchall():
        assert TOKEN not in str(row["value"]), f"token leaked into setting {row['key']}"


def test_connect_rejected_token_surfaces_provider_error(cloud_client, fake_http):
    fake_http.add(
        "POST", DROPBOX_LIST_URL, 401,
        json.dumps({"error_summary": "invalid_access_token/..."}).encode(),
    )

    res = cloud_client.post("/api/cloud/connect", json={"provider": "dropbox", "token": TOKEN})
    assert res.status_code == 400
    detail = res.json()["detail"]
    assert "401" in detail and "invalid_access_token" in detail
    # A rejected token is not stored.
    assert cloud_client.get("/api/cloud/status").json()["dropbox"]["connected"] is False


def test_invalid_provider_is_400_everywhere(cloud_client):
    res = cloud_client.post("/api/cloud/connect", json={"provider": "box", "token": TOKEN})
    assert res.status_code == 400
    assert "Unknown provider" in res.json()["detail"]
    assert cloud_client.get("/api/cloud/list", params={"provider": "box"}).status_code == 400
    assert cloud_client.post(
        "/api/cloud/import", json={"provider": "box", "paths": ["/x"]}
    ).status_code == 400


def test_not_connected_is_400(cloud_client):
    listing = cloud_client.get("/api/cloud/list", params={"provider": "dropbox"})
    assert listing.status_code == 400
    assert "not connected" in listing.json()["detail"]

    importing = cloud_client.post(
        "/api/cloud/import", json={"provider": "dropbox", "paths": ["/hello.txt"]}
    )
    assert importing.status_code == 400
    assert "not connected" in importing.json()["detail"]


# ── Other providers' validation shapes ───────────────────────────────────────

def test_gdrive_and_onedrive_validate_against_their_list_endpoints(cloud_client, fake_http):
    gdrive_url = (
        "https://www.googleapis.com/drive/v3/files?"
        "pageSize=100&fields=nextPageToken%2Cfiles%28id%2Cname%2Csize%2CmimeType%2CmodifiedTime%29"
    )
    fake_http.add("GET", gdrive_url, 200, json.dumps({
        "files": [{"id": "g1", "name": "gdoc.txt", "size": "5",
                   "mimeType": "text/plain", "modifiedTime": "2026-01-01T00:00:00Z"}],
        "nextPageToken": "tok2",
    }).encode())
    res = cloud_client.post("/api/cloud/connect", json={"provider": "gdrive", "token": TOKEN})
    assert res.status_code == 200, res.text
    assert res.json()["gdrive"]["connected"] is True
    assert fake_http.calls[-1]["headers"]["Authorization"] == f"Bearer {TOKEN}"

    onedrive_url = "https://graph.microsoft.com/v1.0/me/drive/root/children?$top=100"
    fake_http.add("GET", onedrive_url, 200, json.dumps({
        "value": [{"id": "od1", "name": "note.md", "size": "3",
                   "lastModifiedDateTime": "2026-01-01T00:00:00Z", "file": {}}],
    }).encode())
    res = cloud_client.post("/api/cloud/connect", json={"provider": "onedrive", "token": TOKEN})
    assert res.status_code == 200, res.text
    assert res.json()["onedrive"]["connected"] is True
    assert fake_http.calls[-1]["url"] == onedrive_url


# ── Listing ───────────────────────────────────────────────────────────────────

def test_list_remote_returns_parsed_files(cloud_client, fake_http):
    fake_http.add("POST", DROPBOX_LIST_URL, 200, DROPBOX_LIST_BODY)
    _connect_dropbox(cloud_client)

    fake_http.add("POST", DROPBOX_LIST_URL, 200, DROPBOX_LIST_BODY)
    res = cloud_client.get("/api/cloud/list", params={"provider": "dropbox"})
    assert res.status_code == 200, res.text
    data = res.json()
    assert [entry["name"] for entry in data["files"]] == ["hello.txt", "broken.txt"]  # no folders
    assert data["files"][0]["path"] == "/hello.txt"
    assert data["files"][0]["id"] == "id:hello"
    assert data["files"][0]["size"] == 11
    assert data["next_cursor"] is None


def test_resolve_paths_paginates_with_cursor(vault, fake_http):
    db = _db()
    page1 = json.dumps({
        "entries": [{".tag": "file", "name": "hello.txt", "id": "id:hello",
                     "path_display": "/hello.txt", "size": 11}],
        "has_more": True, "cursor": "cur:1",
    }).encode()
    page2 = json.dumps({
        "entries": [{".tag": "file", "name": "second.txt", "id": "id:second",
                     "path_display": "/second.txt", "size": 6}],
        "has_more": False, "cursor": "cur:2",
    }).encode()
    fake_http.add("POST", DROPBOX_LIST_URL, 200, page1)
    fake_http.add("POST", DROPBOX_CONTINUE_URL, 200, page2)
    cloud_import.connect(db, "dropbox", TOKEN)

    resolved = cloud_import.resolve_remote_paths(db, "dropbox", ["/second.txt"])
    assert [entry["name"] for entry in resolved] == ["second.txt"]
    assert resolved[0]["id"] == "id:second"
    assert fake_http.calls[-1]["url"] == DROPBOX_CONTINUE_URL

    # Unknown paths come back marked, not raised: the batch must not abort.
    missing = cloud_import.resolve_remote_paths(db, "dropbox", ["/nope.txt"])
    assert missing[0]["error"] == "path not found in remote listing"


# ── Import: through the encrypting pipeline ───────────────────────────────────

async def test_import_file_lands_encrypted_in_vault(vault, fake_http):
    db = _db()
    fake_http.add("POST", DROPBOX_LIST_URL, 200, DROPBOX_LIST_BODY)
    cloud_import.connect(db, "dropbox", TOKEN)
    fake_http.add("POST", DROPBOX_DOWNLOAD_URL, 200, b"hello cloud")

    result = await cloud_import.import_file(
        db, "dropbox",
        {"path": "/hello.txt", "name": "hello.txt", "size": 11, "id": "id:hello"},
    )
    assert result["provider"] == "dropbox"
    assert result["name"] == "hello.txt"
    assert result["size"] == len(b"hello cloud")
    assert result["path"] == "/hello.txt"
    assert result["file_id"]

    # The import went through files_service: the row is listed and the content
    # round-trips through the decrypting pipeline...
    listing = files_service.list_files("/")
    assert "hello.txt" in [entry["name"] for entry in listing["files"]]
    assert await files_service.download_bytes(result["file_id"]) == b"hello cloud"

    # ...and the bytes on disk are ciphertext: the plaintext must not appear
    # in any stored chunk file.
    plaintext = b"hello cloud"
    chunk_files = list(Path(state.app_data_dir).rglob("*.gdc"))
    assert chunk_files, "expected at least one encrypted chunk file on disk"
    for chunk_file in chunk_files:
        assert plaintext not in chunk_file.read_bytes(), (
            f"plaintext found in chunk file {chunk_file}"
        )


async def test_import_respects_dest_path_and_rejects_bad_entries(vault, fake_http):
    db = _db()
    fake_http.add("POST", DROPBOX_LIST_URL, 200, DROPBOX_LIST_BODY)
    cloud_import.connect(db, "dropbox", TOKEN)
    fake_http.add("POST", DROPBOX_DOWNLOAD_URL, 200, b"hello cloud")

    result = await cloud_import.import_file(
        db, "dropbox",
        {"path": "/hello.txt", "name": "hello.txt", "size": 11, "id": "id:hello"},
        dest_path="/cloud-inbox",
    )
    assert result["path"] == "/cloud-inbox/hello.txt"

    with pytest.raises(ValueError, match="not connected"):
        await cloud_import.import_file(
            db, "gdrive", {"path": "/x", "name": "x", "id": "g1"}
        )

    with pytest.raises(ValueError, match="traversal"):
        await cloud_import.import_file(
            db, "dropbox", {"path": "/x", "name": "x", "id": "id:x"},
            dest_path="/a/../../b",
        )


# ── Import via the route: batches, failures, history ─────────────────────────

def test_import_route_partial_failure_never_aborts(cloud_client, fake_http):
    fake_http.add("POST", DROPBOX_LIST_URL, 200, DROPBOX_LIST_BODY)
    _connect_dropbox(cloud_client)

    fake_http.add("POST", DROPBOX_LIST_URL, 200, DROPBOX_LIST_BODY)
    # hello.txt downloads fine; broken.txt 404s; ghost.txt does not even exist
    # in a fresh listing (it fails at resolution, no download attempted).
    fake_http.add("POST", DROPBOX_DOWNLOAD_URL, 200, b"hello cloud")
    fake_http.add(
        "POST", DROPBOX_DOWNLOAD_URL, 404,
        json.dumps({"error_summary": "path/not_found/..."}).encode(),
    )

    res = cloud_client.post("/api/cloud/import", json={
        "provider": "dropbox",
        "paths": ["/hello.txt", "/broken.txt", "/ghost.txt"],
    })
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["imported"] == 1
    assert data["failed"] == 2
    assert data["bytes"] == len(b"hello cloud")
    assert data["results"][0]["status"] == "imported"
    assert data["results"][0]["file_id"]
    failed_broken = data["results"][1]
    assert failed_broken["status"] == "failed"
    assert "404" in failed_broken["error"] and "path/not_found" in failed_broken["error"]
    failed_ghost = data["results"][2]
    assert failed_ghost["status"] == "failed"
    assert "not found in remote listing" in failed_ghost["error"]

    # The successful file really landed in the vault through the pipeline.
    names = [entry["name"] for entry in files_service.list_files("/")["files"]]
    assert "hello.txt" in names

    # History: one summary appended, readable from the route and the setting.
    history = cloud_client.get("/api/cloud/history").json()["history"]
    assert len(history) == 1
    assert history[0]["imported"] == 1 and history[0]["failed"] == 2
    assert history[0]["provider"] == "dropbox" and history[0]["at"]
    stored = json.loads(_db().get_setting(cloud_import.SETTING_HISTORY, "[]"))
    assert stored == history


def test_import_route_rejects_bad_dest_and_empty_paths(cloud_client, fake_http):
    fake_http.add("POST", DROPBOX_LIST_URL, 200, DROPBOX_LIST_BODY)
    _connect_dropbox(cloud_client)
    # Two more resolve listings: one per rejected import (traversal, empty dest).
    fake_http.add("POST", DROPBOX_LIST_URL, 200, DROPBOX_LIST_BODY)
    fake_http.add("POST", DROPBOX_LIST_URL, 200, DROPBOX_LIST_BODY)

    res = cloud_client.post("/api/cloud/import", json={
        "provider": "dropbox", "paths": ["/hello.txt"], "dest_dir": "../../etc",
    })
    assert res.status_code == 400
    assert ".." in res.json()["detail"]

    res = cloud_client.post("/api/cloud/import", json={
        "provider": "dropbox", "paths": ["/hello.txt"], "dest_dir": "",
    })
    assert res.status_code == 400
    assert "empty" in res.json()["detail"].lower()

    res = cloud_client.post("/api/cloud/import", json={"provider": "dropbox", "paths": []})
    assert res.status_code == 400
    assert "No remote paths" in res.json()["detail"]

    # Nothing was imported and no history was written by the rejected calls.
    assert json.loads(_db().get_setting(cloud_import.SETTING_HISTORY, "[]")) == []


def test_disconnect_forgets_token_and_history_is_capped(cloud_client, fake_http, fake_keyring):
    fake_http.add("POST", DROPBOX_LIST_URL, 200, DROPBOX_LIST_BODY)
    _connect_dropbox(cloud_client)
    assert "cloud_dropbox_token" in fake_keyring

    res = cloud_client.post("/api/cloud/disconnect", json={"provider": "dropbox"})
    assert res.status_code == 200, res.text
    assert res.json() == {"provider": "dropbox", "connected": False}
    assert "cloud_dropbox_token" not in fake_keyring

    status = cloud_client.get("/api/cloud/status").json()
    assert status["dropbox"]["connected"] is False
    assert status["dropbox"]["token_hint"] is None
    # Without a token the listing is refused again (400).
    assert cloud_client.get("/api/cloud/list", params={"provider": "dropbox"}).status_code == 400

    # History stays capped at HISTORY_CAP entries, newest first.
    db = _db()
    for i in range(cloud_import.HISTORY_CAP + 5):
        cloud_import.append_import_history(db, {"provider": "dropbox", "imported": i,
                                                "failed": 0, "bytes": 0, "at": str(i)})
    history = cloud_client.get("/api/cloud/history").json()["history"]
    assert len(history) == cloud_import.HISTORY_CAP
    assert history[0]["imported"] == cloud_import.HISTORY_CAP + 4  # newest first
