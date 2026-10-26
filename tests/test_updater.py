"""
test_updater.py -- Safe-by-default update checker.

Covers: version parsing/ordering (PEP 440 subset incl. pre-releases),
feed evaluation for both documented shapes (custom + GitHub releases),
the default-OFF networking guarantee, the 6h re-check cache, checksum
staging, and the /api/update routes (settings, status, check, download,
install confirmation gate) on a locally-built FastAPI app.
"""

import asyncio
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ghostdrive.database.db import GhostDriveDB
from ghostdrive.platform import updater
from ghostdrive.web.routes import update as update_routes
from ghostdrive.web.state import state

PASSPHRASE = "correct horse battery staple"
FEED_URL = "https://api.github.com/repos/ghostdrive/ghostdrive/releases/latest"

CUSTOM_NEW = {
    "version": "0.2.0",
    "url": "https://example.invalid/GhostDrive-0.2.0-setup.exe",
    "sha256": hashlib.sha256(b"installer bytes").hexdigest(),
    "notes": "Fixed the thing",
    "published_at": "2026-10-01T00:00:00Z",
}


@pytest.fixture
def update_client(tmp_path):
    """Fresh unlocked vault + a local app with only auth + the update router.

    Built locally (instead of ghostdrive.web.server) so these route tests
    stay isolated from central router wiring. Same global-state pattern as
    tests/test_recovery_api.py: clean_shutdown() on the way in AND out.
    """
    state.clean_shutdown()
    state.app_data_dir = tmp_path
    state.keystore_path = tmp_path / "keystore.json"
    state.db_path = tmp_path / "ghostdrive.db"

    from ghostdrive.web.routes.auth import router as auth_router

    app = FastAPI()
    app.include_router(auth_router)
    app.include_router(update_routes.router)

    client = TestClient(app)
    res = client.post("/api/auth/setup", json={"passphrase": PASSPHRASE})
    assert res.status_code == 200, res.text

    yield client

    state.clean_shutdown()


@pytest.fixture
def temp_db(tmp_path):
    """A plain, standalone GhostDriveDB (settings persisted, no web state)."""
    db = GhostDriveDB(
        path=tmp_path / "update.db",
        ledger_key=bytes(range(32)),
        genesis_seed=bytes(range(32, 64)),
        master_key=bytes(range(32)),
    )
    db.open()
    yield db
    db.close()


def _enable(db, feed_url: str = FEED_URL) -> None:
    """Turn the checker on with a feed (what POST /api/update/settings does)."""
    with db.transaction():
        db.set_setting(updater.UPDATE_CHECK_ENABLED, "true")
        db.set_setting(updater.UPDATE_FEED_URL, feed_url)


def _json_fetch(payload: dict):
    async def fetch(url: str) -> bytes:
        return json.dumps(payload).encode("utf-8")

    return fetch


# ── Version parsing / ordering ──────────────────────────────────────────────

class TestVersionParsing:
    @pytest.mark.parametrize("raw,expected", [
        ("0.1.0", (0, 1, 0)),
        ("0.1.0-alpha", (0, 1, 0)),          # pre-release suffix stripped
        ("0.1.0-beta.3", (0, 1, 0)),
        ("v1.2.3", (1, 2, 3)),               # GitHub-style "v" prefix
        ("0.1", (0, 1, 0)),                  # zero-padded: 0.1 == 0.1.0
        ("1.0.0-rc.2", (1, 0, 0)),
        ("2.0.0rc1", (2, 0, 0)),             # attached form, no separator
        ("1.0.0+local", (1, 0, 0)),          # local label ignored
    ])
    def test_parse_version_supported_subset(self, raw, expected):
        assert updater.parse_version(raw) == expected

    @pytest.mark.parametrize("garbage", [
        "",
        "   ",
        "abc",
        "x.y.z",
        "not-a-version",
        "version 1.2",
        "1.0.0-what",   # unknown suffix — refuse rather than mis-order
        "1.0.0-1",      # numeric-only suffix (post-release) unsupported
    ])
    def test_parse_version_rejects_garbage(self, garbage):
        with pytest.raises(ValueError):
            updater.parse_version(garbage)

    @pytest.mark.parametrize("raw,prerelease", [
        ("0.1.0-alpha", True),
        ("0.1.0-rc.1", True),
        ("1.0.0-beta", True),
        ("0.1.0", False),
        ("0.1.0+local", False),
    ])
    def test_is_prerelease(self, raw, prerelease):
        assert updater.is_prerelease(raw) is prerelease

    @pytest.mark.parametrize("candidate,current,expected", [
        ("0.1.1", "0.1.0", True),
        ("0.1.0", "0.1.1", False),
        ("0.1.0", "0.1.0", False),
        # Pre-release sorts BELOW the same numeric release, both ways round:
        ("0.1.0-alpha", "0.1.0", False),
        ("0.1.0", "0.1.0-alpha", True),
        # A tie between two pre-releases never triggers an upgrade:
        ("0.1.0-beta", "0.1.0-rc.1", False),
        ("1.0.0", "0.9.9", True),
        ("0.2.0-rc.1", "0.1.0", True),       # numbers win over stage
        ("1.2.3.0", "1.2.3", False),         # equal after zero-padding
        ("v0.2.0", "0.1.0", True),           # "v" prefix parsed
    ])
    def test_is_newer_matrix(self, candidate, current, expected):
        assert updater.is_newer(candidate, current) is expected

    def test_is_newer_rejects_garbage(self):
        with pytest.raises(ValueError):
            updater.is_newer("garbage", "0.1.0")

    def test_current_version_is_parseable(self):
        # The fallback chain must always yield something we can compare.
        assert updater.parse_version(updater.current_version())


# ── check_for_update: disabled by default ───────────────────────────────────

def test_disabled_by_default_never_fetches(temp_db):
    """Fresh settings → disabled, and the fetcher is never touched."""
    called = []

    async def fetch(url: str) -> bytes:
        called.append(url)
        return b"{}"

    result = asyncio.run(updater.check_for_update(temp_db, fetch=fetch))
    assert result == {"status": "disabled"}
    assert called == []


def test_enabled_without_feed_url_still_never_fetches(temp_db):
    """The switch alone is not enough — an empty feed means no request."""
    with temp_db.transaction():
        temp_db.set_setting(updater.UPDATE_CHECK_ENABLED, "true")
    called = []

    async def fetch(url: str) -> bytes:
        called.append(url)
        return b"{}"

    result = asyncio.run(updater.check_for_update(temp_db, fetch=fetch))
    assert result == {"status": "disabled"}
    assert called == []


def test_no_database_means_disabled():
    """db=None (locked vault / not wired) must never turn networking on."""
    result = asyncio.run(updater.check_for_update(None))
    assert result == {"status": "disabled"}


# ── check_for_update: feed evaluation ───────────────────────────────────────

def test_custom_feed_newer_with_sha256(temp_db):
    _enable(temp_db, feed_url="https://example.invalid/latest.json")
    result = asyncio.run(
        updater.check_for_update(temp_db, fetch=_json_fetch(CUSTOM_NEW))
    )
    assert result["status"] == "update_available"
    assert result["current"] == updater.current_version()
    assert result["latest"] == "0.2.0"
    assert result["url"] == CUSTOM_NEW["url"]
    assert result["sha256"] == CUSTOM_NEW["sha256"]
    assert result["notes"] == "Fixed the thing"
    assert result["published_at"] == "2026-10-01T00:00:00Z"
    assert result["checked_at"]


def test_custom_feed_without_hash_is_unverified(temp_db):
    """No hash → unverified: never claim verified without a checksum."""
    _enable(temp_db, feed_url="https://example.invalid/latest.json")
    feed = {"version": "0.2.0", "url": "https://example.invalid/x.exe", "notes": "n"}
    result = asyncio.run(updater.check_for_update(temp_db, fetch=_json_fetch(feed)))
    assert result["status"] == "unverified"
    assert result["sha256"] is None
    assert result["url"] == feed["url"]


def test_up_to_date_feed(temp_db):
    _enable(temp_db, feed_url="https://example.invalid/latest.json")
    feed = dict(CUSTOM_NEW, version="0.0.1")
    result = asyncio.run(updater.check_for_update(temp_db, fetch=_json_fetch(feed)))
    assert result["status"] == "up_to_date"
    assert result["current"] == updater.current_version()
    assert result["checked_at"]


def test_github_shaped_feed_with_asset_digest(temp_db):
    _enable(temp_db)
    feed = {
        "tag_name": "v0.3.0",
        "html_url": "https://github.com/ghostdrive/ghostdrive/releases/tag/v0.3.0",
        "body": "Release notes here",
        "published_at": "2026-10-02T12:00:00Z",
        "assets": [
            {
                "name": "GhostDrive-0.3.0-setup.exe",
                "browser_download_url": (
                    "https://github.com/ghostdrive/ghostdrive/releases/download/"
                    "v0.3.0/GhostDrive-0.3.0-setup.exe"
                ),
                "digest": "sha256:" + "ab" * 32,
            },
            {
                "name": "ghostdrive.spec",
                "browser_download_url": "https://example.invalid/ghostdrive.spec",
            },
        ],
    }
    result = asyncio.run(updater.check_for_update(temp_db, fetch=_json_fetch(feed)))
    assert result["status"] == "update_available"
    assert result["latest"] == "v0.3.0"
    assert result["url"].endswith("GhostDrive-0.3.0-setup.exe")
    assert result["sha256"] == "ab" * 32
    assert result["notes"] == "Release notes here"
    assert result["published_at"] == "2026-10-02T12:00:00Z"


def test_github_shaped_feed_prefers_sha256sums_asset(temp_db):
    """A published SHA256SUMS file wins over the per-asset digest."""
    _enable(temp_db)
    exe_hash = hashlib.sha256(b"setup payload").hexdigest()
    sums_url = (
        "https://github.com/ghostdrive/ghostdrive/releases/download/v0.3.0/SHA256SUMS"
    )
    feed = {
        "tag_name": "v0.3.0",
        "html_url": "https://github.com/ghostdrive/ghostdrive/releases/tag/v0.3.0",
        "body": "notes",
        "published_at": "2026-10-02T12:00:00Z",
        "assets": [
            {
                "name": "GhostDrive-0.3.0-setup.exe",
                "browser_download_url": (
                    "https://github.com/ghostdrive/ghostdrive/releases/download/"
                    "v0.3.0/GhostDrive-0.3.0-setup.exe"
                ),
                "digest": "sha256:" + "cd" * 32,  # deliberately different
            },
            {
                "name": "SHA256SUMS",
                "browser_download_url": sums_url,
            },
        ],
    }
    calls = []

    async def fetch(url: str) -> bytes:
        calls.append(url)
        if url == sums_url:
            return f"{exe_hash}  GhostDrive-0.3.0-setup.exe\n".encode()
        return json.dumps(feed).encode()

    result = asyncio.run(updater.check_for_update(temp_db, fetch=fetch))
    assert result["status"] == "update_available"
    assert result["sha256"] == exe_hash  # sums file, not the cd.. digest
    assert calls == [FEED_URL, sums_url]


def test_malformed_json_returns_error_without_raising(temp_db):
    _enable(temp_db)

    async def fetch(url: str) -> bytes:
        return b'{"tag_name": "v0.3.0", "assets": [oops'

    result = asyncio.run(updater.check_for_update(temp_db, fetch=fetch))
    assert result["status"] == "error"
    assert result["detail"]
    # Errors are never cached — a transient failure must stay retryable.
    assert temp_db.get_setting(updater.UPDATE_LAST_CHECK, "") == ""


def test_network_failure_returns_error_without_raising(temp_db):
    _enable(temp_db)

    async def fetch(url: str) -> bytes:
        raise OSError("network unreachable")

    result = asyncio.run(updater.check_for_update(temp_db, fetch=fetch))
    assert result["status"] == "error"
    assert "network unreachable" in result["detail"]


def test_unrecognized_feed_shape_is_an_error(temp_db):
    _enable(temp_db)
    result = asyncio.run(
        updater.check_for_update(temp_db, fetch=_json_fetch({"something": 1}))
    )
    assert result["status"] == "error"
    assert "unrecognized feed format" in result["detail"]


def test_check_works_with_plain_temp_db_and_persists(temp_db):
    """check_for_update() runs against a bare GhostDriveDB and writes back."""
    _enable(temp_db, feed_url="https://example.invalid/latest.json")
    result = asyncio.run(
        updater.check_for_update(temp_db, fetch=_json_fetch(CUSTOM_NEW))
    )
    assert result["status"] == "update_available"
    # Settings read from this db (not web state) and the cache landed too.
    assert temp_db.get_setting(updater.UPDATE_CHECK_ENABLED, "") == "true"
    assert temp_db.get_setting(updater.UPDATE_FEED_URL, "") == "https://example.invalid/latest.json"
    cached = json.loads(temp_db.get_setting(updater.UPDATE_LAST_CHECK, ""))
    assert cached["checked_at"] == result["checked_at"]
    assert cached["status"] == "update_available"


# ── check_for_update: 6h cache ──────────────────────────────────────────────

def test_six_hour_cache_skips_refetch(temp_db):
    _enable(temp_db, feed_url="https://example.invalid/latest.json")
    calls = []

    async def fetch(url: str) -> bytes:
        calls.append(url)
        return json.dumps(CUSTOM_NEW).encode()

    t0 = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)
    first = asyncio.run(updater.check_for_update(temp_db, now=t0, fetch=fetch))
    assert len(calls) == 1

    # Still fresh5h later → cached result, no second request.
    second = asyncio.run(
        updater.check_for_update(temp_db, now=t0 + timedelta(hours=5), fetch=fetch)
    )
    assert len(calls) == 1
    assert second["checked_at"] == first["checked_at"]

    # Past the 6h window → refetch (and the cache moves forward).
    third = asyncio.run(
        updater.check_for_update(temp_db, now=t0 + timedelta(hours=7), fetch=fetch)
    )
    assert len(calls) == 2
    assert third["checked_at"] != first["checked_at"]


# ── stage_download ──────────────────────────────────────────────────────────

def test_stage_download_verified_installer(tmp_path):
    payload = b"installer bytes " * 1000
    expected = hashlib.sha256(payload).hexdigest()

    def fetch(url: str) -> bytes:
        return payload

    result = updater.stage_download(
        "https://example.invalid/GhostDrive-setup.exe", expected, tmp_path, fetch=fetch
    )
    staged = Path(result["path"])
    assert staged.name == "GhostDrive-update.exe"
    assert staged.parent == tmp_path
    assert staged.exists()
    assert result["sha256"] == expected
    assert result["size"] == len(payload)
    # The .part scratch file must be gone after the rename.
    assert not (tmp_path / updater.UPDATE_PART_NAME).exists()


def test_stage_download_checksum_mismatch_deletes_file(tmp_path):
    def fetch(url: str) -> bytes:
        return b"not the installer we were promised"

    with pytest.raises(RuntimeError, match="checksum mismatch"):
        updater.stage_download(
            "https://example.invalid/evil.exe", "0" * 64, tmp_path, fetch=fetch
        )
    # Neither the final nor the partial file may survive a failed verify.
    assert not (tmp_path / updater.UPDATE_BINARY_NAME).exists()
    assert not (tmp_path / updater.UPDATE_PART_NAME).exists()


def test_stage_download_refuses_missing_checksum(tmp_path):
    """No expected hash → refuse before any network or disk activity."""
    called = []

    def fetch(url: str) -> bytes:
        called.append(url)
        return b"whatever"

    with pytest.raises(RuntimeError, match="checksum"):
        updater.stage_download("https://example.invalid/x.exe", "", tmp_path, fetch=fetch)
    assert called == []


# ── Route tests: local FastAPI + update router ──────────────────────────────

def test_check_route_disabled_by_default(update_client):
    """Default settings → 200 {"status": "disabled"} with zero network use."""
    res = update_client.get("/api/update/check")
    assert res.status_code == 200
    assert res.json() == {"status": "disabled"}


def test_settings_roundtrip_and_status(update_client):
    payload = {"enabled": True, "feed_url": FEED_URL}
    res = update_client.post("/api/update/settings", json=payload)
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["status"] == "success"
    assert data["enabled"] is True
    assert data["feed_url"] == FEED_URL

    status = update_client.get("/api/update/status")
    assert status.status_code == 200
    body = status.json()
    assert body["enabled"] is True
    assert body["feed_url"] == FEED_URL
    assert body["current"] == updater.current_version()
    # Saving settings invalidates any cached check.
    assert body["last_check"] is None

    # Turning it back off persists too.
    res = update_client.post(
        "/api/update/settings", json={"enabled": False, "feed_url": ""}
    )
    assert res.json()["enabled"] is False
    assert update_client.get("/api/update/status").json()["feed_url"] == ""


def test_download_refused_when_unverified(update_client, monkeypatch):
    async def fake_check(db=None, now=None, fetch=None):
        return {"status": "unverified", "sha256": None}

    monkeypatch.setattr(updater, "check_for_update", fake_check)
    res = update_client.post("/api/update/download")
    assert res.status_code == 400
    assert "no checksum available" in res.json()["detail"]


def test_download_refused_without_update_available(update_client, monkeypatch):
    async def fake_check(db=None, now=None, fetch=None):
        return {"status": "up_to_date"}

    monkeypatch.setattr(updater, "check_for_update", fake_check)
    res = update_client.post("/api/update/download")
    assert res.status_code == 400
    assert "no update available" in res.json()["detail"]


def test_download_stages_verified_update(update_client, monkeypatch, tmp_path):
    expected_sha = "ab" * 32

    async def fake_check(db=None, now=None, fetch=None):
        return {
            "status": "update_available",
            "url": "https://example.invalid/GhostDrive-0.2.0-setup.exe",
            "sha256": expected_sha,
        }

    def fake_stage(url, sha256, dest_dir, fetch=None):
        dest_dir = Path(dest_dir)
        dest_dir.mkdir(parents=True, exist_ok=True)
        path = dest_dir / updater.UPDATE_BINARY_NAME
        path.write_bytes(b"stub installer")
        return {"path": str(path), "sha256": sha256, "size": len(b"stub installer")}

    monkeypatch.setattr(updater, "check_for_update", fake_check)
    monkeypatch.setattr(updater, "stage_download", fake_stage)

    res = update_client.post("/api/update/download")
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["sha256"] == expected_sha
    assert data["size"] == len(b"stub installer")
    staged = Path(data["path"])
    assert staged.parent == tmp_path / "updates"
    assert staged.exists()


def test_install_rejects_path_outside_updates_dir(update_client, tmp_path):
    """Path-traversal guard: anything outside our updates dir is a 400."""
    evil = str(tmp_path / "updates" / ".." / "evil.exe")
    res = update_client.post(
        "/api/update/install", json={"path": evil, "confirm": True}
    )
    assert res.status_code == 400
    assert "outside" in res.json()["detail"]


def test_install_requires_confirmation(update_client, tmp_path):
    staged = str(tmp_path / "updates" / updater.UPDATE_BINARY_NAME)
    res = update_client.post(
        "/api/update/install", json={"path": staged, "confirm": False}
    )
    assert res.status_code == 400
    assert "confirmation required" in res.json()["detail"]


def test_install_with_confirmation_starts_installer(
    update_client, monkeypatch, tmp_path
):
    seen = {}

    def fake_run_installer(path, confirm=False):
        seen["path"] = Path(path)
        seen["confirm"] = confirm
        return {"status": "started", "path": str(path)}

    monkeypatch.setattr(updater, "run_installer", fake_run_installer)

    staged = tmp_path / "updates" / updater.UPDATE_BINARY_NAME
    res = update_client.post(
        "/api/update/install", json={"path": str(staged), "confirm": True}
    )
    assert res.status_code == 200, res.text
    assert res.json()["status"] == "started"
    assert seen["confirm"] is True
    assert seen["path"] == staged
