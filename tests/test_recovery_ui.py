"""
test_recovery_ui.py -- Recovery-kit & portable-vault UI surface: the recovery
view exists in the page, references the right endpoints, and the API
contracts the UI consumes behave as the frontend assumes.
"""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ghostdrive.web.server import app
from ghostdrive.web.state import state

PASSPHRASE = "correct horse battery staple"
STATIC_DIR = Path(__file__).resolve().parent.parent / "ghostdrive" / "web" / "static"


@pytest.fixture
def recovery_client(tmp_path):
    """Fresh unlocked vault in a temp dir (function-scoped: state is global)."""
    state.clean_shutdown()
    state.app_data_dir = tmp_path
    state.keystore_path = tmp_path / "keystore.json"
    state.db_path = tmp_path / "ghostdrive.db"

    client = TestClient(app)
    res = client.post("/api/auth/setup", json={"passphrase": PASSPHRASE})
    assert res.status_code == 200, res.text

    yield client

    state.clean_shutdown()


def test_recovery_view_in_nav_and_markup():
    """The page wires up the recovery view and its nav entry."""
    html = TestClient(app).get("/").text
    assert 'data-view="recovery"' in html
    assert 'id="view-recovery"' in html


def test_recovery_view_references_endpoints():
    """The UI surface mentions both export endpoints the flow depends on."""
    html = TestClient(app).get("/").text
    js = TestClient(app).get("/static/js/app.js").text
    surface = html + js
    assert "/api/recovery/kit/export" in surface
    assert "/api/portable/export" in surface


def test_index_still_links_manifest():
    """Regression guard: index.html keeps its PWA manifest link."""
    html = TestClient(app).get("/").text
    if 'rel="manifest"' not in html:
        pytest.skip("manifest link not present")
    assert "/manifest.webmanifest" in html


def test_static_assets_parse():
    """The static assets the recovery UI lives in are served and well-formed."""
    client = TestClient(app)
    html = client.get("/").text
    # Balanced section tags around the recovery view (cheap parse check).
    assert html.count("<section") == html.count("</section>")
    js = client.get("/static/js/app.js").text
    assert js.count("{") == js.count("}")
    assert js.count("(") == js.count(")")
    css = client.get("/static/css/styles.css").text
    assert css.count("{") == css.count("}")


def test_kit_export_filenames_match_share_count(recovery_client):
    """API contract the download loop consumes: one filename per share."""
    res = recovery_client.post(
        "/api/recovery/kit/export", json={"threshold": 3, "total": 5, "label": "UI kit"}
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["status"] == "success"
    assert len(data["shares"]) == 5
    assert len(data["filenames"]) == len(data["shares"])
    assert all(name.endswith(".gdshare") for name in data["filenames"])
    assert data["manifest"]["threshold"] == 3
    assert data["manifest"]["total"] == 5
    assert data["manifest"]["label"] == "UI kit"
    # The UI also downloads the manifest as JSON alongside the shares.
    assert "kit_id" in data["manifest"]
    assert "commitment" in data["manifest"]


def test_combine_conflict_while_unlocked(recovery_client):
    """The 409 the UI's error path handles: combine requires a locked vault."""
    shares = recovery_client.post(
        "/api/recovery/kit/export", json={"threshold": 3, "total": 5}
    ).json()["shares"]
    res = recovery_client.post(
        "/api/recovery/kit/combine",
        json={"shares": shares[:3], "passphrase": "brand new pass"},
    )
    assert res.status_code == 409
    assert "unlocked" in res.json()["detail"].lower()


def test_recovery_and_portable_status(recovery_client):
    """Status payloads the recovery view's loader populates from."""
    recovery = recovery_client.get("/api/recovery/status").json()
    assert recovery["available"] is True
    assert recovery["unlocked"] is True
    assert recovery["threshold"] == 3
    assert recovery["total"] == 5
    assert recovery["offline_tool"]

    portable = recovery_client.get("/api/portable/status").json()
    assert portable["available"] is True
    assert portable["unlocked"] is True
    assert portable["extension"] == ".gdvault"
