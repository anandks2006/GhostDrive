"""
test_pwa.py -- Installable PWA surface: manifest, service worker, and icons.
"""

import json
from pathlib import Path

from fastapi.testclient import TestClient

from ghostdrive.web.server import app

STATIC_DIR = Path(__file__).resolve().parent.parent / "ghostdrive" / "web" / "static"


def test_manifest_route_and_content():
    """GET /manifest.webmanifest serves valid JSON with the right MIME type."""
    response = TestClient(app).get("/manifest.webmanifest")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/manifest+json")
    manifest = response.json()
    assert manifest["name"] == "GhostDrive"
    assert manifest["short_name"] == "GhostDrive"
    assert manifest["display"] == "standalone"
    assert manifest["start_url"] == "/"
    assert manifest["icons"], "manifest must reference at least one icon"


def test_service_worker_is_served():
    """The service worker is reachable at the root scope and via the static mount."""
    client = TestClient(app)
    root = client.get("/serviceworker.js")
    assert root.status_code == 200
    assert "javascript" in root.headers["content-type"]
    # install/activate/fetch handlers and the API bypass must all be present.
    for marker in ("install", "activate", "fetch", "/api/"):
        assert marker in root.text
    assert client.get("/static/serviceworker.js").status_code == 200


def test_index_links_manifest_and_registers_worker():
    """The served index page links the manifest and pulls in the guarded registration."""
    client = TestClient(app)
    html = client.get("/").text
    assert 'rel="manifest"' in html
    assert "/manifest.webmanifest" in html
    assert '<meta name="viewport"' in html
    assert '<meta name="theme-color"' in html
    # Registration lives in the app bundle, guarded by a secure-context check.
    js = client.get("/static/js/app.js").text
    assert 'serviceWorker.register("/serviceworker.js"' in js
    assert "beforeinstallprompt" in js


def test_manifest_icons_exist_on_disk():
    """Every icon referenced by the manifest resolves to a real file on disk."""
    manifest = json.loads((STATIC_DIR / "manifest.webmanifest").read_text(encoding="utf-8"))
    for icon in manifest["icons"]:
        src = icon["src"]
        assert src.startswith("/static/"), f"icon src must be under /static/: {src}"
        path = STATIC_DIR / src[len("/static/"):]
        assert path.is_file(), f"manifest icon missing on disk: {src}"
