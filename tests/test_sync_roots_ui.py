"""
test_sync_roots_ui.py -- Multi-folder auto-vault UI surface: the folder
manager in the Sync & versions view, the JS wiring it relies on, and the
settings-model contract the frontend consumes. Static assertions only --
mirrors tests/test_new_feature_ui.py.
"""

from pathlib import Path

from fastapi.testclient import TestClient

from ghostdrive.web.routes import sync as sync_routes
from ghostdrive.web.server import app

STATIC_DIR = Path(__file__).resolve().parent.parent / "ghostdrive" / "web" / "static"


def _page() -> str:
    return TestClient(app).get("/").text


def _js() -> str:
    return TestClient(app).get("/static/js/app.js").text


def test_sync_view_hosts_folder_manager():
    """The sync view offers an add/remove list of auto-vault folders."""
    html = _page()
    assert 'id="view-sync"' in html
    assert 'id="sync-roots-list"' in html
    assert 'id="sync-root-input"' in html
    assert 'id="btn-sync-add-root"' in html
    assert "Auto-vault folders" in html
    # Friendly empty state so a fresh install knows what to do.
    assert "add one below" in html
    # The old single-root field label is gone (the input id survives for the
    # folder manager).
    assert "<span>Root folder</span>" not in html


def test_app_js_manages_multiple_roots():
    """Add/remove send the full roots list; the scheduler form no longer
    requires a root."""
    js = _js()
    assert "function addSyncRoot" in js
    assert "function removeSyncRoot" in js
    assert "function renderSyncRoots" in js
    assert "function saveSyncRoots" in js
    assert "sync-roots-list" in js
    assert "btn-sync-add-root" in js
    assert "sync-root-remove" in js
    # Both the folder manager and the scheduler form persist via /settings.
    assert js.count("/api/sync/settings") >= 2
    assert "body: { roots }" in js
    # Removing a folder is explicit + confirmed, and never phrased as deletion
    # of data.
    assert "confirmAction(" in js
    assert "Enter a sync root folder." not in js


def test_settings_model_accepts_roots_list():
    """The API contract the UI consumes: roots replaces the whole list, the
    legacy root field still maps to a one-element list."""
    multi = sync_routes.SyncSettingsRequest(
        roots=["/tmp/folder-a", "/tmp/folder-b"], enabled=True
    )
    assert multi.roots == ["/tmp/folder-a", "/tmp/folder-b"]
    assert multi.root is None
    assert multi.enabled is True

    legacy = sync_routes.SyncSettingsRequest(root="/tmp/one")
    assert legacy.root == "/tmp/one"
    assert legacy.roots is None
