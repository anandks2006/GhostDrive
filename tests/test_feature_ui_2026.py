"""
test_feature_ui_2026.py -- Static UI surface for the 2026 feature wave:
tripwires (canary + mass alarm), air-gap & waste, cloud import, remote
access/pairing, content search, burn-after-read, inheritance switch,
weekly health report, WORM toggle, Downloads quick-add, and the extension
link. Static assertions only -- mirrors tests/test_sync_roots_ui.py.
"""

from pathlib import Path

from fastapi.testclient import TestClient

from ghostdrive.web.routes import airgap as airgap_routes
from ghostdrive.web.routes import sync as sync_routes
from ghostdrive.web.server import app

STATIC_DIR = Path(__file__).resolve().parent.parent / "ghostdrive" / "web" / "static"


def _page() -> str:
    return TestClient(app).get("/").text


def _js() -> str:
    return TestClient(app).get("/static/js/app.js").text


def _css() -> str:
    return TestClient(app).get("/static/css/styles.css").text


def test_new_views_and_nav_present():
    html = _page()
    for view in ("view-security", "view-airgap", "view-cloud", "view-remote"):
        assert f'id="{view}"' in html, view
    for view in ("security", "airgap", "cloud", "remote"):
        assert f'data-view="{view}"' in html, view


def test_sync_view_has_downloads_quick_add():
    html = _page()
    assert 'id="btn-sync-quick-add"' in html
    js = _js()
    assert "function quickAddDownloads" in js
    assert '"/api/sync/quick-add"' in js


def test_tripwire_panel_and_js():
    html = _page()
    assert 'id="canary-list"' in html
    assert 'id="canary-path-input"' in html
    assert 'id="btn-canary-check"' in html
    assert 'id="mass-threshold-input"' in html
    assert 'id="btn-mass-check"' in html
    js = _js()
    assert "function loadSecurity" in js
    assert "/api/security/canary/add" in js
    assert "/api/security/canary/check" in js
    assert "/api/security/mass-change/check" in js


def test_airgap_and_waste_panel_and_js():
    html = _page()
    assert 'id="airgap-target-input"' in html
    assert 'id="btn-airgap-export"' in html
    assert 'id="btn-airgap-drill"' in html
    assert 'id="waste-reclaimable"' in html
    js = _js()
    assert "function loadAirgap" in js
    assert "function loadWaste" in js
    assert "/api/airgap/settings" in js
    assert "/api/waste/report" in js


def test_airgap_settings_route_exists():
    """The UI posts to /api/airgap/settings -- the route must exist."""
    paths = {getattr(route, "path", "") for route in airgap_routes.router.routes}
    assert "/api/airgap/settings" in paths


def test_cloud_import_panel_and_js():
    html = _page()
    assert 'id="cloud-provider-input"' in html
    assert 'id="btn-cloud-connect"' in html
    assert 'id="cloud-files-body"' in html
    js = _js()
    assert "function cloudConnect" in js
    assert "function cloudImport" in js
    assert "/api/cloud/connect" in js
    assert "/api/cloud/import" in js


def test_remote_panel_and_js():
    html = _page()
    assert 'id="remote-qr"' in html
    assert 'id="btn-remote-rescan"' in html
    assert "/api/pairing/qr.png" in html
    assert "/metrics" in html
    assert "/api/extension/download" in html
    js = _js()
    assert "function loadRemote" in js
    assert "/api/remote/status" in js


def test_content_search_panel_and_js():
    html = _page()
    assert 'id="content-search-input"' in html
    assert 'id="btn-content-search"' in html
    js = _js()
    assert "function runContentSearch" in js
    assert "/api/search/content" in js


def test_burn_after_read_checkbox():
    html = _page()
    assert 'id="envelope-burn"' in html
    js = _js()
    assert "burn_after_read" in js


def test_inheritance_panel_and_js():
    html = _page()
    assert 'id="inheritance-form"' in html
    assert 'id="btn-inheritance-enable"' in html
    assert 'id="btn-inheritance-checkin"' in html
    js = _js()
    assert "function enableInheritance" in js
    assert "function renderInheritance" in js
    assert "/api/inheritance/enable" in js
    assert "/api/inheritance/check-in" in js


def test_health_report_panel_and_js():
    html = _page()
    assert 'id="health-report-pill"' in html
    assert 'id="btn-health-report-run"' in html
    js = _js()
    assert "function renderHealthReport" in js
    assert "/api/health/run" in js
    assert "/api/health/report" in js


def test_worm_toggle_in_backend_ui():
    html = _page()
    assert 'id="backend-worm"' in html
    js = _js()
    assert '"worm"' in js
    assert "/worm`" in js or "/worm\"" in js
    assert "append_only" in js


def test_css_supports_new_components():
    css = _css()
    for selector in (".bar-row", ".bar-track", ".content-snippet", ".remote-qr"):
        assert selector in css, selector


def test_airgap_settings_model_contract():
    """The request model the UI posts to /api/airgap/settings consumes."""
    req = airgap_routes.AirgapSettingsRequest(
        enabled=True, target_dir="/mnt/backup", interval_hours=24
    )
    assert req.enabled is True
    assert req.target_dir == "/mnt/backup"
    assert req.interval_hours == 24
    empty = airgap_routes.AirgapSettingsRequest()
    assert empty.enabled is None and empty.target_dir is None


def test_quick_add_request_model():
    """The Downloads quick-add body is optional-path only."""
    empty = sync_routes.QuickAddRequest()
    assert empty.path is None
    custom = sync_routes.QuickAddRequest(path="D:/RedirectedDownloads")
    assert custom.path == "D:/RedirectedDownloads"
