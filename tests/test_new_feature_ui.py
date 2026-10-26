"""
test_new_feature_ui.py -- Wave-1 UI surface: the Sync & versions and
Monitoring views exist in the page, the global alert toast + nav badge and
the zero-knowledge envelope share are wired, and the SPA references every
endpoint the new views consume. Static assertions only -- mirrors
tests/test_recovery_ui.py.
"""

from fastapi.testclient import TestClient

from ghostdrive.web.server import app


def _page() -> str:
    return TestClient(app).get("/").text


def _js() -> str:
    return TestClient(app).get("/static/js/app.js").text


def _surface() -> str:
    return _page() + _js()


def test_nav_has_sync_and_monitoring_views():
    """Both nav entries and both view sections exist in the markup."""
    html = _page()
    assert 'data-view="sync"' in html
    assert 'data-view="monitoring"' in html
    assert 'id="view-sync"' in html
    assert 'id="view-monitoring"' in html


def test_new_views_reference_endpoints():
    """The UI surface mentions every wave-1 endpoint the flows depend on."""
    surface = _surface()
    assert "/api/sync/status" in surface
    assert "/api/sync/run" in surface
    assert "/api/sync/versions/" in surface
    assert "/api/monitoring/badge" in surface
    assert "/api/monitoring/drills/run" in surface
    assert "/api/monitoring/alerts" in surface
    assert "/api/sharing/envelope" in surface


def test_badge_img_and_alert_controls():
    """The embeddable badge image plus dismiss/evaluate alert endpoints."""
    html = _page()
    js = _js()
    assert 'src="/api/monitoring/badge.svg"' in html
    assert "/api/monitoring/alerts/evaluate" in js
    # Per-alert dismiss builds the alert id into the DELETE path template.
    assert "/api/monitoring/alerts/${" in js


def test_envelope_share_ui():
    """Per-file envelope action plus the shown-once passphrase warning."""
    surface = _surface()
    assert 'data-action="envelope"' in surface
    assert "shown once" in surface.lower()
    assert "passphrase" in surface.lower()
    assert "Copy passphrase" in surface


def test_loaders_registered_for_new_views():
    """The view switch refreshes both new views on open (loaders map)."""
    js = _js()
    assert "sync: loadSync" in js
    assert "monitoring: loadMonitoring" in js


def test_alert_toast_and_nav_badge_wiring():
    """Global alert polling: session toast dedupe set + nav badge element."""
    html = _page()
    js = _js()
    assert 'id="nav-alert-badge"' in html
    assert "alertToasted" in js
    assert "pollAlerts" in js


def test_static_assets_parse():
    """The assets the new views live in are served and well-formed."""
    client = TestClient(app)
    html = client.get("/").text
    # Balanced section tags around the new views (cheap parse check).
    assert html.count("<section") == html.count("</section>")
    js = client.get("/static/js/app.js").text
    assert js.count("{") == js.count("}")
    assert js.count("(") == js.count(")")
    css = client.get("/static/css/styles.css").text
    assert css.count("{") == css.count("}")
