"""
test_web_app.py -- Automated unit and integration tests for GhostDrive FastAPI Web Interface.
"""

import os
import pytest
from fastapi.testclient import TestClient

from ghostdrive.web.server import app
from ghostdrive.web.state import state
from tests.conftest import FAST_ARGON2_PARAMS

client = TestClient(app)

def test_preflight_endpoint():
    """Verify pre-flight diagnostics endpoint executes system checks."""
    response = client.get("/api/preflight/run")
    assert response.status_code == 200
    data = response.json()
    assert "keyring_ok" in data
    assert "database_ok" in data
    assert "network_ok" in data
    assert "long_paths_ok" in data

def test_auth_status_initial():
    """Check auth status endpoint."""
    response = client.get("/api/auth/status")
    assert response.status_code == 200
    data = response.json()
    assert "keystore_exists" in data
    assert "is_unlocked" in data
    assert "db_opened" in data

def test_storage_tier_advisor():
    """Test storage tier advisor heuristics for file criticality."""
    # Critical file (.key)
    res_crit = client.post("/api/files/tier-advisor", json={
        "filename": "secret.key",
        "file_size": 1024
    })
    assert res_crit.status_code == 200
    assert res_crit.json()["recommended_tier"] == "CRITICAL"

    # Disposable file (.ckpt)
    res_disp = client.post("/api/files/tier-advisor", json={
        "filename": "model.ckpt",
        "file_size": 100 * 1024 * 1024
    })
    assert res_disp.status_code == 200
    assert res_disp.json()["recommended_tier"] == "DISPOSABLE"

    # Default file (.pdf)
    res_imp = client.post("/api/files/tier-advisor", json={
        "filename": "report.pdf",
        "file_size": 5 * 1024 * 1024
    })
    assert res_imp.status_code == 200
    assert res_imp.json()["recommended_tier"] == "IMPORTANT"

def test_backends_list_and_test():
    """Verify backend listing and reachability test endpoint."""
    res_list = client.get("/api/backends/list")
    assert res_list.status_code == 200
    data = res_list.json()
    assert "tiers" in data
    assert len(data["configured_backends"]) >= 3

    res_test = client.post("/api/backends/test", json={
        "provider": "Telegram",
        "tier": "HOT",
        "credentials": {}
    })
    assert res_test.status_code == 200
    assert res_test.json()["success"] is True

def test_analytics_metrics():
    """Verify analytics metrics summary and tier distribution."""
    res = client.get("/api/analytics/metrics")
    assert res.status_code == 200
    data = res.json()
    assert "summary" in data
    assert "tier_distribution" in data
    assert data["summary"]["dedup_ratio"] > 1.0

def test_resilience_scrub():
    """Verify health score and integrity scrub trigger."""
    res_status = client.get("/api/resilience/status")
    assert res_status.status_code == 200
    assert res_status.json()["health_score_percent"] > 90.0

    res_scrub = client.post("/api/resilience/scrub/start", json={
        "tier": "ALL",
        "auto_repair": True
    })
    assert res_scrub.status_code == 200
    assert res_scrub.json()["status"] == "started"

def test_smart_engine_config():
    """Verify smart engine parameters update."""
    res_get = client.get("/api/smart/config")
    assert res_get.status_code == 200
    assert res_get.json()["background_sync"] is True

    res_post = client.post("/api/smart/config", json={
        "background_sync": False,
        "auto_tiering_enabled": True,
        "auto_tiering_days_unused": 60,
        "thermal_throttling_enabled": True,
        "max_cpu_percent_cap": 75,
        "bandwidth_limit_kbps": 500,
        "battery_saver_pause": True
    })
    assert res_post.status_code == 200
    assert res_post.json()["status"] == "success"

def test_settings_routes():
    """Verify settings get/post endpoints."""
    res_get = client.get("/api/settings/")
    assert res_get.status_code == 200

    res_post = client.post("/api/settings/", json={
        "theme": "dark",
        "accent_color": "#8b5cf6",
        "autostart": False,
        "desktop_notifications": True,
        "log_level": "INFO",
        "proxy_type": "none",
        "proxy_host": "",
        "proxy_port": 0
    })
    assert res_post.status_code == 200
    assert res_post.json()["status"] == "success"

def test_sharing_routes():
    """Verify shared links creation and revocation."""
    res_create = client.post("/api/sharing/create", json={
        "file_id": "file_123456",
        "ttl_hours": 48
    })
    assert res_create.status_code == 200
    assert "url" in res_create.json()

    res_links = client.get("/api/sharing/links")
    assert res_links.status_code == 200
    assert len(res_links.json()["shared_links"]) >= 1
