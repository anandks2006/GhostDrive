"""
test_web_app.py -- Automated unit and integration tests for GhostDrive FastAPI Web Interface.
"""

import pytest
from fastapi.testclient import TestClient

from ghostdrive.web.server import app
from ghostdrive.web.state import state

PASSPHRASE = "correct horse battery staple"


@pytest.fixture(scope="module")
def unlocked_client(tmp_path_factory):
    """Create a fresh vault in a temp data dir and return an unlocked client."""
    data_dir = tmp_path_factory.mktemp("ghostdrive_web")
    state.clean_shutdown()
    state.app_data_dir = data_dir
    state.keystore_path = data_dir / "keystore.json"
    state.db_path = data_dir / "ghostdrive.db"

    client = TestClient(app)
    response = client.post("/api/auth/setup", json={"passphrase": PASSPHRASE})
    assert response.status_code == 200, response.text
    assert response.json()["seed_phrase"]

    yield client

    state.clean_shutdown()


def test_preflight_endpoint(tmp_path):
    """Verify pre-flight diagnostics endpoint executes system checks."""
    state.app_data_dir = tmp_path
    response = TestClient(app).get("/api/preflight/run")
    assert response.status_code == 200
    data = response.json()
    assert "keyring_ok" in data
    assert "database_ok" in data
    assert "network_ok" in data
    assert "long_paths_ok" in data


def test_auth_status_initial():
    """Check auth status endpoint before a vault is created."""
    response = TestClient(app).get("/api/auth/status")
    assert response.status_code == 200
    data = response.json()
    assert "keystore_exists" in data
    assert "is_unlocked" in data
    assert "db_opened" in data


def test_storage_tier_advisor():
    """Test storage tier advisor heuristics for file criticality."""
    client = TestClient(app)
    res_crit = client.post("/api/files/tier-advisor", json={
        "filename": "secret.key",
        "file_size": 1024,
    })
    assert res_crit.status_code == 200
    assert res_crit.json()["recommended_tier"] == "CRITICAL"

    res_disp = client.post("/api/files/tier-advisor", json={
        "filename": "model.ckpt",
        "file_size": 100 * 1024 * 1024,
    })
    assert res_disp.status_code == 200
    assert res_disp.json()["recommended_tier"] == "DISPOSABLE"

    res_imp = client.post("/api/files/tier-advisor", json={
        "filename": "report.pdf",
        "file_size": 5 * 1024 * 1024,
    })
    assert res_imp.status_code == 200
    assert res_imp.json()["recommended_tier"] == "IMPORTANT"


def test_locked_vault_rejects_backends():
    """Real storage routes must fail closed while the vault is locked."""
    state.clean_shutdown()
    response = TestClient(app).get("/api/backends/list")
    assert response.status_code == 401


def test_file_lifecycle(unlocked_client):
    """Upload, list, download, verify, tag, rename, trash and restore a real file."""
    payload = b"hello ghostdrive, this is a real encrypted upload\n"

    upload = unlocked_client.post(
        "/api/files/upload",
        files={"file": ("hello.txt", payload, "text/plain")},
        data={"tier": "IMPORTANT", "destination_path": "/docs"},
    )
    assert upload.status_code == 200, upload.text
    body = upload.json()
    assert body["status"] == "success"
    file_id = body["file_id"]

    listing = unlocked_client.get("/api/files/list", params={"path": "/docs"})
    assert listing.status_code == 200
    names = [f["filename"] for f in listing.json()["files"]]
    assert "hello.txt" in names

    metadata = unlocked_client.get(f"/api/files/metadata/{file_id}")
    assert metadata.status_code == 200
    assert metadata.json()["filename"] == "hello.txt"
    assert metadata.json()["chunks"]

    download = unlocked_client.get(f"/api/files/download/{file_id}")
    assert download.status_code == 200
    assert download.content == payload

    verify = unlocked_client.post(f"/api/files/verify/{file_id}")
    assert verify.status_code == 200
    assert verify.json()["healthy"] is True

    tags = unlocked_client.post("/api/files/tags", json={"file_id": file_id, "tags": "test,demo"})
    assert tags.status_code == 200
    assert tags.json()["file"]["tags"] == "test,demo"

    rename = unlocked_client.post("/api/files/rename", json={"file_id": file_id, "new_name": "renamed.txt"})
    assert rename.status_code == 200
    assert rename.json()["file"]["filename"] == "renamed.txt"

    delete = unlocked_client.request(
        "DELETE", "/api/files/delete", json={"file_id": file_id, "purge": False}
    )
    assert delete.status_code == 200
    assert "Trash" in delete.json()["message"]

    trash = unlocked_client.get("/api/files/trash")
    assert trash.status_code == 200
    assert any(f["id"] == file_id for f in trash.json()["files"])

    restore = unlocked_client.post("/api/files/restore", json={"file_id": file_id})
    assert restore.status_code == 200
    assert restore.json()["status"] == "success"


def test_backends_list_and_test(unlocked_client):
    """Verify backend listing and reachability test endpoint."""
    res_list = unlocked_client.get("/api/backends/list")
    assert res_list.status_code == 200
    data = res_list.json()
    assert "tiers" in data
    assert len(data["configured_backends"]) >= 1

    backend = data["configured_backends"][0]
    res_test = unlocked_client.post("/api/backends/test", json={
        "provider": backend["provider"],
        "tier": backend["tier"],
        "credentials": {},
        "backend_id": backend["id"],
    })
    assert res_test.status_code == 200
    assert res_test.json()["success"] is True


def test_backend_toggle_visibility_and_local_guard(unlocked_client, tmp_path):
    """Disabled backends stay visible, but the only local vault cannot be disabled."""
    listing = unlocked_client.get("/api/backends/list")
    assert listing.status_code == 200
    local = next(
        backend
        for backend in listing.json()["configured_backends"]
        if backend["provider_key"] in ("local", "local_fs")
    )
    local_id = local["id"]

    guard = unlocked_client.post(
        "/api/backends/toggle",
        params={"backend_id": local_id, "enabled": False},
    )
    assert guard.status_code == 400
    assert "only local vault" in guard.json()["detail"]

    still_enabled = unlocked_client.get("/api/backends/list").json()["configured_backends"]
    assert next(backend for backend in still_enabled if backend["id"] == local_id)["enabled"] is True

    secondary_path = tmp_path / "secondary-local-vault"
    saved = unlocked_client.post(
        "/api/backends/save",
        json={
            "provider": "local",
            "name": "Secondary test vault",
            "tier": "LOCAL_LOCKER",
            "enabled": True,
            "credentials": {"path": str(secondary_path)},
        },
    )
    assert saved.status_code == 200, saved.text
    secondary_id = saved.json()["backend_id"]

    try:
        toggled = unlocked_client.post(
            "/api/backends/toggle",
            params={"backend_id": local_id, "enabled": False},
        )
        assert toggled.status_code == 200, toggled.text

        configured = unlocked_client.get("/api/backends/list").json()["configured_backends"]
        disabled = next(backend for backend in configured if backend["id"] == local_id)
        assert disabled["enabled"] is False
        assert disabled["status"] == "DISABLED"
    finally:
        unlocked_client.post(
            "/api/backends/toggle",
            params={"backend_id": local_id, "enabled": True},
        )
        unlocked_client.delete(f"/api/backends/remove/{secondary_id}")


def test_analytics_metrics(unlocked_client):
    """Verify analytics metrics summary and tier distribution."""
    res = unlocked_client.get("/api/analytics/metrics")
    assert res.status_code == 200
    data = res.json()
    assert "summary" in data
    assert "tier_distribution" in data
    assert data["summary"]["total_files"] >= 1
    assert data["summary"]["dedup_ratio"] >= 1.0


def test_resilience_scrub(unlocked_client):
    """Verify health score and integrity scrub trigger."""
    res_status = unlocked_client.get("/api/resilience/status")
    assert res_status.status_code == 200
    assert res_status.json()["health_score_percent"] >= 0.0

    res_scrub = unlocked_client.post("/api/resilience/scrub/start", json={
        "tier": "ALL",
        "auto_repair": True,
    })
    assert res_scrub.status_code == 200
    assert res_scrub.json()["status"] in ("started", "running")


def test_durability_contract_and_readiness(unlocked_client):
    """Verify contract settings, recovery confirmation, and worst-case status."""
    contract = unlocked_client.get("/api/resilience/contract")
    assert contract.status_code == 200
    assert contract.json()["required_domain_losses"] >= 0

    saved = unlocked_client.post(
        "/api/resilience/contract",
        json={"required_domain_losses": 2, "requires_offsite": False},
    )
    assert saved.status_code == 200, saved.text
    assert saved.json()["contract"]["required_domain_losses"] == 2
    assert "worst_case" in saved.json()

    impossible = unlocked_client.post(
        "/api/resilience/contract",
        json={"required_domain_losses": 3, "requires_offsite": False},
    )
    assert impossible.status_code == 400

    confirmed = unlocked_client.post("/api/resilience/recovery/confirm")
    assert confirmed.status_code == 200, confirmed.text
    assert confirmed.json()["confirmed_at"]

    status = unlocked_client.get("/api/resilience/status")
    assert status.status_code == 200
    worst_case = status.json()["worst_case"]
    assert worst_case["state"] in ("PROTECTED", "DEGRADED", "UNPROTECTED", "UNKNOWN")
    assert worst_case["recovery"]["ok"] is True


def test_protection_sets_mirror_folder(unlocked_client, tmp_path):
    """Create a protection set, mirror a folder, re-scan changes, and delete it."""
    source = tmp_path / "watch-me"
    (source / "nested").mkdir(parents=True)
    (source / "top.txt").write_text("top level", encoding="utf-8")
    (source / "nested" / "child.txt").write_text("child level", encoding="utf-8")

    created = unlocked_client.post("/api/protection/sets", json={
        "name": "Watch me",
        "source_path": str(source),
        "destination_path": "/protected",
        "tier": "IMPORTANT",
    })
    assert created.status_code == 200, created.text
    set_id = created.json()["set"]["id"]

    first = unlocked_client.post(f"/api/protection/sets/{set_id}/scan", json={"max_files": 20})
    assert first.status_code == 200, first.text
    assert first.json()["uploaded"] == 2
    assert first.json()["set"]["file_count"] == 2

    listing = unlocked_client.get("/api/protection/sets")
    assert listing.status_code == 200
    assert listing.json()["summary"]["files"] == 2

    children = unlocked_client.get(f"/api/protection/sets/{set_id}/files")
    assert children.status_code == 200
    relative = {item["relative_path"] for item in children.json()["files"]}
    assert relative == {"top.txt", "nested/child.txt"}

    nested_files = unlocked_client.get("/api/files/list", params={"path": "/protected/nested"})
    assert nested_files.status_code == 200
    assert any(item["filename"] == "child.txt" for item in nested_files.json()["files"])

    (source / "top.txt").write_text("top level changed", encoding="utf-8")
    second = unlocked_client.post(f"/api/protection/sets/{set_id}/scan", json={"max_files": 20})
    assert second.status_code == 200, second.text
    assert second.json()["uploaded"] == 1, (
        second.json(),
        [str(item.relative_to(source)) for item in source.rglob("*")],
    )
    assert second.json()["unchanged"] == 1, second.json()

    paused = unlocked_client.put(f"/api/protection/sets/{set_id}", json={"enabled": False})
    assert paused.status_code == 200
    assert paused.json()["set"]["enabled"] is False

    deleted = unlocked_client.delete(f"/api/protection/sets/{set_id}")
    assert deleted.status_code == 200
    assert unlocked_client.get("/api/protection/sets").json()["summary"]["count"] == 0


def test_upload_blocked_when_offsite_contract_unmet(unlocked_client):
    """Uploads must fail closed when an offsite-backed contract is configured."""
    saved = unlocked_client.post(
        "/api/resilience/contract",
        json={"required_domain_losses": 2, "requires_offsite": True, "requires_restore_proof": False},
    )
    assert saved.status_code == 200, saved.text

    blocked = unlocked_client.post(
        "/api/files/upload",
        files={"file": ("blocked-upload.txt", b"blocked", "text/plain")},
        data={"tier": "IMPORTANT", "destination_path": "/"},
    )
    assert blocked.status_code == 409, blocked.text
    assert "Upload blocked" in blocked.json()["detail"]

    restored = unlocked_client.post(
        "/api/resilience/contract",
        json={"required_domain_losses": 2, "requires_offsite": False, "requires_restore_proof": False},
    )
    assert restored.status_code == 200, restored.text


def test_index_snapshots_restore_drill_and_what_if(unlocked_client, tmp_path):
    """Create an encrypted index snapshot, verify it, drill it, and simulate loss."""
    upload = unlocked_client.post(
        "/api/files/upload",
        files={"file": ("snapshot.txt", b"snapshot drill data", "text/plain")},
        data={"tier": "DISPOSABLE", "destination_path": "/"},
    )
    assert upload.status_code == 200, upload.text

    created = unlocked_client.post("/api/resilience/snapshots", json={})
    assert created.status_code == 200, created.text
    body = created.json()
    assert body["confirmed_copies"] >= 1
    assert body["blake3_hash"]

    listed = unlocked_client.get("/api/resilience/snapshots")
    assert listed.status_code == 200
    assert any(item["id"] == body["snapshot_id"] for item in listed.json()["snapshots"])

    verified = unlocked_client.post("/api/resilience/snapshots/verify", json={
        "snapshot_id": body["snapshot_id"],
    })
    assert verified.status_code == 200, verified.text
    assert verified.json()["status"] == "verified"
    assert verified.json()["plaintext_size"] > 0

    destination = tmp_path / "recovered.db"
    restored = unlocked_client.post("/api/resilience/snapshots/restore", json={
        "snapshot_id": body["snapshot_id"],
        "destination": str(destination),
    })
    assert restored.status_code == 200, restored.text
    assert destination.exists()
    assert restored.json()["size"] > 0

    drill = unlocked_client.post("/api/resilience/drill")
    assert drill.status_code == 200, drill.text
    assert drill.json()["result"] == "passed", drill.text
    latest = unlocked_client.get("/api/resilience/drill/latest")
    assert latest.status_code == 200
    assert latest.json()["drill"]["result"] == "passed"

    status = unlocked_client.get("/api/resilience/status").json()["worst_case"]
    assert status["metadata"]["snapshot_count"] >= 1
    assert status["restore_proof"]["ok"] is True

    domain_id = status["configured_failure_domains"][0]["id"]
    simulated = unlocked_client.post("/api/resilience/what-if", json={
        "lost_domain_ids": [domain_id],
    })
    assert simulated.status_code == 200, simulated.text
    result = simulated.json()
    assert result["state"] in ("PROTECTED", "DEGRADED", "UNPROTECTED", "UNKNOWN")
    assert result["total_chunks"] >= 1
    assert domain_id in result["lost_domain_ids"]

    presets = unlocked_client.get("/api/resilience/contract/presets")
    assert presets.status_code == 200
    assert any(item["name"] == "paranoid" for item in presets.json()["presets"])

    saved = unlocked_client.post("/api/resilience/contract", json={"preset": "basic"})
    assert saved.status_code == 200, saved.text
    assert saved.json()["contract"]["preset"] == "basic"

    evacuated = unlocked_client.post("/api/resilience/evacuate")
    assert evacuated.status_code == 200, evacuated.text
    assert "repaired_chunks" in evacuated.json()


def test_smart_engine_config(unlocked_client):
    """Verify smart engine parameters are persisted and applied."""
    res_get = unlocked_client.get("/api/smart/config")
    assert res_get.status_code == 200
    assert res_get.json()["background_sync"] is True

    res_post = unlocked_client.post("/api/smart/config", json={
        "background_sync": False,
        "auto_tiering_enabled": True,
        "auto_tiering_days_unused": 60,
        "thermal_throttling_enabled": True,
        "max_cpu_percent_cap": 75,
        "bandwidth_limit_kbps": 500,
        "battery_saver_pause": True,
    })
    assert res_post.status_code == 200
    assert res_post.json()["status"] == "success"

    from ghostdrive.utils.bandwidth_throttle import UPLOAD_LIMITER
    assert UPLOAD_LIMITER.rate_limit == 500 * 1024

    res_again = unlocked_client.get("/api/smart/config")
    assert res_again.json()["background_sync"] is False


def test_settings_routes(unlocked_client):
    """Verify settings get/post endpoints and DB persistence."""
    res_get = unlocked_client.get("/api/settings/")
    assert res_get.status_code == 200

    res_post = unlocked_client.post("/api/settings/", json={
        "theme": "light",
        "accent_color": "#22c55e",
        "autostart": False,
        "desktop_notifications": True,
        "log_level": "DEBUG",
        "proxy_type": "none",
        "proxy_host": "",
        "proxy_port": 0,
    })
    assert res_post.status_code == 200
    assert res_post.json()["status"] == "success"

    stored = unlocked_client.get("/api/settings/").json()
    assert stored["theme"] == "light"
    assert stored["log_level"] == "DEBUG"
    assert unlocked_client.get("/api/smart/config").json()["background_sync"] is False


def test_sharing_and_public_download(unlocked_client):
    """Verify share link creation, listing, public download and revocation."""
    payload = b"shareable content"
    upload = unlocked_client.post(
        "/api/files/upload",
        files={"file": ("share.txt", payload, "text/plain")},
        data={"tier": "DISPOSABLE", "destination_path": "/"},
    )
    assert upload.status_code == 200, upload.text
    file_id = upload.json()["file_id"]

    res_create = unlocked_client.post("/api/sharing/create", json={
        "file_id": file_id,
        "ttl_hours": 48,
        "require_passcode": True,
        "passcode": "open-sesame",
    })
    assert res_create.status_code == 200
    body = res_create.json()
    assert "url" in body
    token = body["token"]

    res_links = unlocked_client.get("/api/sharing/links")
    assert res_links.status_code == 200
    assert any(link["token"] == token for link in res_links.json()["shared_links"])

    public = unlocked_client.get(f"/s/{token}?passcode=open-sesame")
    assert public.status_code == 200
    assert public.content == payload

    denied = unlocked_client.get(f"/s/{token}?passcode=wrong")
    assert denied.status_code == 200
    assert b"Incorrect share passcode" in denied.content

    revoke = unlocked_client.delete(f"/api/sharing/revoke/{token}")
    assert revoke.status_code == 200

    after_revoke = unlocked_client.get(f"/s/{token}?passcode=open-sesame")
    assert b"revoked" in after_revoke.content.lower()


def test_secrets_vault_crud(unlocked_client):
    """Store, read, update and delete an encrypted vault secret."""
    created = unlocked_client.post("/api/secrets/vault", json={
        "label": "Example login",
        "kind": "password",
        "payload": {"username": "alice", "password": "s3cr3t"},
    })
    assert created.status_code == 200, created.text
    secret_id = created.json()["secret_id"]

    fetched = unlocked_client.get(f"/api/secrets/vault/{secret_id}")
    assert fetched.status_code == 200
    assert fetched.json()["payload"]["password"] == "s3cr3t"

    updated = unlocked_client.put(f"/api/secrets/vault/{secret_id}", json={
        "label": "Example login v2",
        "payload": {"username": "alice", "password": "n3w"},
    })
    assert updated.status_code == 200

    listed = unlocked_client.get("/api/secrets/vault")
    assert listed.status_code == 200
    assert any(item["id"] == secret_id for item in listed.json()["secrets"])

    deleted = unlocked_client.delete(f"/api/secrets/vault/{secret_id}")
    assert deleted.status_code == 200
