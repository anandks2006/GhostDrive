"""
test_factory_reset.py -- Full local wipe: service behavior, the typed-confirmation
route, and the lock-screen UI surface.

The keyring is never touched for real: _wipe_keyring_keys and
_windows_keyring_enum are monkeypatched so hermetic runs cannot delete the
developer's actual Credential Manager entries.
"""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ghostdrive.services import factory_reset
from ghostdrive.services.factory_reset import (
    CONFIRM_PHRASE,
    collect_keyring_refs,
    perform_factory_reset,
    wipe_app_data,
)
from ghostdrive.web.server import app
from ghostdrive.web.state import state

PASSPHRASE = "correct horse battery staple"
STATIC_DIR = Path(__file__).resolve().parent.parent / "ghostdrive" / "web" / "static"


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def fake_keyring(monkeypatch):
    """In-memory stand-in for the OS keyring wipe. Records deletions."""
    deleted: list[str] = []
    monkeypatch.setattr(
        factory_reset, "_wipe_keyring_keys",
        lambda keys: (deleted.extend(sorted(set(keys))) or deleted),
    )
    monkeypatch.setattr(factory_reset, "_wipe_windows_keyring_enum", lambda service="ghostdrive": [])
    return deleted


@pytest.fixture
def vault(tmp_path, fake_keyring):
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


def _seed_extra_files(tmp_path: Path) -> None:
    """Create nonce counter + vault dir + an unrelated file that must survive."""
    (tmp_path / "nonce_counter.json").write_text('{"counter": 42}')
    (tmp_path / "vault").mkdir()
    (tmp_path / "vault" / "chunk.bin").write_bytes(b"ciphertext")
    (tmp_path / "updates").mkdir()
    (tmp_path / "updates" / "staged.exe").write_bytes(b"MZ")
    (tmp_path / "my-unrelated-notes.txt").write_text("keep me")


# ── Service ───────────────────────────────────────────────────────────────────

class TestFactoryResetService:
    def test_wipes_keystore_db_nonce_counter_and_dirs(self, vault, tmp_path):
        _seed_extra_files(tmp_path)
        assert state.keystore_path.exists()

        result = perform_factory_reset(state)

        assert result["status"] == "success"
        assert not state.keystore_path.exists()
        assert not state.db_path.exists()
        assert not (tmp_path / "ghostdrive.db-wal").exists()
        assert not (tmp_path / "ghostdrive.db-shm").exists()
        assert not (tmp_path / "nonce_counter.json").exists()
        assert not (tmp_path / "vault").exists()
        assert not (tmp_path / "updates").exists()
        # The allowlist must not touch unrelated files in a user-configured dir.
        assert (tmp_path / "my-unrelated-notes.txt").exists()

    def test_unrelated_files_survive_wipe_app_data(self, tmp_path):
        (tmp_path / "keep.txt").write_text("mine")
        (tmp_path / "ghostdrive.db").write_bytes(b"db")
        removed = wipe_app_data(tmp_path)
        assert (tmp_path / "keep.txt").exists()
        assert not (tmp_path / "ghostdrive.db").exists()
        assert any("ghostdrive.db" in path for path in removed)

    def test_collects_keyring_refs_from_open_db(self, vault, fake_keyring):
        with state.db.transaction():
            state.db._conn.execute(
                """INSERT INTO backends (id, type, credentials_ref, status, priority,
                   last_health_check, quota_used, quota_limit, quota_reserved)
                   VALUES ('bid-1', 'local', 'local_root_bid-1', 'healthy', 1, NULL, 0, 0, 0)"""
            )
        refs = collect_keyring_refs(state.db)
        assert "local_root_bid-1" in refs
        assert "telegram_session" in refs  # static key always included

        perform_factory_reset(state)
        assert "local_root_bid-1" in fake_keyring

    def test_resets_in_memory_settings(self, vault):
        state.settings["theme"] = "light"
        perform_factory_reset(state)
        assert state.settings["theme"] == "dark"
        assert state._settings_loaded is False

    def test_state_returns_to_first_run(self, vault):
        status = vault.get("/api/auth/status").json()
        assert status["keystore_exists"] is True

        perform_factory_reset(state)

        status = vault.get("/api/auth/status").json()
        assert status["keystore_exists"] is False
        assert status["is_unlocked"] is False
        assert status["db_opened"] is False

    def test_new_vault_can_be_created_after_reset(self, vault):
        """The whole point of a reset: setup must work again immediately."""
        perform_factory_reset(state)
        res = vault.post("/api/auth/setup", json={"passphrase": "a brand new passphrase"})
        assert res.status_code == 200, res.text
        assert vault.get("/api/auth/status").json()["keystore_exists"] is True


# ── Route ─────────────────────────────────────────────────────────────────────

class TestFactoryResetRoute:
    def test_wrong_confirmation_rejected(self, vault):
        res = vault.post("/api/auth/factory-reset", json={"confirm": "erase everything"})
        assert res.status_code == 400
        assert CONFIRM_PHRASE in res.json()["detail"]
        # Nothing was wiped.
        assert state.keystore_path.exists()

    def test_empty_confirmation_rejected(self, vault):
        res = vault.post("/api/auth/factory-reset", json={"confirm": ""})
        assert res.status_code == 400

    def test_correct_confirmation_wipes(self, vault, tmp_path):
        _seed_extra_files(tmp_path)
        res = vault.post("/api/auth/factory-reset", json={"confirm": CONFIRM_PHRASE})
        assert res.status_code == 200, res.text
        data = res.json()
        assert data["status"] == "success"
        assert not state.keystore_path.exists()
        assert not state.db_path.exists()

    def test_works_while_locked(self, vault, tmp_path):
        """A forgotten passphrase is exactly the case for this route -- it must
        work with the vault locked."""
        _seed_extra_files(tmp_path)
        assert vault.post("/api/auth/lock").status_code == 200
        res = vault.post("/api/auth/factory-reset", json={"confirm": CONFIRM_PHRASE})
        assert res.status_code == 200, res.text
        assert not state.keystore_path.exists()
        status = vault.get("/api/auth/status").json()
        assert status["keystore_exists"] is False

    def test_whitespace_padded_confirmation_accepted(self, vault):
        res = vault.post("/api/auth/factory-reset", json={"confirm": f"  {CONFIRM_PHRASE}  "})
        assert res.status_code == 200, res.text


# ── UI (static surface, mirrors tests/test_recovery_ui.py) ────────────────────

class TestFactoryResetUI:
    @pytest.fixture(scope="class")
    def page_html(self):
        return TestClient(app).get("/").text

    def test_lock_screen_has_factory_reset_link(self, page_html):
        assert 'id="link-factory-reset"' in page_html
        assert "Forgot your passphrase?" in page_html

    def test_factory_reset_modal_exists(self, page_html):
        assert 'id="factory-reset-modal"' in page_html
        assert 'id="factory-reset-confirm-input"' in page_html
        assert 'id="btn-factory-reset-execute"' in page_html
        assert 'id="factory-reset-error"' in page_html

    def test_modal_requires_typed_phrase(self, page_html):
        assert CONFIRM_PHRASE in page_html
        # The execute button starts disabled -- typed confirmation is mandatory.
        assert 'id="btn-factory-reset-execute" type="button" disabled' in page_html

    def test_modal_warns_about_irreversibility(self, page_html):
        assert "permanently" in page_html.lower()
        assert "no undo" in page_html.lower()

    def test_app_js_wires_the_endpoint(self):
        js = (STATIC_DIR / "js" / "app.js").read_text(encoding="utf-8")
        assert "/api/auth/factory-reset" in js
        assert "link-factory-reset" in js
        assert "btn-factory-reset-execute" in js
        assert 'window.location.reload()' in js  # back to first-run screen
