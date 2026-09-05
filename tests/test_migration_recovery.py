"""
tests/test_migration_recovery.py -- Automated integration/unit tests for Cold-Start Disaster Recovery and Machine Migration.
"""

import os
import json
import pytest
from unittest.mock import patch

from PyQt6.QtWidgets import QApplication

from ghostdrive.crypto.keystore import KeystoreManager
from ghostdrive.database.db import GhostDriveDB
from ghostdrive.gui.unlock_view import UnlockView
from ghostdrive.crypto.credential_store import credential_store
from tests.conftest import FAST_ARGON2_PARAMS

from ghostdrive.crypto.hkdf import (
    derive_index_backup_enc_key,
    derive_backend_credentials_key,
    derive_index_mac_key
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@pytest.fixture(scope="session")
def qapp() -> QApplication:
    import asyncio
    import qasync
    import sys
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = None
    if not isinstance(loop, qasync.QEventLoop):
        loop = qasync.QEventLoop(app)
        asyncio.set_event_loop(loop)
    return app


def test_deterministic_key_derivation(tmp_path) -> None:
    """Verify that recover_from_seed derives salt and genesis seed deterministically from Master Key."""
    keystore_path = tmp_path / "keystore.json"
    km = KeystoreManager(keystore_path)
    
    # 1. Create a fresh keystore and generate seed phrase
    phrase = km.create_new(b"secure_pass", calibrate=False, argon2_params=FAST_ARGON2_PARAMS)
    km.verify_and_save(phrase)
    
    master_key_orig = km.master_key
    salt_orig = km.hkdf_salt
    genesis_orig = km.genesis_seed
    
    # 2. Simulate a new machine by removing keystore file and recovering from seed phrase
    keystore_path.unlink()
    
    km_new = KeystoreManager(keystore_path)
    km_new.recover_from_seed(phrase, b"new_secure_pass")
    
    assert km_new.master_key == master_key_orig
    assert km_new.hkdf_salt == salt_orig
    assert km_new.genesis_seed == genesis_orig


def test_credentials_bundle_encryption_decryption() -> None:
    """Verify that credentials bundle can be packed, encrypted, decrypted, and recovered successfully."""
    master_key = os.urandom(32)
    salt = os.urandom(32)
    
    creds_enc_key = derive_backend_credentials_key(master_key, salt)
    
    # Pack credentials
    original_creds = {
        "telegram_api_id": "123456",
        "telegram_api_hash": "abcdef123456",
        "telegram_phone": "+1234567890",
        "discord_bot_token": "token_xyz",
        "keyring:encrypted:nas_creds": "nas_password"
    }
    
    # Encrypt
    creds_json = json.dumps(original_creds).encode("utf-8")
    aesgcm = AESGCM(creds_enc_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, creds_json, None)
    
    payload = nonce + ciphertext
    
    # Decrypt
    nonce_dec = payload[:12]
    ciphertext_dec = payload[12:]
    decrypted_bytes = aesgcm.decrypt(nonce_dec, ciphertext_dec, None)
    decrypted_creds = json.loads(decrypted_bytes.decode("utf-8"))
    
    assert decrypted_creds == original_creds


def test_database_backup_and_recovery(tmp_path) -> None:
    """Verify that a database can be WAL-checkpointed, encrypted, decrypted, and restored without data loss."""
    db_file = tmp_path / "ghostdrive.db"
    
    master_key = os.urandom(32)
    salt = os.urandom(32)
    ledger_key = derive_index_mac_key(master_key, salt)
    genesis_seed = os.urandom(32)
    
    # 1. Create a database and write some records
    db = GhostDriveDB(
        db_file,
        bytes(bytearray(ledger_key)),
        bytes(bytearray(genesis_seed)),
        bytes(bytearray(master_key))
    )
    db.open()
    
    with db.transaction():
        # Insert a file record
        file_rec = {
            "id": "file-uuid-12345",
            "name": "document.txt",
            "path": "/files/document.txt",
            "size": 1024,
            "mime_type": "text/plain",
            "tier": "IMPORTANT",
            "created_at": "2026-06-24T12:00:00Z",
            "modified_at": "2026-06-24T12:00:00Z",
            "version": 1,
            "version_of": None,
            "tombstone": 0,
            "tombstone_at": None
        }
        db.insert_file(file_rec)
        
    db.wal_checkpoint()
    
    # Read database bytes
    with open(db_file, "rb") as f:
        db_bytes = f.read()
    db.close()
    
    # 2. Encrypt the database bytes
    db_enc_key = derive_index_backup_enc_key(master_key, salt)
    aesgcm = AESGCM(db_enc_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, db_bytes, None)
    payload = nonce + ciphertext
    
    # Delete local database files
    db_file.unlink()
    
    # 3. Decrypt and restore database bytes
    nonce_dec = payload[:12]
    ciphertext_dec = payload[12:]
    decrypted_db_bytes = aesgcm.decrypt(nonce_dec, ciphertext_dec, None)
    
    with open(db_file, "wb") as f:
        f.write(decrypted_db_bytes)
        
    # 4. Open the restored database and verify data
    db_restored = GhostDriveDB(db_file, ledger_key, genesis_seed, master_key)
    db_restored.open()
    
    files = db_restored._conn.execute("SELECT * FROM files").fetchall()
    assert len(files) == 1
    assert files[0]["name"] == "document.txt"
    assert files[0]["size"] == 1024
    
    db_restored.close()


@pytest.mark.asyncio
async def test_recovery_wizard_flow(qapp, tmp_path) -> None:
    """Verify that the full recovery wizard UI transitions and restores database and keyring credentials."""
    keystore_path = tmp_path / "keystore.json"
    db_path = tmp_path / "ghostdrive.db"
    if db_path.exists():
        try:
            db_path.unlink()
        except Exception:
            pass
            
    # Clean credential store
    for k in ["telegram_phone", "telegram_api_id", "telegram_api_hash", "telegram_session", "keyring:encrypted:nas_creds"]:
        credential_store.delete(k)
    
    km_orig = KeystoreManager(keystore_path)
    phrase = km_orig.create_new(b"correct_password", calibrate=False, argon2_params=FAST_ARGON2_PARAMS)
    km_orig.verify_and_save(phrase)
    
    master_key = km_orig.master_key
    salt = km_orig.hkdf_salt
    genesis_seed = km_orig.genesis_seed
    
    # Create a database with 1 file and 1 secret
    ledger_key = derive_index_mac_key(master_key, salt)
    db = GhostDriveDB(
        db_path,
        bytes(bytearray(ledger_key)),
        bytes(bytearray(genesis_seed)),
        bytes(bytearray(master_key))
    )
    db.open()
    with db.transaction():
        db.insert_file({
            "id": "file-1", "name": "recovered.txt", "path": "/files/recovered.txt",
            "size": 100, "mime_type": "text/plain", "tier": "IMPORTANT",
            "created_at": "2026-06-24T12:00:00Z", "modified_at": "2026-06-24T12:00:00Z",
            "version": 1, "version_of": None, "tombstone": 0, "tombstone_at": None
        })
        db.insert_secret({
            "id": "secret-1", "label": "API Key", "kind": "password",
            "encrypted_blob": b"blob", "created_at": "2026-06-24T12:00:00Z",
            "modified_at": "2026-06-24T12:00:00Z"
        })
        # Insert a local backend row to test warnings
        db._conn.execute(
            """INSERT INTO backends
               (id, type, credentials_ref, status, priority, quota_used, quota_limit, quota_reserved)
               VALUES ('local-b1', 'local_fs', 'ref', 'healthy', 100, 0, 10000, 0)"""
        )
    db.wal_checkpoint()
    
    # Read DB bytes
    with open(db_path, "rb") as f:
        db_bytes = f.read()
    db.close()
    
    # Encrypt database bytes
    index_enc_key = derive_index_backup_enc_key(master_key, salt)
    aesgcm_db = AESGCM(index_enc_key)
    nonce_db = os.urandom(12)
    payload_db = nonce_db + aesgcm_db.encrypt(nonce_db, db_bytes, None)
    
    # Encrypt credentials bundle
    creds_enc_key = derive_backend_credentials_key(master_key, salt)
    creds_dict = {"telegram_phone": "+1234567890", "telegram_api_id": "987654"}
    creds_json = json.dumps(creds_dict).encode("utf-8")
    aesgcm_creds = AESGCM(creds_enc_key)
    nonce_creds = os.urandom(12)
    payload_creds = nonce_creds + aesgcm_creds.encrypt(nonce_creds, creds_json, None)
    
    # Delete local keystore, database, and credential store to simulate crash
    keystore_path.unlink()
    db_path.unlink()
    for k in ["telegram_phone", "telegram_api_id", "telegram_api_hash", "telegram_session", "keyring:encrypted:nas_creds"]:
        credential_store.delete(k)
    
    # 2. Launch the recovery wizard
    view = UnlockView(keystore_path=keystore_path)
    assert view.stack.currentWidget() == view.first_run_chooser_widget
    
    # Navigate to recover screen
    view.stack.setCurrentWidget(view.recover_widget)
    
    # Fill in seed and new passphrase
    view.recover_seed_input.setText(phrase)
    view.recover_pass_input.setText("new_password_123")
    
    # Run recovery step 1 (reconstructs keystore and goes to bootstrap view)
    view.on_recover_clicked()
    
    assert keystore_path.exists()
    assert view.stack.currentWidget() == view.recover_bootstrap_widget
    
    # 3. Fill in SFTP NAS bootstrap credentials
    view.rec_backend_combo.setCurrentText("SFTP NAS")
    view.rec_nas_host.setText("192.168.1.50")
    view.rec_nas_username.setText("admin")
    view.rec_nas_password.setText("pass")
    view.rec_nas_dir.setText("GhostDriveData")
    
    # Mock the download method of NASBackend to yield our encrypted payloads
    async def mock_download(self, ref_id):
        if "_9999.gdc" in ref_id:
            # Yield database snapshot in chunks
            yield payload_db[:10]
            yield payload_db[10:]
        elif "_9998.gdc" in ref_id:
            # Yield credentials bundle in chunks
            yield payload_creds[:10]
            yield payload_creds[10:]
            
    # Patch connect and download of NASBackend, and mock paramiko availability
    with patch("ghostdrive.backends.nas_backend._PARAMIKO_AVAILABLE", True), \
         patch("ghostdrive.backends.nas_backend.NASBackend.connect", return_value=None), \
         patch("ghostdrive.backends.nas_backend.NASBackend.download", mock_download):
         
        # Click connect and restore
        await view.on_rec_connect_clicked()
        
    # 4. Verify recovery results
    assert view.stack.currentWidget() == view.recover_complete_widget
    assert db_path.exists()
    
    # Check that database is decrypted and readable
    db_check = GhostDriveDB(db_path, ledger_key, genesis_seed, master_key)
    db_check.open()
    files = db_check._conn.execute("SELECT * FROM files").fetchall()
    secrets = db_check._conn.execute("SELECT * FROM secrets_vault").fetchall()
    assert len(files) == 1
    assert files[0]["name"] == "recovered.txt"
    assert len(secrets) == 1
    db_check.close()
    
    # Check keyring credentials
    credential_store.set_active_key(master_key, salt)
    assert credential_store.load("telegram_phone") == "+1234567890"
    assert credential_store.load("telegram_api_id") == "987654"
    assert credential_store.load("keyring:encrypted:nas_creds") == "pass"
    
    # Check warning visible for the local backend
    assert view.rec_local_warning_label.isHidden() is False
    assert "local_fs" in view.rec_local_warning_label.text()
    
    # Check metrics text matches
    metrics_text = view.rec_metrics_label.text()
    assert "Restored Files: 1" in metrics_text
    assert "Secrets Vault Entries: 1" in metrics_text
