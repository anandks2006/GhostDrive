"""
tests/test_migration_recovery.py -- Automated integration/unit tests for Cold-Start Disaster Recovery and Machine Migration.
"""

import os
import json
import pytest
from unittest.mock import patch

from ghostdrive.crypto.keystore import KeystoreManager
from ghostdrive.database.db import GhostDriveDB
from ghostdrive.crypto.credential_store import credential_store
from tests.conftest import FAST_ARGON2_PARAMS

from ghostdrive.crypto.hkdf import (
    derive_index_backup_enc_key,
    derive_backend_credentials_key,
    derive_index_mac_key
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


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


def test_recovery_wizard_flow(tmp_path) -> None:
    """Verify seed phrase recovery restores keystore and database ledger."""
    keystore_path = tmp_path / "keystore.json"
    db_path = tmp_path / "ghostdrive.db"
    if db_path.exists():
        try:
            db_path.unlink()
        except Exception:
            pass
            
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
    db.wal_checkpoint()
    db.close()
    
    # Simulate disaster by deleting local keystore file
    keystore_path.unlink()
    assert not keystore_path.exists()
    
    # Restore keystore from seed phrase
    km_restored = KeystoreManager(keystore_path)
    km_restored.recover_from_seed(phrase, b"new_password_123")
    
    assert keystore_path.exists()
    assert km_restored.is_unlocked
    
    # Open database with restored keys
    restored_master_key = km_restored.master_key
    restored_salt = km_restored.hkdf_salt
    restored_genesis_seed = km_restored.genesis_seed
    restored_ledger_key = derive_index_mac_key(restored_master_key, restored_salt)

    db_check = GhostDriveDB(db_path, restored_ledger_key, restored_genesis_seed, restored_master_key)
    db_check.open()
    files = db_check._conn.execute("SELECT * FROM files").fetchall()
    secrets = db_check._conn.execute("SELECT * FROM secrets_vault").fetchall()
    assert len(files) == 1
    assert files[0]["name"] == "recovered.txt"
    assert len(secrets) == 1
    db_check.close()
