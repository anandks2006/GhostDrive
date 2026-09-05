"""
tests/test_secrets_vault.py -- Unit tests for SecretsVault and DriveRegistrar.
"""

from __future__ import annotations

import os
import uuid
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from ghostdrive.database.db import GhostDriveDB
from ghostdrive.crypto.secrets_vault import SecretsVault, generate_totp
from ghostdrive.pipeline.drive_registration import DriveRegistrar
import ghostdrive.pipeline.drive_registration as dr
from ghostdrive.platform.drive_monitor import DriveIdentity
from ghostdrive.exceptions import (
    CryptoError,
    SecureEraseBlockedError,
    DriveIdentityError,
)

# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_db(tmp_path: Path) -> GhostDriveDB:
    """Create and open a fresh test database."""
    ledger_key   = bytes(range(32))          # 32 deterministic bytes
    genesis_seed = bytes(range(32, 64))      # 32 different deterministic bytes
    master_key   = b"\x00" * 32              # strict master_key
    db = GhostDriveDB(
        path=tmp_path / "test_vault.db",
        ledger_key=ledger_key,
        genesis_seed=genesis_seed,
        master_key=master_key,
    )
    db.open()
    return db

def _uuid() -> str:
    return str(uuid.uuid4())

# ── SecretsVault Tests ────────────────────────────────────────────────────────

def test_secrets_vault_init():
    """Test that SecretsVault requires 32-byte keys and salts."""
    db = MagicMock(spec=GhostDriveDB)
    
    # Valid
    master_key = os.urandom(32)
    salt = os.urandom(32)
    vault = SecretsVault(db, master_key, salt)
    assert vault._key is not None

    # Invalid master key
    with pytest.raises(CryptoError, match="Master key must be exactly 32 bytes"):
        SecretsVault(db, os.urandom(31), salt)

    # Invalid salt
    with pytest.raises(CryptoError, match="Keystore salt must be exactly 32 bytes"):
        SecretsVault(db, master_key, os.urandom(33))


def test_secrets_vault_encryption_decryption(tmp_path):
    """Test that SecretsVault correctly encrypts and decrypts JSON payloads."""
    db = _make_db(tmp_path)
    master_key = os.urandom(32)
    salt = os.urandom(32)
    vault = SecretsVault(db, master_key, salt)

    payload = {"username": "test_user", "password": "secure_password"}
    encrypted = vault._encrypt(payload)
    assert isinstance(encrypted, bytes)
    assert len(encrypted) > 12 + 16  # Nonce (12) + Tag (16) + Ciphertext

    decrypted = vault._decrypt(encrypted)
    assert decrypted == payload


def test_secrets_vault_lock_zeroes_key(tmp_path):
    """Test that locking the vault zeroes out the key in memory and blocks operations."""
    db = _make_db(tmp_path)
    master_key = os.urandom(32)
    salt = os.urandom(32)
    vault = SecretsVault(db, master_key, salt)

    assert vault._key is not None
    vault.lock()
    assert vault._key is None

    # Operations should fail once locked
    with pytest.raises(CryptoError, match="locked"):
        vault.add_secret("Label", "password", {"val": "123"})

    with pytest.raises(CryptoError, match="locked"):
        vault.get_secret("some-id")

    with pytest.raises(CryptoError, match="locked"):
        vault.update_secret("some-id", "New Label", {"val": "123"})

    with pytest.raises(CryptoError, match="locked"):
        vault.delete_secret("some-id")

    with pytest.raises(CryptoError, match="locked"):
        vault.list_secrets()


def test_secrets_vault_crud(tmp_path):
    """Test full CRUD lifecycle in the secrets vault."""
    db = _make_db(tmp_path)
    master_key = os.urandom(32)
    salt = os.urandom(32)
    vault = SecretsVault(db, master_key, salt)

    # 1. Add secret
    payload = {"url": "https://example.com", "api_key": "abc-123-key"}
    secret_id = vault.add_secret("My API Key", "api_key", payload)
    assert isinstance(secret_id, str)
    assert len(secret_id) > 0

    # 2. Get secret
    record = vault.get_secret(secret_id)
    assert record is not None
    assert record["id"] == secret_id
    assert record["label"] == "My API Key"
    assert record["kind"] == "api_key"
    assert record["payload"] == payload
    assert "created_at" in record
    assert "modified_at" in record
    assert "logical_clock" in record

    # Get non-existent secret
    assert vault.get_secret("non-existent-uuid") is None

    # 3. Update secret
    updated_payload = {"url": "https://example.com", "api_key": "updated-key-456"}
    vault.update_secret(secret_id, "Updated API Key", updated_payload)

    record_updated = vault.get_secret(secret_id)
    assert record_updated["label"] == "Updated API Key"
    assert record_updated["payload"] == updated_payload
    assert record_updated["logical_clock"] > record["logical_clock"]

    # 4. List secrets
    # Add another secret of a different kind
    vault.add_secret("My Note", "note", {"content": "Hello World"})

    all_secrets = vault.list_secrets()
    assert len(all_secrets) == 2
    # Ordered by label: "My Note", "Updated API Key"
    assert all_secrets[0]["label"] == "My Note"
    assert all_secrets[1]["label"] == "Updated API Key"

    # Filtered listing
    notes = vault.list_secrets("note")
    assert len(notes) == 1
    assert notes[0]["label"] == "My Note"

    # 5. Delete secret
    vault.delete_secret(secret_id)
    assert vault.get_secret(secret_id) is None
    assert len(vault.list_secrets()) == 1


def test_secrets_vault_totp_generation():
    """Test standard RFC 6238 TOTP generation."""
    # Test vector with standard base32 seed: JBSWY3DPEHPK3PXP (which is 'Hello!\xde\xad\xbe\xef')
    seed = "JBSWY3DPEHPK3PXP"
    code = generate_totp(seed)
    assert isinstance(code, str)
    assert len(code) == 6
    assert code.isdigit()

    # Empty/invalid seed should degrade gracefully
    bad_code = generate_totp("invalid seed!")
    assert bad_code == "------"


def test_secrets_vault_totp_integration(tmp_path):
    """Test that getting/listing password records automatically appends a live TOTP code if totp_seed is present."""
    db = _make_db(tmp_path)
    master_key = os.urandom(32)
    salt = os.urandom(32)
    vault = SecretsVault(db, master_key, salt)

    payload = {
        "username": "alice",
        "password": "supersecretpassword",
        "totp_seed": "JBSWY3DPEHPK3PXP",
    }
    
    # Must be 'password' kind to generate TOTP code
    secret_id = vault.add_secret("Login", "password", payload)

    # get_secret
    record = vault.get_secret(secret_id)
    assert "totp_code" in record["payload"]
    assert len(record["payload"]["totp_code"]) == 6
    assert record["payload"]["totp_code"].isdigit()

    # list_secrets
    secrets = vault.list_secrets()
    assert len(secrets) == 1
    assert "totp_code" in secrets[0]["payload"]
    assert len(secrets[0]["payload"]["totp_code"]) == 6


# ── DriveRegistrar Tests ──────────────────────────────────────────────────────

def test_drive_registrar_list_connected_drives(tmp_path):
    """Test that list_connected_drives accesses the platform layer."""
    db = _make_db(tmp_path)
    registrar = DriveRegistrar(db)

    mock_drive = DriveIdentity.from_uuid(
        uuid="drive-uuid-1",
        label="ExternalDrive",
        mountpoint="/mnt/drive1",
        capacity_bytes=500 * 1024 * 1024 * 1024,
        drive_type="hdd",
        filesystem="ext4",
    )

    mock_monitor = MagicMock()
    mock_monitor.list_drives.return_value = [mock_drive]

    with patch("ghostdrive.pipeline.drive_registration.get_drive_monitor", return_value=mock_monitor):
        drives = registrar.list_connected_drives()
        assert len(drives) == 1
        assert drives[0].drive_uuid == "drive-uuid-1"
        assert drives[0].label == "ExternalDrive"


@patch("ghostdrive.pipeline.drive_registration._KEYRING_AVAILABLE", True)
def test_drive_registrar_register_external_drive(tmp_path):
    """Test registering an external drive backend and saving path to keyring."""
    db = _make_db(tmp_path)
    registrar = DriveRegistrar(db)

    drive = DriveIdentity.from_uuid(
        uuid="drive-uuid-999",
        label="Backup Drive",
        mountpoint=str(tmp_path / "mock_mount"),
        capacity_bytes=1000 * 1000 * 1000,
        drive_type="ssd",
        filesystem="ntfs",
    )

    with patch(
        "ghostdrive.crypto.credential_store.credential_store.store"
    ) as mock_store:
        res = registrar.register_external_drive(drive, "My SSD")
        assert "backend_id" in res
        assert res["drive_label"] == "My SSD"
        assert res["drive_uuid"] == "drive-uuid-999"

        # Verify credential_store.store() was called with the right key and plaintext path
        backend_id = res["backend_id"]
        mock_store.assert_called_once_with(
            f"local_root_{backend_id}",
            str(Path(drive.mountpoint) / "GhostDriveData"),
        )

        # Check DB entries
        backend_row = db._conn.execute("SELECT * FROM backends WHERE id = ?", (backend_id,)).fetchone()
        assert backend_row is not None
        assert backend_row["type"] == "local"
        assert backend_row["quota_limit"] == drive.capacity_bytes

        registry_row = db.get_drive_registry_by_backend(backend_id)
        assert registry_row is not None
        assert registry_row["drive_uuid"] == "drive-uuid-999"
        assert registry_row["drive_label"] == "My SSD"
        assert registry_row["drive_type"] == "ssd"



def test_drive_registrar_register_without_uuid():
    """Test that registering a drive without a filesystem UUID raises an error."""
    db = MagicMock(spec=GhostDriveDB)
    registrar = DriveRegistrar(db)

    drive = DriveIdentity.from_uuid(
        uuid=None,
        label="No UUID",
        mountpoint="/mnt/no_uuid",
        capacity_bytes=500_000,
        drive_type="hdd",
        filesystem="vfat",
    )

    with pytest.raises(DriveIdentityError, match="Cannot register a drive without a unique filesystem UUID"):
        registrar.register_external_drive(drive, "Bad Drive")


@patch("ghostdrive.pipeline.drive_registration._KEYRING_AVAILABLE", True)
def test_drive_registrar_deregister_s9_redundancy_guardrail(tmp_path):
    """Test that deregistering checks for chunk redundancy under S9 guardrail."""
    db = _make_db(tmp_path)
    registrar = DriveRegistrar(db)

    # Register two backends
    drive1 = DriveIdentity.from_uuid("uuid-1", "D1", str(tmp_path / "d1"), 10**9, "ssd", "ntfs")
    drive2 = DriveIdentity.from_uuid("uuid-2", "D2", str(tmp_path / "d2"), 10**9, "ssd", "ntfs")

    with patch("keyring.set_password"):
        b1 = registrar.register_external_drive(drive1, "D1")["backend_id"]
        b2 = registrar.register_external_drive(drive2, "D2")["backend_id"]

    # Insert a file with IMPORTANT tier (requires redundancy level 3, meaning 2 other copies)
    file_id = _uuid()
    now = datetime_now_iso_helper()
    with db.transaction():
        db.insert_file({
            "id": file_id, "name": "doc.txt", "path": "/doc.txt",
            "size": 100, "mime_type": "text/plain", "tier": "IMPORTANT",
            "created_at": now, "modified_at": now, "version": 1, "version_of": None,
            "tombstone": 0, "tombstone_at": None,
        })

    # Insert a chunk for this file
    chunk_id = _uuid()
    with db.transaction():
        db.insert_chunk({
            "id": chunk_id, "file_id": file_id, "chunk_index": 0,
            "total_chunks": 1, "blake3_hash": "h1", "size": 100,
            "nonce_counter": 1, "sub_block_count": 1, "is_manifest": 0, "ref_count": 1,
        })

    # Scenario A: Chunk exists on both backends
    # Backends: b1 (confirmed), b2 (confirmed)
    # Required redundancy for IMPORTANT: redundancy_level = 3 -> required other copies = 2
    # Since other copies count is 1 (which is < 2), trying to remove b1 is under-redundant!
    with db.transaction():
        db.insert_chunk_location_pending({
            "chunk_id": chunk_id, "sub_block_index": 0, "backend_id": b1,
            "reference_id": "loc1", "url_type": "permanent", "upload_date": now,
            "last_verified": now, "quota_reserved": 0,
        })
        db.confirm_chunk_location(chunk_id, 0, b1, "loc1")

        db.insert_chunk_location_pending({
            "chunk_id": chunk_id, "sub_block_index": 0, "backend_id": b2,
            "reference_id": "loc2", "url_type": "permanent", "upload_date": now,
            "last_verified": now, "quota_reserved": 0,
        })
        db.confirm_chunk_location(chunk_id, 0, b2, "loc2")

    # Try to deregister b1 (should fail due to S9 guardrail because it's under-redundant)
    with patch("keyring.delete_password") as mock_del_pwd:
        with pytest.raises(SecureEraseBlockedError, match="Cannot remove backend"):
            registrar.deregister_backend(b1, force=False)

        # But with force=True, it should succeed!
        registrar.deregister_backend(b1, force=True)
        mock_del_pwd.assert_called_once_with("ghostdrive", f"local_root_{b1}")

    # Check database: b1 and its registry are removed
    backend_row = db._conn.execute("SELECT * FROM backends WHERE id = ?", (b1,)).fetchone()
    assert backend_row is None
    
    registry_row = db.get_drive_registry_by_backend(b1)
    assert registry_row is None

    # Locations on b1 should also be gone
    loc_row = db.find_chunk_location(chunk_id, 0, b1)
    assert loc_row is None


def test_drive_registrar_suggest_nas_backends():
    """Test passive NAS discovery via zeroconf mock."""
    # Ensure _ZEROCONF_AVAILABLE is True and mock classes exist on the module
    dr._ZEROCONF_AVAILABLE = True
    
    mock_zc = MagicMock()
    mock_browser = MagicMock()
    
    # Assign mocks directly to the module
    dr.Zeroconf = MagicMock(return_value=mock_zc)
    dr.ServiceBrowser = MagicMock(return_value=mock_browser)
    
    with patch("time.sleep"):  # Skip the 2-second sleep delay during test
        db = MagicMock(spec=GhostDriveDB)
        registrar = DriveRegistrar(db)
        registrar.suggest_nas_backends()
        
        # Verify Zeroconf was initialized and closed
        dr.Zeroconf.assert_called_once()
        mock_zc.close.assert_called_once()


def datetime_now_iso_helper() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
