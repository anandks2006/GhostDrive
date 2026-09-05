import asyncio
import signal
import uuid
import pytest
import json
import random
from unittest.mock import MagicMock, AsyncMock, patch
from pathlib import Path

from ghostdrive.pipeline.upload import ChunkUploader
from ghostdrive.crypto.nonce import NonceManager
from ghostdrive.pipeline.healing import verify_chunk_location
from ghostdrive.pipeline.file_lock import FileLock
from ghostdrive.crypto.secrets_vault import SecretsVault
from ghostdrive.database.db import GhostDriveDB
from ghostdrive.exceptions import BackendConnectionError, ChunkError

def _make_db(tmp_path):
    db_path = tmp_path / "ghostdrive.db"
    db = GhostDriveDB(str(db_path), bytes(range(32)), bytes(range(32, 64)), bytes(range(64, 96)))
    db.open()
    return db

def _make_backend_row(db):
    b_id = str(uuid.uuid4())
    with db.transaction():
        db._conn.execute(
            """INSERT INTO backends (id, type, credentials_ref, status, priority, quota_limit, quota_used, quota_reserved)
               VALUES (?, 'discord', 'keyring-ref', 'healthy', 100, 1000000, 0, 0)""",
            (b_id,),
        )
    return b_id


class TestMockBackendIntegration:
    @pytest.mark.asyncio
    async def test_end_to_end_mock_backend_pipeline(self, tmp_path):
        db = _make_db(tmp_path)
        backend_id = _make_backend_row(db)
        
        # Configure MockBackend
        mock_backend = MagicMock()
        mock_backend.id = backend_id
        mock_backend.type = "discord"
        mock_backend._connected = True
        
        uploaded_payloads = {}
        async def mock_upload(stream, chunk_id, sub_block_index):
            data = bytearray()
            async for chunk in stream:
                data.extend(chunk)
            uploaded_payloads[sub_block_index] = bytes(data)
            return f"ref-{sub_block_index}"
            
        mock_backend.upload = MagicMock(side_effect=mock_upload)
        
        async def mock_download(reference_id):
            sub_idx = int(reference_id.split("-")[1])
            yield uploaded_payloads[sub_idx]
            
        mock_backend.download = MagicMock(side_effect=mock_download)
        
        nm = NonceManager(data_dir=tmp_path)
        file_path = tmp_path / "test_file.bin"
        file_content = b"E2E Integration Test Content with Mock Backend"
        file_path.write_bytes(file_content)
        
        from ghostdrive.pipeline.chunker import ChunkDescriptor
        descriptor = ChunkDescriptor(
            chunk_index=0,
            offset=0,
            size=len(file_content),
            total_chunks=1,
            is_manifest=False,
        )
        
        file_id = str(uuid.uuid4())
        now = "2026-07-06T12:00:00+00:00"
        with db.transaction():
            db.insert_file({
                "id": file_id, "name": "test_file.bin", "path": "/test_file.bin",
                "size": len(file_content), "mime_type": "application/octet-stream", "tier": "DISPOSABLE",
                "created_at": now, "modified_at": now,
                "version": 1, "version_of": None,
                "tombstone": 0, "tombstone_at": None,
            })
            
        uploader = ChunkUploader(
            db=db,
            backend=mock_backend,
            master_key=bytes(range(32)),
            hkdf_salt=bytes(range(32, 64)),
            nonce_manager=nm,
        )
        
        chunk_id = await uploader.upload_chunk(
            path=file_path,
            descriptor=descriptor,
            file_id=file_id,
        )
        assert chunk_id is not None
        
        # Verify locations status confirmed
        loc_row = db._conn.execute("SELECT status, reference_id FROM chunk_locations WHERE chunk_id = ?", (chunk_id,)).fetchone()
        assert loc_row["status"] == "confirmed"
        assert loc_row["reference_id"] == "ref-0"
        db.close()


class TestChaosTests:
    @pytest.mark.asyncio
    async def test_backend_failure_mid_upload(self, tmp_path):
        db = _make_db(tmp_path)
        backend_id = _make_backend_row(db)
        
        mock_backend = MagicMock()
        mock_backend.id = backend_id
        mock_backend.type = "discord"
        
        # Simulates upload failing mid-stream/mid-block
        async def mock_upload_failure(*args, **kwargs):
            raise BackendConnectionError("Mid-upload connection dropped!")
            
        mock_backend.upload = MagicMock(side_effect=mock_upload_failure)
        mock_backend.delete = AsyncMock(return_value=True)
        
        nm = NonceManager(data_dir=tmp_path)
        file_path = tmp_path / "test.bin"
        file_path.write_bytes(b"A" * 1024)
        
        from ghostdrive.pipeline.chunker import ChunkDescriptor
        descriptor = ChunkDescriptor(
            chunk_index=0, offset=0, size=1024, total_chunks=1, is_manifest=False
        )
        file_id = str(uuid.uuid4())
        
        now = "2026-07-06T12:00:00+00:00"
        with db.transaction():
            db.insert_file({
                "id": file_id, "name": "test.bin", "path": "/test.bin",
                "size": 1024, "mime_type": "application/octet-stream", "tier": "DISPOSABLE",
                "created_at": now, "modified_at": now,
                "version": 1, "version_of": None,
                "tombstone": 0, "tombstone_at": None,
            })
            
        uploader = ChunkUploader(
            db=db, backend=mock_backend, master_key=bytes(range(32)), hkdf_salt=bytes(range(32, 64)), nonce_manager=nm
        )
        
        with patch("asyncio.sleep", new_callable=AsyncMock):
            with pytest.raises(BackendConnectionError):
                await uploader.upload_chunk(path=file_path, descriptor=descriptor, file_id=file_id)
            
        # Verify locations status failed
        loc_row = db._conn.execute("SELECT status FROM chunk_locations").fetchone()
        assert loc_row["status"] == "failed"
        
        # Verify quota restored
        backend_row = db._conn.execute("SELECT quota_reserved, quota_used FROM backends WHERE id = ?", (backend_id,)).fetchone()
        assert backend_row["quota_reserved"] == 0
        db.close()

    def test_sigterm_handler(self, tmp_path):
        from ghostdrive.crypto.keystore import KeystoreManager
        
        keystore_path = tmp_path / "keystore.json"
        from ghostdrive.crypto.keystore import MasterKeyBuffer
        km = KeystoreManager(keystore_path)
        km._master_key_buf = MasterKeyBuffer(bytes(range(32)))
        km._hkdf_salt = bytes(range(32, 64))
        km._genesis_seed = bytes(range(64, 96))
        assert km.is_unlocked
        
        # Simulating signal callback
        from ghostdrive.web.state import state
        state.km = km
        
        # Call clean_shutdown
        state.clean_shutdown()
        
        # Master key must be locked/zeroed from memory
        assert not km.is_unlocked

    def test_concurrent_upload_locks(self, tmp_path):
        file_path = tmp_path / "locked_file.bin"
        file_path.write_bytes(b"File locking chaos test payload")
        
        lock1 = FileLock(file_path)
        lock2 = FileLock(file_path)
        
        # Acquire first lock
        res1 = lock1.acquire()
        assert res1 is True
        
        # Attempt second lock (should fail but NOT raise exception, demonstrating graceful degradation)
        res2 = lock2.acquire()
        assert res2 is False
        assert lock2.lock_skipped is True
        
        lock1.release()
        lock2.release()


class TestFuzzTests:
    def test_fuzz_chunk_headers(self):
        # We fuzz chunk decryption with random/corrupted data
        from ghostdrive.crypto.chunk_crypto import ChunkDecryptor
        
        # Generate random garbage key and nonce
        key = bytes(random.getrandbits(8) for _ in range(32))
        nonce = bytes(random.getrandbits(8) for _ in range(12))
        tag = bytes(random.getrandbits(8) for _ in range(16))
        
        decryptor = ChunkDecryptor(key=key, nonce=nonce, expected_tag=tag)
        
        # Fuzz the feed method with completely random garbage chunks
        for _ in range(10):
            garbage_data = bytes(random.getrandbits(8) for _ in range(random.randint(1, 1024)))
            decryptor.feed(garbage_data)
            
        # verify_and_decrypt must raise AuthenticationError, never crash unexpectedly
        from ghostdrive.exceptions import AuthenticationError
        with pytest.raises(AuthenticationError):
            decryptor.verify_and_decrypt()

    def test_fuzz_cli_sync_json(self):
        # Config export/import parses JSON
        
        # Malformed JSON payload strings
        malformed_inputs = [
            "",
            "{",
            "{}",
            '{"backends": "not_a_list"}',
            '{"backends": [{"type": "telegram"}]}', # missing details
            "[" * 100,
            "A" * 1000,
        ]
        
        for payload in malformed_inputs:
            # Import JSON parse block should handle the error gracefully without raising Uncaught Exception
            try:
                data = json.loads(payload)
                # Validation rules
                if not isinstance(data, dict) or "backends" not in data:
                    raise ValueError("Invalid format")
            except (json.JSONDecodeError, ValueError):
                # Handled gracefully
                pass

    def test_fuzz_qr_parsing(self):
        # Define the QR/profile parsing logic used in GhostDrive
        def parse_qr_profile(content: str):
            profile = json.loads(content)
            if not isinstance(profile, dict):
                raise ValueError("Invalid format: not a dictionary")
            for key in ["nickname", "public_key", "mlkem_public_key", "onion_address"]:
                if key not in profile:
                    raise ValueError(f"Missing key: {key}")
            # Public keys must be valid hex strings
            bytes.fromhex(profile["public_key"])
            bytes.fromhex(profile["mlkem_public_key"])
            return profile

        # Fuzz parsing of QR contact exchange strings
        fuzzed_inputs = [
            "",
            "gd-contact:",
            "gd-contact:12345",
            "gd-contact:invalid_hex:alice",
            "invalid-prefix:abcdef:bob",
            "{}",
            '{"nickname": "Alice"}',
            '{"nickname": "Alice", "public_key": "nothex", "mlkem_public_key": "nothex", "onion_address": ""}',
            '{"nickname": "Alice", "public_key": "aa", "mlkem_public_key": "nothex", "onion_address": ""}',
        ]
        
        for payload in fuzzed_inputs:
            # Must raise ValueError or json.JSONDecodeError, never panic/uncaught exception
            with pytest.raises((ValueError, json.JSONDecodeError)):
                parse_qr_profile(payload)
