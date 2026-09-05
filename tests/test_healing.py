"""
test_healing.py -- Unit and integration tests for background health checking and healing.
"""

import sys
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from PyQt6.QtWidgets import QApplication

from ghostdrive.database.db import GhostDriveDB
from ghostdrive.crypto.keystore import KeystoreManager
from ghostdrive.pipeline.healing import HealthDaemon, HealingQueue, verify_chunk_location
from ghostdrive.exceptions import AuthenticationError

@pytest.fixture(scope="session")
def qapp() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    return app

@pytest.fixture
def test_db(tmp_path) -> GhostDriveDB:
    db = GhostDriveDB(
        path=tmp_path / "test.db",
        ledger_key=bytes(range(32)),
        genesis_seed=bytes(range(32, 64)),
        master_key=b"\x00" * 32,
    )
    db.open()
    return db

@pytest.fixture
def keystore_mgr(tmp_path) -> KeystoreManager:
    km = KeystoreManager(tmp_path / "keystore.json")
    km._master_key_buf = type('Stub', (), {'key': b"\x00"*32, '_zeroed': False})()
    km._hkdf_salt = b"\x01"*32
    km._genesis_seed = b"\x02"*32
    return km


@pytest.mark.asyncio
async def test_verify_chunk_location_success(test_db, keystore_mgr) -> None:
    # 1. Setup mock backend with download returning correct ciphertext
    # (64KB block + 16-byte Poly1305 tag)
    mock_backend = MagicMock()
    mock_backend.type = "telegram"
    mock_backend.id = "tg-id"
    mock_backend.connect = AsyncMock()
    async def def_gen(ref_id):
        yield b"\x00" * 32
    mock_backend.download = MagicMock(side_effect=def_gen)

    active_backends = {"telegram": mock_backend}
    
    loc = {
        "chunk_id": "chunk-1",
        "sub_block_index": 0,
        "backend_id": "tg-id",
        "backend_type": "telegram",
        "reference_id": "ref-1",
        "nonce_counter": 1
    }

    # Populate DB with needed records so the database query returns successfully
    with test_db.transaction():
        test_db._conn.execute(
            "INSERT INTO backends (id, type, credentials_ref, status, priority) VALUES ('tg-id', 'telegram', 'ref', 'healthy', 1)"
        )
        test_db._conn.execute(
            """INSERT INTO files (id, name, path, size, mime_type, tier, created_at, modified_at, tombstone)
               VALUES ('file-1', 'doc.txt', '/files/doc.txt', 100, 'text/plain', 'IMPORTANT', '2026-06-12T00:00:00Z', '2026-06-12T00:00:00Z', 0)"""
        )
        test_db._conn.execute(
            "INSERT INTO chunks (id, file_id, chunk_index, total_chunks, blake3_hash, size, nonce_counter, sub_block_count, ref_count) VALUES ('chunk-1', 'file-1', 0, 1, 'hash', 32, 1, 1, 1)"
        )
        test_db._conn.execute(
            "INSERT INTO chunk_locations (chunk_id, sub_block_index, backend_id, reference_id, url_type, upload_date, status) VALUES ('chunk-1', 0, 'tg-id', 'ref-1', 'permanent', '2026-06-12', 'confirmed')"
        )

    # Patch ChunkDecryptor to return success
    with patch("ghostdrive.pipeline.healing.ChunkDecryptor") as mock_decrypt_cls:
        mock_decrypt = MagicMock()
        mock_decrypt.verify_and_decrypt_streaming.return_value = [b"plaintext"]
        mock_decrypt_cls.return_value = mock_decrypt

        res = await verify_chunk_location(test_db, loc, keystore_mgr, active_backends)
        assert res == "ok"


@pytest.mark.asyncio
async def test_verify_chunk_location_auth_failed(test_db, keystore_mgr) -> None:
    mock_backend = MagicMock()
    mock_backend.type = "telegram"
    mock_backend.id = "tg-id"
    mock_backend.connect = AsyncMock()
    async def def_gen(ref_id):
        yield b"\x00" * 32
    mock_backend.download = MagicMock(side_effect=def_gen)

    active_backends = {"telegram": mock_backend}
    
    loc = {
        "chunk_id": "chunk-1",
        "sub_block_index": 0,
        "backend_id": "tg-id",
        "backend_type": "telegram",
        "reference_id": "ref-1",
        "nonce_counter": 1
    }

    # Populate DB with needed records
    with test_db.transaction():
        test_db._conn.execute(
            "INSERT INTO backends (id, type, credentials_ref, status, priority) VALUES ('tg-id', 'telegram', 'ref', 'healthy', 1)"
        )
        test_db._conn.execute(
            """INSERT INTO files (id, name, path, size, mime_type, tier, created_at, modified_at, tombstone)
               VALUES ('file-1', 'doc.txt', '/files/doc.txt', 100, 'text/plain', 'IMPORTANT', '2026-06-12T00:00:00Z', '2026-06-12T00:00:00Z', 0)"""
        )
        test_db._conn.execute(
            "INSERT INTO chunks (id, file_id, chunk_index, total_chunks, blake3_hash, size, nonce_counter, sub_block_count, ref_count) VALUES ('chunk-1', 'file-1', 0, 1, 'hash', 32, 1, 1, 1)"
        )
        test_db._conn.execute(
            "INSERT INTO chunk_locations (chunk_id, sub_block_index, backend_id, reference_id, url_type, upload_date, status) VALUES ('chunk-1', 0, 'tg-id', 'ref-1', 'permanent', '2026-06-12', 'confirmed')"
        )

    # Patch ChunkDecryptor to raise AuthenticationError
    with patch("ghostdrive.pipeline.healing.ChunkDecryptor") as mock_decrypt_cls:
        mock_decrypt = MagicMock()
        mock_decrypt.verify_and_decrypt_streaming.side_effect = AuthenticationError("MAC verification failed")
        mock_decrypt_cls.return_value = mock_decrypt

        res = await verify_chunk_location(test_db, loc, keystore_mgr, active_backends)
        assert res == "auth_failed"


@pytest.mark.asyncio
async def test_health_daemon_cycle(qapp, test_db, keystore_mgr) -> None:
    # Set up backends in DB
    with test_db.transaction():
        test_db._conn.execute(
            """INSERT INTO backends (id, type, credentials_ref, status, priority, quota_used, quota_limit)
               VALUES ('tg-id', 'telegram', 'keyring', 'healthy', 100, 0, 1000)"""
        )
        test_db._conn.execute(
            """INSERT INTO files (id, name, path, size, mime_type, tier, created_at, modified_at, tombstone)
               VALUES ('file-1', 'doc.txt', '/files/doc.txt', 100, 'text/plain', 'IMPORTANT', '2026-06-12T00:00:00Z', '2026-06-12T00:00:00Z', 0)"""
        )
        test_db._conn.execute(
            """INSERT INTO chunks (id, file_id, chunk_index, total_chunks, blake3_hash, size, nonce_counter, sub_block_count, ref_count)
               VALUES ('chunk-1', 'file-1', 0, 1, 'hash', 100, 1, 1, 1)"""
        )
        test_db._conn.execute(
            """INSERT INTO chunk_locations (chunk_id, sub_block_index, backend_id, reference_id, url_type, upload_date, status)
               VALUES ('chunk-1', 0, 'tg-id', 'ref-1', 'permanent', '2026-06-12T00:00:00Z', 'confirmed')"""
        )

    mock_backend = AsyncMock()
    mock_backend.id = "tg-id"
    mock_backend.type = "telegram"
    mock_backend.health_check.return_value = MagicMock(reachable=True)
    
    mock_notifications = MagicMock()
    mock_main_view = MagicMock()

    daemon = HealthDaemon(
        db=test_db,
        active_backends={"telegram": mock_backend},
        km=keystore_mgr,
        notifications=mock_notifications,
        main_view=mock_main_view,
        loop_interval=1.0
    )

    with patch("ghostdrive.pipeline.healing.verify_chunk_location", AsyncMock(return_value="ok")):
        await daemon.perform_health_sweep()
        
        # Verify status is updated in DB
        with test_db.transaction():
            b_row = test_db._conn.execute("SELECT status, last_health_check FROM backends WHERE id = 'tg-id'").fetchone()
        assert b_row["status"] == "healthy"
        assert b_row["last_health_check"] is not None


@pytest.mark.asyncio
async def test_healing_queue_replicates_chunk(qapp, test_db, keystore_mgr) -> None:
    # 1. Set up two backends: one has chunk (source), one does not (target)
    # File tier is CRITICAL (needs 4 copies, but with 2 healthy backends it will try to replicate to both)
    with test_db.transaction():
        test_db._conn.execute(
            """INSERT INTO backends (id, type, credentials_ref, status, priority, quota_used, quota_limit)
               VALUES ('tg-id', 'telegram', 'ref1', 'healthy', 100, 0, 1000)"""
        )
        test_db._conn.execute(
            """INSERT INTO backends (id, type, credentials_ref, status, priority, quota_used, quota_limit)
               VALUES ('dc-id', 'discord', 'ref2', 'healthy', 50, 0, 1000)"""
        )
        test_db._conn.execute(
            """INSERT INTO files (id, name, path, size, mime_type, tier, created_at, modified_at, tombstone)
               VALUES ('file-1', 'secrets.txt', '/files/secrets.txt', 100, 'text/plain', 'CRITICAL', '2026-06-12T00:00:00Z', '2026-06-12T00:00:00Z', 0)"""
        )
        test_db._conn.execute(
            """INSERT INTO chunks (id, file_id, chunk_index, total_chunks, blake3_hash, size, nonce_counter, sub_block_count, ref_count)
               VALUES ('chunk-1', 'file-1', 0, 1, 'hash', 100, 1, 1, 1)"""
        )
        # Replicated to Telegram only
        test_db._conn.execute(
            """INSERT INTO chunk_locations (chunk_id, sub_block_index, backend_id, reference_id, url_type, upload_date, status)
               VALUES ('chunk-1', 0, 'tg-id', 'ref-tg', 'permanent', '2026-06-12T00:00:00Z', 'confirmed')"""
        )

    mock_tg = MagicMock()
    mock_tg.id = "tg-id"
    mock_tg.type = "telegram"
    mock_tg.connect = AsyncMock()
    async def def_gen(ref_id):
        yield b"\x00" * 32
    mock_tg.download = MagicMock(side_effect=def_gen)

    mock_dc = AsyncMock()
    mock_dc.id = "dc-id"
    mock_dc.type = "discord"
    mock_dc.upload.return_value = "ref-dc-healed"

    active_backends = {
        "telegram": mock_tg,
        "discord": mock_dc
    }

    mock_main_view = MagicMock()
    mock_main_view.active_uploads = 0

    queue = HealingQueue(
        db=test_db,
        active_backends=active_backends,
        km=keystore_mgr,
        main_view=mock_main_view
    )

    with patch("ghostdrive.pipeline.healing.ChunkDecryptor") as mock_decrypt_cls:
        mock_decrypt = MagicMock()
        mock_decrypt.verify_and_decrypt_streaming.return_value = [b"plain"]
        mock_decrypt_cls.return_value = mock_decrypt

        await queue.perform_healing_step()

        # Check target backend received upload
        mock_dc.upload.assert_called_once()
        
        # Verify that chunk location is now confirmed on discord
        with test_db.transaction():
            loc = test_db._conn.execute(
                "SELECT * FROM chunk_locations WHERE chunk_id = 'chunk-1' AND backend_id = 'dc-id'"
            ).fetchone()
        assert loc is not None
        assert loc["status"] == "confirmed"
        assert loc["reference_id"] == "ref-dc-healed"


@pytest.mark.asyncio
async def test_healing_queue_pauses_on_foreground_upload(qapp, test_db, keystore_mgr) -> None:
    mock_main_view = MagicMock()
    mock_main_view.active_uploads = 1 # Throttled!

    queue = HealingQueue(
        db=test_db,
        active_backends={},
        km=keystore_mgr,
        main_view=mock_main_view
    )

    with patch.object(queue, "perform_healing_step", AsyncMock()) as mock_heal_step:
        # Run one step of trickle loop
        queue.start()
        await asyncio.sleep(0.1)
        queue.stop()
        
        mock_heal_step.assert_not_called()


@pytest.mark.asyncio
async def test_healing_queue_replicates_all_sub_blocks(qapp, test_db, keystore_mgr) -> None:
    # 1. Set up two backends: one has chunk (source), one does not (target)
    with test_db.transaction():
        test_db._conn.execute(
            """INSERT INTO backends (id, type, credentials_ref, status, priority, quota_used, quota_limit)
               VALUES ('tg-id-multi', 'telegram', 'ref1', 'healthy', 100, 0, 1000)"""
        )
        test_db._conn.execute(
            """INSERT INTO backends (id, type, credentials_ref, status, priority, quota_used, quota_limit)
               VALUES ('dc-id-multi', 'discord', 'ref2', 'healthy', 50, 0, 1000)"""
        )
        test_db._conn.execute(
            """INSERT INTO files (id, name, path, size, mime_type, tier, created_at, modified_at, tombstone)
               VALUES ('file-multi', 'video.mp4', '/files/video.mp4', 100, 'video/mp4', 'CRITICAL', '2026-06-12T00:00:00Z', '2026-06-12T00:00:00Z', 0)"""
        )
        test_db._conn.execute(
            """INSERT INTO chunks (id, file_id, chunk_index, total_chunks, blake3_hash, size, nonce_counter, sub_block_count, ref_count)
               VALUES ('chunk-multi', 'file-multi', 0, 1, 'hash-multi', 100, 1, 2, 1)"""
        )
        # Replicated to Telegram with 2 sub-blocks
        test_db._conn.execute(
            """INSERT INTO chunk_locations (chunk_id, sub_block_index, backend_id, reference_id, url_type, upload_date, status)
               VALUES ('chunk-multi', 0, 'tg-id-multi', 'ref-tg-0', 'permanent', '2026-06-12T00:00:00Z', 'confirmed')"""
        )
        test_db._conn.execute(
            """INSERT INTO chunk_locations (chunk_id, sub_block_index, backend_id, reference_id, url_type, upload_date, status)
               VALUES ('chunk-multi', 1, 'tg-id-multi', 'ref-tg-1', 'permanent', '2026-06-12T00:00:00Z', 'confirmed')"""
        )

    mock_tg = MagicMock()
    mock_tg.id = "tg-id-multi"
    mock_tg.type = "telegram"
    mock_tg.connect = AsyncMock()
    
    async def download_gen(ref_id):
        if ref_id == "ref-tg-0":
            yield b"\x00" * 32
        elif ref_id == "ref-tg-1":
            yield b"\x11" * 32
            
    mock_tg.download = MagicMock(side_effect=download_gen)

    mock_dc = AsyncMock()
    mock_dc.id = "dc-id-multi"
    mock_dc.type = "discord"
    mock_dc.upload.side_effect = lambda stream, chunk_id, sub_block_index: f"ref-dc-healed-{sub_block_index}"

    active_backends = {
        "telegram": mock_tg,
        "discord": mock_dc
    }

    mock_main_view = MagicMock()
    mock_main_view.active_uploads = 0

    queue = HealingQueue(
        db=test_db,
        active_backends=active_backends,
        km=keystore_mgr,
        main_view=mock_main_view
    )

    with patch("ghostdrive.pipeline.healing.ChunkDecryptor") as mock_decrypt_cls:
        mock_decrypt = MagicMock()
        mock_decrypt.verify_and_decrypt_streaming.return_value = [b"plain"]
        mock_decrypt_cls.return_value = mock_decrypt

        await queue.perform_healing_step()

        # Check target backend received uploads for both sub-blocks
        assert mock_dc.upload.call_count == 2
        
        # Verify that both chunk locations are now confirmed on discord
        with test_db.transaction():
            locs = test_db._conn.execute(
                "SELECT * FROM chunk_locations WHERE chunk_id = 'chunk-multi' AND backend_id = 'dc-id-multi' ORDER BY sub_block_index ASC"
            ).fetchall()
            
        assert len(locs) == 2
        assert locs[0]["sub_block_index"] == 0
        assert locs[0]["status"] == "confirmed"
        assert locs[0]["reference_id"] == "ref-dc-healed-0"
        
        assert locs[1]["sub_block_index"] == 1
        assert locs[1]["status"] == "confirmed"
        assert locs[1]["reference_id"] == "ref-dc-healed-1"
