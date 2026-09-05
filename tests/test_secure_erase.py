"""
tests/test_secure_erase.py -- Unit tests for secure erase and DestructiveOperationGuard.
"""

from __future__ import annotations

import os
import pytest
import blake3
from pathlib import Path

from ghostdrive.platform.secure_erase import overwrite_file, SecureEraseLevel
from ghostdrive.pipeline.secure_erase import (
    DestructiveOperationGuard,
    SecureEraseOperation,
    HARD_BLOCKED_PATHS,
)
from ghostdrive.exceptions import (
    SecureEraseBlockedError,
)
from ghostdrive.database.db import GhostDriveDB


# --- DB Helpers (similar to test_database.py) ---
def _make_db(tmp_path: Path) -> GhostDriveDB:
    ledger_key = bytes(range(32))
    genesis_seed = bytes(range(32, 64))
    master_key = b"\x00" * 32
    db = GhostDriveDB(
        path=tmp_path / "test_erase.db",
        ledger_key=ledger_key,
        genesis_seed=genesis_seed,
        master_key=master_key,
    )
    db.open()
    return db


def _make_backend(db: GhostDriveDB, backend_id: str) -> None:
    db._conn.execute("BEGIN")
    db._conn.execute(
        """INSERT INTO backends
           (id, type, credentials_ref, status, priority,
            quota_used, quota_limit, quota_reserved)
           VALUES (?, 'local', 'ref:test', 'healthy', 1, 0, 1073741824, 0)""",
        (backend_id,),
    )
    db._conn.execute("COMMIT")


# --- Overwrite Unit Tests ---

@pytest.mark.asyncio
async def test_overwrite_file_pass_1(tmp_path):
    test_file = tmp_path / "test_p1.txt"
    test_file.write_bytes(b"A" * 100)
    assert test_file.exists()

    await overwrite_file(test_file, SecureEraseLevel.PASS_1)
    assert not test_file.exists()


@pytest.mark.asyncio
async def test_overwrite_file_pass_3(tmp_path):
    test_file = tmp_path / "test_p3.txt"
    test_file.write_bytes(b"B" * 250)
    assert test_file.exists()

    await overwrite_file(test_file, SecureEraseLevel.PASS_3)
    assert not test_file.exists()


# --- Guardrail Pipeline Tests ---

@pytest.mark.asyncio
async def test_guard_origin_gate(tmp_path):
    db = _make_db(tmp_path)
    guard = DestructiveOperationGuard()
    
    test_file = tmp_path / "target.txt"
    test_file.touch()

    # Calculation of valid dry run hash
    dry_run_details = f"L1-FILE:{test_file.resolve()}:{test_file.stat().st_size}"
    dry_run_hash = blake3.blake3(dry_run_details.encode()).hexdigest()

    op = SecureEraseOperation(
        id="op-1",
        op_level="L1",
        op_type="file_erase",
        target_path=test_file,
        target_label="Target File",
        method="software_overwrite",
        initiated_by="system",  # BLOCKED! Must be 'user'
        dry_run_hash=dry_run_hash,
        session_id="session-1",
    )

    with pytest.raises(SecureEraseBlockedError, match="user"):
        await guard.execute_erase(op, db, vault_dir=tmp_path)
    db.close()


@pytest.mark.asyncio
async def test_guard_classification_block_symlink(tmp_path):
    db = _make_db(tmp_path)
    guard = DestructiveOperationGuard()
    
    target_file = tmp_path / "target.txt"
    target_file.touch()
    
    # Create a symlink (might require admin on Windows, so we wrap in try-except)
    link_file = tmp_path / "link.txt"
    try:
        os.symlink(target_file, link_file)
    except OSError:
        # Skip if symlink creation is not permitted on this Windows user account
        db.close()
        pytest.skip("Symlink creation not supported/permitted")

    dry_run_details = f"L1-FILE:{link_file.resolve()}:0"
    dry_run_hash = blake3.blake3(dry_run_details.encode()).hexdigest()

    op = SecureEraseOperation(
        id="op-2",
        op_level="L1",
        op_type="file_erase",
        target_path=link_file,
        target_label="Link File",
        method="software_overwrite",
        initiated_by="user",
        dry_run_hash=dry_run_hash,
        session_id="session-1",
    )

    with pytest.raises(SecureEraseBlockedError, match="symlink"):
        await guard.execute_erase(op, db, vault_dir=tmp_path)
    db.close()


@pytest.mark.asyncio
async def test_guard_boundary_validation(tmp_path):
    db = _make_db(tmp_path)
    guard = DestructiveOperationGuard()
    
    # Target outside vault
    outside_file = tmp_path / "outside.txt"
    outside_file.touch()
    
    vault_dir = tmp_path / "vault"
    vault_dir.mkdir()

    dry_run_details = f"L1-FILE:{outside_file.resolve()}:{outside_file.stat().st_size}"
    dry_run_hash = blake3.blake3(dry_run_details.encode()).hexdigest()

    op = SecureEraseOperation(
        id="op-3",
        op_level="L1",
        op_type="file_erase",
        target_path=outside_file,
        target_label="Outside File",
        method="software_overwrite",
        initiated_by="user",
        dry_run_hash=dry_run_hash,
        session_id="session-1",
    )

    # Should raise boundary error because it's not in vault and not allowed via picker
    with pytest.raises(SecureEraseBlockedError, match="outside the GhostDrive vault"):
        await guard.execute_erase(op, db, vault_dir=vault_dir)

    # Now allow the path explicitly
    guard.allow_path(outside_file)
    # Re-run: should pass boundary check (it might raise other errors later but not boundary)
    # Since it's outside db, no redundancy check triggers. It should execute successfully!
    await guard.execute_erase(op, db, vault_dir=vault_dir)
    assert not outside_file.exists()
    db.close()


@pytest.mark.asyncio
async def test_guard_hard_blocked_paths(tmp_path):
    db = _make_db(tmp_path)
    guard = DestructiveOperationGuard()

    # Create a dummy file that we will dynamically add to HARD_BLOCKED_PATHS for testing
    blocked_file = tmp_path / "mock_system_file.txt"
    blocked_file.touch()

    HARD_BLOCKED_PATHS.add(blocked_file)

    try:
        op = SecureEraseOperation(
            id="op-4",
            op_level="L1",
            op_type="file_erase",
            target_path=blocked_file,
            target_label="System File",
            method="software_overwrite",
            initiated_by="user",
            dry_run_hash="",
            session_id="session-1",
        )
        with pytest.raises(SecureEraseBlockedError, match="hard-blocked"):
            await guard.execute_erase(op, db, vault_dir=tmp_path)
    finally:
        HARD_BLOCKED_PATHS.discard(blocked_file)
        
    db.close()


@pytest.mark.asyncio
async def test_guard_active_use_check(tmp_path):
    db = _make_db(tmp_path)
    guard = DestructiveOperationGuard()
    
    test_file = tmp_path / "target.txt"
    test_file.touch()
    
    # Register as active operation
    guard.register_active_operation(str(test_file.resolve()))

    dry_run_details = f"L1-FILE:{test_file.resolve()}:{test_file.stat().st_size}"
    dry_run_hash = blake3.blake3(dry_run_details.encode()).hexdigest()

    op = SecureEraseOperation(
        id="op-5",
        op_level="L1",
        op_type="file_erase",
        target_path=test_file,
        target_label="Active File",
        method="software_overwrite",
        initiated_by="user",
        dry_run_hash=dry_run_hash,
        session_id="session-1",
    )

    with pytest.raises(SecureEraseBlockedError, match="active use"):
        await guard.execute_erase(op, db, vault_dir=tmp_path)

    # Unregister active operation
    guard.unregister_active_operation(str(test_file.resolve()))
    # Should now pass active check and erase file successfully!
    await guard.execute_erase(op, db, vault_dir=tmp_path)
    assert not test_file.exists()
    db.close()


@pytest.mark.asyncio
async def test_guard_redundancy_check_blocks_and_accept_loss(tmp_path):
    db = _make_db(tmp_path)
    guard = DestructiveOperationGuard()
    
    test_file = tmp_path / "target.txt"
    test_file.touch()

    # Setup database records simulating a vault file
    file_id = "file-uuid-1"
    chunk_id = "chunk-uuid-1"
    
    with db.transaction():
        db.insert_file({
            "id": file_id,
            "name": "target.txt",
            "path": str(test_file.resolve()),
            "size": 100,
            "mime_type": "text/plain",
            "tier": "IMPORTANT", # IMPORTANT has redundancy level 3, so needs 2 copies on OTHER backends
            "created_at": "2026-06-20T00:00:00Z",
            "modified_at": "2026-06-20T00:00:00Z",
            "version": 1,
            "version_of": None,
            "tombstone": 0,
            "tombstone_at": None,
        })
        db.insert_chunk({
            "id": chunk_id,
            "file_id": file_id,
            "chunk_index": 0,
            "total_chunks": 1,
            "blake3_hash": "dummyhash",
            "size": 100,
            "nonce_counter": 1,
            "sub_block_count": 1,
            "is_manifest": 0,
            "ref_count": 1,
        })

    # Case A: 0 other backend copies (redundancy level is 3, so needs 2 copies). It should block!
    dry_run_details = f"L1-FILE:{test_file.resolve()}:{test_file.stat().st_size}"
    dry_run_hash = blake3.blake3(dry_run_details.encode()).hexdigest()

    op = SecureEraseOperation(
        id="op-6",
        op_level="L1",
        op_type="file_erase",
        target_path=test_file,
        target_label="Vault File",
        method="software_overwrite",
        initiated_by="user",
        dry_run_hash=dry_run_hash,
        session_id="session-1",
    )

    with pytest.raises(SecureEraseBlockedError, match="exists only here"):
        await guard.execute_erase(op, db, vault_dir=tmp_path, accept_data_loss=False)

    # Case B: Redundancy check fails but user accepts permanent data loss (accept_data_loss=True).
    # It should bypass the block and complete!
    await guard.execute_erase(op, db, vault_dir=tmp_path, accept_data_loss=True)
    assert not test_file.exists()

    # Case C: Check that pre-execution and post-execution logs were written to destructive_ops_log!
    with db.transaction():
        logs = db.list_destructive_ops(session_id="session-1")
    assert len(logs) == 1
    assert logs[0]["id"] == "op-6"
    assert logs[0]["result"] == "completed"
    assert logs[0]["op_level"] == "L1"

    db.close()
