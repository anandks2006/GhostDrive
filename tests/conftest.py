"""
conftest.py — pytest shared fixtures and configuration for GhostDrive tests.
"""
import os
from pathlib import Path

import pytest


@pytest.fixture
def tmp_data_dir(tmp_path: Path) -> Path:
    """Fresh temporary GhostDrive data directory for each test."""
    d = tmp_path / "ghostdrive_data"
    d.mkdir(parents=True, exist_ok=True)
    return d


@pytest.fixture
def tmp_keystore_path(tmp_path: Path) -> Path:
    """Path to a keystore.json that does NOT yet exist."""
    return tmp_path / "keystore.json"


@pytest.fixture
def master_key() -> bytes:
    """Fresh random 32-byte Master Key."""
    return os.urandom(32)


@pytest.fixture
def hkdf_salt() -> bytes:
    """Fresh random 32-byte HKDF salt."""
    return os.urandom(32)


@pytest.fixture
def chacha_key() -> bytes:
    """Fresh random 32-byte ChaCha20-Poly1305 key."""
    return os.urandom(32)


@pytest.fixture
def chacha_nonce() -> bytes:
    """Fresh random 12-byte nonce."""
    return os.urandom(12)


# Fast Argon2id parameters for tests (avoids 1-second delay per test)
FAST_ARGON2_PARAMS = {
    "time_cost":   1,
    "memory_cost": 8_192,   # 8 MB
    "parallelism": 1,
    "hash_len":    32,
}
