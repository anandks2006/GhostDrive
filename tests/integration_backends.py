"""
tests/integration_backends.py -- Crypto + Database + Backend joint integration tests.

Validates that the Month 1 crypto core and Month 2 database layer work
correctly end-to-end with BOTH the Telegram and Discord backends.

What this tests
---------------
For EACH backend:
  1. GhostDriveDB opened with HMAC ledger + WAL
  2. FileRecord inserted (Lamport clock incremented)
  3. ChunkRecord inserted with nonce_counter from NonceManager
  4. Quota reserved in same transaction as pending intent (two-phase commit)
  5. File encrypted with ChaCha20-Poly1305 (64 KB streaming)
  6. Encrypted bytes uploaded to real backend
  7. Encrypted bytes downloaded from backend
  8. Decrypted and verified (AuthenticationError on tamper)
  9. BLAKE3 hash of original vs. reassembled bytes -- must match
  10. chunk_locations status confirmed in DB
  11. HMAC chain still valid after all writes
  12. WAL checkpoint succeeds
  13. Cleanup: backend.delete() + tombstone in DB

Run (requires real credentials):
    python tests/integration_backends.py
    python tests/integration_backends.py --backend telegram
    python tests/integration_backends.py --backend discord
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import logging
import mimetypes
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncGenerator

sys.path.insert(0, str(Path(__file__).parent.parent))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("integration_backends")


# ── Crypto imports ─────────────────────────────────────────────────────────────
from ghostdrive.crypto.chunk_crypto import ChunkEncryptor, ChunkDecryptor, BLOCK_SIZE
from ghostdrive.crypto.hkdf import derive_chunk_key
from ghostdrive.crypto.nonce import NonceManager
from ghostdrive.pipeline.dedup import compute_blake3
from ghostdrive.exceptions import AuthenticationError

# ── Database imports ───────────────────────────────────────────────────────────
from ghostdrive.database.db import GhostDriveDB


# ── Credential loaders ────────────────────────────────────────────────────────

def _load_telegram_creds():
    try:
        from telegram_credentials import API_ID, API_HASH, PHONE, SESSION_NAME
        return API_ID, API_HASH, PHONE, SESSION_NAME
    except ImportError:
        return None, None, None, None


def _load_discord_creds():
    try:
        from discord_credentials import BOT_TOKEN, CHANNEL_ID
        return BOT_TOKEN, CHANNEL_ID
    except ImportError:
        return None, None


# ── Test constants ────────────────────────────────────────────────────────────

# 512 KB test payload -- exercises multi-block streaming but stays fast
TEST_DATA_SIZE = 512 * 1024
LEDGER_KEY     = bytes(range(32))
GENESIS_SEED   = bytes(range(32, 64))
MASTER_KEY     = os.urandom(32)
HKDF_SALT      = os.urandom(32)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _uuid() -> str:
    return str(uuid.uuid4())


# ── Crypto helpers ────────────────────────────────────────────────────────────

async def _encrypt_data(
    data: bytes,
    key: bytes,
    nonce: bytes,
) -> bytes:
    """Encrypt data using ChaCha20-Poly1305 streaming (64 KB blocks)."""
    encryptor = ChunkEncryptor(key=key, nonce=nonce)
    buf = bytearray()
    offset = 0
    while offset < len(data):
        block = data[offset : offset + BLOCK_SIZE]
        buf.extend(encryptor.update(block))
        offset += BLOCK_SIZE
    buf.extend(encryptor.finalize())
    return bytes(buf)


async def _decrypt_data(
    ciphertext: bytes,
    key: bytes,
    nonce: bytes,
    original_size: int,
) -> bytes:
    """Decrypt and verify a full ciphertext (tag is last 16 bytes)."""
    tag        = ciphertext[-16:]
    ciphertext = ciphertext[:-16]

    decryptor = ChunkDecryptor(key=key, nonce=nonce, expected_tag=tag)
    offset = 0
    while offset < len(ciphertext):
        block = ciphertext[offset : offset + BLOCK_SIZE]
        decryptor.feed(block)
        offset += BLOCK_SIZE

    plaintext = decryptor.verify_and_decrypt()  # raises AuthenticationError on tamper
    return plaintext


# ── Core integration test ─────────────────────────────────────────────────────

async def run_backend_integration(
    backend_name: str,
    backend,
    db: GhostDriveDB,
    nonce_dir: Path,
    payload_path: str | None = None,
    no_cleanup: bool = False,
) -> bool:
    """
    Full crypto + DB + backend integration test.

    Returns True on success, raises on any failure.
    """
    sep = "-" * 60
    print(f"\n{sep}")
    print(f"  Backend: {backend_name.upper()}")
    print(f"{sep}")

    # -- Step 1: Connect backend -----------------------------------------------
    print(f"\n[1] Connecting to {backend_name} backend...")
    await backend.connect()
    print("    OK -- connected")

    # ── Step 2: Generate test payload + BLAKE3 hash ───────────────────────────
    if payload_path and os.path.exists(payload_path):
        with open(payload_path, "rb") as f:
            original_data = f.read()
        mime_type, _ = mimetypes.guess_type(payload_path)
        mime_type = mime_type or "application/octet-stream"
        payload_name = os.path.basename(payload_path)
        print(f"\n[2] Loading custom payload file '{payload_name}' ({len(original_data):,} bytes)...")
    else:
        original_data = os.urandom(TEST_DATA_SIZE)
        mime_type = "application/octet-stream"
        payload_name = f"integration_{backend_name}.bin"
        print(f"\n[2] Generating {TEST_DATA_SIZE // 1024} KB test payload...")

    payload_size = len(original_data)
    original_blake3 = compute_blake3(original_data)
    original_sha256 = hashlib.sha256(original_data).hexdigest()
    print(f"    BLAKE3: {original_blake3[:32]}...")
    print(f"    SHA-256: {original_sha256[:32]}...")

    # ── Step 3: Derive chunk key + get nonce ──────────────────────────────────
    print("\n[3] Deriving per-chunk key (HKDF) + incrementing nonce...")
    chunk_key = derive_chunk_key(MASTER_KEY, HKDF_SALT)
    nonce_mgr = NonceManager(data_dir=nonce_dir / backend_name)
    nonce = nonce_mgr.next_nonce()
    nonce_counter = NonceManager.nonce_to_counter(nonce)
    print(f"    Chunk key: {chunk_key.hex()[:32]}...")
    print(f"    Nonce counter: {nonce_counter} | nonce: {nonce.hex()}")

    # ── Step 4: DB -- insert file + chunk + pending intent (single txn) ───────
    print("\n[4] DB: insert FileRecord + ChunkRecord + pending intent (one txn)...")
    file_id  = _uuid()
    chunk_id = _uuid()

    with db.transaction():
        db.insert_file({
            "id": file_id, "name": payload_name,
            "path": f"/integration/{backend_name}/{payload_name}",
            "size": payload_size, "mime_type": mime_type,
            "tier": "IMPORTANT", "created_at": _now(), "modified_at": _now(),
            "version": 1, "version_of": None,
            "tombstone": 0, "tombstone_at": None,
        })

    # Need a backend row in DB for FK
    backend_db_id = _uuid()
    db._conn.execute("BEGIN")
    db._conn.execute(
        """INSERT INTO backends
           (id, type, credentials_ref, status, priority, quota_used, quota_limit, quota_reserved)
           VALUES (?, ?, 'ref:integration', 'healthy', 1, 0, 4611686018427387904, 0)""",
        (backend_db_id, backend_name),
    )
    db._conn.execute("COMMIT")

    with db.transaction():
        db.insert_chunk({
            "id": chunk_id, "file_id": file_id, "chunk_index": 0,
            "total_chunks": 1, "blake3_hash": original_blake3,
            "size": payload_size, "nonce_counter": nonce_counter,
            "sub_block_count": 1, "is_manifest": 0, "ref_count": 1,
        })
        # Atomic: nonce + pending intent in same transaction (spec §4.4 / §5.6)
        db.insert_chunk_location_pending({
            "chunk_id": chunk_id, "sub_block_index": 0, "backend_id": backend_db_id,
            "reference_id": "", "url_type": "ephemeral" if backend_name == "discord" else "permanent",
            "upload_date": _now(), "last_verified": None, "quota_reserved": payload_size,
        })

    clock_after_insert = db.current_clock()
    print(f"    OK -- file_id={file_id[:8]}... chunk_id={chunk_id[:8]}... clock={clock_after_insert}")

    # Verify pending record is scannable (startup scan simulation)
    pending = db.pending_chunk_locations()
    assert any(p["chunk_id"] == chunk_id for p in pending), "pending intent not found in DB"
    print(f"    OK -- pending intent visible in startup scan ({len(pending)} pending row(s))")

    # ── Step 5: Encrypt ───────────────────────────────────────────────────────
    print("\n[5] Encrypting payload (ChaCha20-Poly1305, 64 KB blocks)...")
    ciphertext = await _encrypt_data(original_data, chunk_key, nonce)
    print(f"    Plaintext:  {payload_size:,} bytes")
    print(f"    Ciphertext: {len(ciphertext):,} bytes (+16 Poly1305 tag)")

    # ── Step 6: Upload ────────────────────────────────────────────────────────
    print(f"\n[6] Uploading to {backend_name}...")

    async def _enc_stream():
        yield ciphertext

    reference_id = await backend.upload(
        stream=_enc_stream(),
        chunk_id=chunk_id,
        sub_block_index=0,
    )
    print(f"    OK -- reference_id={reference_id}")

    # ── Step 7: DB -- confirm chunk location ──────────────────────────────────
    print("\n[7] DB: confirming chunk_location (status=confirmed)...")
    with db.transaction():
        db.confirm_chunk_location(chunk_id, 0, backend_db_id, reference_id)
        db.confirm_quota(backend_db_id, payload_size)

    confirmed_row = db._conn.execute(
        "SELECT status, reference_id FROM chunk_locations WHERE chunk_id = ?",
        (chunk_id,),
    ).fetchone()
    assert confirmed_row["status"] == "confirmed", f"Expected confirmed, got {confirmed_row['status']}"
    assert confirmed_row["reference_id"] == reference_id
    print(f"    OK -- status=confirmed | reference_id={reference_id}")

    # ── Step 8: Download ──────────────────────────────────────────────────────
    print(f"\n[8] Downloading from {backend_name}...")
    downloaded_ct = b""
    async for block in backend.download(reference_id):
        downloaded_ct += block

    print(f"    Downloaded: {len(downloaded_ct):,} bytes")
    assert len(downloaded_ct) == len(ciphertext), (
        f"Size mismatch: uploaded {len(ciphertext)} bytes, got {len(downloaded_ct)}"
    )

    # ── Step 9: Decrypt + verify ──────────────────────────────────────────────
    print("\n[9] Decrypting + verifying authentication tag...")
    plaintext = await _decrypt_data(downloaded_ct, chunk_key, nonce, payload_size)
    reassembled_blake3 = compute_blake3(plaintext)

    assert original_blake3 == reassembled_blake3, (
        f"BLAKE3 MISMATCH!\n  original:     {original_blake3}\n  reassembled:  {reassembled_blake3}"
    )
    assert original_sha256 == hashlib.sha256(plaintext).hexdigest()
    print(f"    OK -- BLAKE3 match: {original_blake3[:32]}...")
    print("    OK -- Poly1305 authentication tag verified")
    print("    OK -- Byte-perfect integrity confirmed")

    # ── Step 10: Tamper detection test ────────────────────────────────────────
    print("\n[10] Tamper detection: flipping 1 byte of ciphertext body...")
    tampered = bytearray(downloaded_ct)
    tampered[0] ^= 0xFF  # flip first byte
    try:
        await _decrypt_data(bytes(tampered), chunk_key, nonce, payload_size)
        assert False, "Expected AuthenticationError was not raised on tampered data!"
    except AuthenticationError:
        print("     OK -- AuthenticationError raised correctly on tampered ciphertext")

    # ── Step 11: HMAC chain validity ──────────────────────────────────────────
    print("\n[11] Verifying HMAC ledger chain...")
    assert db.verify_hmac_chain() is True
    print("     OK -- HMAC chain valid after all writes")

    # ── Step 12: WAL checkpoint ───────────────────────────────────────────────
    print("\n[12] WAL checkpoint...")
    db.wal_checkpoint()
    print("     OK -- PRAGMA wal_checkpoint(TRUNCATE) succeeded")

    # ── Step 13: Cleanup ──────────────────────────────────────────────────────
    if no_cleanup:
        print(f"\n[13] Skipping backend cleanup (delete) per --no-cleanup.")
    else:
        print(f"\n[13] Cleanup: delete from {backend_name} + tombstone in DB...")
        deleted = await backend.delete(reference_id)
        assert deleted is True, f"backend.delete() returned {deleted}"

        with db.transaction():
            db.tombstone_file(file_id)

        ts_row = db._conn.execute(
            "SELECT tombstone, tombstone_at FROM files WHERE id = ?", (file_id,)
        ).fetchone()
        assert ts_row["tombstone"] == 1
        print(f"     OK -- deleted from {backend_name} | tombstone set in DB")

    await backend.disconnect()

    print(f"\n[PASS] {backend_name.upper()} -- full crypto + DB + backend integration verified")
    return True


# ── Main ──────────────────────────────────────────────────────────────────────

async def main(
    backend_filter: str | None = None,
    payload_path: str | None = None,
    no_cleanup: bool = False,
) -> None:
    sep = "=" * 60
    print(f"\n{sep}")
    print("  GhostDrive -- Crypto + DB + Backend Integration Tests")
    print(f"{sep}")

    nonce_dir = Path(".integration_backends_nonces")
    nonce_dir.mkdir(exist_ok=True)

    # Open shared DB
    db_path = Path(".integration_backends_test.db")
    db = GhostDriveDB(path=db_path, ledger_key=LEDGER_KEY, genesis_seed=GENESIS_SEED)
    db.open()

    results = {}

    try:
        # ── Telegram ─────────────────────────────────────────────────────────
        if backend_filter in (None, "telegram"):
            api_id, api_hash, phone, session = _load_telegram_creds()
            if not api_id:
                print("\n[!] Telegram: no credentials found in telegram_credentials.py -- SKIPPED")
            else:
                from ghostdrive.backends.telegram_backend import TelegramBackend
                tg_backend = TelegramBackend(
                    api_id=api_id, api_hash=api_hash,
                    phone=phone,
                )
                results["telegram"] = await run_backend_integration(
                    "telegram", tg_backend, db, nonce_dir, payload_path=payload_path, no_cleanup=no_cleanup
                )

        # ── Discord ──────────────────────────────────────────────────────────
        if backend_filter in (None, "discord"):
            bot_token, channel_id = _load_discord_creds()
            if not bot_token:
                print("\n[!] Discord: no credentials found in discord_credentials.py -- SKIPPED")
            else:
                from ghostdrive.backends.discord_backend import DiscordBackend
                dc_backend = DiscordBackend(bot_token=bot_token, channel_id=channel_id)
                results["discord"] = await run_backend_integration(
                    "discord", dc_backend, db, nonce_dir, payload_path=payload_path, no_cleanup=no_cleanup
                )

    finally:
        db.close()
        # Clean up test DB and nonce dir
        if db_path.exists():
            db_path.unlink()
        for suf in ["-shm", "-wal"]:
            p = Path(str(db_path) + suf)
            if p.exists():
                p.unlink()
        import shutil
        if nonce_dir.exists():
            shutil.rmtree(nonce_dir)

    # ── Results summary ───────────────────────────────────────────────────────
    print(f"\n{sep}")
    print("INTEGRATION TEST SUMMARY")
    print(sep)

    if not results:
        print("[!] No backends tested (no credentials found).")
        return

    all_pass = True
    for backend_name, passed in results.items():
        status = "[PASS]" if passed else "[FAIL]"
        print(f"{status} {backend_name.upper()}")
        if not passed:
            all_pass = False

    print()
    if all_pass:
        print("ALL TESTED BACKENDS PASS -- Month 1 + Month 2 stack is solid.")
    else:
        print("SOME BACKENDS FAILED -- check logs above.")
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GhostDrive backend integration tests")
    parser.add_argument(
        "--backend",
        choices=["telegram", "discord"],
        default=None,
        help="Run only one backend (default: both)",
    )
    parser.add_argument(
        "--payload",
        default=None,
        help="Path to a custom payload file to upload (default: random bytes)",
    )
    parser.add_argument(
        "--no-cleanup",
        action="store_true",
        help="Skip deleting the uploaded files from Telegram/Discord backends after testing",
    )
    args = parser.parse_args()
    asyncio.run(main(backend_filter=args.backend, payload_path=args.payload, no_cleanup=args.no_cleanup))
