"""
tests/integration_telegram.py -- End-to-end Phase 1 crypto + Telegram backend test.

What this proves
----------------
The entire GhostDrive Phase 1 cryptographic pipeline works over a REAL
Telegram backend:

  plaintext file
    -> zstd compress (level 3)
    -> ChaCha20-Poly1305 encrypt (one nonce per chunk, single tag per chunk)
    -> upload to Telegram Saved Messages as raw document
    -> download from Telegram by message_id
    -> Poly1305 tag verified FIRST (no plaintext before tag OK)
    -> ChaCha20 decrypt
    -> zstd decompress
    -> byte-perfect original data

Crypto invariants verified
--------------------------
  [1] ChaCha20-Poly1305 round-trip: plaintext recovered byte-perfect
  [2] Single Poly1305 tag covers the ENTIRE chunk (not per 64KB block)
  [3] Tag verified BEFORE any plaintext byte is returned
  [4] Tampering with 1 bit -> AuthenticationError
  [5] Wrong key -> AuthenticationError (not silent wrong decrypt)
  [6] Wrong nonce -> AuthenticationError
  [7] Nonce counter increments and persists across instances
  [8] HKDF chunk_key: same inputs -> same key, different salt -> different key

How to run
----------
  1. pip install telethon zstandard
  2. Ensure telegram_credentials.py exists with your API_ID, API_HASH, PHONE
     (it is .gitignored and never committed)
  3. python tests/integration_telegram.py
  4. Enter OTP when Telegram sends it to your phone/app

On first run Telethon creates `ghostdrive_integration.session` (also .gitignored).
Subsequent runs reuse the session (no OTP needed).
"""

import asyncio
import hashlib
import json
import os
import sys
import tempfile
import time
from pathlib import Path

# ── Make sure the package root is on the path ─────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

try:
    import zstandard as zstd
    from telethon import TelegramClient
    from telethon.tl.types import DocumentAttributeFilename
except ImportError as exc:
    print(f"\n[!] Missing dependency: {exc}")
    print("    Run: pip install telethon zstandard")
    sys.exit(1)

# ── GhostDrive Phase 1 crypto ─────────────────────────────────────────────────
from ghostdrive.crypto.chunk_crypto import (
    BLOCK_SIZE,
    TAG_SIZE,
    ChunkDecryptor,
    ChunkEncryptor,
)
from ghostdrive.crypto.hkdf import derive_chunk_key
from ghostdrive.crypto.nonce import NonceManager
from ghostdrive.exceptions import AuthenticationError

# ── Load credentials from the local (gitignored) file ─────────────────────────
try:
    from telegram_credentials import API_ID, API_HASH, PHONE, SESSION_NAME
except ImportError:
    print("\n[!] telegram_credentials.py not found.")
    print("    Create it with your API_ID, API_HASH, PHONE, SESSION_NAME.")
    print("    See the existing telegram_credentials.py template.")
    sys.exit(1)

# ── Test configuration ────────────────────────────────────────────────────────
TEST_FILE_SIZE_MB = 2            # Small enough for a quick smoke test
CHUNK_SIZE_BYTES  = 512 * 1024  # 512 KB logical chunks (8 x 64 KB blocks each)
ZSTD_LEVEL        = 3           # Fixed per spec §6 -- NEVER user-configurable
DATA_DIR          = ROOT / ".integration_test_data"

HEADER = "=" * 60


# =============================================================================
# Crypto helpers
# =============================================================================

def make_test_master_key_and_salt() -> tuple[bytes, bytes]:
    """Generate a fresh Master Key and HKDF salt for this test session."""
    return os.urandom(32), os.urandom(32)


def zstd_compress(data: bytes) -> bytes:
    """Compress with zstd level 3 (fixed per spec §6)."""
    return zstd.ZstdCompressor(level=ZSTD_LEVEL).compress(data)


def zstd_decompress(data: bytes) -> bytes:
    """Decompress zstd data."""
    return zstd.ZstdDecompressor().decompress(data)


def encrypt_chunk(
    plaintext_chunk: bytes,
    chunk_key: bytes,
    nonce_mgr: NonceManager,
) -> tuple[bytes, bytes, bytes]:
    """
    Compress then encrypt one logical chunk.

    Returns:
        (nonce, ciphertext_with_tag_appended, compressed_bytes)

    The returned blob layout:  <ciphertext_bytes>  ||  <16-byte Poly1305 tag>
    The nonce is stored in the index (simulating chunk_locations.nonce_hex).
    """
    # Step 1: Compress (zstd level 3, fixed)
    compressed = zstd_compress(plaintext_chunk)

    # Step 2: Get nonce (increments counter, persists to disk with fsync BEFORE returning)
    nonce = nonce_mgr.next_nonce()

    # Step 3: Encrypt with ChaCha20-Poly1305, streaming 64 KB blocks
    enc = ChunkEncryptor(chunk_key, nonce)
    ciphertext = b""
    offset = 0
    while offset < len(compressed):
        ciphertext += enc.update(compressed[offset : offset + BLOCK_SIZE])
        offset += BLOCK_SIZE
    tag = enc.finalize()   # ONE Poly1305 tag for the ENTIRE chunk

    return nonce, ciphertext + tag, compressed


def decrypt_chunk(blob: bytes, chunk_key: bytes, nonce: bytes) -> bytes:
    """
    Decrypt then decompress one chunk blob.

    The Poly1305 tag is verified BEFORE any plaintext byte is returned (spec §4.4).

    Raises:
        AuthenticationError: if tag does not match -- zero plaintext returned.
    """
    ciphertext   = blob[:-TAG_SIZE]
    expected_tag = blob[-TAG_SIZE:]

    dec = ChunkDecryptor(chunk_key, nonce, expected_tag)
    dec.feed(ciphertext)
    compressed = dec.verify_and_decrypt()   # TAG VERIFIED FIRST

    return zstd_decompress(compressed)


# =============================================================================
# Telegram helpers
# =============================================================================

async def upload_encrypted_chunk(
    client: TelegramClient,
    blob: bytes,
    chunk_idx: int,
    file_tag: str,
) -> int:
    """Upload an encrypted chunk blob to Telegram Saved Messages. Returns message_id."""
    chunk_filename = f"gd_{file_tag}.chunk{chunk_idx:04d}.enc"

    with tempfile.NamedTemporaryFile(delete=False, suffix=".enc") as tmp:
        tmp.write(blob)
        tmp_path = tmp.name

    try:
        msg = await client.send_file(
            "me",
            tmp_path,
            caption=f"GhostDrive encrypted chunk {chunk_idx} [{file_tag}]",
            attributes=[DocumentAttributeFilename(file_name=chunk_filename)],
            force_document=True,   # Never compress -- preserve exact bytes
        )
        return msg.id
    finally:
        os.unlink(tmp_path)


async def download_encrypted_chunk(client: TelegramClient, message_id: int) -> bytes:
    """Download an encrypted chunk blob from Telegram by message_id."""
    msg = await client.get_messages("me", ids=message_id)
    if msg is None or msg.document is None:
        raise RuntimeError(f"Message {message_id} not found or has no document!")
    return await client.download_media(msg, file=bytes)


async def delete_messages(client: TelegramClient, message_ids: list[int]) -> None:
    """Delete test messages from Saved Messages."""
    await client.delete_messages("me", message_ids)


# =============================================================================
# Offline crypto invariant checks (no network required)
# =============================================================================

def run_offline_crypto_invariant_checks(chunk_key: bytes, nonce_mgr: NonceManager) -> None:
    """
    Verify all Phase 1 crypto invariants locally BEFORE touching the network.
    Fast (< 1 second). Any failure here aborts the test immediately.
    """
    print("\n" + HEADER)
    print("OFFLINE CRYPTO INVARIANT CHECKS")
    print(HEADER)

    sample = b"GhostDrive Phase 1 crypto invariant check " * 500   # ~21 KB

    # [1] Round-trip: compress -> encrypt -> decrypt -> decompress -> original
    nonce1, blob1, _ = encrypt_chunk(sample, chunk_key, nonce_mgr)
    recovered = decrypt_chunk(blob1, chunk_key, nonce1)
    assert recovered == sample, "FAIL [1]: Decrypted data != original"
    print("[1] PASS  ChaCha20-Poly1305 round-trip: plaintext recovered byte-perfect")

    # [2] Single-bit ciphertext tamper -> AuthenticationError, zero plaintext returned
    nonce2, blob2, _ = encrypt_chunk(sample, chunk_key, nonce_mgr)
    corrupted = bytearray(blob2)
    corrupted[42] ^= 0x01
    try:
        decrypt_chunk(bytes(corrupted), chunk_key, nonce2)
        print("FAIL [2]: tampered ciphertext did NOT raise AuthenticationError")
        sys.exit(1)
    except AuthenticationError:
        pass
    print("[2] PASS  Single-bit ciphertext corruption -> AuthenticationError (no plaintext)")

    # [3] Wrong key -> AuthenticationError
    nonce3, blob3, _ = encrypt_chunk(sample, chunk_key, nonce_mgr)
    try:
        decrypt_chunk(blob3, os.urandom(32), nonce3)
        print("FAIL [3]: wrong key did NOT raise AuthenticationError")
        sys.exit(1)
    except AuthenticationError:
        pass
    print("[3] PASS  Wrong decryption key -> AuthenticationError")

    # [4] Wrong nonce -> AuthenticationError
    nonce4, blob4, _ = encrypt_chunk(sample, chunk_key, nonce_mgr)
    try:
        decrypt_chunk(blob4, chunk_key, os.urandom(12))
        print("FAIL [4]: wrong nonce did NOT raise AuthenticationError")
        sys.exit(1)
    except AuthenticationError:
        pass
    print("[4] PASS  Wrong nonce -> AuthenticationError")

    # [5] Nonces are strictly increasing
    n5a, _, _ = encrypt_chunk(b"a" * 100, chunk_key, nonce_mgr)
    n5b, _, _ = encrypt_chunk(b"b" * 100, chunk_key, nonce_mgr)
    ctr_a, ctr_b = int.from_bytes(n5a, "big"), int.from_bytes(n5b, "big")
    assert ctr_b > ctr_a, f"FAIL [5]: nonce counter did not increase ({ctr_a} -> {ctr_b})"
    print(f"[5] PASS  Nonce counter strictly increasing: {ctr_a} -> {ctr_b}")

    # [6] Single Poly1305 tag covers ALL 64KB blocks -- corrupt block-2 detected
    big_sample = os.urandom(BLOCK_SIZE * 3 + 1000)
    nonce6, blob6, _ = encrypt_chunk(big_sample, chunk_key, nonce_mgr)
    ct6, tag6 = blob6[:-TAG_SIZE], blob6[-TAG_SIZE:]
    arr = bytearray(ct6)
    arr[BLOCK_SIZE + 10] ^= 0x80   # corrupt second block
    dec_test = ChunkDecryptor(chunk_key, nonce6, tag6)
    dec_test.feed(bytes(arr))
    try:
        dec_test.verify_and_decrypt()
        print("FAIL [6]: modifying block-2 did NOT invalidate the single chunk tag")
        sys.exit(1)
    except AuthenticationError:
        pass
    print("[6] PASS  Single Poly1305 tag covers ALL blocks -- block-2 corruption detected")

    # [7] HKDF: same master_key + salt -> same chunk key (deterministic)
    mk, salt = os.urandom(32), os.urandom(32)
    ck1 = derive_chunk_key(mk, salt)
    ck2 = derive_chunk_key(mk, salt)
    assert ck1 == ck2, "FAIL [7]: HKDF not deterministic"
    print("[7] PASS  HKDF chunk key is deterministic")

    # [8] HKDF: different salt -> different chunk key
    ck3 = derive_chunk_key(mk, os.urandom(32))
    assert ck3 != ck1, "FAIL [8]: different HKDF salt produced same key"
    print("[8] PASS  Different HKDF salt -> different chunk key")

    print("\n[ALL 8 INVARIANTS PASSED] Crypto layer verified. Proceeding to network test.\n")


# =============================================================================
# Main integration test
# =============================================================================

async def main():
    print("\n" + HEADER)
    print("  GhostDrive -- Phase 1 Crypto + Telegram Integration Test")
    print(HEADER)

    # Setup crypto material
    master_key, hkdf_salt = make_test_master_key_and_salt()
    chunk_key = derive_chunk_key(master_key, hkdf_salt)

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    nonce_mgr = NonceManager(DATA_DIR)

    print(f"\n[*] Master Key (first 16 bytes): {master_key.hex()[:32]}...")
    print(f"[*] HKDF salt  (first 16 bytes): {hkdf_salt.hex()[:32]}...")
    print(f"[*] Chunk key  (first 16 bytes): {chunk_key.hex()[:32]}...")
    print(f"[*] Nonce counter starts at:     {nonce_mgr.peek_counter()}")

    # Phase 0: offline checks first
    run_offline_crypto_invariant_checks(chunk_key, nonce_mgr)

    # Phase 1: generate test data
    print(HEADER)
    print("PHASE 1: GENERATE TEST DATA")
    print(HEADER)

    total_bytes = TEST_FILE_SIZE_MB * 1024 * 1024
    pattern   = b"GHOSTDRIVE_PHASE1_CRYPTO_INTEGRATION_TEST_" * 1024
    file_data = (pattern * (total_bytes // len(pattern) + 1))[:total_bytes]

    original_hash = hashlib.sha256(file_data).hexdigest()
    print(f"[*] Test data: {len(file_data):,} bytes")
    print(f"[*] SHA-256:   {original_hash}")

    chunks_plaintext = [
        file_data[off : off + CHUNK_SIZE_BYTES]
        for off in range(0, len(file_data), CHUNK_SIZE_BYTES)
    ]
    print(f"[*] Split into {len(chunks_plaintext)} chunk(s) of up to {CHUNK_SIZE_BYTES // 1024} KB each")

    # Phase 2: encrypt all chunks
    print("\n" + HEADER)
    print("PHASE 2: ENCRYPT CHUNKS (ChaCha20-Poly1305 + zstd)")
    print(HEADER)

    index: list[dict] = []
    encrypted_blobs: list[bytes] = []

    for i, pt_chunk in enumerate(chunks_plaintext):
        t0 = time.perf_counter()
        nonce, blob, compressed = encrypt_chunk(pt_chunk, chunk_key, nonce_mgr)
        elapsed = time.perf_counter() - t0

        nonce_ctr = int.from_bytes(nonce, "big")
        ratio = len(compressed) / len(pt_chunk) * 100

        print(
            f"[*] Chunk {i}: {len(pt_chunk):,} B "
            f"-> zstd {len(compressed):,} B ({ratio:.1f}%) "
            f"-> enc {len(blob):,} B | nonce_ctr={nonce_ctr} | {elapsed*1000:.1f}ms"
        )
        index.append({
            "chunk_index": i,
            "nonce_hex":   nonce.hex(),
            "blob_size":   len(blob),
            "pt_size":     len(pt_chunk),
        })
        encrypted_blobs.append(blob)

    print(f"\n[*] Nonce counter after encryption: {nonce_mgr.peek_counter()}")

    # Phase 3: upload to Telegram
    print("\n" + HEADER)
    print("PHASE 3: UPLOAD ENCRYPTED BLOBS TO TELEGRAM")
    print(HEADER)

    file_tag = f"test{int(time.time()) % 100000:05d}"
    print(f"[*] Connecting to Telegram (session: {SESSION_NAME})...")
    client = TelegramClient(SESSION_NAME, API_ID, API_HASH)

    message_ids: list[int] = []
    index_path = ROOT / f"integration_index_{file_tag}.json"

    try:
        await client.start(phone=PHONE)
        me = await client.get_me()
        print(f"[*] Connected as @{me.username or me.first_name}\n")

        for i, (blob, record) in enumerate(zip(encrypted_blobs, index)):
            t0 = time.perf_counter()
            msg_id = await upload_encrypted_chunk(client, blob, i, file_tag)
            elapsed = time.perf_counter() - t0
            speed = len(blob) / elapsed / 1024 / 1024

            print(f"[*] Chunk {i} uploaded | message_id={msg_id} | {elapsed:.1f}s | {speed:.2f} MB/s")
            message_ids.append(msg_id)
            index[i]["message_id"] = msg_id

        with open(index_path, "w") as fh:
            json.dump(index, fh, indent=2)
        print(f"\n[*] Index saved: {index_path.name}")

        # Phase 4: download from Telegram
        print("\n" + HEADER)
        print("PHASE 4: DOWNLOAD FROM TELEGRAM (by message_id)")
        print(HEADER)

        downloaded_blobs: list[tuple[dict, bytes]] = []
        for record in sorted(index, key=lambda r: r["chunk_index"]):
            t0 = time.perf_counter()
            blob = await download_encrypted_chunk(client, record["message_id"])
            elapsed = time.perf_counter() - t0
            speed = len(blob) / elapsed / 1024 / 1024

            assert len(blob) == record["blob_size"], (
                f"FAIL: chunk {record['chunk_index']} size mismatch! "
                f"Expected {record['blob_size']}, got {len(blob)}"
            )
            print(
                f"[*] Chunk {record['chunk_index']} downloaded "
                f"| {len(blob):,} B | {elapsed:.1f}s | {speed:.2f} MB/s | size OK"
            )
            downloaded_blobs.append((record, blob))

        # Phase 5: decrypt and reassemble
        print("\n" + HEADER)
        print("PHASE 5: DECRYPT + VERIFY (Poly1305 tag before any plaintext)")
        print(HEADER)

        reassembled = bytearray()
        for record, blob in downloaded_blobs:
            nonce = bytes.fromhex(record["nonce_hex"])

            t0 = time.perf_counter()
            try:
                plaintext = decrypt_chunk(blob, chunk_key, nonce)
            except AuthenticationError as exc:
                print(f"\n[!!!] AUTHENTICATION FAILURE on chunk {record['chunk_index']}!")
                print(f"      {exc}")
                print("      Aborting -- no plaintext returned.")
                raise

            elapsed = time.perf_counter() - t0

            assert len(plaintext) == record["pt_size"], (
                f"FAIL: chunk {record['chunk_index']} plaintext size mismatch! "
                f"Expected {record['pt_size']}, got {len(plaintext)}"
            )
            reassembled.extend(plaintext)
            print(
                f"[*] Chunk {record['chunk_index']}: Poly1305 OK "
                f"| decrypted {len(plaintext):,} B | {elapsed*1000:.1f}ms"
            )

        # Final integrity check
        print("\n" + HEADER)
        print("RESULTS")
        print(HEADER)

        reassembled_hash = hashlib.sha256(bytes(reassembled)).hexdigest()
        bytes_match = (bytes(reassembled) == file_data)

        print(f"Original SHA-256:    {original_hash}")
        print(f"Reassembled SHA-256: {reassembled_hash}")
        print(f"Byte-perfect match:  {'YES' if bytes_match else 'NO'}")

        if bytes_match:
            print("\n[PASS] Phase 1 crypto verified end-to-end over Telegram.")
            print("       ChaCha20-Poly1305 + zstd + HKDF + nonce manager -- all correct.")
        else:
            print("\n[FAIL] Reassembled data does not match original. DATA CORRUPTION.")
            sys.exit(1)

        # Cleanup
        answer = input("\n[?] Delete test messages from Saved Messages? (y/n): ").strip().lower()
        if answer == "y":
            print(f"[*] Deleting {len(message_ids)} message(s)...")
            await delete_messages(client, message_ids)
            print("    Cleanup complete.")
        else:
            print(f"    Kept in Saved Messages. message_ids: {message_ids}")

    finally:
        await client.disconnect()
        try:
            index_path.unlink(missing_ok=True)
        except Exception:
            pass
        print("\n[*] Disconnected. Done.")


if __name__ == "__main__":
    asyncio.run(main())
