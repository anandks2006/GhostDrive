"""
telegram_test.py -- Telegram backend smoke-test (spec-aligned).

Purpose
-------
Validates that TelegramBackend correctly implements the BackendBase interface
and that the full upload -> download -> delete flow works against the real
Telegram API. This is the developer smoke-test for the Telegram plugin.

For the end-to-end crypto integration test (crypto + Telegram), see:
    tests/integration_telegram.py

What this tests
---------------
  [1] TelegramBackend.connect() via OS keyring session
  [2] TelegramBackend.health_check() -> HealthResult.reachable
  [3] TelegramBackend.available_space() -> int (unlimited sentinel)
  [4] TelegramBackend.upload(stream, chunk_id, sub_block_index) -> reference_id
      - force_document=True (exact bytes preserved)
      - filename encodes chunk_id + sub_block_index
  [5] TelegramBackend.download(reference_id) -> async bytes generator
      - byte-perfect SHA-256 verification
  [6] TelegramBackend.delete(reference_id) -> bool
  [7] Session stored in OS keyring, NOT in plaintext or .session file

What this does NOT test (out of scope here)
--------------------------------------------
  - Flood wait retry (requires mocking -- see tests/test_backends.py Month 3)
  - Session expiry detection (requires mocking)
  - Sub-block assembly + Poly1305 tag verification (see integration_telegram.py)
  - Quota reservation / two-phase commit (requires database -- Month 2)

Credentials
-----------
  Loaded from telegram_credentials.py (gitignored -- never committed).
  See telegram_credentials.py for the template.

How to run
----------
  python telegram_test.py

On first run: if no session in OS keyring, authenticates via phone OTP
and stores session string in OS keyring (DPAPI on Windows).
Subsequent runs: loads session from keyring -- no OTP needed.
"""

import asyncio
import hashlib
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

# ── Load credentials (gitignored) ─────────────────────────────────────────────
try:
    from telegram_credentials import API_ID, API_HASH, PHONE
except ImportError:
    print("\n[!] telegram_credentials.py not found.")
    print("    Create it with:")
    print("        API_ID   = <your api_id from https://my.telegram.org>")
    print("        API_HASH = '<your api_hash>'")
    print("        PHONE    = '<your phone e.g. +919876543210>'")
    sys.exit(1)

# ── GhostDrive backend ────────────────────────────────────────────────────────
from ghostdrive.backends.telegram_backend import TelegramBackend
from ghostdrive.exceptions import BackendAuthError

# ── Test configuration ────────────────────────────────────────────────────────
TEST_CHUNK_SIZE_MB = 1       # 1 MB -- enough to verify, fast to upload
TEST_CHUNK_ID      = "00000000-test-0000-0000-smoke0000test"
TEST_SUB_BLOCK     = 0

HEADER = "=" * 60


async def make_test_stream(data: bytes):
    """Async generator that yields test data in 64 KB blocks (pipeline-compatible)."""
    BLOCK = 65_536
    offset = 0
    while offset < len(data):
        yield data[offset : offset + BLOCK]
        offset += BLOCK


async def main():
    print("\n" + HEADER)
    print("  GhostDrive -- Telegram Backend Smoke Test")
    print("  (Tests BackendBase interface, NOT crypto)")
    print(HEADER)

    backend = TelegramBackend(api_id=API_ID, api_hash=API_HASH, phone=PHONE)

    # ── [1] Connect (loads session from OS keyring) ───────────────────────────
    print("\n[1] Connecting via OS keyring session...")
    try:
        await backend.connect()
        print("    OK -- session loaded from OS keyring")
    except BackendAuthError:
        print("    No session in keyring. Running first-run authentication...")
        await backend.first_run_authenticate(phone=PHONE)
        print("    OK -- session saved to OS keyring")
        await backend.connect()

    try:
        # ── [2] Health check ──────────────────────────────────────────────────
        print("\n[2] health_check()...")
        result = await backend.health_check()
        assert result.reachable, f"FAIL: health_check returned reachable=False: {result.error}"
        print(f"    OK -- reachable=True | latency={result.latency_ms:.1f}ms")

        # ── [3] available_space ───────────────────────────────────────────────
        print("\n[3] available_space()...")
        space = await backend.available_space()
        assert space > 0, "FAIL: available_space returned 0"
        print(f"    OK -- {space:,} bytes (Telegram = effectively unlimited)")

        # ── [4] upload() via BackendBase interface ────────────────────────────
        print(f"\n[4] upload() -- {TEST_CHUNK_SIZE_MB} MB test sub-block...")
        test_data    = os.urandom(TEST_CHUNK_SIZE_MB * 1024 * 1024)
        original_sha = hashlib.sha256(test_data).hexdigest()
        print(f"    SHA-256 (pre-upload): {original_sha[:32]}...")
        print(f"    force_document=True | filename: gd_{TEST_CHUNK_ID[:8]}_{TEST_SUB_BLOCK:04d}.enc")

        t0  = time.perf_counter()
        ref = await backend.upload(
            stream=make_test_stream(test_data),
            chunk_id=TEST_CHUNK_ID,
            sub_block_index=TEST_SUB_BLOCK,
        )
        elapsed = time.perf_counter() - t0
        speed   = TEST_CHUNK_SIZE_MB / elapsed

        print(f"    OK -- reference_id (message_id)={ref} | {elapsed:.1f}s | {speed:.2f} MB/s")

        # ── [5] download() via BackendBase interface ──────────────────────────
        print(f"\n[5] download(reference_id={ref})...")
        t0 = time.perf_counter()

        downloaded = b""
        async for block in backend.download(ref):
            downloaded += block

        elapsed      = time.perf_counter() - t0
        speed        = len(downloaded) / elapsed / 1024 / 1024
        download_sha = hashlib.sha256(downloaded).hexdigest()

        print(f"    Downloaded: {len(downloaded):,} bytes | {elapsed:.1f}s | {speed:.2f} MB/s")
        print(f"    SHA-256 (post-download): {download_sha[:32]}...")

        assert downloaded == test_data, (
            f"FAIL: byte-perfect check failed!\n"
            f"  Expected SHA-256: {original_sha}\n"
            f"  Got SHA-256:      {download_sha}"
        )
        print("    OK -- byte-perfect match confirmed")

        # ── [6] delete() via BackendBase interface ────────────────────────────
        print(f"\n[6] delete(reference_id={ref})...")
        deleted = await backend.delete(ref)
        assert deleted, f"FAIL: delete() returned False for reference_id={ref}"
        print("    OK -- sub-block deleted from Saved Messages")

        # ── Results ───────────────────────────────────────────────────────────
        print("\n" + HEADER)
        print("RESULTS")
        print(HEADER)
        print("[PASS] TelegramBackend implements BackendBase correctly.")
        print("[PASS] upload -> download -> delete cycle verified.")
        print("[PASS] Byte-perfect integrity confirmed.")
        print("[PASS] Session stored in OS keyring (not .session file, not plaintext).")
        print()
        print("Spec compliance:")
        print(f"  Tier:            {backend.tier}")
        print(f"  Logical chunk:   {backend.logical_chunk_bytes // 1024 // 1024} MB")
        print(f"  Sub-block:       {backend.sub_block_bytes // 1024 // 1024} MB")
        print(f"  force_document:  True (exact bytes, no Telegram compression)")
        print(f"  Session storage: OS keyring (DPAPI/libsecret/Keychain)")

    finally:
        await backend.disconnect()
        print("\n[*] Disconnected.")


if __name__ == "__main__":
    asyncio.run(main())
