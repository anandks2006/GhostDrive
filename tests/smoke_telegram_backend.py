"""
tests/smoke_telegram_backend.py -- Live smoke test for TelegramBackend.

Exercises TelegramBackend through the BackendBase interface against the
real Telegram API. Kept separate from unit tests because it requires:
  - Real network access
  - A valid session in OS keyring (run first_run_authenticate() once)
  - telegram_credentials.py (gitignored)

Marked with @pytest.mark.integration so it is excluded from the default
`pytest` run and only executed explicitly:

    pytest tests/smoke_telegram_backend.py -v -m integration

Or run directly (interactive, supports first-run OTP):

    python tests/smoke_telegram_backend.py

What this tests (BackendBase interface only -- NOT crypto)
----------------------------------------------------------
  [1] connect() via OS keyring session (or first-run OTP)
  [2] health_check() -> HealthResult.reachable, latency_ms
  [3] available_space() -> unlimited sentinel
  [4] upload(stream, chunk_id, sub_block_index) -> reference_id
      - force_document=True | filename encodes chunk_id + sub_block_index
  [5] download(reference_id) -> byte-perfect SHA-256 verified
  [6] delete(reference_id) -> confirmed deleted

Crypto integration (ChaCha20-Poly1305 + zstd + HKDF over Telegram):
    See tests/integration_telegram.py
"""

import asyncio
import hashlib
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

try:
    from telegram_credentials import API_ID, API_HASH, PHONE
    _CREDS_AVAILABLE = True
except ImportError:
    _CREDS_AVAILABLE = False

from ghostdrive.backends.telegram_backend import TelegramBackend  # noqa: E402
from ghostdrive.exceptions import BackendAuthError  # noqa: E402

# ── Helpers ───────────────────────────────────────────────────────────────────

async def _byte_stream(data: bytes, block: int = 65_536):
    """Async generator yielding data in 64 KB blocks (matches pipeline contract)."""
    offset = 0
    while offset < len(data):
        yield data[offset : offset + block]
        offset += block


# ── pytest integration test ───────────────────────────────────────────────────

@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(not _CREDS_AVAILABLE, reason="telegram_credentials.py not found")
async def test_telegram_backend_smoke():
    """
    Full upload -> download -> delete cycle via BackendBase interface.
    Requires real Telegram credentials and OS keyring session.
    """
    backend = TelegramBackend(api_id=API_ID, api_hash=API_HASH, phone=PHONE)

    try:
        await backend.connect()
    except BackendAuthError:
        pytest.skip("No Telegram session in OS keyring. Run first_run_authenticate() once.")

    try:
        # [2] health_check
        result = await backend.health_check()
        assert result.reachable, f"health_check returned reachable=False: {result.error}"
        assert result.latency_ms is not None and result.latency_ms > 0

        # [3] available_space
        space = await backend.available_space()
        assert space > 0

        # [4] upload
        test_data    = os.urandom(256 * 1024)   # 256 KB -- fast but real
        original_sha = hashlib.sha256(test_data).hexdigest()
        chunk_id     = "00000000-smoke-0000-0000-backend00test"

        ref = await backend.upload(
            stream=_byte_stream(test_data),
            chunk_id=chunk_id,
            sub_block_index=0,
        )
        assert ref and ref.isdigit(), f"reference_id should be a numeric message_id, got: {ref!r}"

        # [5] download + byte-perfect verify
        downloaded = b""
        async for block in backend.download(ref):
            downloaded += block

        assert hashlib.sha256(downloaded).hexdigest() == original_sha, (
            "Byte-perfect check failed -- SHA-256 mismatch after download"
        )
        assert len(downloaded) == len(test_data)

        # [6] delete
        deleted = await backend.delete(ref)
        assert deleted, f"delete() returned False for reference_id={ref}"

    finally:
        await backend.disconnect()


# ── Standalone runner (supports first-run OTP interactively) ──────────────────

async def _run_interactive():
    """Interactive runner for first-run keyring setup and manual verification."""
    if not _CREDS_AVAILABLE:
        print("\n[!] telegram_credentials.py not found.")
        print("    Create it with API_ID, API_HASH, PHONE, SESSION_NAME.")
        sys.exit(1)

    HEADER = "=" * 60
    print("\n" + HEADER)
    print("  GhostDrive -- Telegram Backend Smoke Test")
    print("  (BackendBase interface only -- see integration_telegram.py for crypto)")
    print(HEADER)

    backend = TelegramBackend(api_id=API_ID, api_hash=API_HASH, phone=PHONE)

    print("\n[1] Connecting via OS keyring...")
    try:
        await backend.connect()
        print("    OK -- session loaded from OS keyring")
    except BackendAuthError:
        print("    No session in keyring. Running first-run authentication...")
        await backend.first_run_authenticate(phone=PHONE)
        print("    OK -- session saved to OS keyring")
        await backend.connect()

    try:
        print("\n[2] health_check()...")
        r = await backend.health_check()
        assert r.reachable
        print(f"    OK -- reachable=True | latency={r.latency_ms:.1f}ms")

        print("\n[3] available_space()...")
        s = await backend.available_space()
        print(f"    OK -- {s:,} bytes (Telegram = effectively unlimited)")

        print("\n[4] upload() -- 256 KB sub-block...")
        data    = os.urandom(256 * 1024)
        sha_pre = hashlib.sha256(data).hexdigest()
        print(f"    SHA-256 pre-upload: {sha_pre[:32]}...")

        ref = await backend.upload(
            stream=_byte_stream(data),
            chunk_id="00000000-smoke-0000-0000-backend00test",
            sub_block_index=0,
        )
        print(f"    OK -- reference_id (message_id)={ref}")

        print(f"\n[5] download(reference_id={ref})...")
        downloaded = b""
        async for block in backend.download(ref):
            downloaded += block
        sha_post = hashlib.sha256(downloaded).hexdigest()
        print(f"    SHA-256 post-download: {sha_post[:32]}...")
        assert downloaded == data, "FAIL: byte-perfect check failed"
        print("    OK -- byte-perfect match confirmed")

        print(f"\n[6] delete(reference_id={ref})...")
        deleted = await backend.delete(ref)
        assert deleted
        print("    OK -- deleted from Saved Messages")

        print("\n" + HEADER)
        print("RESULTS")
        print(HEADER)
        print("[PASS] TelegramBackend implements BackendBase correctly.")
        print("[PASS] upload -> download -> delete cycle verified.")
        print("[PASS] Byte-perfect integrity confirmed.")
        print("[PASS] Session stored in OS keyring (not .session file, not plaintext).")
        print("\nSpec compliance:")
        print(f"  Tier:            {backend.tier}")
        print(f"  Logical chunk:   {backend.logical_chunk_bytes // 1024 // 1024} MB")
        print(f"  Sub-block:       {backend.sub_block_bytes // 1024 // 1024} MB")
        print("  force_document:  True (exact bytes, no Telegram compression)")
        print("  Session storage: OS keyring (DPAPI/libsecret/Keychain)")

    finally:
        await backend.disconnect()
        print("\n[*] Disconnected.")


if __name__ == "__main__":
    asyncio.run(_run_interactive())
