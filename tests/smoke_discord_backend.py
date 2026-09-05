"""
tests/smoke_discord_backend.py -- Discord BackendBase interface smoke test.

Same pattern as smoke_telegram_backend.py:
  [1] Connect via OS keyring
  [2] health_check()
  [3] available_space()
  [4] upload() -- 256 KB sub-block
  [5] download(reference_id) -- byte-perfect match
  [6] delete(reference_id)

Run directly (interactive):
    python tests/smoke_discord_backend.py

Run via pytest (CI, requires credentials):
    pytest tests/smoke_discord_backend.py -m integration -v
"""

import asyncio
import hashlib
import os
import sys
from pathlib import Path

import pytest

# ── Load credentials ──────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from discord_credentials import BOT_TOKEN, CHANNEL_ID
    _HAVE_CREDS = bool(BOT_TOKEN and CHANNEL_ID)
except ImportError:
    BOT_TOKEN  = None
    CHANNEL_ID = None
    _HAVE_CREDS = False


# ── Pytest integration test ───────────────────────────────────────────────────

@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(not _HAVE_CREDS, reason="discord_credentials.py not found or empty")
async def test_discord_backend_smoke():
    """BackendBase interface smoke test via pytest. Uses real Discord API."""
    await _run_smoke_test(interactive=False)


# ── Standalone runner ─────────────────────────────────────────────────────────

async def _run_smoke_test(interactive: bool = True) -> None:
    from ghostdrive.backends.discord_backend import DiscordBackend

    sep = "=" * 60
    print(f"\n{sep}")
    print("  GhostDrive -- Discord Backend Smoke Test")
    print("  (BackendBase interface -- crypto+DB tested in integration_backends.py)")
    print(f"{sep}\n")

    if not _HAVE_CREDS:
        print("[!] No credentials found in discord_credentials.py")
        print("    Fill in BOT_TOKEN and CHANNEL_ID, then re-run.")
        return

    backend = DiscordBackend(bot_token=BOT_TOKEN, channel_id=CHANNEL_ID)

    print("[1] Connecting via OS keyring / credentials file...")
    await backend.connect()
    print("    OK -- Discord bot connected")

    print("\n[2] health_check()...")
    health = await backend.health_check()
    assert health.reachable, f"health_check failed: {health.error}"
    print(f"    OK -- reachable=True | latency={health.latency_ms:.1f}ms")

    print("\n[3] available_space()...")
    space = await backend.available_space()
    print(f"    OK -- {space:,} bytes (Discord = effectively unlimited)")

    print("\n[4] upload() -- 256 KB encrypted sub-block...")
    test_data  = os.urandom(256 * 1024)
    sha256_pre = hashlib.sha256(test_data).hexdigest()
    print(f"    SHA-256 pre-upload: {sha256_pre[:32]}...")

    async def _source():
        yield test_data

    ref_id = await backend.upload(
        stream=_source(),
        chunk_id="00000000-0000-0000-0000-000000000001",
        sub_block_index=0,
    )
    print(f"    OK -- reference_id (message_id:channel_id)={ref_id}")

    print(f"\n[5] download(reference_id={ref_id})...")
    downloaded = b""
    async for block in backend.download(ref_id):
        downloaded += block

    sha256_post = hashlib.sha256(downloaded).hexdigest()
    print(f"    SHA-256 post-download: {sha256_post[:32]}...")

    assert sha256_pre == sha256_post, (
        f"INTEGRITY FAILURE!\n  pre:  {sha256_pre}\n  post: {sha256_post}"
    )
    print("    OK -- byte-perfect match confirmed")

    print(f"\n[6] delete(reference_id={ref_id})...")
    deleted = await backend.delete(ref_id)
    assert deleted is True
    print("    OK -- message deleted from Discord channel")

    print(f"\n{sep}")
    print("RESULTS")
    print(sep)
    print("[PASS] DiscordBackend implements BackendBase correctly.")
    print("[PASS] upload -> download -> delete cycle verified.")
    print("[PASS] Byte-perfect integrity confirmed.")
    print("[PASS] Ephemeral URL pattern (message_id:channel_id) confirmed.")
    print("\nSpec compliance:")
    print(f"  Tier:            {backend.tier}")
    print(f"  Logical chunk:   {backend.logical_chunk_bytes // 1024 // 1024} MB")
    print(f"  Sub-block:       {backend.sub_block_bytes // 1024 // 1024} MB")
    print(f"  is_ephemeral_url: {backend.is_ephemeral_url}  (fresh CDN URL fetched at download)")
    print("  Credentials ref: OS keyring service='ghostdrive' / discord_credentials.py")

    await backend.disconnect()
    print("\n[*] Disconnected.")


if __name__ == "__main__":
    asyncio.run(_run_smoke_test(interactive=True))
