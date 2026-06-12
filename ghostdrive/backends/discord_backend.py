"""
discord_backend.py -- GhostDrive Discord Backend Plugin.

Spec §6.2 -- Discord
=====================
Tier:              IMPORTANT
Free tier:         Unlimited storage
Logical chunk:     24 MB
Sub-block:         24 MB (same -- Discord sends whole attachments)
is_ephemeral_url:  True -- CDN URLs expire; message_id + channel_id stored
Capability flags:  NOT cold_storage, NOT ml_artifacts_only, NOT cpu_intensive
ToS risk:          Experimental label (spec §6.2 note)

Discord-specific constraints (June 2025)
-----------------------------------------
- Max attachment per message: 10 MB (10,485,760 bytes hard limit)
- Operational chunk size: 8 MB (headroom for multipart overhead)
- Logical chunk cap in spec: 24 MB (split into 3 × 8 MB sub-blocks)
- Sub-block = 1 Discord message with 1 attachment
- CDN URLs expire after ~24 h when accessed outside Discord
- Bot rate limit: ~5 messages / 5 s on free bots -> inter-upload delay

Ephemeral URL pattern (spec §6.1 -- is_ephemeral_url=True)
------------------------------------------------------------
- reference_id stores: "{message_id}:{channel_id}" (colon-separated string)
- On download: fetch fresh CDN URL via Discord API (message_id + channel_id)
- NEVER cache the raw CDN URL -- it expires

Rate limit handling (spec §6.2)
---------------------------------
- 429 HTTPException from discord.py -> wait Retry-After header + jitter
- Max retries: _RATE_LIMIT_MAX_RETRIES (5) before BackendRateLimitError
- 413 Payload Too Large -> reduce sub-block size, raise BackendConnectionError

Session storage (spec §4.5)
----------------------------
- Bot token stored in OS keyring (DPAPI/libsecret/Keychain)
  service="ghostdrive", account="discord_bot_token"
- Channel ID stored in OS keyring: account="discord_channel_id"
- ghostdrive.db backends table: credentials_ref only, never the token
"""

from __future__ import annotations

import asyncio
import io
import logging
import time
from typing import AsyncGenerator, Optional

logger = logging.getLogger(__name__)

try:
    import discord
    import aiohttp
    _DISCORD_AVAILABLE = True
except ImportError:
    _DISCORD_AVAILABLE = False

try:
    import keyring as _keyring
    _KEYRING_AVAILABLE = True
except ImportError:
    _KEYRING_AVAILABLE = False

from ghostdrive.backends.base import BackendBase, HealthResult
from ghostdrive.exceptions import (
    BackendAuthError,
    BackendConnectionError,
    BackendNotFoundError,
    BackendRateLimitError,
)

# ── Constants (spec §5.4, §6.2) ───────────────────────────────────────────────

# Discord hard limit: 10,485,760 bytes. Operational: 8 MB (headroom for overhead)
DISCORD_HARD_LIMIT_BYTES  = 10 * 1024 * 1024     # 10 MB absolute ceiling
OPERATIONAL_SUB_BLOCK_BYTES = 8 * 1024 * 1024    # 8 MB -- safe operational limit

# Spec §5.4: logical chunk = 24 MB, sub-block = 24 MB
# Each sub-block is one Discord attachment (max OPERATIONAL_SUB_BLOCK_BYTES)
LOGICAL_CHUNK_BYTES = 24 * 1024 * 1024            # 24 MB
SUB_BLOCK_BYTES     = OPERATIONAL_SUB_BLOCK_BYTES  # 8 MB per attachment

# Rate limit
_RATE_LIMIT_MAX_RETRIES = 5
_RATE_LIMIT_JITTER_S    = 0.5
_INTER_UPLOAD_DELAY_S   = 1.2    # conservative inter-attachment delay

# OS keyring keys (spec §4.5)
_KEYRING_SERVICE       = "ghostdrive"
_KEYRING_ACCOUNT_TOKEN = "discord_bot_token"
_KEYRING_ACCOUNT_CHAN  = "discord_channel_id"

# reference_id format: "{message_id}:{channel_id}"
_REF_SEP = ":"


def _make_ref(message_id: int, channel_id: int) -> str:
    return f"{message_id}{_REF_SEP}{channel_id}"


def _parse_ref(reference_id: str) -> tuple[int, int]:
    parts = reference_id.split(_REF_SEP, 1)
    return int(parts[0]), int(parts[1])


class _GhostDriveDiscordClient(discord.Client):
    """Internal discord.py Client subclass with a ready event."""

    def __init__(self, **kwargs):
        intents = discord.Intents.default()
        intents.message_content = True
        super().__init__(intents=intents, **kwargs)
        self.ready_event = asyncio.Event()

    async def on_ready(self):
        self.ready_event.set()
        logger.info("Discord backend connected as %s (id=%s)", self.user, self.user.id)


class DiscordBackend(BackendBase):
    """
    GhostDrive Discord backend plugin.

    Implements the BackendBase interface. Stores message_id + channel_id as
    reference_id (is_ephemeral_url=True -- fetches fresh CDN URL on download).

    Usage::

        backend = DiscordBackend(channel_id=...)
        await backend.connect()
        ref_id = await backend.upload(stream, chunk_id="uuid", sub_block_index=0)
        async for block in backend.download(ref_id):
            ...
        await backend.disconnect()

    Bot token is loaded from OS keyring. Use ``store_credentials()`` on first run.
    """

    # ── Capability flags (spec §6.1, §6.2) ───────────────────────────────────
    supports_range_requests: bool = False
    supports_streaming:      bool = False   # Discord sends whole attachments
    supports_deletion:       bool = True
    is_cold_storage:         bool = False
    is_ephemeral_url:        bool = True    # CDN URLs expire -- key spec property
    ml_artifacts_only:       bool = False
    cpu_intensive:           bool = False
    tier:                    str  = "IMPORTANT"

    logical_chunk_bytes: int = LOGICAL_CHUNK_BYTES
    sub_block_bytes:     int = SUB_BLOCK_BYTES

    def __init__(
        self,
        channel_id: Optional[int] = None,
        bot_token: Optional[str]  = None,
    ) -> None:
        """
        Args:
            channel_id: Discord channel ID for uploads. Loaded from OS keyring
                        if not provided (after first store_credentials() call).
            bot_token:  Bot token. Loaded from OS keyring if not provided.
        """
        if not _DISCORD_AVAILABLE:
            raise ImportError(
                "discord.py and aiohttp are required for the Discord backend. "
                "Run: pip install discord.py aiohttp"
            )

        self._channel_id  = channel_id
        self._bot_token   = bot_token
        self._client: Optional[_GhostDriveDiscordClient] = None
        self._bot_task: Optional[asyncio.Task] = None

    # ── Connection lifecycle ──────────────────────────────────────────────────

    async def connect(self) -> None:
        """
        Connect to Discord using bot token from OS keyring.

        Raises:
            BackendAuthError:       No token in keyring.
            BackendConnectionError: Network unreachable.
        """
        token      = self._bot_token or self._load_token_from_keyring()
        channel_id = self._channel_id or self._load_channel_from_keyring()

        if not token:
            raise BackendAuthError(
                "No Discord bot token found in OS keyring. "
                "Call store_credentials(token, channel_id) first."
            )
        if not channel_id:
            raise BackendAuthError(
                "No Discord channel_id found in OS keyring. "
                "Call store_credentials(token, channel_id) first."
            )

        self._channel_id = channel_id
        self._client     = _GhostDriveDiscordClient()

        # Start the bot in a background task (discord.py event loop requirement)
        loop = asyncio.get_event_loop()
        self._bot_task = loop.create_task(self._client.start(token))

        try:
            await asyncio.wait_for(self._client.ready_event.wait(), timeout=30)
        except asyncio.TimeoutError as exc:
            raise BackendConnectionError(
                "Discord bot failed to connect within 30s."
            ) from exc

        logger.info("Discord backend connected.")

    async def disconnect(self) -> None:
        """Cleanly close the Discord connection."""
        if self._client:
            await self._client.close()
            self._client = None
        if self._bot_task:
            self._bot_task.cancel()
            try:
                await self._bot_task
            except (asyncio.CancelledError, Exception):
                pass
            self._bot_task = None
        logger.debug("Discord backend disconnected.")

    # ── First-run credential storage (spec §4.5) ─────────────────────────────

    def store_credentials(self, bot_token: str, channel_id: int) -> None:
        """
        Store bot token and channel_id in OS keyring.
        Called once during the first-run wizard. Subsequent connect() calls
        load from keyring automatically.
        """
        if not _KEYRING_AVAILABLE:
            logger.error("keyring library not available. Discord credentials NOT persisted.")
            return

        _keyring.set_password(_KEYRING_SERVICE, _KEYRING_ACCOUNT_TOKEN, bot_token)
        _keyring.set_password(_KEYRING_SERVICE, _KEYRING_ACCOUNT_CHAN, str(channel_id))
        logger.info("Discord credentials stored in OS keyring.")

    def _load_token_from_keyring(self) -> Optional[str]:
        if not _KEYRING_AVAILABLE:
            return None
        return _keyring.get_password(_KEYRING_SERVICE, _KEYRING_ACCOUNT_TOKEN)

    def _load_channel_from_keyring(self) -> Optional[int]:
        if not _KEYRING_AVAILABLE:
            return None
        val = _keyring.get_password(_KEYRING_SERVICE, _KEYRING_ACCOUNT_CHAN)
        return int(val) if val else None

    # ── BackendBase interface ─────────────────────────────────────────────────

    async def upload(
        self,
        stream: AsyncGenerator[bytes, None],
        chunk_id: str,
        sub_block_index: int,
    ) -> str:
        """
        Upload one sub-block to Discord as a message attachment.

        Enforces 10 MB hard limit before attempting upload.
        Stores reference_id as "{message_id}:{channel_id}" (ephemeral URL pattern).
        Includes inter-upload delay to avoid Discord rate limiting.

        Args:
            stream:          Async generator yielding encrypted bytes.
            chunk_id:        UUIDv4 string (used in filename for traceability).
            sub_block_index: 0-based index.

        Returns:
            "{message_id}:{channel_id}" -- stored in chunk_locations.reference_id.
        """
        self._assert_connected()

        # Assemble sub-block from stream
        buf = io.BytesIO()
        async for block in stream:
            buf.write(block)
        size = buf.tell()

        # Hard enforcement before touching the network
        if size > DISCORD_HARD_LIMIT_BYTES:
            raise BackendConnectionError(
                f"Sub-block is {size:,} bytes ({size/1024/1024:.1f} MB) -- "
                f"exceeds Discord hard limit of {DISCORD_HARD_LIMIT_BYTES:,} bytes (10 MB). "
                "Reduce sub_block_bytes for the Discord backend."
            )

        buf.seek(0)
        filename = f"gd_{chunk_id[:8]}_{sub_block_index:04d}.enc"
        content  = f"GhostDrive {chunk_id[:8]} sub-block {sub_block_index}"

        channel = self._client.get_channel(self._channel_id)
        if channel is None:
            raise BackendConnectionError(
                f"Discord channel {self._channel_id} not found. "
                "Check CHANNEL_ID and bot permissions."
            )

        message = await self._send_with_rate_limit_retry(
            channel, buf, filename, content, sub_block_index
        )

        ref_id = _make_ref(message.id, channel.id)
        logger.info(
            "Discord upload OK: chunk=%s sub_block=%d message_id=%d size=%d",
            chunk_id[:8], sub_block_index, message.id, size,
        )

        # Inter-upload delay (spec §6.2 -- rate limit protection)
        await asyncio.sleep(_INTER_UPLOAD_DELAY_S)

        return ref_id

    async def download(self, reference_id: str) -> AsyncGenerator[bytes, None]:
        """
        Download a sub-block from Discord.

        Implements the ephemeral URL pattern (is_ephemeral_url=True):
          1. Fetch fresh CDN URL via Discord API using message_id + channel_id.
          2. Download bytes via aiohttp.
          3. Yield the raw bytes.

        The fresh URL is NEVER cached. Always re-fetched at download time.

        Args:
            reference_id: "{message_id}:{channel_id}"

        Yields:
            Raw encrypted bytes.

        Raises:
            BackendNotFoundError: Message deleted from Discord.
            BackendConnectionError: Network or CDN error.
        """
        self._assert_connected()

        message_id, channel_id = _parse_ref(reference_id)

        # Step 1: Fetch fresh CDN URL
        fresh_url = await self._fetch_fresh_cdn_url(message_id, channel_id)
        logger.debug("Discord: downloading message_id=%d via fresh CDN URL", message_id)

        # Step 2: Download via aiohttp
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(fresh_url) as response:
                    if response.status == 404:
                        raise BackendNotFoundError(
                            f"Discord CDN returned 404 for message {message_id}. "
                            "The attachment may have been deleted."
                        )
                    if response.status != 200:
                        raise BackendConnectionError(
                            f"Discord CDN returned HTTP {response.status} "
                            f"for message {message_id}."
                        )
                    data = await response.read()

        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            raise BackendConnectionError(
                f"Discord CDN download failed: {exc}"
            ) from exc

        yield data

    async def delete(self, reference_id: str) -> bool:
        """
        Delete a Discord message (and its attachment) by reference_id.

        Args:
            reference_id: "{message_id}:{channel_id}"

        Returns:
            True if deleted, False if already gone (idempotent).
        """
        self._assert_connected()

        message_id, channel_id = _parse_ref(reference_id)
        channel = self._client.get_channel(channel_id)

        if channel is None:
            logger.warning("Discord delete: channel %d not found.", channel_id)
            return False

        try:
            message = await channel.fetch_message(message_id)
            await message.delete()
            logger.info("Discord: deleted message_id=%d", message_id)
            return True
        except discord.NotFound:
            logger.warning("Discord: message_id=%d already deleted.", message_id)
            return False
        except discord.HTTPException as exc:
            raise BackendConnectionError(
                f"Discord delete failed: {exc}"
            ) from exc

    async def health_check(self) -> HealthResult:
        """
        Check Discord bot connectivity.

        Measures latency of a get_channel() + fetch_message call.
        Discord has no storage quota (unlimited), so quota_remaining=None.
        """
        if self._client is None or not self._client.is_ready():
            return HealthResult(reachable=False, error="Not connected")

        try:
            t0 = time.perf_counter()
            me = await self._client.fetch_user(self._client.user.id)
            latency_ms = (time.perf_counter() - t0) * 1000

            return HealthResult(reachable=True, quota_remaining=None, latency_ms=latency_ms)

        except (discord.HTTPException, Exception) as exc:
            return HealthResult(reachable=False, error=str(exc))

    async def available_space(self) -> int:
        """Discord has no storage quota -- return unlimited sentinel."""
        return 2 ** 62

    # ── Rate limit retry ──────────────────────────────────────────────────────

    async def _send_with_rate_limit_retry(
        self,
        channel,
        buf: io.BytesIO,
        filename: str,
        content: str,
        sub_block_index: int,
    ) -> discord.Message:
        """
        Send an attachment with automatic rate-limit (429) retry.
        On 413 Payload Too Large: raises BackendConnectionError immediately.
        """
        for attempt in range(_RATE_LIMIT_MAX_RETRIES + 1):
            buf.seek(0)
            file_obj = discord.File(
                fp=io.BytesIO(buf.read()),  # copy -- discord.File is consumed on send
                filename=filename,
                description=f"GhostDrive encrypted chunk sub-block {sub_block_index}",
            )
            try:
                return await channel.send(content=content, file=file_obj)

            except discord.HTTPException as exc:
                if exc.status == 429:
                    if attempt >= _RATE_LIMIT_MAX_RETRIES:
                        raise BackendRateLimitError(
                            f"Discord rate limit exceeded max retries ({_RATE_LIMIT_MAX_RETRIES})."
                        ) from exc
                    retry_after = getattr(exc, "retry_after", 2.0) + _RATE_LIMIT_JITTER_S
                    logger.warning(
                        "Discord rate limited: waiting %.1fs (attempt %d/%d)",
                        retry_after, attempt + 1, _RATE_LIMIT_MAX_RETRIES,
                    )
                    await asyncio.sleep(retry_after)

                elif exc.status == 413:
                    raise BackendConnectionError(
                        f"Discord rejected attachment: HTTP 413 Payload Too Large. "
                        f"Sub-block size exceeds Discord's {DISCORD_HARD_LIMIT_BYTES/1024/1024:.0f} MB limit."
                    ) from exc

                else:
                    raise BackendConnectionError(
                        f"Discord upload HTTP error {exc.status}: {exc.text}"
                    ) from exc

    async def _fetch_fresh_cdn_url(self, message_id: int, channel_id: int) -> str:
        """
        Fetch a fresh CDN URL from Discord API (ephemeral URL pattern, spec §6.1).

        Discord always returns a currently-valid CDN URL when fetching a message,
        even if the URL from upload time has expired.

        Raises:
            BackendNotFoundError: Message was deleted from Discord.
            BackendConnectionError: Network error.
        """
        channel = self._client.get_channel(channel_id)
        if channel is None:
            raise BackendConnectionError(
                f"Discord channel {channel_id} not accessible. "
                "Bot may have lost access."
            )

        try:
            message = await channel.fetch_message(message_id)
        except discord.NotFound as exc:
            raise BackendNotFoundError(
                f"Discord message {message_id} not found -- "
                "it may have been deleted externally."
            ) from exc
        except discord.HTTPException as exc:
            raise BackendConnectionError(
                f"Discord API error fetching message {message_id}: {exc}"
            ) from exc

        if not message.attachments:
            raise BackendNotFoundError(
                f"Discord message {message_id} has no attachments -- "
                "attachment may have been removed."
            )

        return message.attachments[0].url

    def _assert_connected(self) -> None:
        """Raise BackendConnectionError if not connected."""
        if self._client is None or not self._client.is_ready():
            raise BackendConnectionError(
                "DiscordBackend is not connected. Call connect() first."
            )
