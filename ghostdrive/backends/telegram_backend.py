"""
telegram_backend.py -- GhostDrive Telegram Backend Plugin.

Spec §6.2 -- Telegram
=====================
Tier:              CRITICAL
Free tier:         Unlimited
Logical chunk:     1.5 GB
Sub-block:         50 MB
Session storage:   OS keyring (DPAPI/libsecret/Keychain) via keyring library
                   NOT stored in ghostdrive.db or any plaintext file (Spec §4.5)
Flood wait:        Automatic handler with exponential backoff
Session expiry:    Detected as DISTINCT error from generic auth failure.
                   Triggers manual reauth alert (not a generic auth error dialog).
Dedicated account: Spec requires a dedicated Telegram account, NOT the user's
                   personal account, to avoid accidental deletion of chunks.

Upload flow (per sub-block)
---------------------------
  1. caller: quota_reserved decremented atomically (backends table)
  2. caller: pending intent written to chunk_locations + fsynced
  3. THIS MODULE: stream -> send_file("me", ..., force_document=True)
  4. caller: on success -> status=confirmed, quota_used incremented
  5. caller: on failure -> status=failed, quota_reserved restored

Download flow
-------------
  1. get_messages("me", ids=message_id) -> fetch message by stored message_id
  2. download_media(msg, file=bytes) -> returns encrypted bytes
  3. caller verifies Poly1305 tag BEFORE passing bytes to decryptor

Session management
------------------
  The Telethon session string is stored in OS keyring, NOT in a .session file.
  On first run: authenticate via phone OTP, extract session string, store in keyring.
  On subsequent runs: load session string from keyring, skip OTP.
  Key: service="ghostdrive", username="telegram_session"

Flood wait handling (Spec §6.2)
--------------------------------
  FloodWaitError: wait exactly flood_wait.seconds + 5 s jitter, then retry.
  Max retries: 5 per sub-block before escalating to BackendRateLimitError.
  The retry counter is per-operation, not per-session.

Session expiry detection
------------------------
  SessionExpiredError, AuthKeyError, AuthKeyDuplicatedError from Telethon
  -> TelegramSessionExpiredError (distinct from generic BackendAuthError)
  -> GUI shows "Telegram session expired -- please re-authenticate" alert
  -> NOT the generic "authentication failed" dialog
"""

from __future__ import annotations

import asyncio
import io
import logging
import time
from typing import AsyncGenerator, Optional

logger = logging.getLogger(__name__)

try:
    from telethon import TelegramClient, errors as tl_errors
    from telethon.tl.types import DocumentAttributeFilename
    _TELETHON_AVAILABLE = True
except ImportError:
    _TELETHON_AVAILABLE = False

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
    BackendQuotaError,
    TelegramSessionExpiredError,
)

# ── Constants ─────────────────────────────────────────────────────────────────

# Spec §5.4 -- Telegram chunk/sub-block sizes
LOGICAL_CHUNK_BYTES = 1_500 * 1024 * 1024   # 1.5 GB
SUB_BLOCK_BYTES     =    50 * 1024 * 1024   # 50 MB

# Flood wait
_FLOOD_WAIT_MAX_RETRIES = 5
_FLOOD_WAIT_JITTER_S    = 5

# OS keyring keys for session storage (Spec §4.5)
_KEYRING_SERVICE  = "ghostdrive"
_KEYRING_ACCOUNT  = "telegram_session"

# Telegram Saved Messages target (upload to own account)
_SAVED_MESSAGES = "me"

# Caption prefix for all uploaded sub-blocks (for identification / cleanup)
_CAPTION_PREFIX = "GhostDrive"


class TelegramBackend(BackendBase):
    """
    GhostDrive Telegram backend plugin.

    Implements the BackendBase interface for Telegram using Telethon (MTProto).

    Usage
    -----
        backend = TelegramBackend(api_id=..., api_hash=...)
        await backend.connect()
        ref_id = await backend.upload(stream, chunk_id="uuid", sub_block_index=0)
        async for block in backend.download(ref_id):
            ...
        await backend.disconnect()

    Session lifecycle
    -----------------
    Session string is stored in and loaded from OS keyring.
    Use ``first_run_authenticate()`` to perform the initial OTP authentication
    and persist the session to keyring. Subsequent ``connect()`` calls load
    from keyring automatically.
    """

    # ── Capability flags (Spec §6.1) ─────────────────────────────────────────
    supports_range_requests: bool = False
    supports_streaming:      bool = True
    supports_deletion:       bool = True
    is_cold_storage:         bool = False
    is_ephemeral_url:        bool = False
    ml_artifacts_only:       bool = False
    cpu_intensive:           bool = False
    tier:                    str  = "CRITICAL"

    logical_chunk_bytes: int = LOGICAL_CHUNK_BYTES
    sub_block_bytes:     int = SUB_BLOCK_BYTES

    def __init__(
        self,
        api_id: int,
        api_hash: str,
        phone: Optional[str] = None,
    ) -> None:
        """
        Args:
            api_id:   Telegram API ID (from https://my.telegram.org).
                      Loaded from OS keyring via credentials_ref -- NOT
                      stored in ghostdrive.db or passed in plaintext at
                      runtime. Passed here for the initial first_run only.
            api_hash: Telegram API hash.
            phone:    Phone number for OTP (first_run_authenticate() only).
                      NOT stored after session creation.
        """
        if not _TELETHON_AVAILABLE:
            raise ImportError(
                "Telethon is required for the Telegram backend. "
                "Run: pip install telethon"
            )

        self._api_id   = api_id
        self._api_hash = api_hash
        self._phone    = phone
        self._client: Optional[TelegramClient] = None

    # ── Connection lifecycle ──────────────────────────────────────────────────

    async def connect(self) -> None:
        """
        Connect to Telegram using a session string from OS keyring.

        Raises:
            TelegramSessionExpiredError: Session string in keyring is expired.
            BackendAuthError:            No session in keyring (use first_run_authenticate).
            BackendConnectionError:      Network unreachable.
        """
        session_string = self._load_session_from_keyring()

        if session_string is None:
            raise BackendAuthError(
                "No Telegram session found in OS keyring. "
                "Run first_run_authenticate() to set up the session."
            )

        try:
            from telethon.sessions import StringSession
            self._client = TelegramClient(
                StringSession(session_string),
                self._api_id,
                self._api_hash,
            )
            await self._client.connect()

            if not await self._client.is_user_authorized():
                raise TelegramSessionExpiredError(
                    "Telegram session has expired. Please re-authenticate. "
                    "This is a SESSION EXPIRY -- not a wrong password."
                )

            me = await self._client.get_me()
            logger.info("Telegram backend connected as @%s", me.username or me.first_name)

        except tl_errors.SessionExpiredError as exc:
            raise TelegramSessionExpiredError(
                "Telegram MTProto session expired."
            ) from exc
        except tl_errors.AuthKeyError as exc:
            raise TelegramSessionExpiredError(
                "Telegram auth key invalid (possible account security action)."
            ) from exc
        except (tl_errors.FloodWaitError, ConnectionError, OSError) as exc:
            raise BackendConnectionError(
                f"Telegram connection failed: {exc}"
            ) from exc

    async def first_run_authenticate(self, phone: Optional[str] = None) -> None:
        """
        Perform the initial phone OTP authentication and persist session to keyring.

        This is called ONCE during the first-run wizard. After this call,
        ``connect()`` loads the session from keyring automatically.

        Args:
            phone: Phone number (uses self._phone if not provided).

        Raises:
            BackendAuthError:      Authentication failed.
            BackendConnectionError: Network unreachable.
        """
        phone = phone or self._phone
        if not phone:
            raise BackendAuthError("Phone number required for first-run authentication.")

        from telethon.sessions import StringSession

        self._client = TelegramClient(
            StringSession(),  # Fresh empty session
            self._api_id,
            self._api_hash,
        )

        try:
            await self._client.start(phone=phone)
            session_string = self._client.session.save()
            self._save_session_to_keyring(session_string)

            me = await self._client.get_me()
            logger.info(
                "Telegram first-run auth complete. Signed in as @%s. "
                "Session stored in OS keyring.",
                me.username or me.first_name,
            )

        except tl_errors.PhoneCodeInvalidError as exc:
            raise BackendAuthError("Invalid Telegram OTP code.") from exc
        except tl_errors.PhoneNumberBannedError as exc:
            raise BackendAuthError("Telegram account is banned.") from exc
        except (ConnectionError, OSError) as exc:
            raise BackendConnectionError(f"Telegram auth connection failed: {exc}") from exc

    async def disconnect(self) -> None:
        """Cleanly disconnect from Telegram."""
        if self._client and self._client.is_connected():
            await self._client.disconnect()
            self._client = None
            logger.debug("Telegram backend disconnected.")

    # ── BackendBase interface ─────────────────────────────────────────────────

    async def upload(
        self,
        stream: AsyncGenerator[bytes, None],
        chunk_id: str,
        sub_block_index: int,
    ) -> str:
        """
        Upload one sub-block to Telegram Saved Messages.

        Consumes the async bytes generator, assembles into an in-memory
        buffer (sub-blocks are at most 50 MB -- fits comfortably), and
        uploads as a raw document (force_document=True) to Saved Messages.

        The filename encodes chunk_id + sub_block_index for later retrieval.
        message_id is the reference_id returned to the pipeline.

        Args:
            stream:          Async generator yielding encrypted bytes.
            chunk_id:        UUIDv4 string.
            sub_block_index: 0-based sub-block index.

        Returns:
            str(message_id) -- stored in chunk_locations.reference_id.
        """
        self._assert_connected()

        # Assemble stream into buffer (50 MB sub-block max)
        buf = io.BytesIO()
        async for block in stream:
            buf.write(block)
        buf.seek(0)

        # Filename encodes identity for retrieval and debugging
        filename = f"gd_{chunk_id}_{sub_block_index:04d}.enc"
        caption  = f"{_CAPTION_PREFIX} {chunk_id[:8]} sub-block {sub_block_index}"

        message = await self._upload_with_flood_wait(buf, filename, caption)

        logger.info(
            "Telegram upload OK: chunk=%s sub_block=%d message_id=%d size=%d",
            chunk_id[:8], sub_block_index, message.id, buf.tell(),
        )
        return str(message.id)

    async def download(self, reference_id: str) -> AsyncGenerator[bytes, None]:
        """
        Download a sub-block from Telegram by message_id.

        Args:
            reference_id: str(message_id) returned by upload().

        Yields:
            Raw encrypted bytes (exactly as uploaded).

        Raises:
            BackendNotFoundError: Message not found (deleted externally).
            BackendConnectionError: Network error.
        """
        self._assert_connected()

        message_id = int(reference_id)

        try:
            message = await self._client.get_messages(_SAVED_MESSAGES, ids=message_id)
        except (ConnectionError, OSError) as exc:
            raise BackendConnectionError(f"Telegram download failed: {exc}") from exc

        if message is None or message.document is None:
            raise BackendNotFoundError(
                f"Telegram message {message_id} not found or has no document. "
                "The chunk may have been deleted externally."
            )

        logger.debug("Telegram: downloading message_id=%d", message_id)

        data = await self._download_with_flood_wait(message)

        # Yield as a single chunk (the pipeline reassembles sub-blocks)
        yield data

    async def delete(self, reference_id: str) -> bool:
        """
        Delete a sub-block from Telegram Saved Messages.

        Called only after the 24 h tombstone window (CRITICAL tier) or
        immediately for DISPOSABLE files.

        Args:
            reference_id: str(message_id).

        Returns:
            True if deleted, False if message already gone (idempotent).
        """
        self._assert_connected()

        message_id = int(reference_id)

        try:
            result = await self._client.delete_messages(_SAVED_MESSAGES, [message_id])
            deleted_count = sum(r.pts_count for r in result) if result else 0
            if deleted_count > 0:
                logger.info("Telegram: deleted message_id=%d", message_id)
                return True
            else:
                logger.warning(
                    "Telegram: delete message_id=%d returned 0 pts_count (already deleted?)",
                    message_id,
                )
                return False
        except (ConnectionError, OSError) as exc:
            raise BackendConnectionError(f"Telegram delete failed: {exc}") from exc

    async def health_check(self) -> HealthResult:
        """
        Check Telegram connectivity and session validity.

        Does NOT check storage quota (Telegram is unlimited).
        Measures latency of a get_me() call.

        Returns:
            HealthResult(reachable, quota_remaining=None, latency_ms).
        """
        if self._client is None or not self._client.is_connected():
            return HealthResult(reachable=False, error="Not connected")

        try:
            t0 = time.perf_counter()
            await self._client.get_me()
            latency_ms = (time.perf_counter() - t0) * 1000

            return HealthResult(reachable=True, quota_remaining=None, latency_ms=latency_ms)

        except tl_errors.SessionExpiredError as exc:
            raise TelegramSessionExpiredError("Session expired during health check.") from exc
        except (ConnectionError, OSError) as exc:
            return HealthResult(reachable=False, error=str(exc))

    async def available_space(self) -> int:
        """
        Telegram has no storage quota -- return a large sentinel value.

        The pipeline uses this to decide whether to skip this backend.
        Returning maxint signals "effectively unlimited".
        """
        return 2 ** 62   # ~4.6 EB -- effectively unlimited

    # ── Flood wait helpers ────────────────────────────────────────────────────

    async def _upload_with_flood_wait(
        self,
        buf: io.BytesIO,
        filename: str,
        caption: str,
    ):
        """
        Upload with automatic flood wait retry (Spec §6.2).

        Retries up to _FLOOD_WAIT_MAX_RETRIES times. Each retry waits
        exactly flood_wait.seconds + _FLOOD_WAIT_JITTER_S seconds.
        """
        for attempt in range(_FLOOD_WAIT_MAX_RETRIES + 1):
            try:
                buf.seek(0)
                return await self._client.send_file(
                    _SAVED_MESSAGES,
                    buf,
                    caption=caption,
                    attributes=[DocumentAttributeFilename(file_name=filename)],
                    force_document=True,   # NEVER compress -- preserve exact bytes
                )
            except tl_errors.FloodWaitError as exc:
                if attempt >= _FLOOD_WAIT_MAX_RETRIES:
                    raise BackendRateLimitError(
                        f"Telegram flood wait exceeded max retries ({_FLOOD_WAIT_MAX_RETRIES}). "
                        f"Last wait was {exc.seconds}s."
                    ) from exc
                wait = exc.seconds + _FLOOD_WAIT_JITTER_S
                logger.warning(
                    "Telegram FloodWaitError: waiting %ds (attempt %d/%d)",
                    wait, attempt + 1, _FLOOD_WAIT_MAX_RETRIES,
                )
                await asyncio.sleep(wait)
            except tl_errors.SessionExpiredError as exc:
                raise TelegramSessionExpiredError("Session expired during upload.") from exc
            except (ConnectionError, OSError) as exc:
                raise BackendConnectionError(f"Telegram upload network error: {exc}") from exc

    async def _download_with_flood_wait(self, message) -> bytes:
        """Download with flood wait retry."""
        for attempt in range(_FLOOD_WAIT_MAX_RETRIES + 1):
            try:
                return await self._client.download_media(message, file=bytes)
            except tl_errors.FloodWaitError as exc:
                if attempt >= _FLOOD_WAIT_MAX_RETRIES:
                    raise BackendRateLimitError(
                        f"Telegram flood wait exceeded max retries. Last: {exc.seconds}s."
                    ) from exc
                wait = exc.seconds + _FLOOD_WAIT_JITTER_S
                logger.warning("Telegram FloodWaitError on download: waiting %ds", wait)
                await asyncio.sleep(wait)
            except tl_errors.SessionExpiredError as exc:
                raise TelegramSessionExpiredError("Session expired during download.") from exc
            except (ConnectionError, OSError) as exc:
                raise BackendConnectionError(f"Telegram download network error: {exc}") from exc

    # ── Session keyring helpers (Spec §4.5) ──────────────────────────────────

    def _save_session_to_keyring(self, session_string: str) -> None:
        """
        Store the Telethon session string in OS keyring.

        Platform:  Windows -> DPAPI, Linux -> libsecret, macOS -> Keychain.
        Falls back to a warning if keyring is unavailable (no plaintext fallback
        for session -- user must re-authenticate on next run in that case).
        """
        if not _KEYRING_AVAILABLE:
            logger.error(
                "keyring library not available. Telegram session NOT persisted. "
                "Install it: pip install keyring"
            )
            return

        _keyring.set_password(_KEYRING_SERVICE, _KEYRING_ACCOUNT, session_string)
        logger.info("Telegram session saved to OS keyring (%s / %s)", _KEYRING_SERVICE, _KEYRING_ACCOUNT)

    def _load_session_from_keyring(self) -> Optional[str]:
        """
        Load the Telethon session string from OS keyring.

        Returns:
            Session string, or None if not found.
        """
        if not _KEYRING_AVAILABLE:
            logger.error("keyring library not available. Cannot load Telegram session.")
            return None

        session = _keyring.get_password(_KEYRING_SERVICE, _KEYRING_ACCOUNT)
        if session:
            logger.debug("Telegram session loaded from OS keyring.")
        return session

    def _delete_session_from_keyring(self) -> None:
        """Remove the session from keyring (e.g. after session expiry)."""
        if _KEYRING_AVAILABLE:
            try:
                _keyring.delete_password(_KEYRING_SERVICE, _KEYRING_ACCOUNT)
                logger.info("Telegram session deleted from OS keyring.")
            except Exception:
                pass

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _assert_connected(self) -> None:
        """Raise BackendConnectionError if not connected."""
        if self._client is None or not self._client.is_connected():
            raise BackendConnectionError(
                "TelegramBackend is not connected. Call connect() first."
            )
