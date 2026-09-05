"""
telegram_backend.py -- GhostDrive Telegram Backend Plugin.
"""

from __future__ import annotations

import asyncio
import io
import logging
import time
from typing import Any, AsyncGenerator, Optional

from ghostdrive.backends.base import BackendBase, HealthResult
from ghostdrive.exceptions import (
    BackendAuthError,
    BackendConnectionError,
    BackendNotFoundError,
    BackendRateLimitError,
    TelegramSessionExpiredError,
)

logger = logging.getLogger(__name__)

try:
    from telethon import TelegramClient, errors as tl_errors  # type: ignore
    from telethon.tl.types import DocumentAttributeFilename  # type: ignore
    _TELETHON_AVAILABLE = True
except ImportError:
    _TELETHON_AVAILABLE = False

try:
    import keyring as _keyring  # type: ignore
    _KEYRING_AVAILABLE = True
except ImportError:
    _KEYRING_AVAILABLE = False


LOGICAL_CHUNK_BYTES = 1_500 * 1024 * 1024
SUB_BLOCK_BYTES     =    50 * 1024 * 1024

_FLOOD_WAIT_MAX_RETRIES = 5
_FLOOD_WAIT_JITTER_S    = 5

_KEYRING_SERVICE  = "ghostdrive"
_KEYRING_ACCOUNT  = "telegram_session"
_SAVED_MESSAGES = "me"
_CAPTION_PREFIX = "GhostDrive"


class TelegramBackend(BackendBase):
    """
    GhostDrive Telegram backend plugin.
    Implements the BackendBase interface for Telegram using Telethon (MTProto).
    """

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
        api_id: Optional[int] = None,
        api_hash: Optional[str] = None,
        phone: Optional[str] = None,
        _skip_keyring: bool = False,
    ) -> None:
        """
        Args:
            api_id:        Telegram API ID. Loaded from credential_store if not provided.
            api_hash:      Telegram API hash. Loaded from credential_store if not provided.
            phone:         Phone number for OTP. NOT stored after session creation.
            _skip_keyring: If True, skip keyring lookup (credentials already resolved by caller).
        """
        if not _TELETHON_AVAILABLE:
            raise ImportError(
                "Telethon is required for the Telegram backend. "
                "Run: pip install telethon"
            )

        self._api_id   = api_id
        self._api_hash = api_hash
        self._phone    = phone

        if not _skip_keyring:
            # Load from the process-global credential_store (decrypts from OS Keyring)
            try:
                from ghostdrive.crypto.credential_store import credential_store
                if self._api_id is None:
                    val = credential_store.load("telegram_api_id")
                    self._api_id = int(val) if val and val.isdigit() else None
                if self._api_hash is None:
                    self._api_hash = credential_store.load("telegram_api_hash")
                if self._phone is None:
                    self._phone = credential_store.load("telegram_phone")
            except Exception as exc:
                logger.warning("TelegramBackend: credential_store lookup failed: %s", exc)

        self._client: Optional[TelegramClient] = None
        self._session_str: Optional[str] = None

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

    async def first_run_authenticate(
        self,
        phone: Optional[str] = None,
        code_callback: Optional[Any] = None,
        password_callback: Optional[Any] = None,
    ) -> None:
        """
        Perform the initial phone OTP authentication and persist session to keyring.

        This is called ONCE during the first-run wizard. After this call,
        ``connect()`` loads the session from keyring automatically.

        Args:
            phone:             Phone number (uses self._phone if not provided).
            code_callback:     Optional callback/coroutine to fetch the OTP code.
            password_callback: Optional callback/coroutine to fetch the 2FA password.

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
            await self._client.start(  # type: ignore
                phone=phone,
                code_callback=code_callback,
                password=password_callback,
            )
            session_string = self._client.session.save()
            self._session_str = session_string
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
            await self._client.disconnect()  # type: ignore
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
        size = buf.tell()
        buf.seek(0)

        # Filename encodes identity for retrieval and debugging
        filename = f"gd_{chunk_id}_{sub_block_index:04d}.enc"
        caption  = f"{_CAPTION_PREFIX} {chunk_id[:8]} sub-block {sub_block_index}"

        message = await self._upload_with_flood_wait(buf, filename, caption)

        logger.info(
            "Telegram upload OK: chunk=%s sub_block=%d message_id=%d size=%d",
            chunk_id[:8], sub_block_index, message.id, size,
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
        Encrypt and store the Telethon session string via the process-global
        credential_store (AES-256-GCM + OS Keyring).

        Falls back to a warning if the store is locked — no plaintext fallback.
        """
        try:
            from ghostdrive.crypto.credential_store import credential_store
            credential_store.store(_KEYRING_ACCOUNT, session_string)
            logger.info("Telegram session encrypted and saved to OS keyring (%s / %s)",
                        _KEYRING_SERVICE, _KEYRING_ACCOUNT)
        except Exception as exc:
            logger.error(
                "Failed to save Telegram session to credential_store: %s. "
                "Session will NOT be persisted.", exc
            )

    def _load_session_from_keyring(self) -> Optional[str]:
        """
        Decrypt and load the Telethon session string from the OS Keyring
        via the process-global credential_store.

        Returns:
            Plaintext session string, or None if not found or store locked.
        """
        try:
            from ghostdrive.crypto.credential_store import credential_store
            session = credential_store.load(_KEYRING_ACCOUNT)
            if session:
                logger.debug("Telegram session loaded from credential_store.")
            return session
        except Exception as exc:
            logger.error("Failed to load Telegram session from credential_store: %s", exc)
            return None

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
