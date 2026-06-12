"""
exceptions.py — GhostDrive exception hierarchy.

Exception Handling Philosophy (Spec §9.6)
==========================================
- NO silent exception swallowing in upload/download/heal pipeline.
- Every exception in a pipeline path MUST:
    (a) retry with backoff if it is a transient network error;
    (b) mark the chunk status as 'failed' and restore quota_reserved if persistent;
    (c) escalate to the telemetry panel as WARN or ERROR.
- ``except Exception: pass`` is a BANNED pattern in all pipeline code.
- Code review must verify this before Month 2 ends.
"""


# ─── Base ─────────────────────────────────────────────────────────────────────

class GhostDriveError(Exception):
    """Base exception for all GhostDrive errors."""


# ─── Cryptographic Errors ─────────────────────────────────────────────────────

class CryptoError(GhostDriveError):
    """Base class for cryptographic errors."""


class KeystoreError(CryptoError):
    """
    Keystore-related errors.
    Examples: file not found, version mismatch, bad JSON, state machine violation.
    """


class AuthenticationError(CryptoError):
    """
    Authentication tag verification FAILED.

    Indicates chunk corruption, tampering, wrong decryption key, or wrong nonce.

    CRITICAL: Code raising this exception MUST NOT have returned or yielded
    any decrypted bytes prior to raising. See ChunkDecryptor.verify_and_decrypt().
    """


class NonceExhaustedError(CryptoError):
    """
    Nonce counter overflow.

    With a 96-bit counter this is effectively impossible in practice, but the
    guard is here to make the invariant explicit and testable.
    """


class SeedPhraseError(CryptoError):
    """
    BIP39 seed phrase error.
    Covers: invalid words, wrong word count, checksum mismatch.
    """


# ─── I/O Errors ───────────────────────────────────────────────────────────────

class FileLockError(GhostDriveError):
    """
    File locking error.

    This is INFORMATIONAL — the upload is NOT aborted.
    The file is flagged as 'uploaded-without-integrity-lock' in the index.
    """


class FsyncError(GhostDriveError):
    """
    fsync failure on a critical write.
    Raised when fsyncing a nonce counter, keystore, or WAL checkpoint file fails.
    """


# ─── Pipeline Errors ──────────────────────────────────────────────────────────

class PipelineError(GhostDriveError):
    """Base class for upload/download pipeline errors."""


class ChunkError(PipelineError):
    """Chunk-level error: encryption, assembly, sub-block mismatch."""


class QuotaReservationError(PipelineError):
    """
    Quota reservation failed.
    Raised when the atomic quota_reserved decrement would go negative.
    """


class DedupError(PipelineError):
    """Deduplication logic error."""


class CancellationError(PipelineError):
    """Upload or download was explicitly cancelled by the user."""


# ─── Backend Errors ───────────────────────────────────────────────────────────

class BackendError(GhostDriveError):
    """Base class for backend plugin errors."""


class BackendConnectionError(BackendError):
    """Backend unreachable, DNS failure, or connection timeout."""


class BackendAuthError(BackendError):
    """
    Backend authentication failure.
    Credentials invalid or expired. For Telegram: session expiry is detected
    as a DISTINCT error from generic auth failure (different alert shown).
    """


class TelegramSessionExpiredError(BackendAuthError):
    """
    Telegram MTProto session has expired.
    Triggers manual reauth alert — NOT a generic auth error dialog.
    """


class BackendRateLimitError(BackendError):
    """
    Backend rate limit hit.
    Always retry with exponential backoff. Never surface as a hard failure
    unless the retry budget is exhausted.
    """


class BackendQuotaError(BackendError):
    """
    Backend storage quota exhausted.
    Triggers backend demotion and proactive alert to add more backends.
    """


class BackendNotFoundError(BackendError):
    """Requested chunk not found on backend (HTTP 404 or equivalent)."""


class BackendDuplicateError(BackendError):
    """
    Duplicate filename conflict on backend.
    Specifically: GitHub Releases HTTP 422 on duplicate asset name.
    Handler: delete partial asset, retry with same name.
    """


class BackendEphemeralURLError(BackendError):
    """
    Ephemeral CDN URL has expired (Discord).
    Handler: fetch fresh URL via message_id + channel_id, retry download.
    """


# ─── Database Errors ──────────────────────────────────────────────────────────

class DatabaseError(GhostDriveError):
    """Base class for SQLite/SQLCipher errors."""


class HMACChainError(DatabaseError):
    """
    HMAC ledger chain integrity violation.
    Indicates the index has been tampered with or is corrupted.
    """


class LamportClockError(DatabaseError):
    """Lamport clock consistency error in concurrent batch operations."""


class WALCheckpointError(DatabaseError):
    """WAL checkpoint failed during index snapshot."""


# ─── GUI Errors ───────────────────────────────────────────────────────────────

class GUIError(GhostDriveError):
    """Base class for GUI-layer errors."""


class IndexBootstrapError(GhostDriveError):
    """
    Cold-start index bootstrap failed.
    All configured backends exhausted with no valid snapshot found.
    """
