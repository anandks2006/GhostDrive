"""
nonce.py — Nonce management for ChaCha20-Poly1305 chunk encryption.

Spec §4.4 — Critical Cryptographic Rules (Nonce Counter)
=========================================================
  "Nonce counter: incremented BEFORE the chunk upload begins, not after it
   confirms. A wasted nonce from a failed upload is acceptable. A reused
   nonce from crash-before-increment is catastrophic under ChaCha20-Poly1305."

  "Nonce counter increment and the operation it timestamps must be in the same
   SQLite transaction — atomic with the write they protect."

Month 1 Implementation Notes
-----------------------------
In Month 1 (before the SQLite database layer arrives in Month 2), nonces are
persisted to a JSON file using ``atomic_write()`` + fsync. This ensures the
counter survives crashes.

In Month 2, ``NonceManager`` will be replaced by a database-backed
implementation where the nonce counter increment is inside the same SQLite
transaction as the chunk's ``pending`` intent record. The interface is
intentionally identical so all call sites need no changes.
"""

import json
import os
from pathlib import Path
from typing import Optional

from ghostdrive.exceptions import CryptoError, NonceExhaustedError
from ghostdrive.utils.fsync import atomic_write

# 12-byte (96-bit) nonce — the maximum for ChaCha20-Poly1305
# 2^96 nonces is effectively inexhaustible in practice.
NONCE_BYTES = 12
MAX_NONCE_COUNTER = (2 ** 96) - 1
_COUNTER_FILENAME = "nonce_counter.json"


class NonceManager:
    """
    Monotonic nonce counter for ChaCha20-Poly1305 chunk encryption.

    Contract
    --------
    - Counter starts at 0 in a fresh installation.
    - ``next_nonce()`` increments the counter and persists it BEFORE returning.
    - Counters are strictly increasing; a counter value is NEVER reused.
    - On restart, the counter resumes from the last persisted value (never
      goes backward).

    Thread Safety
    -------------
    Not thread-safe internally. The caller (pipeline/upload.py) is responsible
    for serialising calls to ``next_nonce()`` per installation.
    In Month 2 the database transaction provides the serialisation guarantee.
    """

    def __init__(self, data_dir: Path) -> None:
        """
        Args:
            data_dir: Directory where ``nonce_counter.json`` is stored.
                      This should be the GhostDrive app-data directory.
        """
        self._data_dir = Path(data_dir)
        self._counter_path = self._data_dir / _COUNTER_FILENAME
        self._counter: Optional[int] = None  # Loaded lazily on first use

    # ─── Public interface ──────────────────────────────────────────────────────

    def next_nonce(self) -> bytes:
        """
        Increment the nonce counter, persist it (fsync), and return the nonce.

        CRITICAL ORDER OF OPERATIONS:
          1. Read current counter from disk (if not cached)
          2. Increment counter
          3. Persist incremented counter to disk (atomic write + fsync)
          4. Return nonce bytes

        Steps 3 and 4 are in this order intentionally. If the process crashes
        after step 3 but before upload, the nonce is wasted (acceptable). If the
        process crashes before step 3, the counter has not advanced and will be
        read correctly on restart (no reuse possible).

        Returns:
            12-byte big-endian nonce derived from the incremented counter.

        Raises:
            NonceExhaustedError: If counter would overflow 96 bits (unreachable
                                  in practice; here for correctness).
            FsyncError: If the counter cannot be persisted to disk.
        """
        if self._counter is None:
            self._counter = self._load_counter()

        # Increment BEFORE returning (and BEFORE upload starts)
        new_counter = self._counter + 1

        if new_counter > MAX_NONCE_COUNTER:
            raise NonceExhaustedError(
                "Nonce counter overflow — 2^96 nonces exhausted. "
                "This is effectively impossible in practice."
            )

        # Persist atomically with fsync BEFORE returning the nonce
        self._persist_counter(new_counter)

        # Only update in-memory cache after successful persist
        self._counter = new_counter

        return self._counter_to_bytes(new_counter)

    def peek_counter(self) -> int:
        """
        Return the current counter value without incrementing.
        Loads from disk on first call.
        """
        if self._counter is None:
            self._counter = self._load_counter()
        return self._counter

    # ─── Static helpers ───────────────────────────────────────────────────────

    @staticmethod
    def counter_to_nonce(counter: int) -> bytes:
        """Convert an integer counter to a 12-byte big-endian nonce."""
        if not isinstance(counter, int) or counter <= 0 or counter > MAX_NONCE_COUNTER:
            raise CryptoError(
                f"Invalid nonce counter: {counter!r}. "
                f"Must be a positive integer ≤ 2^96-1."
            )
        return counter.to_bytes(NONCE_BYTES, "big")

    @staticmethod
    def nonce_to_counter(nonce: bytes) -> int:
        """Convert a 12-byte big-endian nonce back to its integer counter."""
        if not isinstance(nonce, bytes) or len(nonce) != NONCE_BYTES:
            raise CryptoError(
                f"Nonce must be exactly {NONCE_BYTES} bytes; got "
                f"{len(nonce) if isinstance(nonce, bytes) else type(nonce).__name__}"
            )
        return int.from_bytes(nonce, "big")

    # ─── Private helpers ──────────────────────────────────────────────────────

    def _load_counter(self) -> int:
        """Load the persisted counter from disk, or return 0 if not yet created."""
        if not self._counter_path.exists():
            return 0  # First use — will become 1 after first increment

        try:
            with open(self._counter_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            raise CryptoError(
                f"Failed to read nonce counter from {self._counter_path}: {exc}"
            ) from exc

        counter = data.get("nonce_counter")
        if not isinstance(counter, int) or counter < 0:
            raise CryptoError(
                f"Corrupted nonce counter file {self._counter_path}: "
                f"expected non-negative integer, got {counter!r}"
            )
        return counter

    def _persist_counter(self, counter: int) -> None:
        """
        Atomically write the counter to disk with fsync.
        Uses ``atomic_write()`` (write-to-temp, fsync, rename) so the file is
        never partially written on crash.
        """
        payload = json.dumps(
            {"nonce_counter": counter, "comment": "DO NOT edit manually"},
            indent=2,
        ).encode("utf-8")
        # atomic_write calls fsync internally — satisfies "fsync on critical writes"
        atomic_write(self._counter_path, payload)

    @staticmethod
    def _counter_to_bytes(counter: int) -> bytes:
        return counter.to_bytes(NONCE_BYTES, "big")
