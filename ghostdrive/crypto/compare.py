"""
compare.py — Constant-time comparison utilities.

Spec §4.1 — hmac.compare_digest for all secret comparisons
===========================================================
Python ``==`` on ``bytes`` is NOT constant-time and leaks timing information
to an attacker who can observe how long comparisons take.

ALL secret comparisons in GhostDrive MUST use the functions in this module.
This covers:
  - Poly1305 authentication tag verification
  - BLAKE3 dedup hash comparisons
  - Passphrase/key comparisons
  - HMAC ledger chain verification
  - BIP39 seed phrase checksum verification
  - Any other comparison involving secret material

Code review MUST verify this before Month 2 ends (Spec §9.6).
"""

import hmac

from ghostdrive.exceptions import CryptoError


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte strings in constant time using ``hmac.compare_digest``.

    This function is the ONLY approved method for comparing secret values
    in GhostDrive. Direct ``==`` on secrets is a banned pattern.

    Args:
        a: First value (bytes or str).
        b: Second value (bytes or str).

    Returns:
        ``True`` if a == b, ``False`` otherwise.

    Raises:
        TypeError: If either argument is not ``bytes`` or ``str``.
    """
    if not isinstance(a, (bytes, str)):
        raise TypeError(f"constant_time_compare requires bytes or str; got {type(a).__name__!r} for first argument")
    if not isinstance(b, (bytes, str)):
        raise TypeError(f"constant_time_compare requires bytes or str; got {type(b).__name__!r} for second argument")
    return hmac.compare_digest(a, b)


def verify_auth_tag(expected_tag: bytes, actual_tag: bytes) -> bool:
    """
    Verify a Poly1305 or AES-GCM authentication tag in constant time.

    Raises ``CryptoError`` if tag lengths differ, because a length
    discrepancy indicates a possible truncation attack and should NEVER
    silently return ``False``.

    Args:
        expected_tag: The tag that was stored alongside the ciphertext.
        actual_tag:   The tag computed over the received/assembled data.

    Returns:
        ``True`` if tags match, ``False`` otherwise.

    Raises:
        CryptoError: If tag lengths differ (possible truncation attack).
    """
    if not isinstance(expected_tag, bytes):
        raise TypeError(f"expected_tag must be bytes; got {type(expected_tag).__name__!r}")
    if not isinstance(actual_tag, bytes):
        raise TypeError(f"actual_tag must be bytes; got {type(actual_tag).__name__!r}")
    if len(expected_tag) != len(actual_tag):
        raise CryptoError(
            f"Authentication tag length mismatch: expected {len(expected_tag)} bytes, "
            f"got {len(actual_tag)} bytes. Possible truncation attack."
        )
    return hmac.compare_digest(expected_tag, actual_tag)


def verify_hmac(expected: bytes, actual: bytes) -> bool:
    """
    Verify an HMAC value in constant time.

    Used for HMAC-SHA512 SQLite ledger chain verification.

    Args:
        expected: The previously stored HMAC.
        actual:   The freshly computed HMAC.

    Returns:
        ``True`` if values match, ``False`` otherwise.
    """
    if not isinstance(expected, bytes) or not isinstance(actual, bytes):
        raise TypeError("Both arguments to verify_hmac must be bytes")
    return hmac.compare_digest(expected, actual)


def verify_blake3_hash(expected: bytes, actual: bytes) -> bool:
    """
    Verify a BLAKE3 chunk hash in constant time.

    Used for deduplication key comparison and chunk integrity verification.

    Args:
        expected: Previously stored BLAKE3 hash.
        actual:   Freshly computed BLAKE3 hash.

    Returns:
        ``True`` if hashes match, ``False`` otherwise.
    """
    if not isinstance(expected, bytes) or not isinstance(actual, bytes):
        raise TypeError("Both arguments to verify_blake3_hash must be bytes")
    return hmac.compare_digest(expected, actual)
