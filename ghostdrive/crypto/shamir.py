"""
shamir.py — Shamir's Secret Sharing over GF(2^8) for threshold recovery.

Spec §4.3 (Threshold Recovery) — 3-of-5 key shares
==================================================
The 256-bit Master Key (the same entropy that backs the 24-word BIP39 seed
phrase) is split into ``total`` shares such that any ``threshold`` of them
reconstruct it exactly, while any ``threshold - 1`` of them reveal nothing
information-theoretically about it.

Design notes
------------
* Arithmetic is GF(2^8) with the AES reduction polynomial 0x11B, the same
  field used by the rest of GhostDrive's crypto stack.
* Each byte of the secret gets an independent random polynomial of degree
  ``threshold - 1`` whose free coefficient is that byte. Share ``i`` is the
  evaluation of every polynomial at ``x = i`` (1-based; ``x = 0`` is the
  secret itself, never transmitted).
* Share encoding is a self-describing binary blob with a SHA-256 checksum so
  that transcription typos are detected on combine rather than producing a
  silently wrong Master Key. The reconstructed secret is additionally checked
  against a commitment stored in the recovery kit manifest.

Binary share layout (12 + len(secret) bytes)::

    offset 0 : magic          b"GDS1"          (4 bytes)
    offset 4 : version        1                (1 byte)
    offset 5 : threshold                       (1 byte)
    offset 6 : total                           (1 byte)
    offset 7 : index           1-based         (1 byte)
    offset 8 : share data     len(secret) bytes
    end      : checksum       SHA-256(header ‖ data)[:4]

Text encoding: ``GDSHARE1:`` prefix followed by unpadded standard Base32 of
the binary blob, wrapped in groups of 8 characters separated by ``-`` so the
share can be transcribed by hand.
"""

from __future__ import annotations

import base64
import hashlib
import secrets as _secrets
from typing import Iterable, Sequence

from ghostdrive.exceptions import CryptoError

# ─── Constants ────────────────────────────────────────────────────────────────

SHARE_MAGIC = b"GDS1"
SHARE_VERSION = 1
TEXT_PREFIX = "GDSHARE1:"
_GROUP = 8  # Base32 characters per transcription group

DEFAULT_THRESHOLD = 3
DEFAULT_TOTAL_SHARES = 5

_KIT_COMMITMENT_LABEL = b"ghostdrive-recovery-kit-v1"


# ─── Errors ───────────────────────────────────────────────────────────────────

class ShamirError(CryptoError):
    """Raised when share splitting/combining fails validation."""


# ─── GF(2^8) arithmetic (AES polynomial 0x11B) ───────────────────────────────

def _build_tables() -> tuple[list[int], list[int]]:
    # 0x03 is a primitive element of GF(2^8) with the AES polynomial 0x11B
    # (2 has order 51 and would produce a colliding log table).
    exp = [0] * 512
    log = [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        x ^= (x << 1)  # multiply by 3 = x*2 ^ x
        if x & 0x100:
            x ^= 0x11B
        x &= 0xFF
    # Duplicate so exp[a + b] works without a modulo (a, b < 255).
    for i in range(255, 512):
        exp[i] = exp[i - 255]
    assert len(set(exp[:255])) == 255, "0x03 must be primitive for 0x11B"
    return exp, log


_GF_EXP, _GF_LOG = _build_tables()


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def _gf_div(a: int, b: int) -> int:
    if b == 0:
        raise ShamirError("GF(256) division by zero.")
    if a == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] - _GF_LOG[b] + 255]


def _gf_pow(a: int, n: int) -> int:
    if a == 0:
        return 0 if n else 1
    return _GF_EXP[(_GF_LOG[a] * n) % 255]


def _eval_poly(coeffs: Sequence[int], x: int) -> int:
    """Horner evaluation of the polynomial at GF element ``x``."""
    y = 0
    for c in reversed(coeffs):
        y = _gf_mul(y, x) ^ c
    return y


# ─── Split / combine ─────────────────────────────────────────────────────────

def split_secret(
    secret: bytes,
    threshold: int = DEFAULT_THRESHOLD,
    total: int = DEFAULT_TOTAL_SHARES,
) -> list[bytes]:
    """
    Split ``secret`` into ``total`` shares, any ``threshold`` of which can
    reconstruct it.

    Args:
        secret:    The secret bytes (the 32-byte Master Key in normal use).
        threshold: Minimum shares required to reconstruct (>= 2).
        total:     Number of shares to produce (>= threshold, <= 255).

    Returns:
        List of ``total`` binary shares (see module docstring for layout).

    Raises:
        ShamirError: Invalid parameters or empty/oversized secret.
    """
    if not isinstance(secret, (bytes, bytearray)) or len(secret) == 0:
        raise ShamirError("Secret must be a non-empty bytes object.")
    if not (2 <= threshold <= total <= 255):
        raise ShamirError(
            f"Require 2 <= threshold <= total <= 255; got threshold={threshold}, total={total}."
        )
    if len(secret) > 255:
        raise ShamirError(f"Secret too long: {len(secret)} > 255 bytes.")

    data = bytes(secret)
    n = len(data)
    # shares_data[i][j] = evaluation of byte-j polynomial at x = i + 1
    shares_data = [bytearray(n) for _ in range(total)]

    for j in range(n):
        coeffs = [data[j]] + [_secrets.randbelow(256) for _ in range(threshold - 1)]
        for i in range(total):
            shares_data[i][j] = _eval_poly(coeffs, i + 1)

    return [
        _pack_share(threshold, total, i + 1, bytes(shares_data[i]))
        for i in range(total)
    ]


def combine_shares(shares: Sequence[bytes]) -> bytes:
    """
    Reconstruct the secret from ``threshold`` (or more) valid shares.

    Args:
        shares: Sequence of binary shares produced by :func:`split_secret`.

    Returns:
        The original secret bytes.

    Raises:
        ShamirError: Too few shares, mismatched parameters, duplicate or
            out-of-range share indexes, corrupted share (checksum), or a
            combination that does not interpolate cleanly.
    """
    if not shares:
        raise ShamirError("No shares provided.")

    parsed = [_unpack_share(s) for s in shares]
    threshold = parsed[0]["threshold"]
    total = parsed[0]["total"]
    secret_len = len(parsed[0]["data"])

    seen: set[int] = set()
    for p in parsed:
        if p["threshold"] != threshold or p["total"] != total:
            raise ShamirError("Shares come from different recovery kits (threshold/total mismatch).")
        if len(p["data"]) != secret_len:
            raise ShamirError("Shares have inconsistent secret lengths.")
        if p["index"] in seen:
            raise ShamirError(f"Duplicate share index {p['index']}; distinct shares are required.")
        if not (1 <= p["index"] <= total):
            raise ShamirError(f"Share index {p['index']} out of range 1..{total}.")
        seen.add(p["index"])

    if len(parsed) < threshold:
        raise ShamirError(
            f"Need at least {threshold} shares to reconstruct; got {len(parsed)}."
        )
    # Use exactly `threshold` shares: deterministic and minimal.
    parsed = sorted(parsed, key=lambda p: p["index"])[:threshold]

    xs = [p["index"] for p in parsed]
    out = bytearray(secret_len)
    for j in range(secret_len):
        acc = 0
        for i, x in enumerate(xs):
            y = parsed[i]["data"][j]
            num, den = 1, 1
            for m, x_m in enumerate(xs):
                if m == i:
                    continue
                num = _gf_mul(num, x_m)
                den = _gf_mul(den, x ^ x_m)  # GF(2^8): subtraction is XOR
            lagrange = _gf_div(num, den)
            acc ^= _gf_mul(y, lagrange)
        out[j] = acc

    return bytes(out)


# ─── Text (transcription) encoding ───────────────────────────────────────────

def share_to_text(share: bytes) -> str:
    """
    Encode a binary share as human-transcribable text.

    Returns e.g. ``GDSHARE1:MZQWY6DJ-MRQXEZLU-...`` — groups of 8 Base32
    characters separated by dashes. Whitespace and dashes are ignored on
    decode, so line wrapping in printed kits is harmless.
    """
    _unpack_share(share)  # validate before exporting
    body = base64.b32encode(share).decode("ascii").rstrip("=")
    groups = [body[i:i + _GROUP] for i in range(0, len(body), _GROUP)]
    return TEXT_PREFIX + "-".join(groups)


def text_to_share(text: str) -> bytes:
    """
    Decode a transcribed share (``share_to_text`` output) back to binary.

    Raises:
        ShamirError: Wrong prefix, bad Base32, or invalid share payload.
    """
    if not isinstance(text, str):
        raise ShamirError("Share text must be a string.")
    cleaned = text.strip()
    # Tolerate pasted line breaks/spaces anywhere after the prefix.
    if TEXT_PREFIX not in cleaned:
        raise ShamirError(f"Not a GhostDrive share (missing {TEXT_PREFIX!r} prefix).")
    body = cleaned.split(TEXT_PREFIX, 1)[1]
    body = "".join(body.split()).replace("-", "").upper()
    pad = (-len(body)) % 8
    try:
        raw = base64.b32decode(body + "=" * pad)
    except Exception as exc:  # binascii.Error and friends
        raise ShamirError(f"Invalid Base32 in share text: {exc}") from exc
    _unpack_share(raw)  # validate, then return the binary share
    return raw


def share_metadata(share: bytes) -> dict:
    """Return non-secret metadata (threshold, total, index) for a binary share."""
    p = _unpack_share(share)
    return {"threshold": p["threshold"], "total": p["total"], "index": p["index"]}


# ─── Commitment (kit manifest verification) ──────────────────────────────────

def secret_commitment(secret: bytes) -> str:
    """
    Binding, non-reversible commitment to the secret for kit manifests.

    The secret is a uniformly random 256-bit value, so publishing SHA-256 of
    it does not weaken it, but it lets :func:`verify_commitment` prove that a
    set of shares reconstructs the *original* key rather than a typo'd one.
    """
    return hashlib.sha256(_KIT_COMMITMENT_LABEL + bytes(secret)).hexdigest()


def verify_commitment(secret: bytes, commitment: str) -> bool:
    """Constant-time check of a reconstructed secret against a kit commitment."""
    import hmac

    return hmac.compare_digest(secret_commitment(secret), str(commitment).lower())


# ─── Pack / unpack ───────────────────────────────────────────────────────────

def _pack_share(threshold: int, total: int, index: int, data: bytes) -> bytes:
    header = SHARE_MAGIC + bytes([SHARE_VERSION, threshold, total, index])
    body = header + data
    return body + hashlib.sha256(body).digest()[:4]


def _unpack_share(blob: bytes) -> dict:
    if not isinstance(blob, (bytes, bytearray)):
        raise ShamirError("Share must be bytes (use text_to_share for transcribed text).")
    blob = bytes(blob)
    min_len = 4 + 1 + 1 + 1 + 1 + 4
    if len(blob) < min_len:
        raise ShamirError(f"Share too short ({len(blob)} bytes).")
    if blob[:4] != SHARE_MAGIC:
        raise ShamirError("Share magic mismatch — not a GhostDrive share.")
    version = blob[4]
    if version != SHARE_VERSION:
        raise ShamirError(f"Unsupported share version {version}.")
    header, data, checksum = blob[:8], blob[8:-4], blob[-4:]
    expected = hashlib.sha256(header + data).digest()[:4]
    if not _ct_eq(checksum, expected):
        raise ShamirError(
            "Share checksum mismatch — the share was corrupted or mis-typed."
        )
    threshold, total, index = blob[5], blob[6], blob[7]
    if not (2 <= threshold <= total <= 255):
        raise ShamirError(f"Invalid share header: threshold={threshold}, total={total}.")
    if index < 1 or index > total:
        raise ShamirError(f"Share index {index} out of range 1..{total}.")
    return {"threshold": threshold, "total": total, "index": index, "data": data}


def _ct_eq(a: bytes, b: bytes) -> bool:
    import hmac

    return hmac.compare_digest(a, b)
