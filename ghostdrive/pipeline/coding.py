"""Explicit Reed-Solomon coding parameters with adaptive planning.

Legacy chunks encoded the zfec padding length inside ``sub_block_count`` as
``6 + padlen * 10``. New chunks store ``erasure_k``, ``erasure_n`` and
``erasure_padlen`` explicitly so repair and restore code never has to infer
the coding scheme from an overloaded counter.

``plan_coding`` picks the (k, n) pair for a new chunk based on the file
tier and the number of independent failure domains available, so a CRITICAL
file spread over many domains earns extra parity shards while everything
else keeps the 4+2 floor.
"""

from __future__ import annotations

from typing import Any

DATA_SHARDS = 4
PARITY_SHARDS = 2
TOTAL_SHARDS = DATA_SHARDS + PARITY_SHARDS


def plan_coding(tier: str, domain_count: int, config: dict | None = None) -> tuple[int, int]:
    """Choose Reed-Solomon ``(k, n)`` parameters for a new erasure chunk.

    Policy (bounded enum, never below the 4+2 floor):

    * ``erasure_scheme = "4+2"`` always yields ``(4, 6)``.
    * ``erasure_scheme = "4+4"`` always yields ``(4, 8)``.
    * ``erasure_scheme = "auto"`` (the default, also for unknown or empty
      values) upgrades to ``(4, 8)`` only when the file is CRITICAL *and*
      the shard layout spans at least 8 independent failure domains;
      otherwise ``(4, 6)``.

    The 4+2 floor is a hard guarantee: erasure coding is never silently
    weakened below it, because every restore path and the worst-case
    durability contract assume at least 4 data + 2 parity shards. ``k`` is
    always ``DATA_SHARDS`` and ``n`` is only ever 6 or 8, which keeps the
    stored ``erasure_k``/``erasure_n`` columns compatible with all existing
    readers.
    """
    scheme = str((config or {}).get("erasure_scheme", "auto") or "auto").strip()
    if scheme == "4+2":
        return DATA_SHARDS, DATA_SHARDS + 2
    if scheme == "4+4":
        return DATA_SHARDS, DATA_SHARDS + 4
    # "auto" (and any unknown/empty value): the extra parity shards only pay
    # off when there are enough independent domains to spread them across.
    if str(tier).upper() == "CRITICAL" and domain_count >= 8:
        return DATA_SHARDS, DATA_SHARDS + 4
    return DATA_SHARDS, TOTAL_SHARDS


def padlen_for(data_len: int, k: int) -> int:
    """Bytes of zero padding zfec needs so the data divides evenly into k shards."""
    return (k - data_len % k) % k


def _value(row: Any, key: str, default: int = 0) -> int:
    try:
        raw = row[key]
    except (KeyError, IndexError, TypeError):
        return default
    if raw is None:
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def erasure_parameters(row: Any) -> tuple[int, int, int, bool]:
    """Return ``(data_shards, total_shards, padlen, is_erasure)``."""
    k = _value(row, "erasure_k")
    n = _value(row, "erasure_n")
    padlen = _value(row, "erasure_padlen")

    if k > 0 and n >= k:
        return k, n, max(0, padlen), n > k

    sub_block_count = max(1, _value(row, "sub_block_count", 1))
    if sub_block_count >= TOTAL_SHARDS:
        legacy_padlen = max(0, (sub_block_count - TOTAL_SHARDS) // 10)
        return DATA_SHARDS, TOTAL_SHARDS, legacy_padlen, True

    return 1, sub_block_count, 0, False


def expected_shards(row: Any) -> int:
    _, n, _, is_erasure = erasure_parameters(row)
    return n if is_erasure else max(1, n)
