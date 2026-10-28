"""Local content search that decrypts at query time — never an index at rest.

This is the deliberate successor to the plaintext-FTS module we deleted: that
module wrote decrypted file contents into an on-disk search index, which
defeated the vault's whole promise (the ciphertext on the backends was
strong, but the plaintext sat next to the database in plain SQLite).  The
correct trade is the opposite one: pay the decryption cost PER QUERY and
keep every byte of plaintext inside this process's RAM, bounded and
wipeable.

Threat model / design rationale:

* decrypt-at-query-time — plaintext only exists between ``iter_file`` yielding
  a block and the snippet being returned; nothing is ever persisted to disk,
  so a stolen laptop yields either ciphertext (backends) or nothing (search);
* the module-level cache (``{file_id: {modified_at, text}}``) is a pure
  performance LRU: total 32 MiB cap, 2 MiB per file, oldest evicted first,
  and :func:`clear_search_cache` empties it wholesale — the exported name is
  the lock/shutdown hook contract (call it when the vault locks so no
  decrypted text outlives the unlock session);
* binary files are skipped by NUL-sniffing the first 8 KiB (images, archives,
  media).  OCR of images is explicitly OUT OF SCOPE — it would mean shipping
  an OCR stack and persisting derived text; users who need it can store text.
* a locked vault fails loudly: ``RuntimeError`` propagates from the service
  and routes map it to 401.

Matching is deliberately simple: case-insensitive substring per token, ANDed
across tokens, no stemming/ranking.  It is honest about what it does (find
the phrase, show where), and it never lies about files it could not read.
"""

from __future__ import annotations

import logging
import re
import time
from collections import OrderedDict
from typing import Any, Optional

from ghostdrive.services import files as files_service
from ghostdrive.services.context import require_db

logger = logging.getLogger("ghostdrive.services.content_search")

CACHE_BYTE_CAP = 32 * 1024 * 1024   # total decoded text kept in RAM (32 MiB)
CACHE_TEXT_CAP = 2_000_000          # per-file cap; matches the read default
BINARY_SNIFF_BYTES = 8192           # NUL in the first 8 KiB => binary, skip
SNIPPET_RADIUS = 80                 # chars of context on each side of a match
MAX_SNIPPETS = 3

# LRU of decoded text.  Insertion order == recency (move_to_end on hit);
# plain dict/OrderedDict operations only — this module must stay importable
# and callable from lock/shutdown hooks with no async machinery.
_cache: "OrderedDict[str, dict[str, Any]]" = OrderedDict()
_cache_bytes = 0


def clear_search_cache() -> dict:
    """Drop every cached file text; callable from a lock/shutdown hook.

    Contract name for state.py-style teardown: wiping the cache is how the
    decrypt-at-query-time promise is kept across lock sessions — RAM held the
    plaintext, this call gives it back.  Returns ``{"cleared": n}``.
    """
    global _cache_bytes
    cleared = len(_cache)
    _cache.clear()
    _cache_bytes = 0
    return {"cleared": cleared}


def search_cache_stats() -> dict:
    """Cache introspection for the UI: entry count and retained UTF-8 bytes."""
    return {"cached_files": len(_cache), "cached_bytes": _cache_bytes}


def _cache_get(file_id: str, modified_at: str) -> Optional[dict[str, Any]]:
    """Entry dict ({"text", "truncated"}) when fresh, else None (LRU touch)."""
    entry = _cache.get(file_id)
    if entry is None or entry["modified_at"] != modified_at:
        return None
    _cache.move_to_end(file_id)
    return entry


def _cache_put(file_id: str, modified_at: str, text: str, truncated: bool) -> None:
    """Store text under both the per-file and total caps (LRU-evicting)."""
    global _cache_bytes
    data = text[:CACHE_TEXT_CAP]
    nbytes = len(data.encode("utf-8", "replace"))
    if nbytes > CACHE_BYTE_CAP // 4:  # keep any one file from eating the LRU
        return
    if file_id in _cache:
        _cache_bytes -= _cache[file_id]["bytes"]
        del _cache[file_id]
    _cache[file_id] = {
        "modified_at": modified_at,
        "text": data,
        "truncated": truncated,
        "bytes": nbytes,
    }
    _cache_bytes += nbytes
    while _cache_bytes > CACHE_BYTE_CAP and _cache:
        _, victim = _cache.popitem(last=False)
        _cache_bytes -= victim["bytes"]


def _tokenize(query: str) -> list[str]:
    """Lowercase, split on non-alphanumeric runs, drop 1-char noise tokens.

    A single-token query keeps short tokens ("ai", "go") — dropping the only
    token would make the search impossible rather than broad.
    """
    tokens = [t for t in re.split(r"\W+", (query or "").lower()) if t]
    if len(tokens) > 1:
        tokens = [t for t in tokens if len(t) >= 2]
    return tokens


async def _read_text_prefix(
    file_id: str, max_file_bytes: int
) -> tuple[Optional[str], bool]:
    """Stream decrypted plaintext up to ``max_file_bytes``.

    Returns ``(text, truncated)``; ``text`` is None for binary content (NUL
    byte in the first 8 KiB — images/media/archives are skipped, OCR is out
    of scope per the module docstring).  Decoding is lossy (``replace``) so a
    few invalid UTF-8 bytes degrade the snippet instead of failing the query.
    """
    out = bytearray()
    truncated = False
    async for block in files_service.iter_file(file_id):
        out.extend(block)
        if len(out) >= max_file_bytes:
            out = out[:max_file_bytes]
            truncated = True
            break
    if b"\x00" in out[:BINARY_SNIFF_BYTES]:
        return None, truncated
    return out.decode("utf-8", errors="replace"), truncated


def _snippets(text: str, tokens: list[str]) -> list[str]:
    """First match per token ± 80 chars, whitespace-normalized, ``...`` marks.

    Overlapping windows are merged so a two-word phrase yields one snippet,
    not two nearly identical ones; at most ``MAX_SNIPPETS`` are returned.
    """
    low = text.lower()
    spans: list[tuple[int, int]] = []
    for tok in tokens:
        idx = low.find(tok)
        if idx < 0:
            continue
        start = max(0, idx - SNIPPET_RADIUS)
        end = min(len(text), idx + len(tok) + SNIPPET_RADIUS)
        if any(start <= s2 and s1 <= end for s1, s2 in spans):
            continue
        spans.append((start, end))
    spans.sort()
    out: list[str] = []
    for start, end in spans[:MAX_SNIPPETS]:
        window = " ".join(text[start:end].split())  # single-line normalize
        prefix = "..." if start > 0 else ""
        suffix = "..." if end < len(text) else ""
        out.append(prefix + window + suffix)
    return out


async def search_content(
    query: str,
    *,
    db=None,
    limit: int = 50,
    max_file_bytes: int = 2_000_000,
    max_files: int = 400,
    now: Optional[float] = None,
) -> dict:
    """Search active files by decrypted content, newest file first.

    Candidate rows are the active (``tombstone = 0``) files, ordered by
    ``modified_at`` DESC (``db.list_files``), scanned up to ``max_files``.
    Each file's text is decrypted fresh unless the in-memory cache holds the
    same ``modified_at`` (``from_cache`` counts those reuses).  All tokens
    must appear (AND); binary files are skipped, and a file that cannot be
    read is logged and skipped instead of aborting the whole search — except
    a locked vault, whose ``RuntimeError`` deliberately propagates (routes
    map it to 401).

    ``max_file_bytes`` truncates the read per file; truncated results carry
    ``truncated: true`` and are NOT cached (a partial text would poison later
    queries made with a larger cap).  ``now`` optionally pins the monotonic
    start time for ``duration_ms`` (tests).
    """
    start = time.monotonic() if now is None else float(now)
    tokens = _tokenize(query)
    if not tokens:
        raise ValueError("Search query must contain at least one alphanumeric token.")
    db = db or require_db()
    limit = max(1, int(limit))
    max_file_bytes = max(1, int(max_file_bytes))
    max_files = max(1, int(max_files))

    rows = db.list_files("/", include_tombstones=False)[:max_files]
    results: list[dict[str, Any]] = []
    scanned = matched = truncated_files = from_cache = 0

    for row in rows:
        scanned += 1
        file_id = row["id"]
        entry = _cache_get(file_id, row["modified_at"])
        if entry is not None:
            text, truncated = entry["text"], entry["truncated"]
            from_cache += 1
        else:
            try:
                text, truncated = await _read_text_prefix(file_id, max_file_bytes)
            except Exception as exc:
                if "locked" in str(exc).lower() or "not open" in str(exc).lower():
                    raise  # vault locked mid-search: fail loudly, not silently
                logger.warning("Content search skipped %s: %s", file_id, exc)
                continue
            if text is None:  # binary: skipped, never cached
                continue
            if not truncated:  # partial text would poison later, bigger-cap queries
                _cache_put(file_id, row["modified_at"], text, truncated)
        if truncated:
            truncated_files += 1

        low = text.lower()
        if not all(tok in low for tok in tokens):
            continue
        matched += 1
        if len(results) < limit:
            results.append({
                "file_id": file_id,
                "name": row["name"],
                "path": row["path"],
                "size": row["size"],
                "mime_type": row["mime_type"],
                "truncated": truncated,
                "snippets": _snippets(text, tokens),
            })

    return {
        "query": query,
        "results": results,
        "scanned": scanned,
        "matched": matched,
        "truncated_files": truncated_files,
        "duration_ms": int((time.monotonic() - start) * 1000),
        "from_cache": from_cache,
    }
