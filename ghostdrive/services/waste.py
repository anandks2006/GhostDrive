"""Waste report: duplicate storage, Trash backlog, and version history footprint.

Pure read-side reporting over data the vault already keeps -- no backend
touches, no writes, cheap enough to answer an HTTP GET on every UI refresh:

* ``dedup``    -- chunks grouped by content identity (BLAKE3 + size, the same
                  composite key ``pipeline/dedup.py`` uses). Bytes that exist
                  more than once in the index are "wasted" logical bytes.
* ``trash``    -- files already soft-deleted (``tombstone=1``) that retention
                  will eventually purge: count, bytes, and the age of the
                  oldest entry.
* ``versions`` -- superseded ``file_versions`` rows (everything below a file's
                  newest version): count and logical bytes.
* ``envelope_links`` -- still-alive share links (informational: links are an
                  exposure surface, not reclaimable bytes).
* ``top_duplicates`` -- the five biggest duplicated contents with up to three
                  sample paths each, so the number has a face.

Honest limits
-------------
* Dedup savings are an upper bound -- reclaiming them means deleting shared
  chunks, which the vault will not do while any file references them. The
  number answers "how much *could* be freed if the duplicates were gone",
  not "press here to free it".
* ``chunks.size`` is the ORIGINAL (pre-compression) chunk size, and erasure
  coding stores more than one shard per chunk, so wasted/trash bytes are
  logical-byte estimates -- the physical footprint on the backends will differ
  with compression and shard overhead.
* Versions are excluded from ``total_reclaimable_bytes`` on purpose: deleting
  version history is destructive (it is the ransomware undo), and version rows
  mostly point at the same chunk rows the live file uses, so the reported
  ``versions.bytes`` overstates what a prune would actually free.
* Trash bytes only become real space when retention purges them (or the user
  empties Trash) -- until then they are held, not reclaimable.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from ghostdrive.services.sharing import ENVELOPE_SETTINGS_KEY

logger = logging.getLogger("ghostdrive.services.waste")


def _parse_iso(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _dedup_section(db: Any) -> dict:
    """Duplicate detection over chunk content identity (BLAKE3 + size).

    ``copies`` per identity is the summed ``ref_count`` of its chunk rows:
    a ref-counted shared chunk (ref_count > 1) and two separately-stored rows
    with the same content both count as duplication -- either way the vault is
    holding the same bytes more than once.
    """
    rows = db._conn.execute(
        """SELECT blake3_hash, size,
                  COUNT(*) AS row_count,
                  COALESCE(SUM(ref_count), 0) AS copies
           FROM chunks
           GROUP BY blake3_hash, size"""
    ).fetchall()

    duplicated_contents = 0
    duplicated_chunks = 0  # redundant copies: one per extra reference
    wasted = 0
    for row in rows:
        copies = int(row["copies"] or 0)
        if copies > 1:
            extra = copies - 1
            duplicated_contents += 1
            duplicated_chunks += extra
            wasted += int(row["size"] or 0) * extra

    return {
        "unique_contents": len(rows),
        "duplicated_contents": duplicated_contents,
        "duplicated_chunks": duplicated_chunks,
        "wasted_bytes": wasted,
        "potential_reclaim_bytes": wasted,
    }


def _trash_section(db: Any, as_of: datetime) -> dict:
    row = db._conn.execute(
        """SELECT COUNT(*) AS n,
                  COALESCE(SUM(size), 0) AS bytes,
                  MIN(tombstone_at) AS oldest
           FROM files WHERE tombstone = 1"""
    ).fetchone()
    oldest_days: int | None = None
    oldest = _parse_iso(row["oldest"] if row else None)
    if oldest is not None:
        oldest_days = max(0, int((as_of - oldest).total_seconds() // 86400))
    return {
        "files": int((row["n"] if row else 0) or 0),
        "bytes": int((row["bytes"] if row else 0) or 0),
        "oldest_age_days": oldest_days,
    }


def _versions_section(db: Any) -> dict:
    """Superseded version rows: every history entry below the file's newest.

    ``bytes`` is the logical size of the historical content (file_versions
    carries a size column). It is NOT part of total_reclaimable_bytes -- see
    the module docstring.
    """
    row = db._conn.execute(
        """SELECT COUNT(*) AS n, COALESCE(SUM(size), 0) AS bytes
           FROM file_versions v
           WHERE v.version < (
               SELECT MAX(v2.version) FROM file_versions v2
               WHERE v2.file_id = v.file_id
           )"""
    ).fetchone()
    return {
        "count": int((row["n"] if row else 0) or 0),
        "bytes": int((row["bytes"] if row else 0) or 0),
    }


def _links_section(db: Any, as_of: datetime) -> dict:
    """Alive share links (classic + envelope rows in share_links) + envelope map.

    "Alive" = not revoked, not past expiry, and not already spent its download
    budget. Informational only: a live link is an exposure, not reclaimable
    storage, so none of these bytes feed the totals.
    """
    iso = as_of.isoformat()
    where = (
        "revoked = 0 AND (expires_at IS NULL OR expires_at > ?) "
        "AND (max_downloads IS NULL OR download_count < max_downloads)"
    )
    alive = db._conn.execute(
        f"SELECT COUNT(*) AS n FROM share_links WHERE {where}", (iso,)
    ).fetchone()
    envelope_alive = db._conn.execute(
        f"SELECT COUNT(*) AS n FROM share_links WHERE {where} AND recipient_alias = 'envelope'",
        (iso,),
    ).fetchone()

    try:
        entries = json.loads(db.get_setting(ENVELOPE_SETTINGS_KEY, "{}") or "{}")
    except ValueError:
        logger.warning("envelope_links setting is not valid JSON")
        entries = {}
    if not isinstance(entries, dict):
        entries = {}

    return {
        "alive": int((alive["n"] if alive else 0) or 0),
        "envelope_alive": int((envelope_alive["n"] if envelope_alive else 0) or 0),
        "settings_entries": len(entries),
        "burned": sum(
            1
            for value in entries.values()
            if isinstance(value, dict) and value.get("burned")
        ),
    }


def _top_duplicates(db: Any, limit: int = 5) -> list[dict]:
    """Biggest duplicated contents with up to 3 sample paths each.

    Paths resolve through the file-per-chunk mapping (chunks.file_id ->
    files.path), tombstoned files last so a live path is preferred. If no path
    resolves (every referencing row was purged -- shouldn't happen while chunk
    rows exist), ``sample_paths`` is empty rather than invented.
    """
    rows = db._conn.execute(
        """SELECT blake3_hash, size, COALESCE(SUM(ref_count), 0) AS copies
           FROM chunks
           GROUP BY blake3_hash, size
           HAVING copies > 1
           ORDER BY size * (copies - 1) DESC, size DESC
           LIMIT ?""",
        (max(1, int(limit)),),
    ).fetchall()

    top: list[dict] = []
    for row in rows:
        paths = db._conn.execute(
            """SELECT f.path FROM chunks c
               JOIN files f ON f.id = c.file_id
               WHERE c.blake3_hash = ? AND c.size = ?
               ORDER BY f.tombstone ASC, f.path ASC
               LIMIT 3""",
            (row["blake3_hash"], row["size"]),
        ).fetchall()
        top.append({
            "size": int(row["size"] or 0),
            "copies": int(row["copies"] or 0),
            "sample_paths": [str(path["path"]) for path in paths],
        })
    return top


def report(db: Any, *, now: datetime | None = None) -> dict:
    """Build the whole waste report (single positional ``db`` arg -- health
    report compatibility: ``services/health_report.py`` calls ``report(db)``).

    Sections and totals, with the caveats documented in the module docstring:
    ``total_reclaimable_bytes`` = dedup wasted + trash bytes (versions
    deliberately excluded -- deleting them is destructive). Returns::

        {
          "generated_at": iso,
          "dedup": {unique_contents, duplicated_contents, duplicated_chunks,
                    wasted_bytes, potential_reclaim_bytes},
          "trash": {files, bytes, oldest_age_days},
          "versions": {count, bytes},
          "envelope_links": {alive, envelope_alive, settings_entries, burned},
          "total_reclaimable_bytes": int,
          "top_duplicates": [{size, copies, sample_paths}, ...],
        }
    """
    as_of = now if isinstance(now, datetime) else datetime.now(timezone.utc)
    if as_of.tzinfo is None:
        as_of = as_of.replace(tzinfo=timezone.utc)

    dedup = _dedup_section(db)
    trash = _trash_section(db, as_of)
    return {
        "generated_at": as_of.isoformat(),
        "dedup": dedup,
        "trash": trash,
        "versions": _versions_section(db),
        "envelope_links": _links_section(db, as_of),
        "total_reclaimable_bytes": int(dedup["wasted_bytes"]) + int(trash["bytes"]),
        "top_duplicates": _top_duplicates(db),
    }
