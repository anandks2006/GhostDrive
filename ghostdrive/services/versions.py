"""File version history: snapshot the current state, restore, and prune.

Versions are immutable metadata rows in ``file_versions`` that point at a
file's ordered chunk manifest (chunk ids + sizes). Chunks are content-addressed
and live in the index until their owning files row is purged, so recording a
version never copies ciphertext -- it is one small row.

History is append-only: nothing in this module rewrites or removes a version
row except prune(), and a restore records a NEW row with reason="restore"
instead of mutating the past.

``file_id`` identifies the *live* files row. Sync re-uploads supersede that row
(new generation -> new row), so sync re-homes version rows onto the fresh row
(see db.rehome_file_versions) to keep one continuous history per path.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import blake3

logger = logging.getLogger("ghostdrive.services.versions")

VALID_REASONS = frozenset({"sync", "manual", "restore", "import"})

# Temporarily re-index parked chunk rows by this offset while a restore swaps
# two generations on and off one files row: SQLite's UNIQUE(file_id,
# chunk_index) would otherwise reject the incoming manifest. Chunk indices are
# small; a -2e9 offset cannot collide with a real index.
_INDEX_PARK_OFFSET = 2_000_000_000


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _coerce_now(now: Optional[Any]) -> str:
    """Accept None (now), a datetime, or a pre-formatted ISO string."""
    if now is None:
        return _now_iso()
    if isinstance(now, datetime):
        return now.isoformat()
    return str(now)


def _manifest_of(chunks) -> list[dict]:
    """Ordered [{"chunk_id", "size"}, ...] for a chunk row list."""
    return [{"chunk_id": row["id"], "size": int(row["size"])} for row in chunks]


def _derived_hash(chunks) -> str:
    """BLAKE3 digest over the ordered (blake3_hash, size) pairs of a chunk set.

    Version history needs a content fingerprint of a file's state without
    re-reading the plaintext from disk or downloading it back from backends.
    Each chunk's stored hash is already BLAKE3 over the original bytes, so
    folding them in chunk order yields a cheap, content-sensitive id: any edit
    changes at least one chunk hash (or the set/size ordering), and the digest
    is stable while chunk rows move between files rows (restore parking),
    because it never includes row ids.
    """
    hasher = blake3.blake3()
    for row in chunks:
        hasher.update(str(row["blake3_hash"]).encode())
        hasher.update(int(row["size"]).to_bytes(8, "big"))
    return hasher.hexdigest()


def _get_chunk_row(db: Any, chunk_id: str):
    return db._conn.execute(
        "SELECT * FROM chunks WHERE id = ?", (chunk_id,)
    ).fetchone()


def version_dict(row, unchanged: bool = False) -> dict:
    """Serialise a file_versions row (manifest as parsed JSON) for callers."""
    try:
        manifest = json.loads(row["manifest"] or "[]")
    except json.JSONDecodeError:
        manifest = []
    return {
        "id": row["id"],
        "file_id": row["file_id"],
        "version": int(row["version"]),
        "reason": row["reason"],
        "size": int(row["size"]),
        "blake3_hash": row["blake3_hash"],
        "manifest": manifest,
        "created_at": row["created_at"],
        "unchanged": unchanged,
    }


async def snapshot_current_file(
    db: Any,
    file_id: str,
    reason: str = "manual",
    now: Optional[Any] = None,
) -> dict:
    """Record the file's CURRENT content as a new immutable version row.

    Reads the live files row and its ordered chunk list (the same list the
    download path replays) and appends version = latest + 1.

    Idempotent: when the newest version already carries the same content
    digest and size it is returned with ``unchanged: True`` and nothing is
    written -- sync passes run every few seconds and an untouched file must
    not grow history (or the HMAC ledger) forever.

    Args:
        db:     Open GhostDriveDB instance.
        file_id: UUID of the live files row.
        reason: One of ``sync``/``manual``/``restore``/``import``.
        now:    Optional datetime/ISO string override for created_at.

    Returns:
        Version record dict (manifest parsed) including ``unchanged``.

    Raises:
        FileNotFoundError: No such file.
        ValueError:        Unknown reason.
        RuntimeError:      The file has no chunks to snapshot.
    """
    if reason not in VALID_REASONS:
        raise ValueError(
            f"Invalid version reason {reason!r}; expected one of {sorted(VALID_REASONS)}"
        )
    row = db.get_file(file_id)
    if row is None:
        raise FileNotFoundError(f"File {file_id} not found.")
    chunks = db.get_file_chunks(file_id)
    if not chunks:
        raise RuntimeError(
            f"File {row['name']!r} has no stored chunks -- cannot snapshot."
        )

    manifest = _manifest_of(chunks)
    size = int(row["size"])
    digest = _derived_hash(chunks)

    latest = db.latest_file_version(file_id)
    if (
        latest is not None
        and latest["blake3_hash"] == digest
        and int(latest["size"]) == size
    ):
        # Content identical to the newest snapshot -- nothing to record.
        return version_dict(latest, unchanged=True)

    record = {
        "id": str(uuid.uuid4()),
        "file_id": file_id,
        "version": (int(latest["version"]) if latest is not None else 0) + 1,
        "reason": reason,
        "size": size,
        "blake3_hash": digest,
        "manifest": json.dumps(manifest, separators=(",", ":")),
        "created_at": _coerce_now(now),
    }
    with db.transaction():
        db.insert_file_version(record)
    return {
        "id": record["id"],
        "file_id": record["file_id"],
        "version": record["version"],
        "reason": record["reason"],
        "size": record["size"],
        "blake3_hash": record["blake3_hash"],
        "manifest": manifest,
        "created_at": record["created_at"],
        "unchanged": False,
    }


async def restore_version(
    db: Any,
    file_id: str,
    version: int,
    objects: Optional[dict] = None,
    now: Optional[Any] = None,
) -> dict:
    """Point the live files row at a historical version's chunk set.

    Verification happens first, inside the same transaction that performs the
    swap: every manifest chunk must still exist in the index with an intact
    ref count, otherwise the restore fails loudly before mutating anything
    (a pruned chunk must never resurrect partial/corrupt content).
    ``objects`` may carry backend objects for future backend-level probes;
    index-level resolution (chunk row + ref_count) is always checked here.

    The swap (all in one transaction):
      1. the pre-restore generation is re-indexed to a temporary offset so the
         incoming manifest can occupy the live row's UNIQUE(file_id, chunk_index)
         slots;
      2. the manifest chunks are re-pointed at the live row (they keep their
         stored chunk indices, so download order is preserved);
      3. the pre-restore generation is parked on the row that just released the
         manifest chunks -- at most one generation lives on a files row at a
         time, so that row is empty afterwards, and its chunks stay in the
         index (Trash retention / their own versions still reference them);
      4. the files row's size/modified_at follow the restored state;
      5. a NEW version row with reason="restore" is appended, keeping history
         append-only.

    Returns:
        {"file_id", "restored_version", "new_version"}

    Raises:
        FileNotFoundError: Missing file or version.
        RuntimeError:       A manifest chunk no longer resolves (pruned), or
                            the index is inconsistent with the manifest.
    """
    row = db.get_file(file_id)
    if row is None:
        raise FileNotFoundError(f"File {file_id} not found.")
    vrow = db.get_file_version(file_id, version)
    if vrow is None:
        raise FileNotFoundError(
            f"Version {version} of file {file_id} not found."
        )

    try:
        manifest = json.loads(vrow["manifest"] or "[]")
    except json.JSONDecodeError:
        manifest = []
    if not manifest:
        raise RuntimeError(
            f"Version {version} of file {file_id} has an empty manifest -- nothing to restore."
        )

    # Verify every manifest chunk still resolves BEFORE any mutation.
    manifest_ids: list[str] = []
    owners: list[str] = []
    for position, entry in enumerate(manifest, start=1):
        chunk_id = entry.get("chunk_id") if isinstance(entry, dict) else None
        chunk = _get_chunk_row(db, chunk_id) if chunk_id else None
        if chunk is None or int(chunk["ref_count"] or 0) < 1:
            raise RuntimeError(
                f"Chunk {position} ({chunk_id}) no longer available -- pruned"
            )
        manifest_ids.append(chunk["id"])
        owner = str(chunk["file_id"])
        if owner != file_id and owner not in owners:
            owners.append(owner)

    manifest_set = set(manifest_ids)
    live_chunks = db.get_file_chunks(file_id)
    live_only = [c for c in live_chunks if c["id"] not in manifest_set]
    live_ids = {c["id"] for c in live_chunks}

    park_home: Optional[str] = None
    if live_only:
        # The incoming manifest must free a row to park the outgoing
        # generation on; that row is the manifest's own host (it becomes
        # empty once the manifest moves to the live file).
        if not owners:
            raise RuntimeError(
                f"Cannot restore version {version}: index inconsistent -- the live "
                f"file holds chunks no version recorded and the manifest has no host row."
            )
        park_home = owners[0]
        strays = db._conn.execute(
            f"SELECT id FROM chunks WHERE file_id = ? AND id NOT IN "
            f"({','.join('?' for _ in manifest_ids)})",
            (park_home, *manifest_ids),
        ).fetchall()
        if strays:
            raise RuntimeError(
                f"Cannot restore version {version}: index inconsistent -- host row "
                f"{park_home} holds chunks outside the manifest."
            )

    created_at = _coerce_now(now)
    with db.transaction():
        latest = db.latest_file_version(file_id)
        new_version = (int(latest["version"]) if latest is not None else 0) + 1

        # 1) Re-index the outgoing generation so the manifest can land.
        for entry in live_only:
            db._conn.execute(
                "UPDATE chunks SET chunk_index = chunk_index - ? WHERE id = ?",
                (_INDEX_PARK_OFFSET, entry["id"]),
            )
        # 2) Point the manifest chunks at the live row (indices already correct).
        for chunk_id in manifest_ids:
            db._conn.execute(
                "UPDATE chunks SET file_id = ? WHERE id = ?",
                (file_id, chunk_id),
            )
        # 3) Park the outgoing generation on the freed host row.
        if park_home is not None:
            for entry in live_only:
                db._conn.execute(
                    "UPDATE chunks SET file_id = ?, chunk_index = chunk_index + ? WHERE id = ?",
                    (park_home, _INDEX_PARK_OFFSET, entry["id"]),
                )
        # 4) The live row now IS the restored version's content.
        clock = db._increment_clock()
        db._conn.execute(
            """UPDATE files
               SET size = ?, modified_at = ?, logical_clock = ?
               WHERE id = ?""",
            (int(vrow["size"]), created_at, clock, file_id),
        )
        db._chain_hmac("files", {
            "op": "restore_version", "id": file_id,
            "restored_version": int(version), "new_version": new_version,
        })
        # 5) Append-only history: the restored state becomes a new row.
        record = {
            "id": str(uuid.uuid4()),
            "file_id": file_id,
            "version": new_version,
            "reason": "restore",
            "size": int(vrow["size"]),
            "blake3_hash": vrow["blake3_hash"],
            "manifest": vrow["manifest"],
            "created_at": created_at,
        }
        db.insert_file_version(record)

    logger.info(
        "Restored %s version %d -> new version %d",
        file_id, int(version), new_version,
    )
    return {
        "file_id": file_id,
        "restored_version": int(version),
        "new_version": new_version,
    }


def prune_versions(
    db: Any,
    file_id: Optional[str] = None,
    keep: int = 10,
) -> dict:
    """Prune old versions for one file (or every file when file_id is None).

    ``keep`` newest versions survive per file. The version the live file
    currently points at is always exempt -- pruning it would orphan the live
    file's state from its history, which is exactly the anchor a
    ransomware-victim restore relies on.

    Chunk GC hook: deleting a version row can leave chunks referenced by no
    version and no live file (GC-eligible). Chunk garbage collection is
    deliberately NOT done here: file_versions never held a chunks.ref_count
    (snapshot does not increment it), so removing a version row never drops a
    chunk's last reference -- ref-count decrement and backend object deletion
    stay owned by files.py (purge_file_permanently / _delete_backend_objects_
    for_file). If versions ever become ref-count holders, the hook is here:
    decrement_ref_count() for each chunk that vanishes from every remaining
    manifest AND from the live file, then let files.py remove backend objects.
    Until then chunk lifetime is anchored to their files row (Trash keeps rows
    for 30 days), which is why restore_version() fails with "pruned" when a
    purged row takes its chunks with it.

    Routes read the ``version_keep`` setting (default "10") via db.get_setting
    when the caller does not pass an explicit keep.
    """
    with db.transaction():
        removed = db.prune_file_versions(file_id, keep)
    return {"file_id": file_id, "keep": int(keep), "removed": removed}
