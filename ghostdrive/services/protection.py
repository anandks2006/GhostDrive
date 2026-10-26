"""Always-on protection sets: mirror local folders into the encrypted vault."""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from ghostdrive.services import files as files_service

logger = logging.getLogger("ghostdrive.protection")

VALID_TIERS = {"CRITICAL", "IMPORTANT", "DISPOSABLE"}
_SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", "node_modules", ".venv", "venv"}
_SKIP_FILES = {".DS_Store", "Thumbs.db", "desktop.ini"}

_watcher_task: Optional[asyncio.Task] = None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalise_destination(value: str) -> str:
    value = (value or "/").strip()
    if not value.startswith("/"):
        value = "/" + value
    return value.rstrip("/") or "/"


def _set_dict(row: Any, files: Optional[list[dict]] = None) -> dict:
    result = {
        "id": str(row["id"]),
        "name": str(row["name"]),
        "source_path": str(row["source_path"]),
        "destination_path": str(row["destination_path"]),
        "tier": str(row["tier"]),
        "enabled": bool(row["enabled"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "last_scan_at": row["last_scan_at"],
        "last_sync_at": row["last_sync_at"],
        "last_error": row["last_error"],
        "file_count": int(row["file_count"] or 0),
        "total_bytes": int(row["total_bytes"] or 0),
    }
    if files is not None:
        result["files"] = files
    return result


def _get_row(db: Any, set_id: str) -> Any:
    row = db._conn.execute("SELECT * FROM protection_sets WHERE id = ?", (set_id,)).fetchone()
    if row is None:
        raise FileNotFoundError("Protection set was not found.")
    return row


def list_sets(db: Any = None) -> list[dict]:
    if db is None:
        from ghostdrive.services.context import require_db
        db = require_db()
    rows = db._conn.execute(
        "SELECT * FROM protection_sets ORDER BY name COLLATE NOCASE ASC"
    ).fetchall()
    return [_set_dict(row) for row in rows]


def get_set(db: Any, set_id: str) -> dict:
    return _set_dict(_get_row(db, set_id))


def list_set_files(db: Any, set_id: str, limit: int = 200) -> list[dict]:
    rows = db._conn.execute(
        """SELECT * FROM protection_set_files
           WHERE set_id = ?
           ORDER BY status != 'uploaded', relative_path
           LIMIT ?""",
        (set_id, max(1, int(limit))),
    ).fetchall()
    return [
        {
            "relative_path": str(row["relative_path"]),
            "source_size": int(row["source_size"] or 0),
            "file_id": row["file_id"],
            "status": str(row["status"]),
            "last_seen_at": row["last_seen_at"],
            "last_synced_at": row["last_synced_at"],
            "error": row["error"],
        }
        for row in rows
    ]


def create_set(
    db: Any,
    name: str,
    source_path: str,
    destination_path: str = "/",
    tier: str = "IMPORTANT",
    enabled: bool = True,
) -> dict:
    source = Path(source_path).expanduser().resolve()
    if not source.exists() or not source.is_dir():
        raise ValueError(f"Source folder does not exist: {source}")
    tier = (tier or "IMPORTANT").upper()
    if tier not in VALID_TIERS:
        raise ValueError(f"Invalid tier {tier!r}; expected one of {sorted(VALID_TIERS)}")
    set_id = str(uuid.uuid4())
    now = _now_iso()
    with db.transaction():
        db._conn.execute(
            """INSERT INTO protection_sets
               (id, name, source_path, destination_path, tier, enabled,
                created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                set_id,
                (name or source.name or "Protected folder").strip(),
                str(source),
                _normalise_destination(destination_path),
                tier,
                1 if enabled else 0,
                now,
                now,
            ),
        )
    return get_set(db, set_id)


def update_set(
    db: Any,
    set_id: str,
    name: Optional[str] = None,
    source_path: Optional[str] = None,
    destination_path: Optional[str] = None,
    tier: Optional[str] = None,
    enabled: Optional[bool] = None,
) -> dict:
    _get_row(db, set_id)
    updates: list[str] = []
    params: list[Any] = []
    if name is not None:
        updates.append("name = ?")
        params.append(name.strip() or "Protected folder")
    if source_path is not None:
        source = Path(source_path).expanduser().resolve()
        if not source.exists() or not source.is_dir():
            raise ValueError(f"Source folder does not exist: {source}")
        updates.append("source_path = ?")
        params.append(str(source))
    if destination_path is not None:
        updates.append("destination_path = ?")
        params.append(_normalise_destination(destination_path))
    if tier is not None:
        tier = tier.upper()
        if tier not in VALID_TIERS:
            raise ValueError(f"Invalid tier {tier!r}; expected one of {sorted(VALID_TIERS)}")
        updates.append("tier = ?")
        params.append(tier)
    if enabled is not None:
        updates.append("enabled = ?")
        params.append(1 if enabled else 0)
    if updates:
        updates.append("updated_at = ?")
        params.append(_now_iso())
        params.append(set_id)
        with db.transaction():
            db._conn.execute(
                f"UPDATE protection_sets SET {', '.join(updates)} WHERE id = ?",
                params,
            )
    return get_set(db, set_id)


def delete_set(db: Any, set_id: str) -> dict:
    _get_row(db, set_id)
    with db.transaction():
        db._conn.execute("DELETE FROM protection_set_files WHERE set_id = ?", (set_id,))
        db._conn.execute("DELETE FROM protection_sets WHERE id = ?", (set_id,))
    return {"status": "success", "deleted": set_id}


def _iter_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [
            name for name in dirnames
            if name not in _SKIP_DIRS and not (Path(dirpath) / name).is_symlink()
        ]
        for filename in filenames:
            if filename in _SKIP_FILES or filename.endswith(".gdl"):
                continue
            path = Path(dirpath) / filename
            if path.is_symlink() or not path.is_file():
                continue
            yield path


async def scan_set(db: Any, set_id: str, max_files: int = 200) -> dict:
    row = _get_row(db, set_id)
    root = Path(row["source_path"])
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"Protection source folder is unavailable: {root}")

    tracked = {
        str(item["relative_path"]): item
        for item in db._conn.execute(
            "SELECT * FROM protection_set_files WHERE set_id = ?", (set_id,)
        ).fetchall()
    }
    seen: set[str] = set()
    uploaded = 0
    unchanged = 0
    failed = 0
    truncated = False
    error_messages: list[str] = []
    destination_root = str(row["destination_path"])
    tier = str(row["tier"])
    now = _now_iso()

    for path in _iter_files(root):
        relative = path.relative_to(root).as_posix()
        seen.add(relative)
        try:
            stat = path.stat()
        except OSError as exc:
            failed += 1
            error_messages.append(f"{relative}: {exc}")
            continue
        size = int(stat.st_size)
        mtime = int(stat.st_mtime_ns)
        existing = tracked.get(relative)
        if (
            existing is not None
            and existing["status"] == "uploaded"
            and int(existing["source_size"]) == size
            and int(existing["source_mtime"]) == mtime
            and existing["file_id"]
        ):
            unchanged += 1
            continue

        if uploaded >= max_files:
            truncated = True
            break

        relative_parent = relative.rsplit("/", 1)[0] if "/" in relative else ""
        destination = destination_root
        if relative_parent:
            destination = _normalise_destination(
                destination_root.rstrip("/") + "/" + relative_parent
            )
        try:
            result = await files_service.upload_stream(
                path, path.name, None, tier, destination
            )
            with db.transaction():
                db._conn.execute(
                    """INSERT INTO protection_set_files
                       (set_id, relative_path, source_size, source_mtime, file_id,
                        status, last_seen_at, last_synced_at, error)
                       VALUES (?, ?, ?, ?, ?, 'uploaded', ?, ?, NULL)
                       ON CONFLICT(set_id, relative_path) DO UPDATE SET
                         source_size = excluded.source_size,
                         source_mtime = excluded.source_mtime,
                         file_id = excluded.file_id,
                         status = 'uploaded',
                         last_seen_at = excluded.last_seen_at,
                         last_synced_at = excluded.last_synced_at,
                         error = NULL""",
                    (
                        set_id, relative, size, mtime, result.get("file_id"),
                        now, now,
                    ),
                )
            uploaded += 1
        except Exception as exc:
            failed += 1
            error_messages.append(f"{relative}: {exc}")
            logger.warning("Protection upload failed for %s: %s", relative, exc)
            with db.transaction():
                db._conn.execute(
                    """INSERT INTO protection_set_files
                       (set_id, relative_path, source_size, source_mtime, file_id,
                        status, last_seen_at, last_synced_at, error)
                       VALUES (?, ?, ?, ?, NULL, 'failed', ?, NULL, ?)
                       ON CONFLICT(set_id, relative_path) DO UPDATE SET
                         source_size = excluded.source_size,
                         source_mtime = excluded.source_mtime,
                         status = 'failed',
                         last_seen_at = excluded.last_seen_at,
                         error = excluded.error""",
                    (set_id, relative, size, mtime, now, str(exc)),
                )

    missing = 0
    if not truncated:
        for relative, existing in tracked.items():
            if relative in seen:
                continue
            if existing["status"] == "missing":
                continue
            missing += 1
            with db.transaction():
                db._conn.execute(
                    "UPDATE protection_set_files SET status = 'missing' WHERE set_id = ? AND relative_path = ?",
                    (set_id, relative),
                )

    totals = db._conn.execute(
        """SELECT COUNT(*) AS count, COALESCE(SUM(source_size), 0) AS bytes
           FROM protection_set_files WHERE set_id = ? AND status = 'uploaded'""",
        (set_id,),
    ).fetchone()
    last_error = "; ".join(error_messages[:3]) if error_messages else None
    with db.transaction():
        db._conn.execute(
            """UPDATE protection_sets
               SET last_scan_at = ?, last_sync_at = ?, last_error = ?,
                   file_count = ?, total_bytes = ?, updated_at = ?
               WHERE id = ?""",
            (
                now,
                now if uploaded else row["last_sync_at"],
                last_error,
                int(totals["count"] or 0),
                int(totals["bytes"] or 0),
                now,
                set_id,
            ),
        )
    return {
        "status": "success" if failed == 0 else "partial",
        "set_id": set_id,
        "uploaded": uploaded,
        "unchanged": unchanged,
        "failed": failed,
        "missing": missing,
        "truncated": truncated,
        "errors": error_messages[:10],
        "set": get_set(db, set_id),
    }


async def scan_all(db: Any = None, max_files: int = 200) -> dict:
    if db is None:
        from ghostdrive.services.context import require_db
        db = require_db()
    results: list[dict] = []
    for item in list_sets(db):
        if not item["enabled"]:
            continue
        try:
            results.append(await scan_set(db, item["id"], max_files=max_files))
        except Exception as exc:
            logger.warning("Protection scan failed for %s: %s", item["name"], exc)
            results.append({
                "status": "failed",
                "set_id": item["id"],
                "error": str(exc),
            })
    return {
        "status": "success" if all(r.get("status") != "failed" for r in results) else "partial",
        "sets": len(results),
        "uploaded": sum(int(r.get("uploaded", 0)) for r in results),
        "failed": sum(int(r.get("failed", 0)) for r in results),
        "results": results,
    }


async def _watch_loop(interval_seconds: int) -> None:
    while True:
        await asyncio.sleep(max(15, int(interval_seconds)))
        try:
            from ghostdrive.services.context import require_db
            db = require_db()
            await scan_all(db)
        except Exception as exc:
            logger.debug("Protection watcher idle: %s", exc)


def start_watcher(interval_seconds: int = 60) -> Optional[asyncio.Task]:
    global _watcher_task
    if _watcher_task is not None and not _watcher_task.done():
        return _watcher_task
    _watcher_task = asyncio.create_task(_watch_loop(interval_seconds))
    return _watcher_task


def stop_watcher() -> None:
    global _watcher_task
    if _watcher_task is not None and not _watcher_task.done():
        _watcher_task.cancel()
    _watcher_task = None
