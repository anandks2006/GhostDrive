"""Real-time folder sync: watch a sync root and mirror changes into the vault.

One pass (``run_sync_pass``) walks the configured sync root and reconciles it
against the index by relative path:

* new local file        -> full upload through ``files_service.upload_stream``
  (the exact service path the web/CLI use -- never ChunkUploader directly);
* changed local file    -> ``snapshot_current_file(reason="sync")`` FIRST (so
  the outgoing bytes are preserved as an immutable version), then upload the
  new content -- the pipeline is content-addressed, so unchanged chunks are
  never re-encrypted/re-sent to a backend that already holds them;
* deleted local file    -> snapshot FIRST (the version preserves it), then move
  the index row to Trash. Deleted-on-disk files are NEVER hard-deleted: Trash's
  30-day retention is the natural ransomware undo, and versions on top of it
  make even a purge-then-regret recoverable while history remains.

Change detection is cheap by design: (size, mtime_ns, BLAKE3 of the first +
last 64 KiB). Size+mtime gate first, so an untouched file costs one stat and a
<=128 KiB read per pass; the edge fingerprint catches rewrites that preserve
both. Tradeoff: a file edited, restored, and touch-ed within one interval with
identical size/edges can be missed until mtime moves -- acceptable for a
seconds-long sync loop, versus hashing entire gigabyte files every pass.

Feedback-loop guard: the vault's own app-data dir (ciphertext, WAL, snapshots)
must never be a sync root or sit inside one -- re-uploading freshly written
ciphertext would create "new" files, write more ciphertext, and grow without
bound.

There is no extra watcher dependency: the interval loop itself is the change
detector. ``sync_on_change`` means the loop polls at the short interval while
sync is enabled (the mtime scan is cheap), versus the long configured interval
otherwise.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import stat as stat_module
import time
from pathlib import Path
from typing import Any, Optional

import blake3

from ghostdrive.services import files as files_service
from ghostdrive.services import versions as versions_service

logger = logging.getLogger("ghostdrive.services.sync")

# ── Settings keys ─────────────────────────────────────────────────────────────
SETTING_ENABLED = "sync_enabled"              # "true" / "false"  (default false)
SETTING_ROOT = "sync_root"                    # absolute local folder (default "")
SETTING_INTERVAL = "sync_interval_seconds"    # default "60", clamped to >= 15
SETTING_ON_CHANGE = "sync_on_change"          # "true" / "false"  (default true)
SETTING_VERSION_KEEP = "sync_version_keep"    # versions kept per file (default "10")
SETTING_LAST_RUN_AT = "sync_last_run_at"      # ISO-8601 of last finished pass
SETTING_LAST_RESULT = "sync_last_result"      # JSON counters of last pass
SETTING_STATE = "sync_state"                  # JSON per-relpath change detector

DEFAULT_TIER = "IMPORTANT"
MIN_INTERVAL_SECONDS = 15
EDGE_BYTES = 64 * 1024

_SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", "node_modules", ".venv", "venv"}
_SKIP_FILES = {".DS_Store", "Thumbs.db", "desktop.ini"}

_scheduler_task: Optional[asyncio.Task] = None


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def _resolve_db(db: Any = None):
    if db is not None:
        return db
    from ghostdrive.services.context import require_db

    return require_db()


def _setting_bool(db: Any, key: str, default: str) -> bool:
    return str(db.get_setting(key, default)).strip().lower() in ("1", "true", "yes", "on")


def _setting_int(db: Any, key: str, default: int) -> int:
    try:
        return int(db.get_setting(key, str(default)) or default)
    except (TypeError, ValueError):
        return default


# ── Filesystem scanning ───────────────────────────────────────────────────────

def _is_link_like(path: Path) -> bool:
    """True for symlinks, NTFS junctions, and other reparse points.

    Windows junctions are NOT reported by ``Path.is_symlink()`` on older
    Python versions, but they behave like links: walking into one can loop
    back up the tree (junction -> ancestor -> same directory forever) or drop
    the walker inside the vault's app-data dir. ``os.path.isjunction`` (3.12+)
    and the lstat st_mode check cover the gap.
    """
    try:
        if path.is_symlink():
            return True
        isjunction = getattr(os.path, "isjunction", None)
        if isjunction is not None and isjunction(path):
            return True
        return stat_module.S_ISLNK(os.lstat(path).st_mode)
    except OSError:
        # Unreadable entry: skip rather than fail the whole pass.
        return True


def _iter_files(root: Path):
    """Yield (path, fingerprint-dict-source stat) for regular files under root.

    Directories that are links are pruned and files that are reparse points
    are skipped (see ``_is_link_like`` for the junction-loop rationale).
    """
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, topdown=True):
        dirnames[:] = [
            name
            for name in dirnames
            if name not in _SKIP_DIRS and not _is_link_like(Path(dirpath) / name)
        ]
        for name in filenames:
            if name in _SKIP_FILES or name.endswith(".gdl"):
                continue
            path = Path(dirpath) / name
            if _is_link_like(path):
                continue
            try:
                st = os.stat(path, follow_symlinks=False)
            except OSError:
                continue
            if not stat_module.S_ISREG(st.st_mode):
                continue
            yield path


def _fingerprint(path: Path) -> dict:
    """Cheap change fingerprint: size, mtime_ns, edge BLAKE3 (first+last 64 KiB)."""
    st = os.stat(path, follow_symlinks=False)
    hasher = blake3.blake3()
    size = int(st.st_size)
    with open(path, "rb") as handle:
        head = handle.read(EDGE_BYTES)
        hasher.update(head)
        if size > EDGE_BYTES:
            handle.seek(max(EDGE_BYTES, size - EDGE_BYTES))
            hasher.update(handle.read(EDGE_BYTES))
    return {"size": size, "mtime_ns": int(st.st_mtime_ns), "edge": hasher.hexdigest()}


def _detect_change(entry: Optional[dict], fp: dict) -> tuple[bool, str]:
    """Decide whether a tracked local file changed since the last pass.

    Order matters: size and mtime are free (one stat already done); only when
    both match do we trust -- or verify with -- the edge fingerprint. A mere
    touch (mtime bump, same bytes) counts as changed on purpose: re-running
    the upload is idempotent and cheaper than being wrong about a real edit.
    """
    if entry is None:
        return True, "untracked"
    if int(entry.get("size", -1)) != fp["size"]:
        return True, "size changed"
    if int(entry.get("mtime_ns", -1)) != fp["mtime_ns"]:
        return True, "mtime changed"
    if str(entry.get("edge", "")) != fp["edge"]:
        return True, "content changed (edge fingerprint)"
    return False, "unchanged"


def _virtual_path(rel: str) -> str:
    """Index path for a POSIX relative path under the sync root (root -> '/')."""
    return "/" + rel if rel else "/"


def _destination_for(rel: str) -> str:
    """Parent directory in the vault for a relative path ('a/b.txt' -> '/a')."""
    if "/" not in rel:
        return "/"
    return "/" + rel.rsplit("/", 1)[0]


def _find_live_rows(db: Any, path: str):
    """Active index rows at one virtual path, newest first.

    Each sync re-upload supersedes the previous row with a fresh one (new
    content generation); the newest row is the live one for that path.
    """
    return db._conn.execute(
        """SELECT * FROM files
           WHERE path = ? AND tombstone = 0
           ORDER BY modified_at DESC, created_at DESC""",
        (path,),
    ).fetchall()


def _load_state(db: Any) -> dict:
    raw = str(db.get_setting(SETTING_STATE, "") or "")
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError:
        logger.warning("Sync detector state unreadable; rescanning from scratch.")
        return {}


def _feedback_guard(root: Path) -> Optional[str]:
    """Refuse roots that overlap the vault's own app-data directory.

    GhostDrive writes ciphertext under app-data (local backend vault, WAL,
    index snapshots). Syncing it would treat freshly written ciphertext as new
    user files, encrypt it again, write more ciphertext -- a feedback loop
    that also leaks encrypted blobs into the sync as "new" content. Both
    directions are refused: root == app-data, root inside it, or app-data
    inside root.
    """
    from ghostdrive.web.state import state

    try:
        app_dir = Path(state.app_data_dir).resolve()
        resolved = Path(root).resolve()
    except OSError as exc:
        return f"Could not resolve sync root {root}: {exc}"
    if (
        resolved == app_dir
        or app_dir in resolved.parents
        or resolved in app_dir.parents
    ):
        return (
            f"Sync root {resolved} overlaps the GhostDrive app-data directory "
            f"{app_dir} -- refusing (feedback-loop guard: vault data must never "
            "be re-uploaded as new content)."
        )
    return None


# ── Trash helper ──────────────────────────────────────────────────────────────

async def _trash_row(db: Any, row: Any) -> None:
    """Move one index row to Trash -- sync NEVER hard-deletes.

    Uses files.py's trash path (tombstone + 30-day retention), except for
    DISPOSABLE tier where files.py's delete_file would purge the bytes
    immediately: a locally deleted file must survive locally-deleted-by-malware
    scenarios too, so even DISPOSABLE rows are only tombstoned here.
    """
    if str(row["tier"]) == "DISPOSABLE":
        with db.transaction():
            db.tombstone_file(row["id"])
    else:
        await files_service.delete_file(row["id"])


# ── Status ────────────────────────────────────────────────────────────────────

def sync_status(db: Any = None) -> dict:
    """Current sync configuration and runtime state.

    Returns keys: enabled, root, interval_seconds, on_change, running
    (scheduler task alive), last_run_at, last_result (persisted pass counters:
    scanned/uploaded/unchanged/versioned/trashed/errors/duration_ms), watched.
    """
    db = _resolve_db(db)
    root = str(db.get_setting(SETTING_ROOT, "") or "")
    interval = max(MIN_INTERVAL_SECONDS, _setting_int(db, SETTING_INTERVAL, 60))
    on_change = _setting_bool(db, SETTING_ON_CHANGE, "true")
    enabled = _setting_bool(db, SETTING_ENABLED, "false")
    running = _scheduler_task is not None and not _scheduler_task.done()
    last_run_at = str(db.get_setting(SETTING_LAST_RUN_AT, "") or "") or None
    raw = str(db.get_setting(SETTING_LAST_RESULT, "") or "")
    last_result: Optional[dict] = None
    if raw:
        try:
            parsed = json.loads(raw)
            last_result = parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            last_result = None
    return {
        "enabled": enabled,
        "root": root,
        "interval_seconds": interval,
        "on_change": on_change,
        "running": running,
        "last_run_at": last_run_at,
        "last_result": last_result,
        "watched": bool(enabled and on_change and root),
    }


# ── One-shot pass ─────────────────────────────────────────────────────────────

def _finish(db: Any, counters: dict, errors: list[str], started: float, now: Optional[Any]) -> dict:
    result = {
        **counters,
        "errors": errors,
        "duration_ms": int((time.perf_counter() - started) * 1000),
    }
    try:
        db.set_setting(SETTING_LAST_RESULT, json.dumps(result))
        db.set_setting(
            SETTING_LAST_RUN_AT,
            now.isoformat() if hasattr(now, "isoformat") else (str(now) if now else _now_iso()),
        )
    except Exception as exc:  # status persistence must not break the pass
        logger.warning("Could not persist sync last result: %s", exc)
    return result


async def run_sync_pass(
    db: Any = None,
    objects: Optional[dict] = None,
    root: Optional[Path] = None,
    now: Optional[Any] = None,
) -> dict:
    """Reconcile the sync root against the index once (see module docstring).

    ``objects`` may carry pre-built backend objects; the upload and trash
    paths build their own via services.context so this pass behaves exactly
    like a manual web/CLI upload.

    Returns: {"scanned", "uploaded", "unchanged", "versioned", "trashed",
              "errors": [str, ...], "duration_ms"}. Guard violations and
              unusable roots are reported as error entries with zero uploads
              instead of raising, so a scheduled pass always survives.
    """
    started = time.perf_counter()
    counters = {
        "scanned": 0,
        "uploaded": 0,
        "unchanged": 0,
        "versioned": 0,
        "trashed": 0,
    }
    errors: list[str] = []
    db = _resolve_db(db)
    _ = objects  # see docstring: upload/trash resolve backends themselves

    if root is None:
        configured = str(db.get_setting(SETTING_ROOT, "") or "").strip()
        root = Path(configured) if configured else None
    if root is None:
        errors.append("Sync root is not configured.")
        return _finish(db, counters, errors, started, now)
    root = Path(root)

    guard = _feedback_guard(root)
    if guard:
        errors.append(guard)
        return _finish(db, counters, errors, started, now)
    if not root.exists() or not root.is_dir():
        errors.append(f"Sync root is not a directory: {root}")
        return _finish(db, counters, errors, started, now)

    state = _load_state(db)
    seen: set[str] = set()

    for path in _iter_files(root):
        rel = path.relative_to(root).as_posix()
        seen.add(rel)
        counters["scanned"] += 1
        vpath = _virtual_path(rel)
        try:
            fp = _fingerprint(path)
            rows = _find_live_rows(db, vpath)
            entry = state.get(rel)

            if not rows:
                # New file -> full upload through the shared service entrypoint.
                await files_service.upload_stream(
                    path, path.name, None, DEFAULT_TIER, _destination_for(rel)
                )
                state[rel] = fp
                counters["uploaded"] += 1
                continue

            newest = rows[0]
            if entry is None:
                # Row exists without detector state (first pass over a
                # manually uploaded file): adopt it when the sizes agree,
                # otherwise treat the local copy as authoritative/changing.
                changed = int(newest["size"]) != fp["size"]
                reason = "adopted" if not changed else "size differs from index"
            else:
                changed, reason = _detect_change(entry, fp)

            if not changed:
                counters["unchanged"] += 1
                continue

            # Preserve the outgoing bytes FIRST: the version is the safety net
            # that makes an overwrite (or a hostile one) reversible.
            result = await versions_service.snapshot_current_file(
                db, newest["id"], reason="sync", now=now
            )
            if not result.get("unchanged"):
                counters["versioned"] += 1

            await files_service.upload_stream(
                path, path.name, None, DEFAULT_TIER, _destination_for(rel)
            )
            counters["uploaded"] += 1
            state[rel] = fp

            # History follows the path: the fresh upload superseded the old
            # row, so re-home its versions onto the new live row.
            fresh = _find_live_rows(db, vpath)
            if fresh and fresh[0]["id"] != newest["id"]:
                with db.transaction():
                    db.rehome_file_versions(newest["id"], fresh[0]["id"])
            logger.debug("Sync changed %s (%s)", rel, reason)
        except Exception as exc:
            errors.append(f"{rel}: {exc}")
            logger.warning("Sync failed for %s: %s", rel, exc)

    # Locally deleted files: snapshot, then Trash -- never an immediate purge.
    for rel in list(state.keys()):
        if rel in seen:
            continue
        vpath = _virtual_path(rel)
        try:
            rows = _find_live_rows(db, vpath)
            if rows:
                newest = rows[0]
                try:
                    result = await versions_service.snapshot_current_file(
                        db, newest["id"], reason="sync", now=now
                    )
                    if not result.get("unchanged"):
                        counters["versioned"] += 1
                except Exception as exc:
                    # Still trash the row: the local content is gone and an
                    # unversioned ghost row must not keep claiming the path.
                    errors.append(f"{rel}: snapshot before trash failed: {exc}")
                for row in rows:
                    await _trash_row(db, row)
                    counters["trashed"] += 1
            state.pop(rel, None)
        except Exception as exc:
            errors.append(f"{rel}: {exc}")
            logger.warning("Sync trash failed for %s: %s", rel, exc)

    db.set_setting(SETTING_STATE, json.dumps(state))
    return _finish(db, counters, errors, started, now)


# ── Scheduler ─────────────────────────────────────────────────────────────────

async def _sync_loop() -> None:
    """Sleep between passes; any failure is logged and the loop survives."""
    while True:
        try:
            db = _resolve_db()
            interval = max(
                MIN_INTERVAL_SECONDS, _setting_int(db, SETTING_INTERVAL, 60)
            )
            on_change = _setting_bool(db, SETTING_ON_CHANGE, "true")
            enabled = _setting_bool(db, SETTING_ENABLED, "false")
        except Exception as exc:
            # Vault locked / no database yet: idle instead of dying.
            logger.debug("Sync scheduler idle: %s", exc)
            db, interval, on_change, enabled = None, MIN_INTERVAL_SECONDS, True, False

        # on_change contract: this loop IS the filesystem watcher (a
        # size/mtime/edge rescan is cheap). While enabled + watching it polls
        # at the short interval; otherwise it sleeps the long configured one.
        if enabled and on_change:
            sleep_for = MIN_INTERVAL_SECONDS
        else:
            sleep_for = max(MIN_INTERVAL_SECONDS, interval)
        await asyncio.sleep(sleep_for)

        if not enabled:
            continue
        try:
            db = _resolve_db()
            await run_sync_pass(db)
            keep = _setting_int(db, SETTING_VERSION_KEEP, 10)
            # Retire old versions for every file (never the live version).
            versions_service.prune_versions(db, file_id=None, keep=max(1, keep))
        except Exception as exc:
            logger.warning("Sync pass failed: %s", exc)


def start_sync_scheduler(db: Any = None) -> Optional[asyncio.Task]:
    """Start the module-global sync loop (idempotent: double-start is a no-op).

    ``db`` is accepted for API symmetry; the loop re-reads settings every
    cycle so a start made before unlock still behaves once the vault opens.
    """
    global _scheduler_task
    if _scheduler_task is not None and not _scheduler_task.done():
        return _scheduler_task
    _scheduler_task = asyncio.create_task(_sync_loop())
    return _scheduler_task


def stop_sync_scheduler() -> Optional[asyncio.Task]:
    """Cancel the module-global sync loop if it is running.

    Returns the cancelled task (so async callers can await its teardown and
    avoid pending-task warnings) or ``None`` when nothing was running.
    """
    global _scheduler_task
    task = _scheduler_task
    if task is not None and not task.done():
        task.cancel()
    _scheduler_task = None
    return task
