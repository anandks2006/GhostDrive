"""Auto-vault: watch any number of local folders and mirror them into the vault.

The user configures an unlimited list of sync roots (``sync_roots``). One pass
(``run_sync_pass``) walks **every** configured root and reconciles each against
the index by relative path:

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

Root isolation (multi-folder correctness): each root owns a *namespace* -- its
files live in the vault under ``/<slug>/<rel>`` and its change-detector state
is keyed by that slug (``root_slug`` derives the slug from the folder's own
resolved path, so it never shifts when other roots are added or removed).
Consequences by design:

* two watched folders containing ``a/b.txt`` each stay distinct rows;
* a deletion in root A can only ever trash root A's rows;
* a bad root (guard violation, missing directory) is reported as an error for
  that root while every other root still syncs in the same pass.

Change detection is cheap by design: (size, mtime_ns, BLAKE3 of the first +
last 64 KiB). Size+mtime gate first, so an untouched file costs one stat and a
<=128 KiB read per pass; the edge fingerprint catches rewrites that preserve
both. Tradeoff: a file edited, restored, and touch-ed within one interval with
identical size/edges can be missed until mtime moves -- acceptable for a
seconds-long sync loop, versus hashing entire gigabyte files every pass.

Feedback-loop guard: the vault's own app-data dir (ciphertext, WAL, snapshots)
must never be a sync root or sit inside one -- re-uploading freshly written
ciphertext would create "new" files, write more ciphertext, and grow without
bound. The guard runs per root: one offending folder does not disable the
others.

There is no extra watcher dependency: the interval loop itself is the change
detector. ``sync_on_change`` means the loop polls at the short interval while
sync is enabled (the mtime scan is cheap), versus the long configured interval
otherwise.

Backward compatibility: the legacy single-root ``sync_root`` setting is still
read as a one-element root list (and written back as ``sync_roots[0]``), and
the legacy flat detector state is migrated to per-root keys on load.
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
SETTING_ROOT = "sync_root"                    # legacy single root (mirrors sync_roots[0])
SETTING_ROOTS = "sync_roots"                  # JSON list of absolute folders (default "[]")
SETTING_INTERVAL = "sync_interval_seconds"    # default "60", clamped to >= 15
SETTING_ON_CHANGE = "sync_on_change"          # "true" / "false"  (default true)
SETTING_VERSION_KEEP = "sync_version_keep"    # versions kept per file (default "10")
SETTING_LAST_RUN_AT = "sync_last_run_at"      # ISO-8601 of last finished pass
SETTING_LAST_RESULT = "sync_last_result"      # JSON counters of last pass (incl. per_root)
SETTING_STATE = "sync_state"                  # JSON detector state, see _save_state

#: Detector-state format version. v2 = {"v": 2, "roots": {slug: {rel: fp}}};
#: anything older is the legacy flat {rel: fp} map of the single-root era.
STATE_VERSION = 2

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


# ── Root list ─────────────────────────────────────────────────────────────────

def root_slug(root: Any) -> str:
    """Stable per-folder vault namespace segment for one sync root.

    The slug depends only on the folder's own resolved, case-normalized path
    -- never on which other roots are configured -- so files from ``C:\\Docs``
    live under ``/Docs-3f2a9b/...`` forever, and adding/removing another
    watched folder can never remap existing rows or detector state.

    The readable basename prefix keeps vault paths human-meaningful; a 4-byte
    BLAKE3 of the full path disambiguates same-named folders (``C:\\Docs``
    vs ``D:\\Docs``) and the same folder typed with different case resolves
    to the same slug (``os.path.normcase``).
    """
    try:
        resolved = Path(root).expanduser().resolve()
    except OSError:
        resolved = Path(root).expanduser()
    normalized = os.path.normcase(str(resolved))
    raw_name = resolved.name or "drive"          # drive roots ("/", "C:\\") have no name
    safe_name = "".join(
        ch if (ch.isalnum() or ch in "._-") else "_" for ch in raw_name
    ).strip(" .")[:48] or "drive"
    digest = blake3.blake3(normalized.encode("utf-8")).hexdigest(length=4)
    return f"{safe_name}-{digest}"


def get_sync_roots(db: Any) -> list[str]:
    """Configured sync roots, in configuration order (empty list = none).

    Reads ``sync_roots`` (JSON list). When it holds nothing, falls back to the
    legacy single-root ``sync_root`` setting, so pre-multi-folder
    configurations keep working without a data migration step.
    """
    raw = str(db.get_setting(SETTING_ROOTS, "") or "").strip()
    roots: list[str] = []
    if raw:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, list):
            roots = [str(item) for item in parsed if str(item).strip()]
    if not roots:
        legacy = str(db.get_setting(SETTING_ROOT, "") or "").strip()
        if legacy:
            roots = [legacy]
    return roots


def set_sync_roots(db: Any, roots: list[str]) -> list[str]:
    """Replace the configured root list (trimmed, deduplicated, in order).

    Also mirrors the first root into the legacy ``sync_root`` key so any older
    reader of the single-root setting stays consistent ("" when the list is
    cleared). Returns the stored list.
    """
    seen: set[str] = set()
    stored: list[str] = []
    for root in roots:
        candidate = str(root).strip()
        if not candidate:
            continue
        key = os.path.normcase(str(Path(candidate).expanduser()))
        if key in seen:
            continue
        seen.add(key)
        stored.append(candidate)
    db.set_setting(SETTING_ROOTS, json.dumps(stored))
    db.set_setting(SETTING_ROOT, stored[0] if stored else "")
    return stored


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


def _virtual_path(slug: str, rel: str) -> str:
    """Vault path for a file under one root's namespace ('/slug' + '/' + rel)."""
    base = "/" + slug
    return f"{base}/{rel}" if rel else base


def _destination_for(slug: str, rel: str) -> str:
    """Parent directory in the vault for a relative path ('a/b.txt' -> '/slug/a')."""
    base = "/" + slug
    if "/" not in rel:
        return base
    return base + "/" + rel.rsplit("/", 1)[0]


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
    """Detector state as ``{slug: {rel: fingerprint}}``.

    Current format (v2): ``{"v": 2, "roots": {slug: {rel: fp}}}``. The legacy
    flat ``{rel: fp}`` map of the single-root era is migrated in memory --
    re-homed under the legacy ``sync_root``'s slug -- so upgrading does not
    force a full re-upload; the next pass persists the v2 format.
    """
    raw = str(db.get_setting(SETTING_STATE, "") or "")
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("Sync detector state unreadable; rescanning from scratch.")
        return {}
    if not isinstance(data, dict):
        return {}
    if "v" in data or "roots" in data:
        roots_map = data.get("roots")
        if not isinstance(roots_map, dict):
            return {}
        return {
            str(slug): {
                str(rel): fp for rel, fp in sub.items() if isinstance(fp, dict)
            }
            for slug, sub in roots_map.items()
            if isinstance(sub, dict)
        }
    # Legacy flat format: top-level rel paths -> fingerprints.
    flat = {str(rel): fp for rel, fp in data.items() if isinstance(fp, dict)}
    if not flat:
        return {}
    legacy_root = str(db.get_setting(SETTING_ROOT, "") or "").strip()
    if legacy_root:
        logger.debug("Migrating legacy single-root sync state to per-folder keys.")
        return {root_slug(legacy_root): flat}
    return {}


def _save_state(db: Any, state: dict) -> None:
    """Persist detector state in the current (v2) format."""
    db.set_setting(
        SETTING_STATE, json.dumps({"v": STATE_VERSION, "roots": state})
    )


def feedback_guard(root: Path) -> Optional[str]:
    """Refuse roots that overlap the vault's own app-data directory.

    GhostDrive writes ciphertext under app-data (local backend vault, WAL,
    index snapshots). Syncing it would treat freshly written ciphertext as new
    user files, encrypt it again, write more ciphertext -- a feedback loop
    that also leaks encrypted blobs into the sync as "new" content. Both
    directions are refused: root == app-data, root inside it, or app-data
    inside root.

    Public: the settings route validates candidate roots with it before
    persisting, so a bad folder is rejected at configuration time (and the
    per-root check still runs every pass for roots that went bad afterwards).
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

    Returns keys: enabled, root (legacy: first root or ""), roots (all
    configured folders), root_details ([{path, slug, tracked}] -- tracked =
    detector entries, i.e. files being watched per folder), interval_seconds,
    on_change, running (scheduler task alive), last_run_at, last_result
    (persisted pass counters: scanned/uploaded/unchanged/versioned/trashed/
    errors/duration_ms/per_root), watched.
    """
    db = _resolve_db(db)
    roots = get_sync_roots(db)
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
    state = _load_state(db)
    root_details = []
    for path in roots:
        slug = root_slug(path)
        root_details.append(
            {"path": path, "slug": slug, "tracked": len(state.get(slug, {}))}
        )
    return {
        "enabled": enabled,
        "root": roots[0] if roots else "",
        "roots": roots,
        "root_details": root_details,
        "interval_seconds": interval,
        "on_change": on_change,
        "running": running,
        "last_run_at": last_run_at,
        "last_result": last_result,
        "watched": bool(enabled and on_change and roots),
    }


# ── One-shot pass ─────────────────────────────────────────────────────────────

def _finish(
    db: Any,
    counters: dict,
    errors: list[str],
    started: float,
    now: Optional[Any],
    per_root: Optional[list] = None,
) -> dict:
    result = {
        **counters,
        "errors": errors,
        "duration_ms": int((time.perf_counter() - started) * 1000),
        "per_root": per_root or [],
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


async def _sync_root(
    db: Any,
    root: Path,
    slug: str,
    state: dict,
    counters: dict,
    errors: list[str],
    now: Optional[Any],
) -> None:
    """Reconcile ONE root (see module docstring) into its namespace.

    ``state`` is this root's own ``{rel: fingerprint}`` map (mutated in
    place); ``counters``/``errors`` are this root's own, so the caller can
    report them per root before merging into the pass totals. Every path --
    upload destination, version snapshot, trash lookup -- carries the slug,
    which is what keeps roots hermetic from each other.
    """
    seen: set[str] = set()

    for path in _iter_files(root):
        rel = path.relative_to(root).as_posix()
        seen.add(rel)
        counters["scanned"] += 1
        vpath = _virtual_path(slug, rel)
        try:
            fp = _fingerprint(path)
            rows = _find_live_rows(db, vpath)
            entry = state.get(rel)

            if not rows:
                # New file -> full upload through the shared service entrypoint.
                await files_service.upload_stream(
                    path, path.name, None, DEFAULT_TIER, _destination_for(slug, rel)
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
                path, path.name, None, DEFAULT_TIER, _destination_for(slug, rel)
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
    # Only THIS root's detector keys are considered, so a file disappearing
    # from root A can never touch root B's rows even when the relative paths
    # are identical.
    for rel in list(state.keys()):
        if rel in seen:
            continue
        vpath = _virtual_path(slug, rel)
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


async def run_sync_pass(
    db: Any = None,
    objects: Optional[dict] = None,
    root: Optional[Path] = None,
    now: Optional[Any] = None,
) -> dict:
    """Reconcile the configured sync roots against the index once.

    With ``root`` given, only that folder is reconciled (manual/one-shot
    usage); otherwise every folder in ``sync_roots`` is processed, in
    configuration order. Roots are isolated: a root that fails validation
    (guard violation, missing directory) is recorded as an error while the
    remaining roots still sync. A root removed from the configuration keeps
    its vaulted rows and detector state untouched (they simply stop being
    synced -- removal is not deletion).

    ``objects`` may carry pre-built backend objects; the upload and trash
    paths build their own via services.context so this pass behaves exactly
    like a manual web/CLI upload.

    Returns: {"scanned", "uploaded", "unchanged", "versioned", "trashed",
              "errors": [str, ...], "duration_ms", "per_root": [{"root",
              "slug", counters..., "errors"}, ...]}. ``scanned`` and friends
              are aggregates across all roots; guard violations and unusable
              roots appear in ``errors`` and in their ``per_root`` entry with
              zero uploads instead of raising, so a scheduled pass survives.
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
    per_root: list[dict] = []
    db = _resolve_db(db)
    _ = objects  # see docstring: upload/trash resolve backends themselves

    if root is not None:
        roots = [str(Path(root))]
    else:
        roots = get_sync_roots(db)
    if not roots:
        errors.append("Sync root is not configured.")
        return _finish(db, counters, errors, started, now, per_root)

    state = _load_state(db)
    for configured in roots:
        rpath = Path(configured)
        slug = root_slug(rpath)
        root_counters = {key: 0 for key in counters}
        root_errors: list[str] = []

        guard = feedback_guard(rpath)
        if guard:
            root_errors.append(guard)
        elif not rpath.exists() or not rpath.is_dir():
            root_errors.append(f"Sync root is not a directory: {rpath}")
        else:
            await _sync_root(
                db, rpath, slug, state.setdefault(slug, {}),
                root_counters, root_errors, now,
            )

        errors.extend(root_errors)
        per_root.append(
            {"root": str(rpath), "slug": slug, **root_counters, "errors": root_errors}
        )
        for key in counters:
            counters[key] += root_counters[key]

    _save_state(db, state)
    return _finish(db, counters, errors, started, now, per_root)


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
