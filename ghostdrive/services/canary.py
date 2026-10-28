"""Canary tripwire: decoy files whose tampering betrays an attacker early.

Ransomware and data-theft tooling share one habit -- they walk the user's
folders and rewrite or delete everything they can reach.  Sync makes the
damage *recoverable* (versions + Trash) and the mass-modification alarm
catches the bulk-rate signature, but both are statistical: a careful attacker
who changes few files slowly can stay under every rate threshold.

A canary file is the non-statistical signal.  It sits in a watched folder
looking like a small credential note; no legitimate workflow ever touches it,
so ANY modification or deletion is an event.  Each planted decoy is
fingerprinted (size, mtime_ns, full-file BLAKE3) and re-armed after every
trigger: the generation counter bumps, so the *next* tamper produces a fresh
alert id while the already-reported state never re-fires on every interval.

Honest limits: a canary proves activity at its own path only -- it is not a
general integrity monitor and it cannot see reads.  A user who knowingly
edits their own folders can trip it; that is the intended trade (the file is
meant to be boring to humans and irresistible to automation).  The decoy
content carries a ``GHOSTDRIVE-CANARY v1`` marker line so anyone who opens
the file can tell it is machine-planted rather than real secrets, and the
marker doubles as the delete-safety check (unregistering never unlinks a
file that does not carry it).

Planting never flips ``canary_enabled``: the check loop honors that flag, so
an operator can plant a full set of decoys before arming the tripwire.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import blake3

from ghostdrive.services import alerts as alerts_service

logger = logging.getLogger("ghostdrive.services.canary")

# ── Settings keys ─────────────────────────────────────────────────────────────
SETTING_ENABLED = "canary_enabled"             # "true" / "false"  (default false)
SETTING_INTERVAL = "canary_interval_seconds"   # default "60", clamped to >= 15
SETTING_STATE = "canary_state"                 # JSON {path: entry}, see _load_state

MIN_INTERVAL_SECONDS = 15
DEFAULT_INTERVAL_SECONDS = 60

#: Marker line appended to every planted decoy.  Self-describing if a human
#: opens the file, and the presence check that keeps delete_file from ever
#: unlinking a real user file.
CANARY_MARKER = "GHOSTDRIVE-CANARY v1"

# Believable decoy content: a few plausible stale credential lines a real
# "notes" file might hold, terminated by the machine marker so the file is
# honest about what it is once fully read.
_DECOY_TEMPLATE = """\
# home-lab notes -- keep for later
router admin: http://192.168.1.1  user: admin  pass: r3d-fox-2016!
openvpn profile: gd-backup / Wn7#paleHorse
smb: \\\\nas-01\\archive  user: serviceacct  pass: old-s3cret-w0rd
{marker}
"""

_scheduler_task: Optional[asyncio.Task] = None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _setting_bool(db: Any, key: str, default: str) -> bool:
    return str(db.get_setting(key, default)).strip().lower() in ("1", "true", "yes", "on")


def _setting_int(db: Any, key: str, default: int) -> int:
    try:
        return int(str(db.get_setting(key, str(default))).strip() or default)
    except (TypeError, ValueError):
        return default


def _configured_interval(db: Any) -> int:
    return max(MIN_INTERVAL_SECONDS, _setting_int(db, SETTING_INTERVAL, DEFAULT_INTERVAL_SECONDS))


# ── Path + fingerprint helpers ────────────────────────────────────────────────

def _resolve_path(raw: Any) -> Path:
    """Normalize a canary path and refuse anything inside the app-data dir.

    A decoy inside the vault's own data directory would be indistinguishable
    from vault internals to the user and could be clobbered by GhostDrive's
    own writes -- refuse at registration time (routes map this to 400).
    """
    text = str(raw or "").strip()
    if not text:
        raise ValueError("Canary path must not be empty.")
    resolved = Path(text).expanduser().resolve()
    from ghostdrive.web.state import state

    try:
        app_dir = Path(state.app_data_dir).resolve()
    except OSError:
        app_dir = Path(state.app_data_dir)
    if resolved == app_dir or app_dir in resolved.parents:
        raise ValueError(
            f"Canary path {resolved} overlaps the GhostDrive app-data directory "
            f"{app_dir} -- refusing (decoys must live in user folders, never in "
            "vault internals)."
        )
    return resolved


def _fingerprint(path: Path) -> dict:
    """Full-file fingerprint: size, mtime_ns, BLAKE3 of every byte.

    Canary files are tiny by design, so unlike sync's edge fingerprint the
    whole file is hashed: a same-size same-mtime rewrite (a sophisticated
    encryptor's attempt) still trips on content.
    """
    st = os.stat(path, follow_symlinks=False)
    hasher = blake3.blake3()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            hasher.update(chunk)
    return {
        "size": int(st.st_size),
        "mtime_ns": int(st.st_mtime_ns),
        "content_hash": hasher.hexdigest(),
    }


def _is_canary_file(path: Path) -> bool:
    """True when the file at ``path`` carries the canary marker line."""
    try:
        with open(path, "rb") as handle:
            return CANARY_MARKER.encode("utf-8") in handle.read()
    except OSError:
        return False


# ── State persistence ─────────────────────────────────────────────────────────

def _load_state(db: Any) -> dict:
    """``{path: entry}``; unreadable JSON degrades to "no canaries" (logged)."""
    raw = str(db.get_setting(SETTING_STATE, "") or "")
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("Canary state unreadable; treating all canaries as unregistered.")
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): v for k, v in data.items() if isinstance(v, dict)}


def _save_state(db: Any, state: dict) -> None:
    with db.transaction():
        db.set_setting(SETTING_STATE, json.dumps(state))


def _make_entry(stamp: str, fp: dict) -> dict:
    return {
        "generation": 0,
        "planted_at": stamp,
        "size": fp["size"],
        "mtime_ns": fp["mtime_ns"],
        "content_hash": fp["content_hash"],
        "missing": False,
    }


# ── Registration ──────────────────────────────────────────────────────────────

async def plant_canary(db: Any, path: Any, *, now: Optional[datetime] = None) -> dict:
    """Plant a decoy canary file at ``path`` and register its fingerprint.

    Creates the decoy when absent.  A pre-existing file that already carries
    the canary marker is re-fingerprinted (re-arm after cleanup); any other
    pre-existing file raises FileExistsError -- silently overwriting a user's
    real file to plant a decoy is exactly the behavior this feature exists to
    detect (pass ``plant=False`` semantics -- register_existing_canary -- to
    watch an existing file as-is instead).  Already-registered paths also
    raise FileExistsError; unregister first.

    Planting does NOT set ``canary_enabled`` -- the check loop honors that
    flag, so a whole set of decoys can be planted before arming.
    """
    resolved = _resolve_path(path)
    key = str(resolved)
    state = _load_state(db)
    if key in state:
        raise FileExistsError(f"Canary already registered at {key}.")

    stamp = (now or _now()).isoformat()
    if resolved.exists():
        if not _is_canary_file(resolved):
            raise FileExistsError(
                f"{resolved} already exists and is not a GhostDrive canary file; "
                "refusing to overwrite it. Register it unchanged with plant=false."
            )
    else:
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(
            _DECOY_TEMPLATE.format(marker=CANARY_MARKER), encoding="utf-8"
        )

    entry = _make_entry(stamp, _fingerprint(resolved))
    state[key] = entry
    _save_state(db, state)
    logger.info("Canary planted at %s (generation 0).", key)
    return dict(entry, path=key)


def register_existing_canary(
    db: Any, path: Any, *, now: Optional[datetime] = None
) -> dict:
    """Register an existing file as a canary WITHOUT modifying it.

    For ``plant=False`` additions: the file is fingerprinted as-is, which is
    what a user wants when a specific file's presence/content must never
    change.  Because the file never carried the decoy marker, unregistering
    with ``delete_file=True`` will refuse to unlink it (see
    ``unregister_canary``) -- watching is non-destructive by construction.
    """
    resolved = _resolve_path(path)
    key = str(resolved)
    state = _load_state(db)
    if key in state:
        raise FileExistsError(f"Canary already registered at {key}.")
    if not resolved.exists() or not resolved.is_file():
        raise ValueError(
            f"File does not exist (or is not a regular file): {resolved}. "
            "plant=false only registers files that already exist."
        )

    stamp = (now or _now()).isoformat()
    entry = _make_entry(stamp, _fingerprint(resolved))
    state[key] = entry
    _save_state(db, state)
    logger.info("Existing file registered as canary: %s (generation 0).", key)
    return dict(entry, path=key)


def unregister_canary(db: Any, path: Any, delete_file: bool = False) -> dict:
    """Remove a canary registration; optionally unlink the planted decoy.

    The unlink is marker-guarded: only a file that still carries the canary
    marker is deleted.  A registered *existing* file (added with
    plant=false), or anything the attacker swapped in its place, survives --
    unregistering must never destroy data it did not plant.
    """
    resolved = _resolve_path(path)
    key = str(resolved)
    state = _load_state(db)
    entry = state.pop(key, None)
    if entry is None:
        raise FileNotFoundError(f"No canary registered at {key}.")
    if delete_file:
        try:
            if resolved.exists() and _is_canary_file(resolved):
                resolved.unlink()
        except OSError as exc:
            logger.warning("Could not delete canary file %s: %s", resolved, exc)
    _save_state(db, state)
    logger.info("Canary unregistered at %s.", key)
    return dict(entry, path=key)


# ── Status ────────────────────────────────────────────────────────────────────

def canary_list(db: Any) -> list[dict]:
    state = _load_state(db)
    return [
        {
            "path": key,
            "planted_at": str(entry.get("planted_at") or ""),
            "size": int(entry.get("size") or 0),
            "missing": bool(entry.get("missing")),
            "generation": int(entry.get("generation") or 0),
        }
        for key, entry in sorted(state.items())
    ]


def canary_status(db: Any) -> dict:
    return {
        "enabled": _setting_bool(db, SETTING_ENABLED, "false"),
        "interval_seconds": _configured_interval(db),
        "canaries": canary_list(db),
    }


# ── Check pass ────────────────────────────────────────────────────────────────

async def check_canaries(db: Any, *, now: Optional[datetime] = None) -> dict:
    """Check every registered canary against its stored fingerprint.

    A trigger fires when the file was modified (size/mtime/content changed),
    or disappeared without having been reported missing before.  On trigger
    the canary RE-ARMS: generation bumps and the fingerprint is refreshed to
    the file's current state (or marked missing with the last fingerprint
    kept), so the current situation never re-alerts every interval while the
    next unrelated tamper -- generation N+1 -- gets a fresh alert id.

    Alert identity is ``{path}#{generation}``: one alert per tamper event per
    canary, dismissible once.  Persistence (``record_alerts``) and delivery
    (``dispatch``) are individually guarded; a check pass never raises.

    Returns {"checked", "triggers", "alerts", "results", "dispatched"}.
    """
    now = now or _now()
    stamp = now.isoformat()
    state = _load_state(db)
    results: list[dict] = []
    alerts: list[dict] = []

    for key, entry in sorted(state.items()):
        path = Path(key)
        generation = int(entry.get("generation") or 0)
        exists = path.exists() and path.is_file()
        fp: Optional[dict] = None

        trigger: Optional[str] = None  # "modified" | "deleted"
        if not exists:
            if bool(entry.get("missing")):
                # Already reported and re-armed: still missing is not news.
                results.append({
                    "path": key,
                    "status": "missing",
                    "detail": "still missing (already reported)",
                })
                continue
            trigger = "deleted"
        else:
            try:
                fp = _fingerprint(path)
            except OSError as exc:
                # Unreadable but present: not proof of tampering; skip.
                results.append({
                    "path": key,
                    "status": "ok",
                    "detail": f"present but not fingerprintable: {exc}",
                })
                continue
            changed = (
                int(entry.get("size", -1)) != fp["size"]
                or int(entry.get("mtime_ns", -1)) != fp["mtime_ns"]
                or str(entry.get("content_hash", "")) != fp["content_hash"]
            )
            if changed:
                trigger = "modified"
            elif bool(entry.get("missing")):
                # Byte-identical file reappeared: treat as restored, not news.
                entry["missing"] = False
                results.append({
                    "path": key,
                    "status": "ok",
                    "detail": "file restored with identical content",
                })
                continue

        if trigger is None:
            results.append({"path": key, "status": "ok", "detail": "unchanged"})
            continue

        subject = f"{key}#{generation}"
        reason = "was deleted" if trigger == "deleted" else "was modified (size/mtime/content changed)"
        alerts.append({
            "id": alerts_service.alert_id("canary_tampered", subject),
            "kind": "canary_tampered",
            "severity": "critical",
            "subject_id": subject,
            "title": "Canary file tampered",
            "detail": (
                f"Canary file {reason}: {key} (generation {generation}). A canary "
                "is only touched by tooling enumerating or encrypting folders -- "
                "treat this as a ransomware/attacker signal."
            ),
            "detected_at": stamp,
        })

        # Re-arm: bump the generation so the next tamper gets a fresh alert
        # id, and adopt the current on-disk state (or last-known fingerprint
        # with missing=true) so the current situation never re-fires.
        entry["generation"] = generation + 1
        if fp is not None:
            entry.update(fp)
            entry["missing"] = False
        else:
            entry["missing"] = True
        results.append({
            "path": key,
            "status": "missing" if trigger == "deleted" else "tampered",
            "detail": f"{trigger} detected; re-armed as generation {entry['generation']}",
        })

    _save_state(db, state)

    dispatched = 0
    new_alerts: list[dict] = []
    if alerts:
        try:
            new_alerts = alerts_service.record_alerts(db, alerts, now=now)
        except Exception as exc:
            # Still deliver: alerting must survive a wedged settings row.
            logger.warning("Could not persist canary alerts: %s", exc)
            new_alerts = list(alerts)
        if new_alerts:
            try:
                outcome = await alerts_service.dispatch(db, new_alerts)
                dispatched = int(outcome.get("delivered", 0))
            except Exception as exc:
                logger.warning("Could not dispatch canary alerts: %s", exc)

    return {
        "checked": len(state),
        "triggers": len(alerts),
        "alerts": alerts,
        "results": results,
        "dispatched": dispatched,
    }


# ── Scheduler ─────────────────────────────────────────────────────────────────

async def _canary_loop(db: Any, fallback_interval: int) -> None:
    """Sleep between checks, honoring the enable flag re-read every cycle."""
    while True:
        try:
            from ghostdrive.services.context import require_db

            target = db if db is not None else require_db()
            enabled = _setting_bool(target, SETTING_ENABLED, "false")
            interval = max(
                MIN_INTERVAL_SECONDS,
                _setting_int(target, SETTING_INTERVAL, fallback_interval),
            )
        except Exception as exc:
            # Locked vault / no database yet: idle instead of dying.
            logger.debug("Canary scheduler idle: %s", exc)
            enabled, interval = False, MIN_INTERVAL_SECONDS

        await asyncio.sleep(interval)
        if not enabled:
            continue
        try:
            from ghostdrive.services.context import require_db

            target = db if db is not None else require_db()
            await check_canaries(target)
        except Exception as exc:
            logger.warning("Canary check cycle failed: %s", exc)


def start_canary_scheduler(
    interval_seconds: Optional[int] = None,
    db: Any = None,
) -> Optional[asyncio.Task]:
    """Start the module-global canary loop (idempotent: double-start no-op).

    ``interval_seconds`` only seeds the fallback used while the persisted
    ``canary_interval_seconds`` setting is unset; the loop re-reads settings
    every cycle, so a start made before unlock still behaves once the vault
    opens.
    """
    global _scheduler_task
    if _scheduler_task is not None and not _scheduler_task.done():
        return _scheduler_task
    fallback = max(MIN_INTERVAL_SECONDS, int(interval_seconds or DEFAULT_INTERVAL_SECONDS))
    _scheduler_task = asyncio.create_task(_canary_loop(db, fallback))
    return _scheduler_task


def stop_canary_scheduler() -> Optional[asyncio.Task]:
    """Cancel the canary loop; return the cancelled task (or None)."""
    global _scheduler_task
    task = _scheduler_task
    if task is not None and not task.done():
        task.cancel()
    _scheduler_task = None
    return task
