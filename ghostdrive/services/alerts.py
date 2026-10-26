"""Resilience alerting: surface durability events instead of burying in logs.

GhostDrive already *measures* everything that can go wrong -- failed or stale
restore drills, degraded/unreachable backends, hostile-backend verdicts,
layouts below the durability contract, chunks at risk, quota pressure -- but
until now none of it was ever pushed at the user.  This module turns those
existing signals into a single evaluation pass with stable identities, a
bounded persisted state (dedupe + dismiss), and pluggable delivery channels
(a registered async deliverer such as the tray, plus an optional webhook).

Nothing here creates new tables: every condition is read from data that
already exists, and the only persisted state is one JSON settings row.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import random
import urllib.request
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from ghostdrive.services import durability
from ghostdrive.services import hostility
from ghostdrive.services import restore_drills

logger = logging.getLogger("ghostdrive.services.alerts")

# Settings keys.  ``alerts_state`` holds the dedupe/dismiss JSON; the webhook
# URL is optional and only consulted during dispatch.
ALERTS_STATE_KEY = "alerts_state"
ALERT_WEBHOOK_URL_KEY = "alert_webhook_url"
KEY_ALERTS_INTERVAL_MINUTES = "alerts_interval_minutes"

DEFAULT_INTERVAL_MINUTES = 15.0

# Bounded ``seen`` map: the state row is read on every badge/alert fetch, so
# it must never grow without limit.  500 covers months of weekly drill
# alerts; once full, the oldest first-seen entries are evicted, which is a
# better trade-off than unbounded growth (an alert unseen that long may
# re-announce once).
_SEEN_CAP = 500

# Delivery channels registered at process start (e.g. the tray will call
# ``register_deliverer`` with ``async (alert) -> None``).
_DELIVERERS: list[Callable[[dict], Any]] = []

# Same module-global task pattern as protection.start_watcher.
_alerts_task: Optional[asyncio.Task] = None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def alert_id(kind: str, subject_id: str) -> str:
    """Stable 16-hex id for (kind, subject).

    Hashing only the *identity* of the condition means the same recurring
    alert keeps the same id forever: it can be dismissed once and stays
    dismissed, and injecting a different ``now`` never changes identity.
    """
    digest = hashlib.sha256(f"{kind}\x1f{subject_id}".encode("utf-8")).hexdigest()
    return digest[:16]


# ─── Evaluation (pure) ───────────────────────────────────────────────────────


def evaluate(
    db: Any,
    objects: Optional[dict] = None,
    now: datetime | None = None,
) -> list[dict]:
    """Evaluate every alert condition and return the active alert dicts.

    Each data source is wrapped independently: one broken subsystem (the
    hostility detector is the paranoid case) must never take the whole alert
    feed down with it -- resilience alerting has to be the thing that still
    works when something else is on fire.
    """
    now = now or _now()
    stamp = now.isoformat()
    alerts: list[dict] = []

    def _emit(kind: str, severity: str, subject_id: str, title: str, detail: str) -> None:
        alerts.append({
            "id": alert_id(kind, subject_id),
            "kind": kind,
            "severity": severity,
            "subject_id": subject_id,
            "title": title,
            "detail": detail,
            "detected_at": stamp,
        })

    # -- restore drills ----------------------------------------------------
    try:
        summary = restore_drills.drill_summary(db)
        last = summary.get("last")
        if last and last.get("result") == "failed":
            _emit(
                "drill_failed",
                "critical",
                str(last["id"]),
                "Restore drill failed",
                "The most recent restore drill could not prove a restore: "
                + str(last.get("detail") or "unknown error"),
            )
        if summary.get("stale"):
            seen = summary.get("last_success_at")
            _emit(
                "drill_stale",
                "warning",
                "restore-drills",
                "Restore drill is stale",
                f"No successful restore drill in the last "
                f"{restore_drills._STALE_DAYS} days"
                + (f"; last success {seen}" if seen else "; none recorded")
                + ".",
            )
    except Exception as exc:
        logger.warning("Drill alerts unavailable: %s", exc)

    # -- backend health and quota ------------------------------------------
    try:
        for row in db.list_backends(include_deprecated=True):
            backend_id = str(row["id"])
            label = f"{row['type']} backend {backend_id[:8]}"
            status = str(row["status"] or "")
            if status == "degraded":
                _emit(
                    "backend_degraded", "warning", backend_id,
                    "Backend degraded",
                    f"{label} is degraded: recent operations are failing or slow.",
                )
            elif status == "unreachable":
                _emit(
                    "backend_unreachable", "critical", backend_id,
                    "Backend unreachable",
                    f"{label} cannot be reached; its shards may not be restorable right now.",
                )
            try:
                used = int(row["quota_used"] or 0)
                limit = int(row["quota_limit"] or 0)
            except (TypeError, ValueError):
                used, limit = 0, 0
            if limit > 0 and used / limit > 0.9:
                pct = 100.0 * used / limit
                _emit(
                    "quota_low", "warning", backend_id,
                    "Backend quota low",
                    f"{label} is at {pct:.0f}% of quota ({used}/{limit} bytes); "
                    "new shards may stop fitting soon.",
                )
    except Exception as exc:
        logger.warning("Backend alerts unavailable: %s", exc)

    # -- hostile-backend verdicts -------------------------------------------
    try:
        flagged = hostility.detect_withholding(db).get("flagged", [])
        for item in flagged:
            verdict = str(item.get("verdict", ""))
            backend_id = str(item.get("backend_id", ""))
            label = f"backend {backend_id[:8]}"
            if verdict == "withholding":
                _emit(
                    "backend_withholding", "critical", backend_id,
                    "Backend is withholding data",
                    f"{label} confirms uploads but denies reads that peers can "
                    "serve; quarantine is advised.",
                )
            elif verdict == "corrupting":
                _emit(
                    "backend_corrupting", "critical", backend_id,
                    "Backend is corrupting data",
                    f"{label} serves corrupted bytes for chunks other backends "
                    "prove intact; quarantine is advised.",
                )
            # 'failing' verdicts mean unreliable, not hostile: no peer could
            # serve the chunks either, so backend status alerts cover it.
    except Exception as exc:
        # Tolerate hostility's absence/failure defensively: one subsystem
        # must never break the whole alert feed.
        logger.warning("Hostility alerts unavailable: %s", exc)

    # -- durability contract and at-risk chunks ------------------------------
    contract: Optional[dict] = None
    try:
        contract = durability.contract_from_settings(db)
        audit = durability.audit_readiness(db, objects=objects, contract=contract)
        total_chunks = int(audit.get("total_chunks") or 0)
        guaranteed = audit.get("minimum_survivable_domain_losses")
        required = int(contract.get("required_domain_losses") or 0)
        if total_chunks and guaranteed is not None and guaranteed < required:
            _emit(
                "durability_below_contract", "critical", "durability-contract",
                "Durability below contract",
                f"Guaranteed survivable domain losses: {guaranteed}; contract "
                f"requires {required} ({total_chunks} chunks audited).",
            )
    except Exception as exc:
        logger.warning("Durability contract alert unavailable: %s", exc)

    try:
        contract = contract or durability.contract_from_settings(db)
        at_risk = durability.list_at_risk_chunks(
            db, objects=objects, contract=contract, limit=1000
        )
        if at_risk:
            # ONE aggregated alert rather than one per chunk: dozens of
            # near-identical notifications would flood the tray, each with its
            # own id the user has to dismiss individually, while the
            # actionable unit is "the layout is at risk" -- the count says how
            # urgent it is.
            first = at_risk[0]
            _emit(
                "at_risk_chunks", "warning", "at-risk-chunks",
                "Chunks below durability contract",
                f"{len(at_risk)} chunk(s) cannot survive the contracted number "
                f"of failure-domain losses; first is {first.get('filename')} "
                f"(tier {first.get('tier')}).",
            )
    except Exception as exc:
        logger.warning("At-risk chunk alerts unavailable: %s", exc)

    return alerts


# ─── Persistence: dedupe + dismiss ───────────────────────────────────────────


def _load_state(db: Any) -> dict:
    raw = ""
    try:
        raw = db.get_setting(ALERTS_STATE_KEY, "")
    except Exception as exc:
        logger.warning("Could not read alert state: %s", exc)
    try:
        parsed = json.loads(raw) if raw else {}
    except ValueError:
        parsed = {}
    if not isinstance(parsed, dict):
        parsed = {}

    def _str_map(value: Any) -> dict:
        if not isinstance(value, dict):
            return {}
        return {str(k): str(v) for k, v in value.items()}

    last_generated = parsed.get("last_generated_at")
    return {
        "seen": _str_map(parsed.get("seen")),
        "dismissed": _str_map(parsed.get("dismissed")),
        "last_generated_at": str(last_generated) if last_generated else None,
    }


def _save_state(db: Any, state: dict) -> None:
    with db.transaction():
        db.set_setting(ALERTS_STATE_KEY, json.dumps(state))


def record_alerts(db: Any, alerts: list[dict], now: datetime | None = None) -> list[dict]:
    """Persist evaluation results; return only alerts nobody has seen yet.

    The second evaluation under identical conditions therefore yields zero
    new alerts (dedupe by stable id), while a dismissed id is never
    resurrected into ``seen``.
    """
    stamp = (now or _now()).isoformat()
    state = _load_state(db)
    new = [
        alert for alert in alerts
        if alert["id"] not in state["seen"] and alert["id"] not in state["dismissed"]
    ]
    for alert in alerts:
        if alert["id"] in state["dismissed"]:
            continue  # dismissed stays dismissed; don't re-record it as seen
        state["seen"].setdefault(alert["id"], str(alert.get("detected_at") or stamp))

    if len(state["seen"]) > _SEEN_CAP:
        overflow = len(state["seen"]) - _SEEN_CAP
        # Evict the oldest first-seen entries (ISO strings sort chronologically
        # for the UTC stamps we always write) -- bounded, see _SEEN_CAP.
        oldest = sorted(state["seen"].items(), key=lambda kv: kv[1])[:overflow]
        for alert_id_key, _ in oldest:
            del state["seen"][alert_id_key]

    state["last_generated_at"] = stamp
    _save_state(db, state)
    return new


def alert_state(db: Any) -> dict:
    """Stored dedupe/dismiss state merged with the currently-active alerts."""
    stored = _load_state(db)
    merged = []
    for alert in evaluate(db):
        merged.append({
            **alert,
            "first_seen_at": stored["seen"].get(alert["id"]),
            "dismissed": alert["id"] in stored["dismissed"],
        })
    return {
        "alerts": merged,
        "active_count": sum(1 for alert in merged if not alert["dismissed"]),
        "seen": stored["seen"],
        "dismissed": stored["dismissed"],
        "last_generated_at": stored["last_generated_at"],
    }


def dismiss_alert(db: Any, alert_id: str) -> dict:
    """Move an alert into the dismissed map; FileNotFoundError if unknown.

    An alert can be dismissed *before* the first ``record_alerts`` run (the
    user is looking at the live list), so "known" includes the currently
    active evaluation, not just previously-seen ids.
    """
    state = _load_state(db)
    known = alert_id in state["seen"] or alert_id in state["dismissed"]
    if not known:
        known = any(a["id"] == alert_id for a in evaluate(db))
    if not known:
        raise FileNotFoundError(f"Unknown alert id {alert_id!r}.")
    dismissed_at = _now().isoformat()
    state["seen"].pop(alert_id, None)  # move, don't duplicate
    state["dismissed"][alert_id] = dismissed_at
    _save_state(db, state)
    return {"alert_id": alert_id, "dismissed_at": dismissed_at}


# ─── Delivery ────────────────────────────────────────────────────────────────


def register_deliverer(fn: Callable[[dict], Any]) -> None:
    """Register an ``async (alert) -> None`` delivery channel.

    The tray (or any UI hook) registers once at startup; tests can replace
    the ``_DELIVERERS`` list to stay hermetic.  Failures in one channel are
    logged, never raised.
    """
    _DELIVERERS.append(fn)


async def _post_webhook(url: str, payload: dict) -> None:
    """POST the alert JSON with stdlib only (zero new dependencies).

    ``urllib`` is blocking, so the whole request runs in a worker thread via
    ``asyncio.to_thread`` to keep the event loop responsive.
    """
    def _do() -> None:
        request = urllib.request.Request(  # noqa: S310 - user-configured URL
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            response.read()

    await asyncio.to_thread(_do)


async def dispatch(
    db: Any,
    alerts: list[dict],
    deliver: Optional[Callable[[dict], Any]] = None,
) -> dict:
    """Deliver alerts to every registered channel plus the optional webhook.

    Returns ``{"delivered": n, "errors": n}``; delivery failures are logged
    and counted, never raised, so one broken sink cannot suppress the rest.
    """
    deliverers = list(_DELIVERERS)
    if deliver is not None:
        deliverers.append(deliver)
    webhook = ""
    try:
        webhook = str(db.get_setting(ALERT_WEBHOOK_URL_KEY, "") or "").strip()
    except Exception as exc:
        logger.warning("Could not read webhook setting: %s", exc)

    delivered = 0
    errors = 0
    for alert in alerts:
        for fn in deliverers:
            try:
                await fn(alert)
                delivered += 1
            except Exception as exc:
                errors += 1
                logger.warning("Alert delivery failed for %s: %s", alert.get("id"), exc)
        if webhook:
            try:
                await _post_webhook(webhook, alert)
                delivered += 1
            except Exception as exc:
                errors += 1
                logger.warning(
                    "Alert webhook POST to %s failed: %s", webhook, exc
                )
    return {"delivered": delivered, "errors": errors}


# ─── Scheduler ───────────────────────────────────────────────────────────────


async def _alerts_loop(db: Any, interval_minutes: float) -> None:
    while True:
        # Same rationale as the drill scheduler: +/-10% jitter keeps many
        # installs from hitting shared webhook/backend targets in lockstep,
        # and the >=1s clamp means a zero setting can never busy-loop.
        base = max(1.0, float(interval_minutes) * 60.0)
        await asyncio.sleep(base * random.uniform(0.9, 1.1))
        try:
            if db is not None:
                target = db
            else:
                from ghostdrive.services.context import require_db

                target = require_db()
            found = evaluate(target)
            new = record_alerts(target, found)
            if new:
                result = await dispatch(target, new)
                logger.info(
                    "Dispatched %d new alert(s) (%d errors).",
                    result["delivered"], result["errors"],
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # Locked vault, busy database, etc: log and keep ticking so
            # alerting comes back by itself.
            logger.warning("Alerts scheduler cycle failed: %s", exc)


def _configured_minutes(db: Any, fallback: float) -> float:
    try:
        if db is None:
            from ghostdrive.services.context import require_db

            db = require_db()
        raw = str(db.get_setting(KEY_ALERTS_INTERVAL_MINUTES, "")).strip()
        value = float(raw) if raw else float(fallback)
        return value if value > 0 else float(fallback)
    except Exception:
        return float(fallback)


def start_alerts_scheduler(
    interval_minutes: float = 15,
    db: Any = None,
) -> Optional[asyncio.Task]:
    """Start the background evaluate -> record -> dispatch loop (idempotent).

    The persisted ``alerts_interval_minutes`` setting wins when present so a
    ``POST /api/monitoring/scheduler`` and server-startup wiring agree;
    ``interval_minutes`` is the ad-hoc fallback for callers and tests.
    """
    global _alerts_task
    if _alerts_task is not None and not _alerts_task.done():
        return _alerts_task
    minutes = _configured_minutes(db, interval_minutes)
    _alerts_task = asyncio.create_task(_alerts_loop(db, minutes))
    return _alerts_task


def stop_alerts_scheduler() -> None:
    """Cancel the alerts loop and clear the module global."""
    global _alerts_task
    if _alerts_task is not None and not _alerts_task.done():
        _alerts_task.cancel()
    _alerts_task = None

