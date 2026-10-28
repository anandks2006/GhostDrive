"""Inheritance / dead-man's switch: release a sealed recovery package after missed check-ins.

The problem this solves: the owner may die or become incapacitated while
everything stays encrypted.  While enabled, the owner "checks in" periodically;
if no check-in happens for ``inheritance_interval_days``, the sealed
inheritance package is POSTed to the configured contact webhooks.

What the package contains: Shamir 3-of-5 shares of the CURRENT master key,
sealed with AES-256-GCM under a key derived from a release passphrase
(PBKDF2-HMAC-SHA256, 600 000 iterations, random salt -- the same construction
as ``services/sharing.py``'s envelope wrap).  The passphrase is never stored
here; it must be relayed to the contacts (or their lawyer) out of band.  The
stored commitment lets the beneficiary verify that the reconstructed key is
the original one, exactly like the recovery-kit manifest.

Honest limits (read before enabling):

* The sealed package must be readable without the owner present, so it is
  encrypted ONLY under the release passphrase.  Anyone who steals the package
  AND learns the passphrase owns the vault -- there is no second factor.
* The release passphrase's strength is the whole ballgame.  600k PBKDF2
  iterations slow an offline attacker down; they do not stop one.  Use a long
  passphrase and treat it like the 24-word seed.
* Webhooks are contacted via the provider's TLS, but the far side of a
  webhook (Discord/Slack/whatever operates the URL) sees the sealed package
  in the clear of its own storage.  It cannot decrypt it without the
  passphrase, but it can record that a release happened and keep the
  ciphertext forever.
* Delivery payload is ``{"content": "..."}`` -- natively Discord-webhook
  compatible and accepted by Slack-compatible endpoints; arbitrary other
  endpoints may reject it.  Every contact receives the SAME package;
  per-contact sealing would need per-contact passphrases (future work).
* Partial delivery marks the package released (any successful contact got
  it); if ALL deliveries fail, the switch stays unreleased so the next
  scheduler cycle retries.  Once released, ``released_at`` is recorded and
  the loop stops re-sending; disable + re-enable resets the record.
* A locked vault cannot re-seal shares: enabling requires the unlocked master
  key.  The check loop only reads settings, so it survives a locked vault;
  it logs and returns instead of crashing.
* This is a dead-man's switch, not a will executor: it can deliver bytes, it
  cannot decide whether the owner is actually gone.  ``release_now`` is the
  manual escape hatch (e.g. before planned surgery), route-enforced
  ``confirm=true``.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import math
import random
import secrets
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ghostdrive.crypto.shamir import (
    secret_commitment,
    share_to_text,
    split_secret,
)
from ghostdrive.services.alerts import alert_id, dispatch, record_alerts

logger = logging.getLogger("ghostdrive.services.inheritance")

# ── Settings keys (exact names; the web UI and tests depend on them) ──────────
KEY_ENABLED = "inheritance_enabled"              # "true" / "false" (default false)
KEY_INTERVAL_DAYS = "inheritance_interval_days"  # int >= 7 (default "90")
KEY_LAST_CHECK_IN = "inheritance_last_check_in"  # ISO-8601 or ""
KEY_CONTACTS = "inheritance_contacts"            # JSON list [{name, webhook_url}]
KEY_PACKAGE = "inheritance_package"              # JSON sealed package (see _seal)
KEY_STATE = "inheritance_state"                  # JSON release bookkeeping

DEFAULT_INTERVAL_DAYS = 90
MIN_INTERVAL_DAYS = 7          # refuse anything faster: a week of travel must
                               # not accidentally trigger a release
MIN_PASSPHRASE_LENGTH = 12     # the passphrase is the ONLY protection of the
                               # package once it leaves this machine

# Share parameters match the recovery kit (services/recovery_kit.py).
SHARE_THRESHOLD = 3
SHARE_TOTAL = 5

PACKAGE_VERSION = 1
PACKAGE_AAD = b"ghostdrive-inheritance-v1"  # binds the ciphertext to this format
PBKDF2_ITERATIONS = 600_000                 # OWASP 2023 guidance (see sharing.py)
SALT_BYTES = 16
NONCE_BYTES = 12                            # 96-bit nonce required by AES-GCM

DELIVERY_TIMEOUT_SECONDS = 10

ALERT_KIND = "inheritance_overdue"
ALERT_SUBJECT = "inheritance"

# Module-global task, same pattern as restore_drills._drill_task.
_inheritance_task: Optional[asyncio.Task] = None


# ── Small helpers ─────────────────────────────────────────────────────────────


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _resolve_db(db: Any = None) -> Any:
    if db is not None:
        return db
    from ghostdrive.services.context import require_db

    return require_db()


def _setting_bool(db: Any, key: str, default: bool) -> bool:
    raw = str(db.get_setting(key, "true" if default else "false")).strip().lower()
    return raw in ("1", "true", "yes", "on")


def _interval_days(db: Any) -> int:
    try:
        value = int(str(db.get_setting(KEY_INTERVAL_DAYS, "")).strip() or DEFAULT_INTERVAL_DAYS)
    except (TypeError, ValueError):
        return DEFAULT_INTERVAL_DAYS
    return max(MIN_INTERVAL_DAYS, value)


def _load_json(db: Any, key: str, fallback: Any) -> Any:
    raw = str(db.get_setting(key, "") or "")
    if not raw:
        return fallback
    try:
        return json.loads(raw)
    except ValueError:
        logger.warning("Inheritance setting %s is not valid JSON; ignoring.", key)
        return fallback


def _contacts(db: Any) -> list[dict]:
    parsed = _load_json(db, KEY_CONTACTS, [])
    if not isinstance(parsed, list):
        return []
    return [c for c in parsed if isinstance(c, dict)]


def _package(db: Any) -> Optional[dict]:
    parsed = _load_json(db, KEY_PACKAGE, None)
    return parsed if isinstance(parsed, dict) and parsed.get("ct") else None


def _load_state(db: Any) -> dict:
    parsed = _load_json(db, KEY_STATE, {})
    if not isinstance(parsed, dict):
        parsed = {}
    return {
        "enabled_at": parsed.get("enabled_at"),
        "overdue_notified_at": parsed.get("overdue_notified_at"),
        "released_at": parsed.get("released_at"),
        "results": parsed.get("results") if isinstance(parsed.get("results"), list) else [],
    }


def _save_state(db: Any, state: dict) -> None:
    with db.transaction():
        db.set_setting(KEY_STATE, json.dumps(state))


def _normalize_contacts(contacts: Any) -> list[dict]:
    """Validate and normalize the contact list; raises ValueError on junk."""
    if not isinstance(contacts, (list, tuple)) or not contacts:
        raise ValueError("At least one inheritance contact is required.")
    normalized: list[dict] = []
    for entry in contacts:
        if not isinstance(entry, dict):
            raise ValueError("Each contact must be an object with {name, webhook_url}.")
        name = str(entry.get("name") or "").strip()
        url = str(entry.get("webhook_url") or "").strip()
        if not name:
            raise ValueError("Each inheritance contact needs a non-empty name.")
        if not url.lower().startswith(("http://", "https://")):
            raise ValueError(f"Contact {name!r} needs an http(s) webhook_url.")
        normalized.append({"name": name, "webhook_url": url})
    return normalized


# ── Sealing ───────────────────────────────────────────────────────────────────


def _seal_package(master_key: bytes, release_passphrase: str, now: datetime) -> dict:
    """Seal the Shamir shares of ``master_key`` under the release passphrase.

    Returns the JSON-safe package dict persisted under ``inheritance_package``.
    The passphrase and the plaintext shares are NEVER part of the result.
    """
    shares = split_secret(master_key, SHARE_THRESHOLD, SHARE_TOTAL)
    plaintext = json.dumps([share_to_text(share) for share in shares]).encode("utf-8")
    salt = secrets.token_bytes(SALT_BYTES)
    nonce = secrets.token_bytes(NONCE_BYTES)
    wrap_key = hashlib.pbkdf2_hmac(
        "sha256", release_passphrase.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    ciphertext = AESGCM(wrap_key).encrypt(nonce, plaintext, PACKAGE_AAD)
    return {
        "v": PACKAGE_VERSION,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ct": base64.b64encode(ciphertext).decode("ascii"),
        "threshold": SHARE_THRESHOLD,
        "total": SHARE_TOTAL,
        "commitment": secret_commitment(master_key),
        "created_at": now.isoformat(),
    }


# ── Status ────────────────────────────────────────────────────────────────────


def inheritance_status(db: Any = None, *, now: datetime | None = None) -> dict:
    """One-glance switch status.

    ``contacts`` is returned in full (names + webhook URLs) because the UI
    must show what is configured.  The web server binds to 127.0.0.1 only
    (see ``web/server.py``), so this payload never leaves the machine via
    GhostDrive itself -- but treat any future remote exposure as a leak of
    the contact list (NOT of vault data: the URLs alone cannot decrypt
    anything).
    """
    db = _resolve_db(db)
    when = now or _now()
    enabled = _setting_bool(db, KEY_ENABLED, False)
    interval = _interval_days(db)
    last = _parse_iso(db.get_setting(KEY_LAST_CHECK_IN, ""))
    contacts = _contacts(db)
    state = _load_state(db)

    due_at = last + timedelta(days=interval) if (enabled and last) else None
    if due_at is not None:
        remaining_seconds = (due_at - when).total_seconds()
        days_remaining: Optional[int] = math.floor(remaining_seconds / 86400.0)
        overdue = remaining_seconds <= 0
    else:
        days_remaining = None
        overdue = False

    return {
        "enabled": enabled,
        "interval_days": interval,
        "last_check_in": last.isoformat() if last else None,
        "due_at": due_at.isoformat() if due_at else None,
        # Whole days, floor(): 7 when freshly enabled with interval 7; becomes
        # negative once overdue (honest countdown, not clamped at 0).
        "days_remaining": days_remaining,
        "overdue": overdue,
        "contacts": contacts,
        "contact_count": len(contacts),
        "package_sealed": _package(db) is not None,
        "enabled_at": state["enabled_at"],
        "overdue_notified_at": state["overdue_notified_at"],
        "released_at": state["released_at"],
    }


# ── Enable / disable / check-in ──────────────────────────────────────────────


async def enable_inheritance(
    db: Any = None,
    interval_days: int = DEFAULT_INTERVAL_DAYS,
    release_passphrase: str = "",
    contacts: list[dict] | None = None,
    *,
    now: datetime | None = None,
    force: bool = False,
) -> dict:
    """Enable the dead-man's switch (requires the unlocked vault).

    Re-enabling while already enabled is refused unless ``force=True`` --
    re-enabling RE-SEALS the package from the CURRENT master key, which means
    the previously delivered (or previously stored) package becomes stale:
    beneficiaries holding an old ciphertext can still decrypt it, but its
    shares describe a key the vault may no longer use.  Forcing makes that
    trade consciously instead of by accident.
    """
    db = _resolve_db(db)
    when = now or _now()

    if _setting_bool(db, KEY_ENABLED, False) and not force:
        raise ValueError(
            "Inheritance is already enabled. Disable it first, or pass force=True -- "
            "re-enabling re-seals the package from the CURRENT master key."
        )

    try:
        days = int(interval_days)
    except (TypeError, ValueError):
        raise ValueError("interval_days must be an integer >= 7.") from None
    if days < MIN_INTERVAL_DAYS:
        raise ValueError(
            f"interval_days must be at least {MIN_INTERVAL_DAYS}; "
            "a faster dead-man's switch would fire during ordinary travel."
        )
    if not release_passphrase or len(release_passphrase) < MIN_PASSPHRASE_LENGTH:
        raise ValueError(
            f"release_passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters."
        )
    normalized = _normalize_contacts(contacts)

    from ghostdrive.services.context import get_master_key

    master_key = get_master_key()  # raises RuntimeError when locked -> 401
    package = _seal_package(master_key, release_passphrase, when)
    state = {
        "enabled_at": when.isoformat(),
        "overdue_notified_at": None,
        "released_at": None,
        "results": [],
    }
    with db.transaction():
        db.set_setting(KEY_PACKAGE, json.dumps(package))
        db.set_setting(KEY_STATE, json.dumps(state))
        db.set_setting(KEY_CONTACTS, json.dumps(normalized))
        db.set_setting(KEY_LAST_CHECK_IN, when.isoformat())
        db.set_setting(KEY_INTERVAL_DAYS, str(days))
        db.set_setting(KEY_ENABLED, "true")
    logger.info(
        "Inheritance enabled: %d-day interval, %d contact(s), 3-of-5 sealed shares.",
        days, len(normalized),
    )
    return inheritance_status(db, now=when)


def disable_inheritance(db: Any = None, *, wipe_package: bool = True) -> dict:
    """Turn the switch off; wipe the sealed package by default.

    Contacts and the interval are KEPT so re-enabling only needs a fresh
    release passphrase (and re-seals from the current master key).  Only the
    ciphertext and the release record are destroyed -- a stolen package
    cannot be un-stolen, but at least this machine stops carrying one.
    """
    db = _resolve_db(db)
    with db.transaction():
        db.set_setting(KEY_ENABLED, "false")
        if wipe_package:
            db.set_setting(KEY_PACKAGE, "")
            db.set_setting(
                KEY_STATE,
                json.dumps(
                    {
                        "enabled_at": None,
                        "overdue_notified_at": None,
                        "released_at": None,
                        "results": [],
                    }
                ),
            )
    return inheritance_status(db)


def check_in(db: Any = None, *, now: datetime | None = None) -> dict:
    """Reset the dead-man's timer (the owner is alive and present).

    Clears a pending overdue notification so a FUTURE overdue period alerts
    again; a recorded release (``released_at``) is NOT cleared -- once the
    package went out, the reset is disable + re-enable, not a check-in.
    """
    db = _resolve_db(db)
    when = now or _now()
    state = _load_state(db)
    state["overdue_notified_at"] = None
    with db.transaction():
        db.set_setting(KEY_LAST_CHECK_IN, when.isoformat())
        db.set_setting(KEY_STATE, json.dumps(state))
    return inheritance_status(db, now=when)


# ── Delivery ──────────────────────────────────────────────────────────────────


def _post_json(url: str, payload: dict) -> None:
    """Blocking stdlib POST; callers wrap it in asyncio.to_thread."""
    request = urllib.request.Request(  # noqa: S310 - user-configured URL
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=DELIVERY_TIMEOUT_SECONDS) as response:
        response.read()


def _release_message(package: dict) -> str:
    """Discord/Slack-compatible ``content`` text carrying the sealed package."""
    return (
        "GhostDrive inheritance release: the vault owner has not checked in "
        "within the configured interval, so the sealed inheritance package is "
        f"being released to {package.get('total', SHARE_TOTAL)}-share custody.\n"
        f"Inside are Shamir shares of the vault master key ({package.get('threshold')}"
        f"-of-{package.get('total')}): any {package.get('threshold')} of them "
        "reconstruct the key once the package is decrypted with the release "
        "passphrase.\n"
        "The release passphrase is NOT in this message -- relay it to the "
        "beneficiary out-of-band (it was given to you separately at setup).\n"
        "Offline recovery: ghostdrive.cli.recovery_tool, or combine_shares() "
        "after decrypting (AES-256-GCM, PBKDF2-SHA256, AAD "
        "'ghostdrive-inheritance-v1').\n"
        "Sealed package (JSON):\n" + json.dumps(package, indent=2)
    )


async def _deliver_package(contacts: list[dict], package: dict) -> list[dict]:
    """POST the release message to every contact; per-contact results.

    One failing contact never stops the others -- every configured contact is
    an independent chance for the beneficiary to actually receive the data.
    """
    content = _release_message(package)
    results: list[dict] = []
    for contact in contacts:
        name = str(contact.get("name") or "contact")
        url = str(contact.get("webhook_url") or "")
        try:
            await asyncio.to_thread(_post_json, url, {"content": content})
            results.append({"name": name, "ok": True, "error": None})
        except Exception as exc:
            logger.warning("Inheritance delivery to %s failed: %s", name, exc)
            results.append({"name": name, "ok": False, "error": str(exc)})
    return results


# ── The loop body ─────────────────────────────────────────────────────────────


async def check_inheritance(
    db: Any = None, *, now: datetime | None = None, deliver: bool = True
) -> dict:
    """One dead-man's evaluation: alert when overdue, deliver when allowed.

    Never raises for vault/DB problems (locked vault, closed database): those
    are logged and returned as a no-op result so the scheduler survives them.
    """
    try:
        return await _check_inheritance_inner(db, now=now, deliver=deliver)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.warning("Inheritance check failed: %s", exc)
        return {
            "overdue": False,
            "released": False,
            "results": [],
            "alerted": False,
            "error": str(exc),
        }


async def _check_inheritance_inner(
    db: Any = None, *, now: datetime | None = None, deliver: bool = True
) -> dict:
    db = _resolve_db(db)
    when = now or _now()

    if not _setting_bool(db, KEY_ENABLED, False):
        return {"overdue": False, "released": False, "results": [], "alerted": False}

    state = _load_state(db)
    if state["released_at"]:
        # Already released this cycle of the switch: do NOT re-send every
        # day -- the contacts got it once; re-sending would just spam them.
        return {
            "overdue": True,
            "released": True,
            "results": state["results"],
            "alerted": False,
        }

    last = _parse_iso(db.get_setting(KEY_LAST_CHECK_IN, ""))
    if last is None:
        logger.warning(
            "Inheritance is enabled but no check-in timestamp exists; skipping."
        )
        return {"overdue": False, "released": False, "results": [], "alerted": False}

    due_at = last + timedelta(days=_interval_days(db))
    if when < due_at:
        return {"overdue": False, "released": False, "results": [], "alerted": False}

    contacts = _contacts(db)
    missed_days = int((when - last).total_seconds() // 86400)

    alerted = False
    if not state["overdue_notified_at"]:
        alert = {
            "id": alert_id(ALERT_KIND, ALERT_SUBJECT),
            "kind": ALERT_KIND,
            "severity": "critical",
            "subject_id": ALERT_SUBJECT,
            "title": "Inheritance switch overdue",
            "detail": (
                f"No check-in for {missed_days} days; the release package will "
                f"be sent to {len(contacts)} contact(s)."
            ),
            "detected_at": when.isoformat(),
        }
        new = record_alerts(db, [alert], now=when)
        if new:
            await dispatch(db, new)
        state["overdue_notified_at"] = when.isoformat()
        _save_state(db, state)
        alerted = bool(new)

    if not deliver:
        return {"overdue": True, "released": False, "results": [], "alerted": alerted}

    package = _package(db)
    if not package:
        logger.warning(
            "Inheritance overdue but no sealed package is stored; nothing to release."
        )
        return {"overdue": True, "released": False, "results": [], "alerted": alerted}
    if not contacts:
        logger.warning("Inheritance overdue but no contacts are configured.")
        return {"overdue": True, "released": False, "results": [], "alerted": alerted}

    results = await _deliver_package(contacts, package)
    state["results"] = results
    if any(item["ok"] for item in results):
        # Partial success still marks released: at least one beneficiary can
        # act.  If ALL fail, released_at stays unset so the next cycle
        # retries the whole delivery.
        state["released_at"] = when.isoformat()
    _save_state(db, state)
    return {
        "overdue": True,
        "released": bool(state["released_at"]),
        "results": results,
        "alerted": alerted,
    }


async def release_now(
    db: Any = None, *, now: datetime | None = None, confirm: bool = False
) -> dict:
    """Manual escape hatch: deliver the package regardless of overdue.

    Used e.g. before planned surgery.  ``confirm=True`` is mandatory because
    delivery is irreversible (the sealed package leaves this machine).
    """
    if not confirm:
        raise ValueError(
            "Releasing the inheritance package requires confirm=True; "
            "delivery to contacts is irreversible."
        )
    db = _resolve_db(db)
    when = now or _now()
    if not _setting_bool(db, KEY_ENABLED, False):
        raise ValueError("Inheritance is not enabled.")
    package = _package(db)
    if not package:
        raise ValueError(
            "No sealed inheritance package is stored; re-enable inheritance first."
        )
    contacts = _contacts(db)
    if not contacts:
        raise ValueError("No inheritance contacts are configured.")

    state = _load_state(db)
    results = await _deliver_package(contacts, package)
    state["results"] = results
    if any(item["ok"] for item in results):
        state["released_at"] = when.isoformat()
    _save_state(db, state)
    return {
        "released": bool(state["released_at"]),
        "results": results,
        "delivered_to": [item["name"] for item in results if item["ok"]],
    }


# ── Scheduler ─────────────────────────────────────────────────────────────────


async def _inheritance_loop(db: Any, interval_hours: float) -> None:
    while True:
        # Same +/-10% jitter rationale as the drill/alert loops: many installs
        # share the same webhook providers; don't hit them in lockstep.
        base = max(1.0, float(interval_hours) * 3600.0)
        await asyncio.sleep(base * random.uniform(0.9, 1.1))
        try:
            target = _resolve_db(db)
            if not _setting_bool(target, KEY_ENABLED, False):
                continue  # honors the flag every cycle, like the drill loop
            outcome = await check_inheritance(target)
            if outcome.get("overdue"):
                logger.info(
                    "Inheritance check: overdue, released=%s, alerted=%s",
                    outcome.get("released"), outcome.get("alerted"),
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # Locked vault, busy database, etc.: log and keep ticking so the
            # switch comes back by itself.
            logger.warning("Inheritance scheduler cycle failed: %s", exc)


def start_inheritance_scheduler(
    interval_hours: float = 24.0, db: Any = None
) -> Optional[asyncio.Task]:
    """Start the background check loop (idempotent; double-start is a no-op).

    Once a day by default: with a >= 7-day interval that leaves at least six
    cycles of warning before a release can fire, and the overdue alert goes
    out on the FIRST overdue cycle, not the last.
    """
    global _inheritance_task
    if _inheritance_task is not None and not _inheritance_task.done():
        return _inheritance_task
    _inheritance_task = asyncio.create_task(
        _inheritance_loop(db, max(1.0, float(interval_hours)))
    )
    return _inheritance_task


def stop_inheritance_scheduler() -> Optional[asyncio.Task]:
    """Cancel the check loop; returns the cancelled task (or None)."""
    global _inheritance_task
    task = _inheritance_task
    if task is not None and not task.done():
        task.cancel()
    _inheritance_task = None
    return task
