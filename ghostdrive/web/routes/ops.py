"""
ops.py -- Operator endpoints: phone pairing (QR), remote-access status, and a
hand-rolled Prometheus /metrics exposition.

Three routers live here on purpose. Pairing must answer while the vault is
LOCKED (scanning a QR code needs no vault access), so none of these routes
call require_db(); each request takes a best-effort snapshot of the global
state and degrades instead of erroring:

* ``pairing_router`` -- GET /api/pairing/status (works locked, flips
  ``vault_unlocked`` to False) and GET /api/pairing/qr.png (PNG QR of a
  validated http/https URL; default = first remote URL, else first local).
* ``remote_router``  -- GET /api/remote/status and POST /api/remote/rescan:
  the same access_status payload; "rescan" simply re-runs Tailscale
  detection so the UI gets a honest "check again" button.
* ``metrics_router`` -- GET /metrics, Prometheus text exposition 0.0.4,
  rendered by hand (no instrumentator middleware, no side effects).

/metrics never returns 500: a locked vault serves the minimal set
(``ghostdrive_up``, ``ghostdrive_vault_unlocked 0``, uptime), and every
metric family is collected independently, so one failing query skips that
family rather than the whole scrape. The ``metrics_enabled`` setting
(default "true") turns the endpoint into a 404 -- the flag lives in the
vault DB, so it is honored only while unlocked; a locked vault serves the
minimal set regardless. Metrics are metadata only (counts, sizes, states --
never file names or content), but metadata still describes the vault; see
docs/REMOTE_ACCESS.md before exposing the port.
"""

from __future__ import annotations

import io
import logging
import time
from typing import Any, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, Response

from ghostdrive.services import alerts as alerts_service
from ghostdrive.services import durability
from ghostdrive.services import restore_drills as drills_service
from ghostdrive.services import sync as sync_service
from ghostdrive.services import remote_access
from ghostdrive.web.state import state

logger = logging.getLogger("ghostdrive_web.ops")

pairing_router = APIRouter(prefix="/api/pairing", tags=["pairing"])
remote_router = APIRouter(prefix="/api/remote", tags=["remote"])
metrics_router = APIRouter(tags=["metrics"])

#: Kill-switch settings key for GET /metrics (stored in the vault DB).
SETTING_METRICS_ENABLED = "metrics_enabled"

#: One-hot durability label set emitted by audit_readiness.
_DURABILITY_STATES = ("PROTECTED", "DEGRADED", "UNPROTECTED", "UNKNOWN")

#: Wall clock at import; uptime = now - this (documented as wall-clock, so an
#: NTP step can move it -- acceptable for a scrape-time gauge).
_PROCESS_STARTED_AT = time.time()

_METRIC_HELP = {
    "ghostdrive_up": "GhostDrive process is answering requests.",
    "ghostdrive_vault_unlocked": "1 when the vault is unlocked and the database is open.",
    "ghostdrive_files_total": "Active (non-trash) files in the vault index.",
    "ghostdrive_files_bytes": "Total original bytes of active files.",
    "ghostdrive_trash_total": "Tombstoned (Trash) files retained for recovery.",
    "ghostdrive_backends_total": "Configured storage backends.",
    "ghostdrive_backends_healthy": "Backends whose last health check reported healthy.",
    "ghostdrive_alerts_active": "Non-dismissed alerts currently active.",
    "ghostdrive_alerts_critical": "Non-dismissed alerts with critical severity.",
    "ghostdrive_last_drill_success": "1 when the most recent restore drill passed.",
    "ghostdrive_drill_last_run_timestamp_seconds": "Unix time of the last restore drill completion (0 = never).",
    "ghostdrive_durability_state": "One-hot worst-case durability audit state.",
    "ghostdrive_sync_enabled": "1 when folder auto-vault sync is enabled.",
    "ghostdrive_sync_roots": "Number of configured sync roots.",
    "ghostdrive_uptime_seconds": "Seconds since the GhostDrive web process started.",
}


def _http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, FileNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, ValueError):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, RuntimeError) and "locked" in str(exc).lower():
        return HTTPException(status_code=401, detail=str(exc))
    logger.exception("Ops operation failed: %s", exc)
    return HTTPException(status_code=500, detail=str(exc))


def _open_db() -> Optional[Any]:
    """Best-effort open database handle, or None when locked. Never raises."""
    try:
        if state.km is not None and state.km.is_unlocked:
            db = state.db
            if db is not None and getattr(db, "_conn", None) is not None:
                return db
    except Exception as exc:
        logger.debug("Vault state unreadable: %s", exc)
    return None


# ─── QR pairing ───────────────────────────────────────────────────────────────


def _validate_qr_url(url: str) -> str:
    """Accept only absolute http(s) URLs without embedded credentials.

    The QR code is opened on a phone we do not control, so anything that
    smells like a phishing/exfiltration vector (javascript:, data:, ftp:,
    user:pass@host, control characters) is refused with a 400.
    """
    candidate = str(url or "").strip()
    if not candidate:
        raise HTTPException(status_code=400, detail="URL is empty.")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in candidate):
        raise HTTPException(status_code=400, detail="URL contains control characters.")
    parsed = urlparse(candidate)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(
            status_code=400, detail="Only http:// and https:// URLs can be encoded."
        )
    if not parsed.hostname:
        raise HTTPException(status_code=400, detail="URL has no host.")
    if parsed.username is not None or parsed.password is not None:
        raise HTTPException(
            status_code=400,
            detail="URLs with embedded credentials are not allowed.",
        )
    return candidate


def _qr_png(url: str) -> bytes:
    """Render the URL as a PNG QR code (level M, box 8, border 2).

    qrcode is an optional dependency (not in the core lockfile group), so it
    is imported lazily and a missing install surfaces as a 500 with a clear
    message instead of an import-time crash of the whole route module.
    """
    import qrcode  # lazy: only /qr.png needs it

    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=2,
    )
    qr.add_data(url)
    qr.make(fit=True)
    image = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


@pairing_router.get("/status")
def pairing_status() -> dict:
    """Pairing status; answers while the vault is locked (vault_unlocked=False)."""
    return remote_access.access_status(_open_db())


@pairing_router.get("/qr.png")
def pairing_qr(url: Optional[str] = None) -> Response:
    """PNG QR code for the given http(s) URL, or the best default URL.

    Default = first remote (Tailscale) URL when one exists, else the loopback
    URL. The response is never cached: it may encode a rotating tailnet IP.
    """
    try:
        if url is None:
            status = remote_access.access_status(_open_db())
            candidates = status["remote_urls"] or status["local_urls"]
            url = candidates[0]
        target = _validate_qr_url(url)
        png = _qr_png(target)
    except HTTPException:
        raise
    except Exception as exc:
        raise _http_error(exc)
    return Response(
        content=png,
        media_type="image/png",
        headers={"Cache-Control": "no-store"},
    )


# ─── Remote access status ────────────────────────────────────────────────────


@remote_router.get("/status")
def remote_status() -> dict:
    """Full access status: bind/port, URLs, Tailscale detection, steps."""
    return remote_access.access_status(_open_db())


@remote_router.post("/rescan")
def remote_rescan() -> dict:
    """Re-run Tailscale detection now (the UI's "check again" button)."""
    return remote_access.access_status(_open_db())


# ─── Prometheus metrics ──────────────────────────────────────────────────────


def _uptime_seconds() -> int:
    return int(time.time() - _PROCESS_STARTED_AT)


def _parse_iso(value: Any) -> Optional[float]:
    """ISO-8601 timestamp -> epoch seconds, or None when unparseable/absent."""
    if not value:
        return None
    try:
        from datetime import datetime, timezone

        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _collect_metrics(db: Any) -> list[tuple[str, str, Any]]:
    """Sample every metric family from an unlocked vault.

    Each family is guarded independently: a failing query drops that family
    and the scrape continues. Durability's audit_readiness is the heaviest
    call (it walks every chunk's shard placement); we accept it once per
    scrape rather than cache a stale verdict, but wrap it like everything
    else so a slow/failing audit never breaks the endpoint.
    """
    samples: list[tuple[str, str, Any]] = [
        ("ghostdrive_up", "", 1),
        ("ghostdrive_vault_unlocked", "", 1),
        ("ghostdrive_uptime_seconds", "", _uptime_seconds()),
    ]

    try:
        row = db._conn.execute(
            "SELECT COUNT(*) AS n, COALESCE(SUM(size), 0) AS b "
            "FROM files WHERE tombstone = 0"
        ).fetchone()
        samples.append(("ghostdrive_files_total", "", int(row["n"] or 0)))
        samples.append(("ghostdrive_files_bytes", "", int(row["b"] or 0)))
    except Exception as exc:
        logger.debug("files metrics skipped: %s", exc)

    try:
        row = db._conn.execute(
            "SELECT COUNT(*) AS n FROM files WHERE tombstone = 1"
        ).fetchone()
        samples.append(("ghostdrive_trash_total", "", int(row["n"] or 0)))
    except Exception as exc:
        logger.debug("trash metrics skipped: %s", exc)

    try:
        row = db._conn.execute(
            "SELECT COUNT(*) AS n, COALESCE(SUM(status = 'healthy'), 0) AS h "
            "FROM backends"
        ).fetchone()
        samples.append(("ghostdrive_backends_total", "", int(row["n"] or 0)))
        samples.append(("ghostdrive_backends_healthy", "", int(row["h"] or 0)))
    except Exception as exc:
        logger.debug("backend metrics skipped: %s", exc)

    try:
        alert_state = alerts_service.alert_state(db)
        active = [a for a in alert_state["alerts"] if not a.get("dismissed")]
        samples.append(("ghostdrive_alerts_active", "", len(active)))
        samples.append(
            (
                "ghostdrive_alerts_critical",
                "",
                sum(1 for a in active if a.get("severity") == "critical"),
            )
        )
    except Exception as exc:
        logger.debug("alert metrics skipped: %s", exc)

    try:
        summary = drills_service.drill_summary(db)
        last = summary.get("last") or {}
        samples.append(
            (
                "ghostdrive_last_drill_success",
                "",
                1 if last.get("result") == "passed" else 0,
            )
        )
        ran_at = _parse_iso(last.get("completed_at") or last.get("started_at"))
        samples.append(
            (
                "ghostdrive_drill_last_run_timestamp_seconds",
                "",
                int(ran_at) if ran_at else 0,
            )
        )
    except Exception as exc:
        logger.debug("drill metrics skipped: %s", exc)

    try:
        audit = durability.audit_readiness(db)
        current = str(audit.get("state") or "UNKNOWN").upper()
        for name in _DURABILITY_STATES:
            samples.append(
                ("ghostdrive_durability_state", f'state="{name}"', 1 if current == name else 0)
            )
    except Exception as exc:
        logger.debug("durability metrics skipped: %s", exc)

    try:
        sync_status = sync_service.sync_status(db)
        samples.append(
            ("ghostdrive_sync_enabled", "", 1 if sync_status.get("enabled") else 0)
        )
        samples.append(
            ("ghostdrive_sync_roots", "", len(sync_status.get("roots") or []))
        )
    except Exception as exc:
        logger.debug("sync metrics skipped: %s", exc)

    return samples


def _render_prometheus(samples: list[tuple[str, str, Any]]) -> str:
    """Prometheus text exposition 0.0.4: HELP/TYPE per metric, then samples."""
    lines: list[str] = []
    emitted: set[str] = set()
    for name, labels, value in samples:
        if name not in emitted:
            emitted.add(name)
            lines.append(f"# HELP {name} {_METRIC_HELP.get(name, name)}")
            lines.append(f"# TYPE {name} gauge")
        lines.append(f"{name}{{{labels}}} {value}" if labels else f"{name} {value}")
    return "\n".join(lines) + "\n"


@metrics_router.get("/metrics")
def prometheus_metrics() -> Response:
    """Prometheus text exposition. Metadata only -- never file content.

    Locked vault: 200 with the minimal set (up, vault_unlocked 0, uptime).
    Unlocked: the ``metrics_enabled`` setting (default "true") may turn this
    into a 404; each metric family is collected independently so one bad
    query skips that family instead of failing the scrape.
    """
    db = _open_db()
    if db is None:
        samples: list[tuple[str, str, Any]] = [
            ("ghostdrive_up", "", 1),
            ("ghostdrive_vault_unlocked", "", 0),
            ("ghostdrive_uptime_seconds", "", _uptime_seconds()),
        ]
    else:
        try:
            raw = str(
                db.get_setting(SETTING_METRICS_ENABLED, "true") or ""
            ).strip().lower()
        except Exception as exc:
            logger.debug("metrics_enabled unreadable, defaulting on: %s", exc)
            raw = "true"
        if raw not in ("1", "true", "yes", "on"):
            raise HTTPException(
                status_code=404,
                detail="/metrics is disabled by the metrics_enabled setting.",
            )
        samples = _collect_metrics(db)

    return Response(
        content=_render_prometheus(samples),
        media_type="text/plain; version=0.0.4",
        headers={"Cache-Control": "no-store"},
    )
