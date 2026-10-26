"""Hostile-backend detection and quarantine.

The database records raw per-backend integrity signals -- integrity_log rows
(ok / hash_mismatch / not_found / auth_failed per backend per chunk) -- but
nothing correlates them across backends. That correlation is what separates a
hostile or withholding backend (one that confirms uploads, then denies or
corrupts reads) from an honest backend whose chunks merely broke or whose
network is down: if at least one OTHER backend served the same chunk 'ok'
inside the same window, the chunk and the network are exonerated and the
failure belongs to this backend alone.

Quarantine reuses the existing 'deprecated' backend status rather than adding
a new one: upload routing selects WHERE status = 'healthy', so marking a
backend deprecated removes it from future shard placement immediately.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

# Fixed tie-break order for the dominant failure result: when two failure
# kinds tie on count, the more security-relevant result wins. A stable order
# keeps the verdict deterministic regardless of row iteration order.
_DOMINANT_ORDER = ("hash_mismatch", "auth_failed", "not_found")

_VERDICT_OK = "ok"
_VERDICT_INSUFFICIENT = "insufficient_data"
_VERDICT_FAILING = "failing"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def detect_withholding(
    db: Any,
    window_hours: int = 168,
    now: Optional[datetime] = None,
    min_checks: int = 6,
) -> dict:
    """Correlate integrity_log rows across backends to spot hostile behavior.

    A backend is only called hostile when a peer exonerates the chunk: a
    failure on a chunk that NO other backend could serve just means the chunk
    (or the network) is broken, which is not evidence against the backend.
    """
    now = now or _utc_now()
    since = (now - timedelta(hours=int(window_hours))).isoformat()

    rows = db._conn.execute(
        """SELECT il.backend_id, il.chunk_id, il.result, b.type AS backend_type
           FROM integrity_log il
           JOIN backends b ON b.id = il.backend_id
           WHERE il.checked_at >= ?
           ORDER BY il.backend_id, il.chunk_id""",
        (since,),
    ).fetchall()

    # chunk_id -> backends that served it successfully. This is the peer
    # control: a failed chunk present here is proven good by someone else.
    ok_by_chunk: dict[str, set[str]] = {}
    for row in rows:
        if str(row["result"]) == "ok":
            ok_by_chunk.setdefault(str(row["chunk_id"]), set()).add(str(row["backend_id"]))

    per_backend: dict[str, dict] = {}
    for row in rows:
        backend_id = str(row["backend_id"])
        entry = per_backend.setdefault(
            backend_id,
            {
                "type": str(row["backend_type"]),
                "checks": 0,
                "failures": 0,
                "failures_by_result": {},
                "failed_chunks": set(),
                "peer_ok_chunks": set(),
            },
        )
        entry["checks"] += 1
        chunk_id = str(row["chunk_id"])
        result = str(row["result"])
        if result != "ok":
            entry["failures"] += 1
            entry["failures_by_result"][result] = entry["failures_by_result"].get(result, 0) + 1
            entry["failed_chunks"].add(chunk_id)
            peers = ok_by_chunk.get(chunk_id, set()) - {backend_id}
            if peers:
                entry["peer_ok_chunks"].add(chunk_id)

    backends: list[dict] = []
    flagged: list[dict] = []
    for backend_id, entry in sorted(per_backend.items()):
        checks = entry["checks"]
        failures = entry["failures"]
        failure_rate = (failures / checks) if checks else 0.0
        peer_ok_failures = len(entry["peer_ok_chunks"])

        if checks < int(min_checks):
            verdict = _VERDICT_INSUFFICIENT
        elif failure_rate >= 0.5 and peer_ok_failures >= 2:
            # Dominant result decides the flavor of hostility: denial
            # (not_found / auth_failed) vs corruption (hash_mismatch).
            counts = entry["failures_by_result"]
            dominant = max(
                _DOMINANT_ORDER,
                key=lambda result: (counts.get(result, 0), -_DOMINANT_ORDER.index(result)),
            )
            verdict = (
                "corrupting" if dominant == "hash_mismatch" else "withholding"
            )
        elif failure_rate >= 0.8:
            # Very high failure rate but no peer could serve the chunks
            # either: unreliable, not proven hostile.
            verdict = _VERDICT_FAILING
        else:
            verdict = _VERDICT_OK

        record = {
            "backend_id": backend_id,
            "type": entry["type"],
            "checks": checks,
            "failures": failures,
            "failure_rate": round(failure_rate, 4),
            "peer_ok_failures": peer_ok_failures,
            "verdict": verdict,
            "evidence_chunks": sorted(entry["failed_chunks"])[:5],
        }
        backends.append(record)
        if verdict not in (_VERDICT_OK, _VERDICT_INSUFFICIENT):
            flagged.append({"backend_id": backend_id, "verdict": verdict})

    return {
        "window_hours": int(window_hours),
        "min_checks": int(min_checks),
        "evaluated_at": now.isoformat(),
        "backends": backends,
        "flagged": flagged,
    }


def quarantine_backend(db: Any, backend_id: str, reason: str = "") -> dict:
    """Mark a backend 'deprecated' so upload routing stops placing shards on it.

    Idempotent: quarantining an already-deprecated backend is a no-op that
    still reports the existing quarantine timestamp.
    """
    quarantined_at = _utc_now().isoformat()
    with db.transaction():
        row = db._conn.execute(
            "SELECT * FROM backends WHERE id = ?", (backend_id,)
        ).fetchone()
        if row is None:
            raise FileNotFoundError(f"Backend {backend_id} does not exist.")
        if str(row["status"]) == "deprecated":
            quarantined_at = row["deprecated_at"] or quarantined_at
        else:
            db._conn.execute(
                """UPDATE backends
                   SET status = 'deprecated', deprecated_at = ?, last_error = ?
                   WHERE id = ?""",
                (quarantined_at, reason, backend_id),
            )
            db._chain_hmac("backends", {
                "op": "quarantine",
                "id": backend_id,
                "status": "deprecated",
                "deprecated_at": quarantined_at,
                "reason": reason,
            })
    return {
        "backend_id": backend_id,
        "status": "deprecated",
        "quarantined_at": quarantined_at,
        "reason": reason,
        "already_quarantined": str(row["status"]) == "deprecated",
    }


def clear_quarantine(db: Any, backend_id: str) -> dict:
    """Return a quarantined backend to the healthy pool (upload routing again)."""
    cleared_at = _utc_now().isoformat()
    with db.transaction():
        row = db._conn.execute(
            "SELECT * FROM backends WHERE id = ?", (backend_id,)
        ).fetchone()
        if row is None:
            raise FileNotFoundError(f"Backend {backend_id} does not exist.")
        if str(row["status"]) != "healthy":
            db._conn.execute(
                """UPDATE backends
                   SET status = 'healthy', deprecated_at = NULL
                   WHERE id = ?""",
                (backend_id,),
            )
            db._chain_hmac("backends", {
                "op": "clear_quarantine",
                "id": backend_id,
                "status": "healthy",
                "cleared_at": cleared_at,
            })
    return {
        "backend_id": backend_id,
        "status": "healthy",
        "deprecated_at": None,
        "cleared_at": cleared_at,
        # last_error is intentionally preserved: it is diagnostic history,
        # not part of the quarantine state being cleared.
        "last_error": row["last_error"],
    }
