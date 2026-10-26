"""Failure-domain model and worst-case durability auditing.

This module deliberately separates *physical failure domains* from backend
rows. Two folder backends on the same disk are one failure domain, while a
Telegram backend and a NAS are separate domains even if they share a network.

The audit reports the strongest guarantee the current layout actually provides:
how many independent domains can be lost before a chunk drops below the
Reed-Solomon recovery threshold. It never estimates a probability.
"""

from __future__ import annotations

import itertools
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

from ghostdrive.pipeline.coding import (
    DATA_SHARDS,
    PARITY_SHARDS,
    TOTAL_SHARDS,
    erasure_parameters,
    plan_coding,
)

# Single source of truth for the shard constants lives in pipeline.coding;
# they are re-exported here so ``from ghostdrive.services.durability import
# DATA_SHARDS`` keeps working for existing callers and tests.
MAX_DOMAIN_LOSSES = TOTAL_SHARDS - DATA_SHARDS
METADATA_MAX_AGE_DAYS = 30
RESTORE_PROOF_MAX_AGE_DAYS = 30

_REQUIRED_DOMAINS_KEY = "durability_required_domain_losses"
_REQUIRES_OFFSITE_KEY = "durability_requires_offsite"
_REQUIRES_RESTORE_PROOF_KEY = "durability_requires_restore_proof"
_RECOVERY_CONFIRMED_KEY = "durability_recovery_confirmed_at"

CONTRACT_PRESETS = {
    "basic": {
        "required_domain_losses": 1,
        "requires_offsite": False,
        "requires_restore_proof": False,
    },
    "safe": {
        "required_domain_losses": 1,
        "requires_offsite": True,
        "requires_restore_proof": True,
    },
    "paranoid": {
        "required_domain_losses": 2,
        "requires_offsite": True,
        "requires_restore_proof": True,
    },
}


def _row_value(row: Any, key: str, default: Any = None) -> Any:
    try:
        value = row[key]
    except (KeyError, IndexError, TypeError):
        return default
    return default if value is None else value


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_timestamp(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _backend_label(row: Any, db: Any = None) -> str:
    backend_id = str(_row_value(row, "id", ""))
    if db is not None:
        try:
            label = db.get_setting(f"backend_label_{backend_id}", "")
            if label:
                return str(label)
        except Exception:
            pass
    backend_type = str(_row_value(row, "type", "backend")).replace("_", " ")
    return f"{backend_type.title()} {backend_id[:8]}"


def backend_failure_domain(
    row: Any,
    backend_obj: Any = None,
    drive_uuid: Optional[str] = None,
) -> dict:
    """Return the physical/provider failure domain for one backend row.

    Local and external folders on the same filesystem share a domain. NAS
    devices are grouped by host. Telegram and Discord are grouped by provider.
    The returned label never contains a full local path.
    """
    backend_id = str(_row_value(row, "id", "unknown"))
    backend_type = str(_row_value(row, "type", "unknown")).lower()
    label = _backend_label(row)

    if backend_type in ("local", "local_fs", "local_folder") or backend_type == "external_drive":
        if backend_type == "external_drive":
            identity = (
                drive_uuid
                or getattr(backend_obj, "drive_uuid", None)
                or _row_value(row, "credentials_ref", None)
            )
            if identity:
                return {
                    "id": f"external:{identity}",
                    "label": f"External drive {str(identity)[:8]}",
                    "kind": "external",
                    "backend_id": backend_id,
                }

        root = getattr(backend_obj, "root_path", None)
        if root is None:
            credentials_ref = str(_row_value(row, "credentials_ref", "") or "")
            if credentials_ref and not credentials_ref.startswith(("ref:", "keyring:")):
                root = Path(credentials_ref)
        if root:
            root = Path(root)
            try:
                st_dev = os.stat(root).st_dev
                identity = f"device:{st_dev}"
                drive = root.drive or root.anchor or "local"
                domain_label = f"This PC / {drive or 'local storage'}"
            except OSError:
                drive = root.drive or root.anchor or "local"
                identity = f"device:{str(drive).lower()}"
                domain_label = f"This PC / {drive or 'local storage'}"
            return {
                "id": identity,
                "label": domain_label,
                "kind": "external" if backend_type == "external_drive" else "local",
                "backend_id": backend_id,
            }

        return {
            "id": f"backend:{backend_id}",
            "label": label,
            "kind": "local",
            "backend_id": backend_id,
        }

    if backend_type == "nas":
        host = ""
        try:
            host = str(getattr(backend_obj, "host", "") or "")
        except Exception:
            host = ""
        if not host:
            credentials_ref = str(_row_value(row, "credentials_ref", "") or "")
            host = credentials_ref if credentials_ref and not credentials_ref.startswith(("ref:", "keyring:")) else ""
        if host:
            return {
                "id": f"nas:{host.lower()}",
                "label": f"NAS / {host}",
                "kind": "nas",
                "backend_id": backend_id,
            }
        return {
            "id": f"backend:{backend_id}",
            "label": label,
            "kind": "nas",
            "backend_id": backend_id,
        }

    if backend_type in ("telegram", "discord", "s3"):
        if backend_type == "s3":
            # Each S3 endpoint+bucket pair is its own provider failure domain:
            # B2, Wasabi, MinIO and AWS are independent operators even though
            # they share the same protocol, so they must not collapse into a
            # single "provider:s3" domain.
            endpoint = str(getattr(backend_obj, "endpoint_url", "") or "")
            bucket = str(getattr(backend_obj, "bucket", "") or "")
            identity = f"{endpoint.rstrip('/')}/{bucket}".lower()
            return {
                "id": f"provider:s3:{identity}",
                "label": f"S3 / {bucket or 'bucket'}",
                "kind": "provider",
                "backend_id": backend_id,
            }
        return {
            "id": f"provider:{backend_type}",
            "label": f"{backend_type.title()} cloud",
            "kind": "provider",
            "backend_id": backend_id,
        }

    return {
        "id": f"backend:{backend_id}",
        "label": label,
        "kind": "unknown",
        "backend_id": backend_id,
    }


def _backend_rows_with_domains(db: Any, objects: Optional[dict] = None) -> tuple[list[dict], dict[str, dict]]:
    rows = db.list_backends()
    objects = objects or {}
    backends: list[dict] = []
    domains: dict[str, dict] = {}

    for row in rows:
        backend_id = str(row["id"])
        backend_obj = objects.get(backend_id)
        drive_uuid = None
        if str(row["type"]).lower() == "external_drive" and backend_obj is None:
            try:
                registry = db.get_drive_registry_by_backend(backend_id)
                drive_uuid = registry["drive_uuid"] if registry else None
            except Exception:
                drive_uuid = None
        domain = backend_failure_domain(row, backend_obj, drive_uuid=drive_uuid)
        item = {
            "id": backend_id,
            "type": str(row["type"]),
            "label": _backend_label(row, db),
            "status": str(_row_value(row, "status", "unknown")),
            "enabled": str(_row_value(row, "status", "")) != "deprecated",
            "domain_id": domain["id"],
            "domain_label": domain["label"],
            "domain_kind": domain["kind"],
        }
        backends.append(item)
        domain_entry = domains.setdefault(
            domain["id"],
            {
                "id": domain["id"],
                "label": domain["label"],
                "kind": domain["kind"],
                "backend_ids": [],
                "backend_types": [],
            },
        )
        domain_entry["backend_ids"].append(backend_id)
        if item["type"] not in domain_entry["backend_types"]:
            domain_entry["backend_types"].append(item["type"])

    return backends, domains


def _row_is_cold(row: Any, objects: Optional[dict] = None) -> bool:
    """True when this backend row should count as cold/archive storage.

    Coldness comes from the live backend object's ``is_cold_storage`` flag
    (previously declared but never consulted) or, as a fallback, from an
    embedded ``is_cold_storage`` column on the row mapping itself.
    """
    objects = objects or {}
    backend_id = str(_row_value(row, "id", ""))
    obj = objects.get(backend_id)
    if obj is not None and getattr(obj, "is_cold_storage", False):
        return True
    try:
        return bool(row["is_cold_storage"])
    except (KeyError, IndexError, TypeError):
        return False


def assign_shards_to_backends(
    backend_rows: Iterable[Any],
    shard_count: int,
    objects: Optional[dict] = None,
    *,
    tier: str = "IMPORTANT",
) -> list[Any]:
    """Assign shard indexes across physical failure domains.

    Domains are filled in rounds: one shard per domain, then the next shard on
    each domain. This avoids putting all shards on two folder backends that sit
    on the same disk merely because they are separate backend rows.

    Within each domain group, cold-storage rows are ordered according to the
    file tier: CRITICAL/IMPORTANT place hot (fast) rows first and cold archive
    rows last, DISPOSABLE places cold (cheap archive) rows first. The sort is
    stable, so a fully-hot layout is assigned byte-for-byte identically to
    before.
    """
    if shard_count <= 0:
        return []
    objects = objects or {}
    groups: dict[str, list[Any]] = {}
    for row in backend_rows:
        backend_id = str(_row_value(row, "id", ""))
        domain = backend_failure_domain(row, objects.get(backend_id))
        groups.setdefault(domain["id"], []).append(row)

    if not groups:
        return []

    tier_key = str(tier or "").upper()
    if tier_key in ("CRITICAL", "IMPORTANT"):
        # Durable tiers: hot rows first, cold archive rows last within the
        # group (stable sort keeps the original order among same-coldness rows).
        def reorder(row: Any) -> int:
            return 1 if _row_is_cold(row, objects) else 0
    elif tier_key == "DISPOSABLE":
        # Disposable files may live on cheap archive storage: cold first.
        def reorder(row: Any) -> int:
            return 0 if _row_is_cold(row, objects) else 1
    else:
        reorder = None
    if reorder is not None:
        for domain_id, rows in groups.items():
            groups[domain_id] = sorted(rows, key=reorder)

    assignment: list[Any] = []
    positions = {domain_id: 0 for domain_id in groups}
    while len(assignment) < shard_count:
        progressed = False
        for domain_id, rows in groups.items():
            if len(assignment) >= shard_count:
                break
            position = positions[domain_id]
            assignment.append(rows[position % len(rows)])
            positions[domain_id] += 1
            progressed = True
        if not progressed:
            break
    return assignment


def _max_survivable_domain_losses(shard_domains: dict[str, set[int]], required_shards: int) -> int:
    """Largest k for which every combination of k lost domains leaves enough shards."""
    domains = list(shard_domains)
    if required_shards <= 0:
        return len(domains)
    unique_shards = len(set().union(*shard_domains.values())) if shard_domains else 0
    upper_bound = min(len(domains), max(0, unique_shards - required_shards))
    for losses in range(upper_bound + 1):
        for lost in itertools.combinations(domains, losses):
            lost_set = set(lost)
            remaining: set[int] = set()
            for domain_id, shard_indexes in shard_domains.items():
                if domain_id not in lost_set:
                    remaining.update(shard_indexes)
            if len(remaining) < required_shards:
                return max(0, losses - 1)
    return upper_bound


def _min_remaining_after_losses(
    shard_domains: dict[str, set[int]],
    losses: int,
) -> tuple[int, list[str]]:
    domains = list(shard_domains)
    if not domains:
        return 0, []
    losses = max(0, min(losses, len(domains)))
    if losses == 0:
        return len(set().union(*shard_domains.values())), []
    worst_remaining = 10**9
    worst_lost: list[str] = []
    for lost in itertools.combinations(domains, losses):
        lost_set = set(lost)
        remaining: set[int] = set()
        for domain_id, shard_indexes in shard_domains.items():
            if domain_id not in lost_set:
                remaining.update(shard_indexes)
        count = len(remaining)
        if count < worst_remaining:
            worst_remaining = count
            worst_lost = list(lost)
    return max(0, worst_remaining), worst_lost


def contract_from_settings(db: Any) -> dict:
    try:
        required = int(db.get_setting(_REQUIRED_DOMAINS_KEY, "2"))
    except (TypeError, ValueError):
        required = 2

    def _setting_bool(key: str, default: bool) -> bool:
        raw = str(db.get_setting(key, "true" if default else "false")).strip().lower()
        return raw in ("1", "true", "yes", "on")

    return {
        "required_domain_losses": max(0, min(required, MAX_DOMAIN_LOSSES)),
        "max_domain_losses": MAX_DOMAIN_LOSSES,
        "requires_offsite": _setting_bool(_REQUIRES_OFFSITE_KEY, False),
        "requires_restore_proof": _setting_bool(_REQUIRES_RESTORE_PROOF_KEY, False),
        "requires_metadata_backup": True,
        "requires_recovery_confirmation": True,
        "preset": _contract_preset_name(
            max(0, min(required, MAX_DOMAIN_LOSSES)),
            _setting_bool(_REQUIRES_OFFSITE_KEY, False),
            _setting_bool(_REQUIRES_RESTORE_PROOF_KEY, False),
        ),
    }


def _contract_preset_name(required: int, offsite: bool, restore_proof: bool) -> str:
    for name, preset in CONTRACT_PRESETS.items():
        if (
            preset["required_domain_losses"] == required
            and preset["requires_offsite"] == offsite
            and preset["requires_restore_proof"] == restore_proof
        ):
            return name
    return "custom"


def contract_preset(name: str) -> dict:
    key = str(name or "").strip().lower()
    if key not in CONTRACT_PRESETS:
        raise ValueError(f"Unknown contract preset {name!r}; expected one of {sorted(CONTRACT_PRESETS)}.")
    return {
        **CONTRACT_PRESETS[key],
        "max_domain_losses": MAX_DOMAIN_LOSSES,
        "requires_metadata_backup": True,
        "requires_recovery_confirmation": True,
        "preset": key,
    }


def save_contract(
    db: Any,
    required_domain_losses: int,
    requires_offsite: bool,
    requires_restore_proof: bool = False,
) -> dict:
    required = int(required_domain_losses)
    if required < 0 or required > MAX_DOMAIN_LOSSES:
        raise ValueError(
            f"4+2 erasure coding can survive at most {MAX_DOMAIN_LOSSES} "
            "independent single-shard domain losses."
        )
    with db.transaction():
        db.set_setting(_REQUIRED_DOMAINS_KEY, str(required))
        db.set_setting(_REQUIRES_OFFSITE_KEY, "true" if requires_offsite else "false")
        db.set_setting(
            _REQUIRES_RESTORE_PROOF_KEY,
            "true" if requires_restore_proof else "false",
        )
    return contract_from_settings(db)


def confirm_recovery_saved(db: Any) -> str:
    timestamp = _now().isoformat()
    with db.transaction():
        db.set_setting(_RECOVERY_CONFIRMED_KEY, timestamp)
    return timestamp


def _metadata_status(db: Any) -> dict:
    try:
        row = db._conn.execute(
            "SELECT COUNT(*) AS total, MAX(snapshot_at) AS latest FROM index_snapshots"
        ).fetchone()
        total = int(row["total"] or 0) if row else 0
        latest = row["latest"] if row else None
    except Exception:
        total = 0
        latest = None

    copy_count = 0
    copy_domains = 0
    try:
        copy_row = db._conn.execute(
            """SELECT COUNT(*) AS total,
                      COUNT(DISTINCT domain_id) AS domains
               FROM index_snapshot_copies WHERE status = 'confirmed'"""
        ).fetchone()
        copy_count = int(copy_row["total"] or 0) if copy_row else 0
        copy_domains = int(copy_row["domains"] or 0) if copy_row else 0
    except Exception:
        pass

    latest_dt = _parse_timestamp(latest)
    fresh = bool(latest_dt and _now() - latest_dt <= timedelta(days=METADATA_MAX_AGE_DAYS))
    return {
        "snapshot_count": total,
        "latest_snapshot_at": latest,
        "fresh": fresh,
        "status": "ok" if total > 0 and fresh else ("stale" if total > 0 else "missing"),
        "max_age_days": METADATA_MAX_AGE_DAYS,
        "copy_count": copy_count,
        "copy_failure_domains": copy_domains,
    }


def _restore_proof_status(db: Any) -> dict:
    try:
        row = db._conn.execute(
            """SELECT * FROM restore_drills
               ORDER BY started_at DESC LIMIT 1"""
        ).fetchone()
    except Exception:
        row = None
    if row is None:
        return {
            "ok": False,
            "result": "missing",
            "completed_at": None,
            "max_age_days": RESTORE_PROOF_MAX_AGE_DAYS,
        }
    completed = _parse_timestamp(row["completed_at"] or row["started_at"])
    fresh = bool(
        row["result"] == "passed"
        and completed
        and _now() - completed <= timedelta(days=RESTORE_PROOF_MAX_AGE_DAYS)
    )
    return {
        "ok": fresh,
        "result": row["result"],
        "completed_at": row["completed_at"] or row["started_at"],
        "duration_ms": int(row["duration_ms"] or 0),
        "detail": row["detail"],
        "max_age_days": RESTORE_PROOF_MAX_AGE_DAYS,
    }


def simulate_domain_losses(
    db: Any = None,
    lost_domain_ids: Optional[Iterable[str]] = None,
    lost_backend_ids: Optional[Iterable[str]] = None,
    objects: Optional[dict] = None,
    contract: Optional[dict] = None,
) -> dict:
    """Answer "what happens if these failure domains disappear now?"."""
    if db is None:
        from ghostdrive.services.context import require_db
        db = require_db()

    contract = contract or contract_from_settings(db)
    backends, domains = _backend_rows_with_domains(db, objects)
    backend_domains = {item["id"]: item["domain_id"] for item in backends}
    lost_domains = {str(item) for item in (lost_domain_ids or [])}
    lost_backends = {str(item) for item in (lost_backend_ids or [])}
    required_losses = int(contract["required_domain_losses"])
    required_for_protection = max(1, required_losses)

    rows = db._conn.execute(
        """SELECT c.id AS chunk_id, c.sub_block_count,
                  c.erasure_k, c.erasure_n, c.erasure_padlen, c.size AS chunk_size,
                  f.id AS file_id, f.name AS filename, f.size AS file_size, f.tier,
                  cl.sub_block_index, cl.backend_id, cl.status
           FROM chunks c
           JOIN files f ON c.file_id = f.id
           LEFT JOIN chunk_locations cl ON cl.chunk_id = c.id
           WHERE f.tombstone = 0
           ORDER BY c.id, cl.sub_block_index"""
    ).fetchall()

    chunks: dict[str, dict] = {}
    for row in rows:
        chunk_id = str(row["chunk_id"])
        entry = chunks.setdefault(chunk_id, {
            "chunk_id": chunk_id,
            "file_id": str(row["file_id"]),
            "filename": str(row["filename"]),
            "file_size": int(row["file_size"] or 0),
            "tier": str(row["tier"]),
            "sub_block_count": int(row["sub_block_count"] or 1),
            "erasure_k": int(row["erasure_k"] or 0),
            "erasure_n": int(row["erasure_n"] or 0),
            "erasure_padlen": int(row["erasure_padlen"] or 0),
            "locations": [],
        })
        if row["status"] == "confirmed" and row["backend_id"]:
            entry["locations"].append({
                "sub_block_index": int(row["sub_block_index"]),
                "backend_id": str(row["backend_id"]),
            })

    blinded = 0
    below_contract = 0
    unaffected = 0
    affected_files: set[str] = set()
    affected_bytes = 0
    per_chunk: list[dict] = []

    for chunk in chunks.values():
        k, n, _, is_erasure = erasure_parameters(chunk)
        required_shards = k if is_erasure else max(1, n)
        shard_domains: dict[str, set[int]] = {}
        removed = 0
        for loc in chunk["locations"]:
            domain_id = backend_domains.get(loc["backend_id"], f"backend:{loc['backend_id']}")
            if domain_id in lost_domains or loc["backend_id"] in lost_backends:
                removed += 1
                continue
            shard_domains.setdefault(domain_id, set()).add(loc["sub_block_index"])

        remaining = len(set().union(*shard_domains.values())) if shard_domains else 0
        survivable = _max_survivable_domain_losses(shard_domains, required_shards)
        readable = remaining >= required_shards
        meets = survivable >= required_for_protection
        if removed:
            affected_files.add(chunk["file_id"])
            affected_bytes += chunk["file_size"]
        if not readable:
            blinded += 1
        elif not meets:
            below_contract += 1
        else:
            unaffected += 1
        if removed and len(per_chunk) < 30:
            per_chunk.append({
                "chunk_id": chunk["chunk_id"],
                "file_id": chunk["file_id"],
                "filename": chunk["filename"],
                "tier": chunk["tier"],
                "confirmed_shards_remaining": remaining,
                "required_shards": required_shards,
                "failure_domains_remaining": len(shard_domains),
                "removed_shards": removed,
                "readable": readable,
                "survivable_domain_losses": survivable,
                "meets_contract": meets,
            })

    if not chunks:
        state = "UNKNOWN"
        summary = "No files exist yet, so there is nothing to simulate."
    elif blinded:
        state = "UNPROTECTED"
        summary = (
            f"Losing the selected domain(s) makes {blinded} of {len(chunks)} "
            "chunks unreadable."
        )
    elif below_contract:
        state = "DEGRADED"
        summary = (
            f"{below_contract} of {len(chunks)} chunks remain readable but fall "
            "below the contracted guarantee."
        )
    else:
        state = "PROTECTED"
        summary = "Every chunk remains readable and meets the contract under this scenario."

    return {
        "state": state,
        "summary": summary,
        "lost_domain_ids": sorted(lost_domains),
        "lost_backend_ids": sorted(lost_backends),
        "lost_domain_labels": [
            domains[domain_id]["label"] for domain_id in sorted(lost_domains) if domain_id in domains
        ],
        "total_chunks": len(chunks),
        "unreadable_chunks": blinded,
        "below_contract_chunks": below_contract,
        "unaffected_chunks": unaffected,
        "affected_files": len(affected_files),
        "affected_bytes": affected_bytes,
        "chunks": per_chunk,
        "contract": contract,
    }


def list_at_risk_chunks(
    db: Any = None,
    objects: Optional[dict] = None,
    contract: Optional[dict] = None,
    limit: int = 100,
) -> list[dict]:
    """Return chunks that do not meet the contract, rarest first."""
    if db is None:
        from ghostdrive.services.context import require_db
        db = require_db()
    contract = contract or contract_from_settings(db)
    backends, _ = _backend_rows_with_domains(db, objects)
    backend_domains = {item["id"]: item["domain_id"] for item in backends}
    required_for_protection = max(1, int(contract["required_domain_losses"]))

    rows = db._conn.execute(
        """SELECT c.id AS chunk_id, c.sub_block_count,
                  c.erasure_k, c.erasure_n, c.erasure_padlen,
                  f.id AS file_id, f.name AS filename, f.tier,
                  cl.sub_block_index, cl.backend_id, cl.status
           FROM chunks c
           JOIN files f ON c.file_id = f.id
           LEFT JOIN chunk_locations cl ON cl.chunk_id = c.id
           WHERE f.tombstone = 0
           ORDER BY c.id, cl.sub_block_index"""
    ).fetchall()

    chunks: dict[str, dict] = {}
    for row in rows:
        chunk_id = str(row["chunk_id"])
        entry = chunks.setdefault(chunk_id, {
            "chunk_id": chunk_id,
            "file_id": str(row["file_id"]),
            "filename": str(row["filename"]),
            "tier": str(row["tier"]),
            "sub_block_count": int(row["sub_block_count"] or 1),
            "erasure_k": int(row["erasure_k"] or 0),
            "erasure_n": int(row["erasure_n"] or 0),
            "erasure_padlen": int(row["erasure_padlen"] or 0),
            "locations": [],
        })
        if row["status"] == "confirmed" and row["backend_id"]:
            entry["locations"].append((int(row["sub_block_index"]), str(row["backend_id"])))

    at_risk: list[dict] = []
    for chunk in chunks.values():
        k, n, _, is_erasure = erasure_parameters(chunk)
        required_shards = k if is_erasure else max(1, n)
        shard_domains: dict[str, set[int]] = {}
        for sub_index, backend_id in chunk["locations"]:
            domain_id = backend_domains.get(backend_id, f"backend:{backend_id}")
            shard_domains.setdefault(domain_id, set()).add(sub_index)
        survivable = _max_survivable_domain_losses(shard_domains, required_shards)
        if survivable < required_for_protection:
            at_risk.append({
                "chunk_id": chunk["chunk_id"],
                "file_id": chunk["file_id"],
                "filename": chunk["filename"],
                "tier": chunk["tier"],
                "failure_domains": len(shard_domains),
                "survivable_domain_losses": survivable,
                "required_shards": required_shards,
            })
    at_risk.sort(key=lambda item: (item["survivable_domain_losses"], item["failure_domains"]))
    return at_risk[:max(1, int(limit))]


def audit_readiness(
    db: Any = None,
    objects: Optional[dict] = None,
    contract: Optional[dict] = None,
) -> dict:
    """Audit whether the current layout meets the worst-case contract."""
    if db is None:
        from ghostdrive.services.context import require_db

        db = require_db()

    contract = contract or contract_from_settings(db)
    backends, domains = _backend_rows_with_domains(db, objects)
    required_losses = int(contract["required_domain_losses"])
    required_for_protection = max(1, required_losses)

    rows = db._conn.execute(
        """SELECT c.id AS chunk_id, c.sub_block_count,
                  c.erasure_k, c.erasure_n, c.erasure_padlen,
                  c.chunk_index,
                  f.id AS file_id, f.name AS filename, f.tier,
                  cl.sub_block_index, cl.backend_id, cl.status,
                  b.type AS backend_type
           FROM chunks c
           JOIN files f ON c.file_id = f.id
           LEFT JOIN chunk_locations cl ON cl.chunk_id = c.id
           LEFT JOIN backends b ON cl.backend_id = b.id
           WHERE f.tombstone = 0
           ORDER BY c.id, cl.sub_block_index"""
    ).fetchall()

    chunks: dict[str, dict] = {}
    for row in rows:
        chunk_id = str(row["chunk_id"])
        entry = chunks.setdefault(
            chunk_id,
            {
                "chunk_id": chunk_id,
                "file_id": str(row["file_id"]),
                "filename": str(row["filename"]),
                "tier": str(row["tier"]),
                "sub_block_count": int(row["sub_block_count"] or 1),
                "erasure_k": int(row["erasure_k"] or 0),
                "erasure_n": int(row["erasure_n"] or 0),
                "erasure_padlen": int(row["erasure_padlen"] or 0),
                "confirmed": [],
            },
        )
        if row["status"] == "confirmed" and row["backend_id"]:
            entry["confirmed"].append(
                {
                    "sub_block_index": int(row["sub_block_index"]),
                    "backend_id": str(row["backend_id"]),
                    "backend_type": row["backend_type"],
                }
            )

    protected = 0
    at_risk = 0
    unprotected = 0
    per_chunk: list[dict] = []
    domain_shard_counts: dict[str, int] = {domain_id: 0 for domain_id in domains}
    domain_kinds = {domain_id: domain["kind"] for domain_id, domain in domains.items()}
    backend_domains = {item["id"]: item["domain_id"] for item in backends}
    tier_totals: dict[str, dict] = {}
    chunks_missing_offsite = 0
    minimum_survivable: Optional[int] = None

    for chunk in chunks.values():
        k, n, padlen, erasure = erasure_parameters(chunk)
        required_shards = k if erasure else max(1, n)
        shard_domains: dict[str, set[int]] = {}
        for loc in chunk["confirmed"]:
            backend_id = loc["backend_id"]
            domain_id = backend_domains.get(backend_id, f"backend:{backend_id}")
            shard_domains.setdefault(domain_id, set()).add(loc["sub_block_index"])
            domain_shard_counts[domain_id] = domain_shard_counts.get(domain_id, 0) + 1

        if not any(domain_kinds.get(domain_id) == "provider" for domain_id in shard_domains):
            chunks_missing_offsite += 1

        survivable = _max_survivable_domain_losses(shard_domains, required_shards)
        minimum_survivable = (
            survivable
            if minimum_survivable is None
            else min(minimum_survivable, survivable)
        )
        remaining, worst_domains = _min_remaining_after_losses(shard_domains, required_losses)
        survives_contract = survivable >= required_for_protection
        if survives_contract:
            protected += 1
        elif survivable >= 1:
            at_risk += 1
        else:
            unprotected += 1

        tier_entry = tier_totals.setdefault(
            chunk["tier"], {"chunks": 0, "protected": 0, "at_risk": 0, "unprotected": 0}
        )
        tier_entry["chunks"] += 1
        if survives_contract:
            tier_entry["protected"] += 1
        elif survivable >= 1:
            tier_entry["at_risk"] += 1
        else:
            tier_entry["unprotected"] += 1

        if len(per_chunk) < 30:
            per_chunk.append(
                {
                    "chunk_id": chunk["chunk_id"],
                    "file_id": chunk["file_id"],
                    "filename": chunk["filename"],
                    "tier": chunk["tier"],
                    "erasure_coded": erasure,
                    "data_shards": k,
                    "total_shards": n,
                    "confirmed_shards": len({loc["sub_block_index"] for loc in chunk["confirmed"]}),
                    "required_shards": required_shards,
                    "failure_domains": len(shard_domains),
                    "survivable_domain_losses": survivable,
                    "worst_case_shards_remaining": remaining,
                    "worst_case_lost_domains": worst_domains,
                    "meets_contract": survives_contract,
                }
            )

    total_chunks = len(chunks)
    metadata = _metadata_status(db)
    restore_proof = _restore_proof_status(db)
    recovery_confirmed_at = db.get_setting(_RECOVERY_CONFIRMED_KEY, "") or None
    recovery_ok = bool(recovery_confirmed_at)
    failure_domains = [
        domain
        for domain_id, domain in domains.items()
        if domain_shard_counts.get(domain_id, 0) > 0
    ]
    offsite_domains = [domain for domain in domains.values() if domain["kind"] == "provider"]
    offsite_ok = bool(offsite_domains) and (
        total_chunks == 0 or chunks_missing_offsite == 0
    )
    metadata_ok = metadata["status"] == "ok"

    if total_chunks == 0:
        state = "UNKNOWN"
        summary = "No files yet. Upload data to measure the worst-case guarantee."
    elif unprotected > 0:
        state = "UNPROTECTED"
        summary = (
            f"{unprotected} of {total_chunks} chunks cannot survive even one "
            "failure-domain loss."
        )
    elif at_risk > 0 or (contract["requires_metadata_backup"] and not metadata_ok) or (
        contract["requires_recovery_confirmation"] and not recovery_ok
    ) or (contract["requires_offsite"] and not offsite_ok) or (
        contract.get("requires_restore_proof") and not restore_proof["ok"]
    ):
        state = "DEGRADED"
        if required_losses == 0:
            summary = "All chunks are readable, but the contract checks are not fully met."
        else:
            summary = (
                f"All chunks are readable, but the layout does not yet meet the "
                f"contract of surviving {required_losses} independent failure-domain loss"
                f"{'es' if required_losses != 1 else ''}."
            )
    else:
        state = "PROTECTED"
        if required_losses == 0:
            summary = "Every chunk is currently recoverable from its confirmed shards."
        else:
            summary = (
                f"Every chunk survives any {required_losses} independent failure-domain "
                f"loss{'es' if required_losses != 1 else ''}."
            )

    findings: list[str] = []
    if total_chunks:
        if len(failure_domains) <= 1:
            findings.append(
                "All stored shards share a single failure domain. Losing that disk or provider loses every copy."
            )
        if len(failure_domains) < required_losses:
            findings.append(
                f"The contract requires {required_losses} independent domain losses, but data currently occupies only {len(failure_domains)}."
            )
        if unprotected:
            findings.append(
                f"{unprotected} chunk{'s' if unprotected != 1 else ''} cannot survive a single domain loss."
            )
        if at_risk:
            findings.append(
                f"{at_risk} chunk{'s' if at_risk != 1 else ''} survive one domain loss but not the contracted {required_losses}."
            )
        if not metadata_ok:
            findings.append(
                "The local index has no fresh external snapshot. A dead primary machine would lose filenames, tiers, and shard references."
            )
        elif metadata.get("copy_count", 0) == 0:
            findings.append(
                "The latest index snapshot exists only in the local index. Run a snapshot to copy it into independent failure domains."
            )
        elif metadata.get("copy_failure_domains", 0) < 2:
            findings.append(
                "The latest index snapshot is replicated to only one failure domain. A second independent copy is still needed."
            )
        if contract.get("requires_restore_proof") and not restore_proof["ok"]:
            findings.append(
                "The contract requires a recent restore proof, but no successful restore drill is recorded."
            )
        if not recovery_ok:
            findings.append(
                "Saving the recovery phrase has not been confirmed. A lost passphrase would make every backend copy unreadable."
            )
        if contract["requires_offsite"] and not offsite_ok:
            if not offsite_domains:
                findings.append(
                    "The contract requires an offsite provider domain, but only local or LAN storage is configured."
                )
            else:
                findings.append(
                    f"{chunks_missing_offsite} chunk{'s' if chunks_missing_offsite != 1 else ''} "
                    "have no confirmed shard on an offsite provider."
                )
        if not findings:
            findings.append("The current layout meets every configured worst-case check.")
    else:
        findings.append("Upload a file to establish the first durability baseline.")

    return {
        "state": state,
        "summary": summary,
        "contract": contract,
        "total_chunks": total_chunks,
        "protected_chunks": protected,
        "at_risk_chunks": at_risk,
        "unprotected_chunks": unprotected,
        "minimum_survivable_domain_losses": minimum_survivable,
        "failure_domains": failure_domains,
        "failure_domain_count": len(failure_domains),
        "configured_failure_domains": list(domains.values()),
        "configured_failure_domain_count": len(domains),
        "offsite_domain_count": len(offsite_domains),
        "offsite_chunks_missing": chunks_missing_offsite,
        "domain_shard_counts": domain_shard_counts,
        "backends": backends,
        "tiers": tier_totals,
        "metadata": metadata,
        "metadata_ok": metadata_ok,
        "restore_proof": restore_proof,
        "recovery": {
            "confirmed_at": recovery_confirmed_at,
            "ok": recovery_ok,
        },
        "offsite_ok": offsite_ok,
        "findings": findings,
        "chunks": per_chunk,
        "scheme": {
            "data_shards": DATA_SHARDS,
            "parity_shards": PARITY_SHARDS,
            "total_shards": TOTAL_SHARDS,
            "recovery_threshold": DATA_SHARDS,
            "storage_overhead": TOTAL_SHARDS / DATA_SHARDS,
        },
    }
