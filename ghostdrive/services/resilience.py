"""Integrity scrubbing and Reed-Solomon shard repair."""

from __future__ import annotations

import asyncio
import blake3
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

from zfec.easyfec import Encoder

from ghostdrive.crypto.chunk_crypto import ChunkDecryptor
from ghostdrive.crypto.hkdf import derive_chunk_key
from ghostdrive.crypto.nonce import NonceManager
from ghostdrive.pipeline.coding import DATA_SHARDS, TOTAL_SHARDS, erasure_parameters, expected_shards
from ghostdrive.services.context import (
    active_backends,
    get_master_key,
    hkdf_salt,
    require_db,
)
from ghostdrive.services.durability import (
    audit_readiness,
    backend_failure_domain,
    list_at_risk_chunks,
)
from ghostdrive.services.files import _assemble_chunk, READ_BLOCK
from ghostdrive.services.telemetry import meter

logger = logging.getLogger("ghostdrive.services.resilience")

_LAST_SCRUB_KEY = "last_scrub_at"
_SCRUB_LOG_KEY = "scrub_log"
_MAX_STORED_LOGS = 80


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _append_log(db, line: str) -> None:
    stamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
    try:
        raw = db.get_setting(_SCRUB_LOG_KEY, "[]")
        logs = json.loads(raw) if raw else []
        if not isinstance(logs, list):
            logs = []
    except Exception:
        logs = []
    logs.append(f"[{stamp}] {line}")
    logs = logs[-_MAX_STORED_LOGS:]
    try:
        with db.transaction():
            db.set_setting(_SCRUB_LOG_KEY, json.dumps(logs))
    except Exception as exc:
        logger.warning("Could not persist scrub log: %s", exc)


def status() -> dict:
    db = require_db()
    rows = db._conn.execute(
        """SELECT c.id AS chunk_id, c.sub_block_count,
                  c.erasure_k, c.erasure_n, c.erasure_padlen,
                  f.tier AS tier,
                  SUM(CASE WHEN cl.status = 'confirmed' THEN 1 ELSE 0 END) AS confirmed,
                  COUNT(cl.backend_id) AS total
           FROM chunks c
           JOIN files f ON c.file_id = f.id
           LEFT JOIN chunk_locations cl ON cl.chunk_id = c.id
           WHERE f.tombstone = 0
           GROUP BY c.id"""
    ).fetchall()

    total_chunks = len(rows)
    verified = 0
    corrupted = 0
    missing_mirrors = 0
    # (data_shards, total_shards) -> chunk count for every erasure chunk.
    profiles: dict[tuple[int, int], int] = {}
    erasure_chunks = 0
    for row in rows:
        confirmed = int(row["confirmed"] or 0)
        total = int(row["total"] or 0)
        expected = expected_shards(row)
        if confirmed >= expected:
            verified += 1
        elif confirmed == 0:
            corrupted += 1
        else:
            missing_mirrors += 1
        if total == 0:
            corrupted += 1
        k, n, _padlen, is_erasure = erasure_parameters(row)
        if is_erasure:
            erasure_chunks += 1
            profiles[(k, n)] = profiles.get((k, n), 0) + 1

    health = round((verified / total_chunks) * 100, 2) if total_chunks else 100.0
    try:
        logs = json.loads(db.get_setting(_SCRUB_LOG_KEY, "[]"))
    except Exception:
        logs = []
    if not logs:
        logs = [
            "No scrub has run yet.",
            f"{total_chunks} chunk{'s' if total_chunks != 1 else ''} indexed, {verified} fully replicated.",
        ]

    recent_events = []
    try:
        for event in db.list_integrity_events(limit=10):
            recent_events.append({
                "chunk_id": event["chunk_id"],
                "filename": event["filename"],
                "result": event["result"],
                "checked_at": event["checked_at"],
            })
    except Exception:
        pass

    try:
        worst_case = audit_readiness(db)
    except Exception as exc:
        logger.warning("Worst-case readiness audit failed: %s", exc)
        worst_case = {
            "state": "UNKNOWN",
            "summary": "Worst-case readiness could not be measured.",
            "findings": [f"Readiness audit failed: {exc}"],
            "contract": {},
            "failure_domains": [],
            "failure_domain_count": 0,
            "metadata": {"status": "unknown", "snapshot_count": 0},
            "recovery": {"ok": False, "confirmed_at": None},
        }

    # Adaptive coding report: dominant profile is the most common (k, n) by
    # chunk count; ties resolve deterministically toward the smaller profile.
    if profiles:
        (dom_k, dom_n) = max(
            profiles.items(), key=lambda item: (item[1], -item[0][1])
        )[0]
    else:
        dom_k, dom_n = DATA_SHARDS, TOTAL_SHARDS
    dom_parity = dom_n - dom_k
    scheme_profiles = [
        {"data_shards": k, "parity_shards": n - k, "chunks": count}
        for (k, n), count in sorted(profiles.items(), key=lambda item: (-item[1], item[0]))
    ]

    return {
        "health_score_percent": health,
        "total_chunks_scanned": total_chunks,
        "verified_chunks": verified,
        "corrupted_chunks": corrupted,
        "missing_mirrors": missing_mirrors,
        "last_scrub_timestamp": db.get_setting(_LAST_SCRUB_KEY, "") or None,
        "scrub_running": bool(getattr(__import__("ghostdrive.web.state", fromlist=["state"]).state, "scrub_job", None)),
        "erasure_coding": {
            "enabled": True if total_chunks == 0 else bool(erasure_chunks),
            "scheme": f"Reed-Solomon (zfec {dom_k}+{dom_parity})",
            "data_shards": dom_k,
            "parity_shards": dom_parity,
            "total_shards": dom_k + dom_parity,
            "schemes": scheme_profiles,
            "recovery_threshold": (
                f"{dom_k} of {dom_k + dom_parity} shards required for full recovery"
            ),
            "adaptive": any(
                (k, n) != (DATA_SHARDS, TOTAL_SHARDS) for (k, n) in profiles
            ),
        },
        "recent_scrub_logs": logs,
        "recent_integrity_events": recent_events,
        "worst_case": worst_case,
    }


async def _verify_chunk(chunk, objects, chunk_key: bytes) -> tuple[str, Optional[str]]:
    try:
        ciphertext = await _assemble_chunk(chunk, objects)
        if len(ciphertext) < 16:
            return "not_found", None
        tag, body = ciphertext[-16:], ciphertext[:-16]
        nonce = NonceManager.counter_to_nonce(int(chunk["nonce_counter"]))
        decryptor = ChunkDecryptor(key=chunk_key, nonce=nonce, expected_tag=tag)
        for offset in range(0, len(body), READ_BLOCK):
            decryptor.feed(body[offset:offset + READ_BLOCK])
        hasher = blake3.blake3()
        for block in decryptor.verify_and_decrypt_streaming():
            hasher.update(block)
        actual = hasher.hexdigest()
        return ("ok", actual) if actual == chunk["blake3_hash"] else ("hash_mismatch", actual)
    except Exception as exc:
        logger.warning("Chunk %s verification failed: %s", chunk["id"], exc)
        return "not_found", None


async def start_scrub(tier: str = "ALL", auto_repair: bool = True) -> dict:
    db = require_db()
    from ghostdrive.web.state import state

    if getattr(state, "scrub_job", None):
        return {
            "status": "running",
            "job_id": state.scrub_job,
            "message": "A scrub is already running.",
        }

    job_id = f"scrub_{uuid.uuid4().hex[:10]}"
    state.scrub_job = job_id
    task = asyncio.create_task(_run_scrub(job_id, tier, auto_repair))
    state.background_tasks.add(task)
    task.add_done_callback(state.background_tasks.discard)
    _append_log(db, f"Integrity scrub {job_id} queued (tier={tier}, auto_repair={auto_repair}).")
    return {
        "status": "started",
        "job_id": job_id,
        "message": f"Integrity scrub started for {tier} tier (auto-repair: {auto_repair}).",
    }


async def _run_scrub(job_id: str, tier: str, auto_repair: bool) -> None:
    db = require_db()
    from ghostdrive.web.state import state
    started = time.monotonic()
    _append_log(db, f"Scrub {job_id} started (tier={tier}).")
    try:
        sql = """SELECT c.* FROM chunks c
                 JOIN files f ON c.file_id = f.id
                 WHERE f.tombstone = 0"""
        params: list = []
        if tier and tier.upper() != "ALL":
            sql += " AND f.tier = ?"
            params.append(tier.upper())
        sql += " ORDER BY c.file_id, c.chunk_index"
        chunks = db._conn.execute(sql, params).fetchall()

        if not chunks:
            _append_log(db, "Scrub finished: no chunks to verify.")
            return

        _, objects = await active_backends(connect_remote=False)
        chunk_key = derive_chunk_key(get_master_key(), hkdf_salt())
        ok_count = 0
        bad_count = 0
        repaired = 0

        for index, chunk in enumerate(chunks, start=1):
            result, actual = await _verify_chunk(chunk, objects, chunk_key)
            if result == "ok":
                ok_count += 1
            else:
                bad_count += 1
            locations = db.get_chunk_locations(chunk["id"])
            backend_id = locations[0]["backend_id"] if locations else None
            if backend_id:
                try:
                    db.insert_integrity_log(str(uuid.uuid4()), chunk["id"], backend_id, result)
                except Exception as exc:
                    logger.warning("Could not write integrity log: %s", exc)

            if auto_repair and erasure_parameters(chunk)[3]:
                confirmed_indexes = {
                    int(loc["sub_block_index"])
                    for loc in locations
                    if loc["status"] == "confirmed"
                }
                missing_indexes = [
                    idx
                    for idx in range(int(erasure_parameters(chunk)[1]))
                    if idx not in confirmed_indexes
                ]
                if result == "hash_mismatch" or missing_indexes:
                    try:
                        repair = await repair_chunk(
                            chunk["id"], objects, force=result == "hash_mismatch"
                        )
                        if repair.get("repaired", 0) > 0:
                            repaired += repair["repaired"]
                    except Exception as exc:
                        logger.warning("Repair failed for chunk %s: %s", chunk["id"], exc)

            if index % 25 == 0 or index == len(chunks):
                _append_log(db, f"Scrub progress: {index}/{len(chunks)} chunks checked.")

        _append_log(
            db,
            f"Scrub {job_id} completed in {time.monotonic() - started:.1f}s: "
            f"{ok_count} OK, {bad_count} bad, {repaired} shards repaired.",
        )
        with db.transaction():
            db.set_setting(_LAST_SCRUB_KEY, _now_iso())
        meter.status(f"Scrub {job_id} complete: {ok_count}/{len(chunks)} OK")
    except asyncio.CancelledError:
        _append_log(db, f"Scrub {job_id} cancelled.")
        raise
    except Exception as exc:
        logger.exception("Scrub %s failed", job_id)
        _append_log(db, f"Scrub {job_id} failed: {exc}")
    finally:
        state.scrub_job = None


async def repair_chunk(
    chunk_id: str, objects: Optional[dict] = None, force: bool = False
) -> dict:
    """Re-upload missing Reed-Solomon shards for one chunk."""
    db = require_db()
    chunk = db._conn.execute("SELECT * FROM chunks WHERE id = ?", (chunk_id,)).fetchone()
    if chunk is None:
        raise FileNotFoundError(f"Chunk {chunk_id} not found.")

    k, n, padlen, is_erasure = erasure_parameters(chunk)
    if not is_erasure:
        return {"status": "skipped", "repaired": 0, "message": "Chunk is not erasure-coded."}

    locations = db.get_chunk_locations(chunk_id)
    confirmed = {int(loc["sub_block_index"]): loc for loc in locations if loc["status"] == "confirmed"}
    missing = [idx for idx in range(n) if idx not in confirmed]
    if not missing and not force:
        return {"status": "healthy", "repaired": 0, "message": f"All {n} shards are present."}
    if force and not missing:
        missing = list(range(n))

    if objects is None:
        _, objects = await active_backends(connect_remote=False)
    if not objects:
        raise RuntimeError("No storage backends are available for repair.")

    ciphertext = await _assemble_chunk(chunk, objects)
    encoder = Encoder(k, n)
    shards = encoder.encode(ciphertext)

    backend_rows = [row for row in db.list_backends() if row["id"] in objects]
    if not backend_rows:
        raise RuntimeError("No reachable storage backends are available for repair.")

    domain_shard_counts: dict[str, int] = {}
    domain_indexes: dict[str, set[int]] = {}
    for loc in locations:
        if loc["status"] != "confirmed":
            continue
        row = next((r for r in backend_rows if r["id"] == loc["backend_id"]), None)
        if row is None:
            continue
        domain = backend_failure_domain(row, objects.get(row["id"]))["id"]
        domain_shard_counts[domain] = domain_shard_counts.get(domain, 0) + 1
        domain_indexes.setdefault(domain, set()).add(int(loc["sub_block_index"]))

    repaired = 0
    repaired_domains: list[str] = []
    # Cold-storage backends are a last resort for durable tiers: repairs for
    # CRITICAL/IMPORTANT files prefer hot domains so restores stay fast.
    tier_row = db._conn.execute(
        "SELECT tier FROM files WHERE id = ?", (chunk["file_id"],)
    ).fetchone()
    file_tier = str(tier_row["tier"]) if tier_row and tier_row["tier"] else "IMPORTANT"
    prefer_hot = file_tier in ("CRITICAL", "IMPORTANT")

    def _cold_penalty(row) -> int:
        backend_obj = objects.get(row["id"])
        cold = backend_obj is not None and getattr(backend_obj, "is_cold_storage", False)
        return 1 if (cold and prefer_hot) else 0

    for sub_index in missing:
        shard = shards[sub_index]
        candidates = []
        for row in backend_rows:
            domain = backend_failure_domain(row, objects.get(row["id"]))["id"]
            if sub_index in domain_indexes.get(domain, set()):
                continue
            candidates.append((
                domain_shard_counts.get(domain, 0),
                0 if row["type"] in ("local", "local_fs") else 1,
                _cold_penalty(row),
                -int(row["priority"] or 0),
                row,
                domain,
            ))
        if not candidates:
            for row in backend_rows:
                domain = backend_failure_domain(row, objects.get(row["id"]))["id"]
                candidates.append((
                    domain_shard_counts.get(domain, 0),
                    0 if row["type"] in ("local", "local_fs") else 1,
                    _cold_penalty(row),
                    -int(row["priority"] or 0),
                    row,
                    domain,
                ))
        candidates.sort(key=lambda item: item[:4])
        _, _, _, _, row, domain = candidates[0]
        target_id = row["id"]
        target = objects[target_id]

        existing = db.find_chunk_location(chunk_id, sub_index, target_id)
        record = {
            "chunk_id": chunk_id,
            "sub_block_index": sub_index,
            "backend_id": target_id,
            "reference_id": "",
            "url_type": "permanent",
            "upload_date": _now_iso(),
            "last_verified": None,
            "quota_reserved": len(shard),
        }
        try:
            with db.transaction():
                if existing:
                    db.update_chunk_location_pending(record)
                else:
                    db.insert_chunk_location_pending(record)
            if not getattr(target, "_connected", False) and row["type"] in ("nas", "telegram", "discord"):
                await target.connect()
                target._connected = True

            async def _one_block(data=shard):
                yield data

            reference_id = await target.upload(
                stream=_one_block(),
                chunk_id=chunk_id,
                sub_block_index=sub_index,
            )
            with db.transaction():
                db.confirm_chunk_location(chunk_id, sub_index, target_id, reference_id)
            repaired += 1
            repaired_domains.append(domain)
            domain_shard_counts[domain] = domain_shard_counts.get(domain, 0) + 1
            domain_indexes.setdefault(domain, set()).add(sub_index)
        except Exception as exc:
            logger.warning("Could not repair shard %d of %s: %s", sub_index, chunk_id[:8], exc)
            try:
                with db.transaction():
                    db.fail_chunk_location(chunk_id, sub_index, target_id)
            except Exception:
                pass

    return {
        "status": "repaired" if repaired else "failed",
        "chunk_id": chunk_id,
        "repaired": repaired,
        "repaired_domains": repaired_domains,
        "message": f"{repaired} shard(s) re-uploaded to independent domains.",
    }


async def evacuate_at_risk(limit: int = 20) -> dict:
    """Repair chunks whose current layout misses the durability contract."""
    db = require_db()
    _, objects = await active_backends(connect_remote=False)
    at_risk = list_at_risk_chunks(db, objects=objects, limit=limit)
    repaired_chunks = 0
    repaired_shards = 0
    failures = 0
    for item in at_risk:
        try:
            result = await repair_chunk(item["chunk_id"], objects)
            if result.get("repaired", 0) > 0:
                repaired_chunks += 1
                repaired_shards += int(result["repaired"])
            elif result.get("status") == "failed":
                failures += 1
        except Exception as exc:
            failures += 1
            logger.warning("Evacuation failed for chunk %s: %s", item["chunk_id"], exc)
    _append_log(
        db,
        f"Evacuation pass: {repaired_chunks} chunk(s), {repaired_shards} shard(s), {failures} failure(s).",
    )
    return {
        "status": "success" if failures == 0 else "partial",
        "examined": len(at_risk),
        "repaired_chunks": repaired_chunks,
        "repaired_shards": repaired_shards,
        "failures": failures,
        "chunks": at_risk,
    }
