"""Encrypted index snapshots, cross-domain copies, and restore proofs.

The index snapshot is a byte-for-byte copy of the open SQLite database after a
WAL checkpoint. It is wrapped in AES-256-GCM with a subkey derived from the
master key, then written to one backend per failure domain using a
deterministic chunk name. A cold-start recovery tool can therefore locate the
latest snapshot from the master key alone.

The snapshot header carries the snapshot id, creation time, and plaintext
BLAKE3 digest. The whole header is authenticated as AES-GCM associated data.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import blake3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from zfec.easyfec import Decoder

from ghostdrive.crypto.chunk_crypto import ChunkDecryptor
from ghostdrive.crypto.hkdf import (
    derive_chunk_key,
    derive_index_backup_enc_key,
    derive_index_backup_name,
)
from ghostdrive.crypto.nonce import NonceManager
from ghostdrive.pipeline.coding import erasure_parameters
from ghostdrive.services.durability import backend_failure_domain
from ghostdrive.services.files import READ_BLOCK, _load_location_bytes

SNAPSHOT_MAGIC = b"GDIDXSNAP1\x00"
SNAPSHOT_VERSION = 1
SNAPSHOT_SLOTS = 3
SNAPSHOT_TARGET_DOMAINS = 4
_HEADER_FIXED = len(SNAPSHOT_MAGIC) + 1 + 12 + 32 + 36 + 32


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _snapshot_token(master_key: bytes, salt: bytes) -> str:
    return derive_index_backup_name(master_key, salt).hex()[:20]


def snapshot_chunk_id(master_key: bytes, salt: bytes, slot: int) -> str:
    return f"indexsnap{_snapshot_token(master_key, salt)}{slot % SNAPSHOT_SLOTS:02d}"


def _encode_snapshot(
    raw: bytes,
    key: bytes,
    snapshot_id: str,
    snapshot_at: str,
) -> bytes:
    nonce = os.urandom(12)
    digest = blake3.blake3(raw).digest()
    stamp = snapshot_at.encode("ascii")[:32].ljust(32, b"\x00")
    header = (
        SNAPSHOT_MAGIC
        + bytes([SNAPSHOT_VERSION])
        + nonce
        + digest
        + snapshot_id.encode("ascii")[:36].ljust(36, b"\x00")
        + stamp
    )
    ciphertext = AESGCM(key).encrypt(nonce, raw, header)
    return header + ciphertext


def _header_metadata(blob: bytes) -> dict:
    if len(blob) < _HEADER_FIXED or not blob.startswith(SNAPSHOT_MAGIC):
        raise ValueError("Not a GhostDrive index snapshot.")
    offset = len(SNAPSHOT_MAGIC)
    version = blob[offset]
    if version != SNAPSHOT_VERSION:
        raise ValueError(f"Unsupported index snapshot version {version}.")
    offset += 1
    nonce = blob[offset:offset + 12]
    offset += 12
    plain_digest = blob[offset:offset + 32]
    offset += 32
    snapshot_id = blob[offset:offset + 36].rstrip(b"\x00").decode("ascii", "replace")
    offset += 36
    snapshot_at = blob[offset:offset + 32].rstrip(b"\x00").decode("ascii", "replace")
    return {
        "version": version,
        "nonce": nonce,
        "plain_digest": plain_digest,
        "snapshot_id": snapshot_id,
        "snapshot_at": snapshot_at,
        "header": blob[:_HEADER_FIXED],
        "ciphertext": blob[_HEADER_FIXED:],
    }


def decode_snapshot(blob: bytes, key: bytes) -> tuple[bytes, dict]:
    meta = _header_metadata(blob)
    raw = AESGCM(key).decrypt(meta["nonce"], meta["ciphertext"], meta["header"])
    if not blake3.blake3(raw).digest() == meta["plain_digest"]:
        raise ValueError("Index snapshot plaintext digest mismatch.")
    return raw, meta


def _domain_targets(rows: list[Any], objects: dict[str, Any]) -> list[Any]:
    groups: dict[str, list[Any]] = {}
    for row in rows:
        backend_id = str(row["id"])
        if backend_id not in objects:
            continue
        domain = backend_failure_domain(row, objects.get(backend_id))
        groups.setdefault(domain["id"], []).append(row)
    targets = [rows[0] for rows in groups.values()]
    targets.sort(key=lambda row: (0 if str(row["type"]) in ("local", "local_fs") else 1, -int(row["priority"] or 0)))
    return targets[:SNAPSHOT_TARGET_DOMAINS]


async def _ensure_connected(backend, row: Any) -> None:
    if getattr(backend, "_connected", False):
        return
    if str(row["type"]) in ("nas", "telegram", "discord"):
        await backend.connect()
        backend._connected = True


async def _upload_blob(backend, row: Any, blob: bytes, chunk_id: str, sub_index: int = 0) -> str:
    await _ensure_connected(backend, row)

    async def _one():
        yield blob

    return await backend.upload(stream=_one(), chunk_id=chunk_id, sub_block_index=sub_index)


async def create_snapshot(
    db: Any = None,
    objects: Optional[dict[str, Any]] = None,
    master_key: Optional[bytes] = None,
    salt: Optional[bytes] = None,
) -> dict:
    """Checkpoint the index, encrypt it, and replicate it across domains."""
    if db is None:
        from ghostdrive.services.context import require_db
        db = require_db()
    if master_key is None or salt is None:
        from ghostdrive.services.context import get_master_key, hkdf_salt
        master_key = master_key or get_master_key()
        salt = salt or hkdf_salt()
    if objects is None:
        from ghostdrive.services.context import active_backends
        _, objects = await active_backends(connect_remote=False)

    db_path = Path(db._path)
    db.wal_checkpoint()
    raw = db_path.read_bytes()
    if not raw:
        raise RuntimeError("Index database is empty; snapshot aborted.")

    snapshot_id = str(uuid.uuid4())
    snapshot_at = _now_iso()
    key = derive_index_backup_enc_key(master_key, salt)
    blob = _encode_snapshot(raw, key, snapshot_id, snapshot_at)
    file_hash = blake3.blake3(blob).hexdigest()

    count_row = db._conn.execute("SELECT COUNT(*) AS total FROM index_snapshots").fetchone()
    slot = int(count_row["total"] or 0) % SNAPSHOT_SLOTS
    chunk_id = snapshot_chunk_id(master_key, salt, slot)

    rows = db.list_backends()
    targets = _domain_targets(rows, objects)
    if not targets:
        raise RuntimeError("No reachable storage backend is available for the index snapshot.")

    copies: list[dict] = []
    for row in targets:
        backend_id = str(row["id"])
        backend = objects[backend_id]
        domain = backend_failure_domain(row, backend)
        try:
            reference_id = await _upload_blob(backend, row, blob, chunk_id)
            copies.append({
                "snapshot_id": snapshot_id,
                "backend_id": backend_id,
                "domain_id": domain["id"],
                "reference_id": reference_id,
                "blake3_hash": file_hash,
                "size": len(blob),
                "status": "confirmed",
                "created_at": snapshot_at,
                "verified_at": snapshot_at,
            })
        except Exception:
            copies.append({
                "snapshot_id": snapshot_id,
                "backend_id": backend_id,
                "domain_id": domain["id"],
                "reference_id": "",
                "blake3_hash": file_hash,
                "size": len(blob),
                "status": "failed",
                "created_at": snapshot_at,
                "verified_at": None,
            })

    confirmed = [copy for copy in copies if copy["status"] == "confirmed"]
    if not confirmed:
        raise RuntimeError("Every index snapshot replica failed to upload.")

    hash_backend_id = confirmed[1]["backend_id"] if len(confirmed) > 1 else confirmed[0]["backend_id"]
    with db.transaction():
        db._conn.execute(
            """INSERT INTO index_snapshots
               (id, snapshot_at, blake3_hash, hash_backend_id, wal_checkpointed, slot, snapshot_size)
               VALUES (?, ?, ?, ?, 1, ?, ?)""",
            (snapshot_id, snapshot_at, file_hash, hash_backend_id, slot, len(blob)),
        )
        db._chain_hmac("index_snapshots", {
            "op": "created", "id": snapshot_id, "snapshot_at": snapshot_at,
            "blake3_hash": file_hash, "slot": slot, "size": len(blob),
        })
        for copy in copies:
            db._conn.execute(
                """INSERT INTO index_snapshot_copies
                   (snapshot_id, backend_id, domain_id, reference_id, blake3_hash,
                    size, status, created_at, verified_at)
                   VALUES (:snapshot_id, :backend_id, :domain_id, :reference_id,
                           :blake3_hash, :size, :status, :created_at, :verified_at)""",
                copy,
            )

    return {
        "status": "success",
        "snapshot_id": snapshot_id,
        "snapshot_at": snapshot_at,
        "slot": slot,
        "chunk_id": chunk_id,
        "size": len(blob),
        "blake3_hash": file_hash,
        "copies": copies,
        "confirmed_copies": len(confirmed),
        "failure_domains": len({copy["domain_id"] for copy in confirmed}),
    }


def list_snapshots(db: Any = None, limit: int = 20) -> list[dict]:
    if db is None:
        from ghostdrive.services.context import require_db
        db = require_db()
    rows = db._conn.execute(
        """SELECT s.*,
                  (SELECT COUNT(*) FROM index_snapshot_copies c
                   WHERE c.snapshot_id = s.id AND c.status = 'confirmed') AS confirmed_copies,
                  (SELECT COUNT(DISTINCT c.domain_id) FROM index_snapshot_copies c
                   WHERE c.snapshot_id = s.id AND c.status = 'confirmed') AS domain_count
           FROM index_snapshots s
           ORDER BY s.snapshot_at DESC LIMIT ?""",
        (max(1, int(limit)),),
    ).fetchall()
    return [
        {
            "id": row["id"],
            "snapshot_at": row["snapshot_at"],
            "blake3_hash": row["blake3_hash"],
            "size": int(row["snapshot_size"] or 0),
            "slot": int(row["slot"] or 0),
            "wal_checkpointed": bool(row["wal_checkpointed"]),
            "confirmed_copies": int(row["confirmed_copies"] or 0),
            "failure_domains": int(row["domain_count"] or 0),
        }
        for row in rows
    ]


def _latest_snapshot(db: Any) -> Any:
    return db._conn.execute(
        "SELECT * FROM index_snapshots ORDER BY snapshot_at DESC LIMIT 1"
    ).fetchone()


def _copy_rows(db: Any, snapshot_id: str) -> list[Any]:
    return db._conn.execute(
        """SELECT c.*, b.type AS backend_type
           FROM index_snapshot_copies c
           JOIN backends b ON b.id = c.backend_id
           WHERE c.snapshot_id = ? AND c.status = 'confirmed'
           ORDER BY c.created_at ASC""",
        (snapshot_id,),
    ).fetchall()


async def _download_copy(copy: Any, objects: dict[str, Any]) -> bytes:
    loc = {
        "backend_id": copy["backend_id"],
        "backend_type": copy["backend_type"],
        "reference_id": copy["reference_id"],
    }
    return await _load_location_bytes(loc, objects)


async def verify_snapshot(
    db: Any = None,
    snapshot_id: Optional[str] = None,
    objects: Optional[dict[str, Any]] = None,
    master_key: Optional[bytes] = None,
    salt: Optional[bytes] = None,
) -> dict:
    if db is None:
        from ghostdrive.services.context import require_db
        db = require_db()
    if master_key is None or salt is None:
        from ghostdrive.services.context import get_master_key, hkdf_salt
        master_key = master_key or get_master_key()
        salt = salt or hkdf_salt()
    if objects is None:
        from ghostdrive.services.context import active_backends
        _, objects = await active_backends(connect_remote=False)

    row = (
        db._conn.execute("SELECT * FROM index_snapshots WHERE id = ?", (snapshot_id,)).fetchone()
        if snapshot_id
        else _latest_snapshot(db)
    )
    if row is None:
        raise FileNotFoundError("No index snapshot has been created yet.")

    key = derive_index_backup_enc_key(master_key, salt)
    copies = _copy_rows(db, str(row["id"]))
    attempts: list[dict] = []
    for copy in copies:
        try:
            blob = await _download_copy(copy, objects)
            digest = blake3.blake3(blob).hexdigest()
            if digest != copy["blake3_hash"]:
                raise ValueError("Encrypted snapshot digest mismatch.")
            raw, meta = decode_snapshot(blob, key)
            attempts.append({
                "backend_id": copy["backend_id"],
                "domain_id": copy["domain_id"],
                "status": "ok",
                "snapshot_id": meta["snapshot_id"],
                "plaintext_size": len(raw),
            })
            return {
                "status": "verified",
                "snapshot_id": str(row["id"]),
                "snapshot_at": row["snapshot_at"],
                "plaintext_size": len(raw),
                "copies_attempted": len(attempts),
                "copy": attempts[-1],
            }
        except Exception as exc:
            attempts.append({
                "backend_id": copy["backend_id"],
                "domain_id": copy["domain_id"],
                "status": "failed",
                "error": str(exc),
            })

    return {
        "status": "failed",
        "snapshot_id": str(row["id"]),
        "snapshot_at": row["snapshot_at"],
        "copies_attempted": len(attempts),
        "attempts": attempts,
    }


async def restore_latest_bytes(
    db: Any = None,
    objects: Optional[dict[str, Any]] = None,
    master_key: Optional[bytes] = None,
    salt: Optional[bytes] = None,
    snapshot_id: Optional[str] = None,
) -> tuple[bytes, dict]:
    """Return decrypted index bytes from a verified snapshot (newest by default)."""
    if db is None:
        from ghostdrive.services.context import require_db
        db = require_db()
    if master_key is None or salt is None:
        from ghostdrive.services.context import get_master_key, hkdf_salt
        master_key = master_key or get_master_key()
        salt = salt or hkdf_salt()
    if objects is None:
        from ghostdrive.services.context import active_backends
        _, objects = await active_backends(connect_remote=False)

    if snapshot_id:
        row = db._conn.execute(
            "SELECT * FROM index_snapshots WHERE id = ?", (snapshot_id,)
        ).fetchone()
        if row is None:
            raise FileNotFoundError("Requested index snapshot was not found.")
    else:
        row = _latest_snapshot(db)
    if row is None:
        raise FileNotFoundError("No index snapshot has been created yet.")
    key = derive_index_backup_enc_key(master_key, salt)
    errors = []
    for copy in _copy_rows(db, str(row["id"])):
        try:
            blob = await _download_copy(copy, objects)
            if blake3.blake3(blob).hexdigest() != copy["blake3_hash"]:
                raise ValueError("Encrypted snapshot digest mismatch.")
            raw, meta = decode_snapshot(blob, key)
            return raw, meta
        except Exception as exc:
            errors.append(f"{copy['backend_id'][:8]}: {exc}")
    raise RuntimeError("No readable snapshot copy remains: " + "; ".join(errors))


def write_restored_index(raw: bytes, destination: Path | str) -> Path:
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(raw)
    return destination


def _decrypt_and_hash(ciphertext: bytes, chunk: Any, chunk_key: bytes) -> tuple[str, int]:
    if len(ciphertext) < 16:
        raise ValueError("Chunk is truncated (no authentication tag).")
    tag, body = ciphertext[-16:], ciphertext[:-16]
    nonce = NonceManager.counter_to_nonce(int(chunk["nonce_counter"]))
    decryptor = ChunkDecryptor(key=chunk_key, nonce=nonce, expected_tag=tag)
    for offset in range(0, len(body), READ_BLOCK):
        decryptor.feed(body[offset:offset + READ_BLOCK])
    hasher = blake3.blake3()
    size = 0
    for block in decryptor.verify_and_decrypt_streaming():
        hasher.update(block)
        size += len(block)
    return hasher.hexdigest(), size


async def run_restore_drill(
    db: Any = None,
    objects: Optional[dict[str, Any]] = None,
    master_key: Optional[bytes] = None,
    salt: Optional[bytes] = None,
) -> dict:
    """Prove that a snapshot and a file chunk restore from minimal shards."""
    if db is None:
        from ghostdrive.services.context import require_db
        db = require_db()
    if master_key is None or salt is None:
        from ghostdrive.services.context import get_master_key, hkdf_salt
        master_key = master_key or get_master_key()
        salt = salt or hkdf_salt()
    if objects is None:
        from ghostdrive.services.context import active_backends
        _, objects = await active_backends(connect_remote=False)

    drill_id = str(uuid.uuid4())
    started_at = _now_iso()
    began = time.monotonic()
    result = "failed"
    detail = ""
    snapshot_id = None
    file_id = None
    chunk_id = None
    shards_used = 0
    domains_used = 0
    bytes_restored = 0

    try:
        snapshot = await verify_snapshot(db, objects=objects, master_key=master_key, salt=salt)
        if snapshot.get("status") != "verified":
            raise RuntimeError("Index snapshot verification failed.")
        snapshot_id = snapshot["snapshot_id"]
        bytes_restored += int(snapshot.get("plaintext_size") or 0)

        chunks = db._conn.execute(
            """SELECT c.* FROM chunks c JOIN files f ON c.file_id = f.id
               WHERE f.tombstone = 0 ORDER BY c.chunk_index DESC, c.id LIMIT 40"""
        ).fetchall()
        if chunks:
            chunk = chunks[0]
            chunk_id = str(chunk["id"])
            file_id = str(chunk["file_id"])
            locations = [
                loc for loc in db.get_chunk_locations(chunk_id)
                if loc["status"] == "confirmed"
            ]
            k, n, padlen, is_erasure = erasure_parameters(chunk)
            by_index: dict[int, list[Any]] = {}
            for loc in locations:
                by_index.setdefault(int(loc["sub_block_index"]), []).append(loc)

            chosen: list[Any] = []
            used_domains: set[str] = set()
            if is_erasure:
                for sub_index in sorted(by_index):
                    candidates = by_index[sub_index]
                    candidate = next(
                        (
                            loc for loc in candidates
                            if backend_failure_domain(
                                {"id": loc["backend_id"], "type": loc["backend_type"]},
                                objects.get(loc["backend_id"]),
                            )["id"] not in used_domains
                        ),
                        candidates[0],
                    )
                    chosen.append(candidate)
                    used_domains.add(
                        backend_failure_domain(
                            {"id": candidate["backend_id"], "type": candidate["backend_type"]},
                            objects.get(candidate["backend_id"]),
                        )["id"]
                    )
                    if len(chosen) >= k:
                        break
                if len(chosen) < k:
                    raise RuntimeError(f"Only {len(chosen)} independent shards available; need {k}.")
                shards = []
                sharenums = []
                for loc in chosen:
                    shards.append(await _load_location_bytes(loc, objects))
                    sharenums.append(int(loc["sub_block_index"]))
                ciphertext = Decoder(k, n).decode(shards, sharenums, padlen)
                shards_used = len(shards)
            else:
                from ghostdrive.services.files import _assemble_chunk
                ciphertext = await _assemble_chunk(chunk, objects)
                shards_used = len({loc["sub_block_index"] for loc in locations})

            actual, size = _decrypt_and_hash(
                ciphertext, chunk, derive_chunk_key(master_key, salt)
            )
            if actual != chunk["blake3_hash"]:
                raise RuntimeError("Restored chunk hash does not match the index.")
            bytes_restored += size
            domains_used = len(used_domains)
            result = "passed"
            detail = f"Snapshot and chunk {chunk_id[:8]} restored from {shards_used} shards."
        else:
            result = "passed"
            detail = "Snapshot restored. No file chunks exist yet."
    except Exception as exc:
        detail = str(exc)
        result = "failed"

    duration_ms = int((time.monotonic() - began) * 1000)
    with db.transaction():
        db._conn.execute(
            """INSERT INTO restore_drills
               (id, started_at, completed_at, snapshot_id, file_id, chunk_id,
                shards_used, domains_used, bytes_restored, duration_ms, result, detail)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                drill_id, started_at, _now_iso(), snapshot_id, file_id, chunk_id,
                shards_used, domains_used, bytes_restored, duration_ms, result, detail,
            ),
        )
    return {
        "id": drill_id,
        "started_at": started_at,
        "completed_at": _now_iso(),
        "snapshot_id": snapshot_id,
        "file_id": file_id,
        "chunk_id": chunk_id,
        "shards_used": shards_used,
        "domains_used": domains_used,
        "bytes_restored": bytes_restored,
        "duration_ms": duration_ms,
        "result": result,
        "detail": detail,
    }


def latest_drill(db: Any = None) -> Optional[dict]:
    if db is None:
        from ghostdrive.services.context import require_db
        db = require_db()
    row = db._conn.execute(
        "SELECT * FROM restore_drills ORDER BY started_at DESC LIMIT 1"
    ).fetchone()
    if row is None:
        return None
    return {
        "id": row["id"],
        "started_at": row["started_at"],
        "completed_at": row["completed_at"],
        "snapshot_id": row["snapshot_id"],
        "file_id": row["file_id"],
        "chunk_id": row["chunk_id"],
        "shards_used": int(row["shards_used"] or 0),
        "domains_used": int(row["domains_used"] or 0),
        "bytes_restored": int(row["bytes_restored"] or 0),
        "duration_ms": int(row["duration_ms"] or 0),
        "result": row["result"],
        "detail": row["detail"],
    }


# ─── Immutable offsite copy ──────────────────────────────────────────────────

# Settings key holding the JSON record of the single immutable offsite copy.
IMMUTABLE_COPY_KEY = "immutable_offsite_copy"


def _is_offsite_row(row: Any, backend_obj: Any = None) -> bool:
    """Reuse durability's definition of 'offsite' rather than inventing one.

    durability.audit_readiness treats a shard as offsite exactly when it lives
    in a failure domain of kind 'provider' (the Telegram/Discord clouds);
    local, external-drive, and NAS domains are on-premises. Same predicate
    here so the two features never disagree about what counts as offsite.
    """
    return backend_failure_domain(row, backend_obj)["kind"] == "provider"


def _immutable_record(db: Any) -> Optional[dict]:
    raw = db.get_setting(IMMUTABLE_COPY_KEY, "")
    if not raw:
        return None
    try:
        record = json.loads(raw)
    except ValueError:
        return None
    return record if isinstance(record, dict) else None


async def create_immutable_copy(
    snapshot_id: Optional[str] = None,
    db: Any = None,
    objects: Optional[dict[str, Any]] = None,
) -> dict:
    """Seal one immutable, hash-verifiable offsite copy of an index snapshot.

    Normal snapshot copies rotate through three slots (slot = count % 3) and
    reuse the same deterministic chunk_id per slot, so every older copy is
    eventually overwritten and cannot be re-verified later. The immutable copy
    instead uses a UNIQUE chunk_id that slot rotation will never reproduce, so
    the sealed blob stays retrievable and its recorded BLAKE3 hash stays
    meaningful indefinitely -- the property that lets us later prove a
    withholding or tampering backend.
    """
    if db is None:
        from ghostdrive.services.context import require_db
        db = require_db()
    if objects is None:
        from ghostdrive.services.context import active_backends
        _, objects = await active_backends(connect_remote=False)

    if snapshot_id:
        snap = db._conn.execute(
            "SELECT * FROM index_snapshots WHERE id = ?", (snapshot_id,)
        ).fetchone()
    else:
        snap = _latest_snapshot(db)
    if snap is None:
        raise ValueError(
            "No index snapshot exists yet; create a snapshot before sealing an immutable copy."
        )
    snapshot_id = str(snap["id"])

    # Reuse an existing confirmed copy's bytes rather than re-encoding the
    # index ourselves: the sealed blob must be byte-for-byte what the snapshot
    # already uploaded, so its recorded digest stays authoritative.
    blob: Optional[bytes] = None
    for copy in _copy_rows(db, snapshot_id):
        try:
            blob = await _download_copy(copy, objects)
            break
        except Exception:
            continue
    if blob is None:
        raise RuntimeError(
            "No confirmed snapshot copy could be downloaded; create a snapshot first."
        )

    # Idempotence: if the recorded immutable copy already targets a reachable,
    # healthy offsite backend for this snapshot, leave it untouched.
    existing = _immutable_record(db)
    reserved: Optional[str] = None
    if existing and existing.get("snapshot_id") == snapshot_id:
        reserved = str(existing.get("backend_id") or "") or None
        current = db.get_backend(reserved) if reserved else None
        if (
            current is not None
            and str(current["status"]) == "healthy"
            and reserved in objects
            and _is_offsite_row(current, objects[reserved])
        ):
            return {**existing, "status": "sealed", "unchanged": True}

    # Choose the target: a healthy offsite (provider-domain) backend that is
    # reachable and not already holding this snapshot's immutable copy.
    # Highest priority wins, mirroring the snapshot placement preference.
    candidates: list[Any] = []
    for row in db.list_backends():
        backend_id = str(row["id"])
        if backend_id == reserved or backend_id not in objects:
            continue
        if str(row["status"]) != "healthy":
            continue
        if _is_offsite_row(row, objects[backend_id]):
            candidates.append(row)
    if not candidates:
        raise RuntimeError("No healthy offsite backend is available to hold the immutable copy.")
    candidates.sort(key=lambda row: -int(row["priority"] or 0))
    target = candidates[0]
    backend_id = str(target["id"])

    # The unique chunk_id is the entire immutability mechanism: slot rotation
    # reuses deterministic names, so only a name no rotation can ever produce
    # survives as a permanent, re-verifiable artifact on the backend.
    chunk_id = f"immutable-{snapshot_id}-{uuid.uuid4().hex[:12]}"
    reference_id = await _upload_blob(objects[backend_id], target, blob, chunk_id)
    record = {
        "snapshot_id": snapshot_id,
        "backend_id": backend_id,
        "domain_id": backend_failure_domain(target, objects[backend_id])["id"],
        "reference_id": reference_id,
        "blake3_hash": blake3.blake3(blob).hexdigest(),
        "size": len(blob),
        "sealed_at": _now_iso(),
        "chunk_id": chunk_id,
    }
    with db.transaction():
        db.set_setting(IMMUTABLE_COPY_KEY, json.dumps(record, sort_keys=True))
        db._chain_hmac("index_snapshot_copies", {"op": "sealed", **record})
    return {**record, "status": "sealed"}


def immutable_copy_status(db: Any = None) -> dict:
    """Report whether the immutable offsite copy still references a live snapshot."""
    if db is None:
        from ghostdrive.services.context import require_db
        db = require_db()
    record = _immutable_record(db)
    if record is None:
        return {"status": "absent", "record": None}
    snap = db._conn.execute(
        "SELECT id FROM index_snapshots WHERE id = ?", (record.get("snapshot_id"),)
    ).fetchone()
    snapshot_exists = snap is not None
    sealed_at = datetime.fromisoformat(record["sealed_at"])
    age_hours = (datetime.now(timezone.utc) - sealed_at).total_seconds() / 3600.0
    return {
        "status": "sealed" if snapshot_exists else "orphaned",
        "record": record,
        "snapshot_exists": snapshot_exists,
        "age_hours": round(age_hours, 4),
    }


async def verify_immutable_copy(
    db: Any = None,
    objects: Optional[dict[str, Any]] = None,
    now: Optional[datetime] = None,
) -> dict:
    """Re-download the immutable copy and compare its BLAKE3 against the sealed record.

    The blob itself is never included in the result -- only digests -- so a
    tampering backend cannot learn the snapshot contents from a report.
    """
    if db is None:
        from ghostdrive.services.context import require_db
        db = require_db()
    checked_at = (now or datetime.now(timezone.utc)).isoformat()
    record = _immutable_record(db)
    if record is None:
        return {"status": "absent"}
    if objects is None:
        from ghostdrive.services.context import active_backends
        _, objects = await active_backends(connect_remote=False)

    backend_id = str(record["backend_id"])
    backend = objects.get(backend_id)
    if backend is None:
        # Reachable-in-principle but not connected right now: report, never
        # raise, so a routine verification pass cannot break the caller.
        return {"status": "unreachable", "backend_id": backend_id}

    try:
        parts: list[bytes] = []
        async for block in backend.download(record["reference_id"]):
            parts.append(block)
        blob = b"".join(parts)
    except Exception as exc:
        return {"status": "error", "detail": str(exc)}

    actual = blake3.blake3(blob).hexdigest()
    return {
        "status": "valid" if actual == record["blake3_hash"] else "tampered",
        "expected": record["blake3_hash"],
        "actual": actual,
        "snapshot_id": record["snapshot_id"],
        "checked_at": checked_at,
    }
