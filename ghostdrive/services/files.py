"""File service: the single real implementation behind web and CLI operations.

The upload path wires the FastAPI route into the existing ChunkUploader
pipeline (chunking -> encryption -> two-phase commit -> backend upload).
The download path reverses that pipeline, including Reed-Solomon recovery.
"""

from __future__ import annotations

import asyncio
import logging
import mimetypes
import os
import shutil
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncGenerator, Optional

import blake3
from zfec.easyfec import Decoder

from ghostdrive.crypto.chunk_crypto import ChunkDecryptor
from ghostdrive.crypto.hkdf import derive_chunk_key
from ghostdrive.crypto.nonce import NonceManager
from ghostdrive.pipeline.chunker import split_file
from ghostdrive.pipeline.coding import erasure_parameters, expected_shards
from ghostdrive.pipeline.file_lock import FileLock
from ghostdrive.pipeline.upload import ChunkUploader
from ghostdrive.services.context import (
    active_backends,
    ensure_local_backend,
    get_master_key,
    hkdf_salt,
    nonce_manager,
    require_db,
)
from ghostdrive.services.telemetry import meter

logger = logging.getLogger("ghostdrive.services.files")

MAX_WEB_CHUNK_BYTES = 64 * 1024 * 1024
READ_BLOCK = 64 * 1024
VALID_TIERS = {"CRITICAL", "IMPORTANT", "DISPOSABLE"}
REDUNDANCY = {"CRITICAL": "RS 4+2", "IMPORTANT": "RS 4+2", "DISPOSABLE": "single copy"}

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg"}
DOCUMENT_EXTENSIONS = {".pdf", ".txt", ".doc", ".docx", ".md", ".csv", ".json", ".xml", ".yaml", ".yml"}
MEDIA_EXTENSIONS = {".mp4", ".mkv", ".mp3", ".wav", ".flac", ".avi", ".mov", ".webm"}
ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".7z", ".rar", ".bz2", ".xz"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalise_dir(directory: Optional[str]) -> str:
    directory = (directory or "/").strip().replace("\\", "/")
    if not directory.startswith("/"):
        directory = "/" + directory
    if len(directory) > 1:
        directory = directory.rstrip("/")
    return directory


def _virtual_path(directory: str, filename: str) -> str:
    directory = _normalise_dir(directory)
    return f"/{filename}" if directory == "/" else f"{directory}/{filename}"


def file_dict(row) -> dict:
    """Serialise a files table row for the API/CLI."""
    name = row["name"]
    return {
        "id": row["id"],
        "file_id": row["id"],
        "filename": name,
        "name": name,
        "path": row["path"],
        "size": row["size"],
        "file_size": row["size"],
        "mime_type": row["mime_type"] or (mimetypes.guess_type(name)[0] or "application/octet-stream"),
        "tier": row["tier"],
        "redundancy": REDUNDANCY.get(row["tier"], "single copy"),
        "created_at": row["created_at"],
        "modified_at": row["modified_at"],
        "modified": row["modified_at"],
        "deleted_at": row["tombstone_at"],
        "version": row["version"],
        "version_of": row["version_of"],
        "tombstone": bool(row["tombstone"]),
        "tags": row["tags"] or "",
        "logical_clock": row["logical_clock"],
    }


def _category_matches(name: str, category: Optional[str]) -> bool:
    if not category or category.lower() in ("all", "everything"):
        return True
    ext = Path(name).suffix.lower()
    category = category.lower()
    if category == "images":
        return ext in IMAGE_EXTENSIONS
    if category == "documents":
        return ext in DOCUMENT_EXTENSIONS
    if category == "media":
        return ext in MEDIA_EXTENSIONS
    if category == "archives":
        return ext in ARCHIVE_EXTENSIONS
    return True


def list_files(directory: str = "/", category: Optional[str] = None, search: Optional[str] = None) -> dict:
    db = require_db()
    rows = db.list_files(directory=directory, search=search)
    items = [file_dict(row) for row in rows if _category_matches(row["name"], category)]
    return {"current_directory": _normalise_dir(directory), "files": items}


def get_file_row(file_id: str):
    db = require_db()
    row = db.get_file(file_id)
    if row is None:
        raise FileNotFoundError(f"File {file_id} not found.")
    return row


async def upload_stream(
    source,
    filename: str,
    mime_type: Optional[str],
    tier: str,
    destination_path: str = "/",
    temp_dir: Optional[Path] = None,
) -> dict:
    """Persist an uploaded file object through the encryption pipeline.

    ``source`` may be a path, a file-like object, or an UploadFile-compatible
    object.  UploadFile bodies are spooled to a temporary file first so the
    whole file never has to live in RAM.
    """
    tier = (tier or "IMPORTANT").upper()
    if tier not in VALID_TIERS:
        raise ValueError(f"Invalid tier {tier!r}; expected one of {sorted(VALID_TIERS)}")

    filename = os.path.basename(filename or "uploaded_file") or "uploaded_file"
    mime_type = mime_type or mimetypes.guess_type(filename)[0] or "application/octet-stream"

    temp_path: Optional[Path] = None
    if isinstance(source, (str, os.PathLike)):
        path = Path(source)
    else:
        fd, tmp_name = tempfile.mkstemp(prefix="ghostdrive_upload_", dir=str(temp_dir) if temp_dir else None)
        os.close(fd)
        temp_path = Path(tmp_name)
        if hasattr(source, "file"):
            source.file.seek(0)
            with open(temp_path, "wb") as out:
                shutil.copyfileobj(source.file, out, length=1024 * 1024)
        elif hasattr(source, "read"):
            with open(temp_path, "wb") as out:
                shutil.copyfileobj(source, out, length=1024 * 1024)
        else:
            raise TypeError("Unsupported upload source type.")
        path = temp_path

    try:
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"Source file not found: {path}")
        return await _upload_path(path, filename, mime_type, tier, destination_path)
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                logger.warning("Could not remove temporary upload file %s", temp_path)


async def _upload_path(
    source: Path,
    filename: str,
    mime_type: str,
    tier: str,
    destination_path: str,
) -> dict:
    db = require_db()
    master_key = get_master_key()
    salt = hkdf_salt()
    size = source.stat().st_size
    file_id = str(uuid.uuid4())
    directory = _normalise_dir(destination_path)
    created = _now_iso()

    with db.transaction():
        db.insert_file({
            "id": file_id,
            "name": filename,
            "path": _virtual_path(directory, filename),
            "size": size,
            "mime_type": mime_type,
            "tier": tier,
            "created_at": created,
            "modified_at": created,
            "version": 1,
            "version_of": None,
            "tombstone": 0,
            "tombstone_at": None,
            "tags": "",
        })

    ensure_local_backend()
    rows, objects = await active_backends(connect_remote=True)
    if not rows or not objects:
        with db.transaction():
            db.purge_file_permanently(file_id)
        raise RuntimeError("No usable storage backend is available.")

    from ghostdrive.services import durability as durability_service
    if durability_service.contract_from_settings(db)["requires_offsite"]:
        readiness = durability_service.audit_readiness(db, objects=objects)
        if not readiness.get("offsite_ok"):
            raise RuntimeError(
                "Upload blocked: durability contract requires an offsite copy, but none is currently confirmed."
            )

    # Restrict the uploader's erasure routing to backends that are reachable now.
    eligible_ids = [row["id"] for row in rows]
    with db.transaction():
        db.set_setting(f"routing_{tier.lower()}_backends", ",".join(eligible_ids))

    primary_row = next(
        (row for row in rows if row["type"] in ("local", "local_fs")),
        rows[0],
    )
    primary = objects.get(primary_row["id"]) or next(iter(objects.values()))

    logical_sizes = [
        int(getattr(obj, "logical_chunk_bytes", MAX_WEB_CHUNK_BYTES))
        for obj in objects.values()
    ]
    logical_chunk_bytes = max(
        1024 * 1024,
        min(min(logical_sizes + [MAX_WEB_CHUNK_BYTES]), MAX_WEB_CHUNK_BYTES),
    )

    uploader = ChunkUploader(
        db,
        primary,
        master_key,
        salt,
        nonce_manager(),
        active_backends=objects,
    )

    lock = FileLock(source)
    lock.acquire()
    if lock.lock_skipped:
        logger.warning("Upload proceeding without OS integrity lock: %s", filename)

    meter.status(f"Uploading {filename} ({size} bytes) in {tier} tier")
    state_entry = {"file_id": file_id, "filename": filename, "size": size, "tier": tier}
    from ghostdrive.web.state import state
    state.active_uploads[file_id] = state_entry
    try:
        for descriptor in split_file(source, logical_chunk_bytes):
            await uploader.upload_chunk(source, descriptor, file_id, mime_type)
            meter.record_upload(descriptor.size)
            meter.status(
                f"Encrypted chunk {descriptor.chunk_index + 1}/{descriptor.total_chunks} of {filename}"
            )
    except Exception:
        logger.exception("Upload failed for %s; cleaning up partial data", filename)
        try:
            await _delete_backend_objects_for_file(file_id, objects)
        finally:
            with db.transaction():
                db.purge_file_permanently(file_id)
        raise
    finally:
        lock.release()
        state.active_uploads.pop(file_id, None)

    row = db.get_file(file_id)
    meter.status(f"Upload complete: {filename}")
    return {
        "status": "success",
        "file_id": file_id,
        "filename": filename,
        "size": size,
        "tier": tier,
        "chunks": len(db.get_file_chunks(file_id)),
        "message": "File encrypted, distributed, and committed.",
        "file": file_dict(row) if row is not None else None,
    }


async def _load_location_bytes(loc, objects: dict) -> bytes:
    """Download one sub-block/shard from its backend."""
    backend_id = loc["backend_id"]
    obj = objects.get(backend_id)
    if obj is None:
        db = require_db()
        row = db.get_backend(backend_id)
        if row is None:
            raise RuntimeError(f"Backend {backend_id} no longer exists.")
        from ghostdrive.services.context import build_backend
        obj = build_backend(row)
        objects[backend_id] = obj

    if loc["backend_type"] in ("telegram", "discord", "nas"):
        if not getattr(obj, "_connected", False):
            await obj.connect()
            obj._connected = True

    parts = []
    async for block in obj.download(loc["reference_id"]):
        parts.append(block)
    return b"".join(parts)


async def _assemble_chunk(chunk, objects: dict) -> bytes:
    """Reassemble the raw ciphertext+tag for one logical chunk."""
    db = require_db()
    locations = [
        loc for loc in db.get_chunk_locations(chunk["id"])
        if loc["status"] == "confirmed"
    ]
    if not locations:
        raise RuntimeError(f"Chunk {chunk['id']} has no confirmed locations.")

    is_erasure = erasure_parameters(chunk)[3]
    if is_erasure:
        k, n, padlen, _ = erasure_parameters(chunk)
        # Reed-Solomon 4+2: any four distinct shards reconstruct the chunk.
        by_index = {}
        for loc in locations:
            by_index.setdefault(int(loc["sub_block_index"]), []).append(loc)

        decoded_blocks: list[bytes] = []
        sharenums: list[int] = []
        # NOTE: this is a whole-chunk assembly path (restore / scrub / repair),
        # so it intentionally stops after the first k fetchable shards -- a
        # throughput shortcut: n-k extra parity downloads per restore would be
        # pure waste. Because of that shortcut this path CANNOT detect a
        # corrupted shard beyond the first k; that is fine, because per-shard
        # integrity (including parity shards) is the job of the verify path
        # ghostdrive.pipeline.healing.verify_chunk_location, which forces the
        # specific shard under verification to be fetched from its own backend
        # and to participate in the decode.
        for sub_index in sorted(by_index):
            for loc in by_index[sub_index]:
                try:
                    decoded_blocks.append(await _load_location_bytes(loc, objects))
                    sharenums.append(sub_index)
                    break
                except Exception as exc:
                    logger.warning("Shard %s on %s unavailable: %s", sub_index, loc["backend_id"][:8], exc)
            if len(decoded_blocks) >= k:
                break

        if len(decoded_blocks) < k:
            raise RuntimeError(
                f"Chunk {chunk['id']} is unrecoverable: only {len(decoded_blocks)} of {n} shards available."
            )

        decoder = Decoder(k, n)
        return decoder.decode(decoded_blocks, sharenums, padlen)

    # Non-erasure layout: every sub-block must be present in index order.
    by_index = {}
    for loc in locations:
        by_index.setdefault(int(loc["sub_block_index"]), []).append(loc)

    expected = max(int(chunk["sub_block_count"]), len(by_index))
    blocks: list[bytes] = []
    for sub_index in range(expected):
        candidates = by_index.get(sub_index, [])
        if not candidates:
            raise RuntimeError(f"Chunk {chunk['id']} is missing sub-block {sub_index}.")
        last_error = None
        for loc in candidates:
            try:
                blocks.append(await _load_location_bytes(loc, objects))
                break
            except Exception as exc:
                last_error = exc
        else:
            raise RuntimeError(
                f"Chunk {chunk['id']} sub-block {sub_index} could not be read: {last_error}"
            )
    return b"".join(blocks)


async def iter_file(file_id: str) -> AsyncGenerator[bytes, None]:
    """Yield decrypted plaintext blocks for a file."""
    db = require_db()
    row = get_file_row(file_id)
    chunks = db.get_file_chunks(file_id)
    if not chunks:
        raise RuntimeError(f"File {row['name']!r} has no stored chunks.")

    master_key = get_master_key()
    salt = hkdf_salt()
    chunk_key = derive_chunk_key(master_key, salt)
    _, objects = await active_backends(connect_remote=False)

    from ghostdrive.web.state import state
    state.active_downloads[file_id] = {"file_id": file_id, "filename": row["name"]}
    meter.status(f"Downloading {row['name']}")
    try:
        for chunk in chunks:
            ciphertext = await _assemble_chunk(chunk, objects)
            if len(ciphertext) < 16:
                raise RuntimeError(f"Chunk {chunk['id']} is truncated (no Poly1305 tag).")
            tag = ciphertext[-16:]
            body = ciphertext[:-16]
            nonce = NonceManager.counter_to_nonce(int(chunk["nonce_counter"]))
            decryptor = ChunkDecryptor(key=chunk_key, nonce=nonce, expected_tag=tag)
            for offset in range(0, len(body), READ_BLOCK):
                decryptor.feed(body[offset:offset + READ_BLOCK])
            blocks: list[bytes] = []
            hasher = blake3.blake3()
            for block in decryptor.verify_and_decrypt_streaming():
                hasher.update(block)
                blocks.append(block)
                meter.record_download(len(block))
            actual_hash = hasher.hexdigest()
            if actual_hash != chunk["blake3_hash"]:
                from ghostdrive.services.resilience import repair_chunk as repair_chunk_service

                repair = await repair_chunk_service(chunk["id"], objects, force=True)
                if repair.get("repaired", 0) < 1 and repair.get("status") != "repaired":
                    raise RuntimeError(
                        f"Chunk {chunk['id']} failed hash verification and automatic repair did not replace a shard."
                    )
                ciphertext = await _assemble_chunk(chunk, objects)
                if len(ciphertext) < 16:
                    raise RuntimeError(f"Chunk {chunk['id']} is truncated (no Poly1305 tag).")
                tag = ciphertext[-16:]
                body = ciphertext[:-16]
                nonce = NonceManager.counter_to_nonce(int(chunk["nonce_counter"]))
                decryptor = ChunkDecryptor(key=chunk_key, nonce=nonce, expected_tag=tag)
                for offset in range(0, len(body), READ_BLOCK):
                    decryptor.feed(body[offset:offset + READ_BLOCK])
                blocks = []
                hasher = blake3.blake3()
                for block in decryptor.verify_and_decrypt_streaming():
                    hasher.update(block)
                    blocks.append(block)
                    meter.record_download(len(block))
                actual_hash = hasher.hexdigest()
            if actual_hash != chunk["blake3_hash"]:
                raise RuntimeError(f"Chunk {chunk['id']} failed hash verification after repair.")
            for block in blocks:
                yield block

    finally:
        state.active_downloads.pop(file_id, None)


async def download_bytes(file_id: str, limit: Optional[int] = None) -> bytes:
    out = bytearray()
    async for block in iter_file(file_id):
        out.extend(block)
        if limit is not None and len(out) >= limit:
            return bytes(out[:limit])
    return bytes(out)


def metadata(file_id: str) -> dict:
    db = require_db()
    row = get_file_row(file_id)
    chunks = db.get_file_chunks(file_id)
    chunk_items = []
    for chunk in chunks:
        locations = db.get_chunk_locations(chunk["id"])
        k, n, padlen, erasure = erasure_parameters(chunk)
        chunk_items.append({
            "chunk_id": chunk["id"],
            "chunk_index": chunk["chunk_index"],
            "total_chunks": chunk["total_chunks"],
            "size": chunk["size"],
            "blake3_hash": chunk["blake3_hash"],
            "sub_block_count": chunk["sub_block_count"],
            "erasure": {
                "data_shards": k,
                "total_shards": n,
                "padlen": padlen,
                "enabled": erasure,
            } if erasure else None,
            "nonce_counter": chunk["nonce_counter"],
            "ref_count": chunk["ref_count"],
            "is_manifest": bool(chunk["is_manifest"]),
            "backends": [
                {
                    "sub_block_index": loc["sub_block_index"],
                    "backend_id": loc["backend_id"],
                    "backend_type": loc["backend_type"],
                    "status": loc["status"],
                    "reference_id": loc["reference_id"],
                    "last_verified": loc["last_verified"],
                }
                for loc in locations
            ],
            "status": "VERIFIED" if all(loc["status"] == "confirmed" for loc in locations) and locations else "PENDING",
        })
    backend_count = len({location["backend_id"] for chunk in chunks for location in db.get_chunk_locations(chunk["id"])})
    data = file_dict(row)
    data.update({
        "blake3_hash": chunks[0]["blake3_hash"] if len(chunks) == 1 else None,
        "redundancy": f"{REDUNDANCY.get(row['tier'], 'single copy')} ({backend_count} backend{'s' if backend_count != 1 else ''})",
        "chunk_count": len(chunks),
        "chunks": chunk_items,
        "poly1305_authenticated": True,
        "erasure_coded": any(erasure_parameters(c)[3] for c in chunks),
    })
    return data


def rename(file_id: str, new_name: str) -> dict:
    db = require_db()
    row = get_file_row(file_id)
    new_name = os.path.basename((new_name or "").strip())
    if not new_name:
        raise ValueError("New filename cannot be empty.")
    parent = os.path.dirname(row["path"]) or "/"
    parent = _normalise_dir(parent)
    db.rename_file(file_id, new_name, _virtual_path(parent, new_name))
    return {"status": "success", "file": file_dict(get_file_row(file_id))}


async def _delete_backend_objects_for_file(file_id: str, objects: Optional[dict] = None) -> None:
    db = require_db()
    if objects is None:
        _, objects = await active_backends(connect_remote=False)
    for chunk in db.get_file_chunks(file_id):
        for loc in db.get_chunk_locations(chunk["id"]):
            if loc["status"] != "confirmed" or not loc["reference_id"]:
                continue
            shared = db._conn.execute(
                """SELECT 1 FROM chunk_locations
                   WHERE reference_id = ? AND backend_id = ? AND chunk_id != ?
                   LIMIT 1""",
                (loc["reference_id"], loc["backend_id"], chunk["id"]),
            ).fetchone()
            if shared:
                continue
            obj = objects.get(loc["backend_id"])
            if obj is None:
                continue
            try:
                await obj.delete(loc["reference_id"])
            except Exception as exc:
                logger.warning("Backend delete failed for %s: %s", loc["reference_id"], exc)


async def delete_file(file_id: str, purge: bool = False) -> dict:
    db = require_db()
    row = get_file_row(file_id)
    if purge or row["tier"] == "DISPOSABLE":
        await _delete_backend_objects_for_file(file_id)
        with db.transaction():
            db.purge_file_permanently(file_id)
        meter.status(f"Permanently deleted {row['name']}")
        return {"status": "success", "message": f"File {row['name']!r} permanently deleted."}

    with db.transaction():
        db.tombstone_file(file_id)
    meter.status(f"Moved {row['name']} to Trash")
    return {"status": "success", "message": f"File {row['name']!r} moved to Trash (30-day retention)."}


def trash(older_than_days: Optional[int] = None) -> dict:
    db = require_db()
    rows = db.list_tombstoned_files(older_than_days=older_than_days)
    return {"files": [file_dict(row) for row in rows]}


def restore(file_id: str) -> dict:
    db = require_db()
    row = get_file_row(file_id)
    if not row["tombstone"]:
        raise ValueError("File is not in Trash.")
    with db.transaction():
        db.restore_file(file_id)
    meter.status(f"Restored {row['name']} from Trash")
    return {"status": "success", "message": f"File {row['name']!r} restored."}


async def empty_trash(older_than_days: Optional[int] = None) -> dict:
    db = require_db()
    rows = db.list_tombstoned_files(older_than_days=older_than_days)
    purged = 0
    for row in rows:
        await delete_file(row["id"], purge=True)
        purged += 1
    return {"status": "success", "purged": purged}


def versions(file_id: str) -> dict:
    db = require_db()
    rows = db.get_file_versions(file_id)
    if not rows:
        raise FileNotFoundError(f"File {file_id} not found.")
    return {"file_id": file_id, "versions": [file_dict(row) for row in rows]}


def restore_version(file_id: str, version_id: str) -> dict:
    db = require_db()
    with db.transaction():
        db.restore_file_version(file_id, version_id)
    row = get_file_row(file_id)
    return {"status": "success", "file": file_dict(row)}


def set_tags(file_id: str, tags: str) -> dict:
    db = require_db()
    get_file_row(file_id)
    with db.transaction():
        db.update_file_tags(file_id, tags or "")
    return {"status": "success", "file": file_dict(get_file_row(file_id))}


async def verify_file(file_id: str) -> dict:
    """Decrypt every chunk and verify its BLAKE3 hash against the index."""
    db = require_db()
    row = get_file_row(file_id)
    chunks = db.get_file_chunks(file_id)
    _, objects = await active_backends(connect_remote=False)
    master_key = get_master_key()
    salt = hkdf_salt()
    chunk_key = derive_chunk_key(master_key, salt)
    results = []

    for chunk in chunks:
        try:
            ciphertext = await _assemble_chunk(chunk, objects)
            tag, body = ciphertext[-16:], ciphertext[:-16]
            nonce = NonceManager.counter_to_nonce(int(chunk["nonce_counter"]))
            decryptor = ChunkDecryptor(key=chunk_key, nonce=nonce, expected_tag=tag)
            for offset in range(0, len(body), READ_BLOCK):
                decryptor.feed(body[offset:offset + READ_BLOCK])
            hasher = blake3.blake3()
            for block in decryptor.verify_and_decrypt_streaming():
                hasher.update(block)
            actual = hasher.hexdigest()
            ok = actual == chunk["blake3_hash"]
            result = "ok" if ok else "hash_mismatch"
        except Exception as exc:
            logger.warning("Verification failed for chunk %s: %s", chunk["id"], exc)
            actual = None
            result = "not_found"

        locations = db.get_chunk_locations(chunk["id"])
        backend_id = locations[0]["backend_id"] if locations else None
        if backend_id:
            try:
                db.insert_integrity_log(str(uuid.uuid4()), chunk["id"], backend_id, result)
            except Exception as exc:
                logger.warning("Could not write integrity log: %s", exc)
        results.append({
            "chunk_id": chunk["id"],
            "chunk_index": chunk["chunk_index"],
            "expected_hash": chunk["blake3_hash"],
            "actual_hash": actual,
            "result": result,
        })

    healthy = all(r["result"] == "ok" for r in results) if results else True
    meter.status(f"Verified {row['name']}: {'OK' if healthy else 'FAILED'}")
    return {
        "file_id": file_id,
        "filename": row["name"],
        "healthy": healthy,
        "chunks_checked": len(results),
        "chunks": results,
    }
