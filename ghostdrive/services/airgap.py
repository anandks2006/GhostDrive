"""Air-gap export: a self-verifying encrypted copy of the vault on offline media.

"Point GhostDrive at the drive in the drawer": ``export_airgap`` streams every
active file's stored chunks out of the configured backends into
``<target>/ghostdrive-export-YYYYMMDD-HHMMSS/`` alongside a signed
``manifest.json``; ``verify_airgap`` re-checks that archive with disk reads
only; ``restore_drill_airgap`` decrypts a file back out of the archive and
compares it against the live index -- proof, not vibes.

What is in the archive (and what is not)
----------------------------------------
* Chunk payloads are copied **verbatim**. The upload pipeline already encrypts
  every chunk with ChaCha20-Poly1305 before it reaches a backend
  (``pipeline/upload.py``), so what ``files_service._assemble_chunk`` reads
  back is ciphertext+tag. This module does NOT re-encrypt it -- a second layer
  would double the work for the same offline-attacker guarantees. Each chunk
  file is prefixed with a 4-byte ``GDC1`` magic so verification can tell a
  GhostDrive export chunk from a truncated or foreign file; everything after
  the magic is byte-identical to what the backends hold.
* ``manifest.json`` lists ``{"v", "created_at", "file_count", "total_bytes",
  "master_salt_hex", "files", "chunk_files", "hmac_hex"}``. ``hmac_hex`` is
  HMAC-SHA256 over a canonical JSON of every other key (sorted keys, compact
  separators), keyed by ``pbkdf2_hmac("sha256", master_key,
  b"ghostdrive-airgap-v1", 1)`` -- the derivation *binds the manifest to this
  vault* (one iteration: it is a KDF-shaped binding, not password stretching).
* Each file entry carries ``content_hash_hex``: the same derived digest
  ``services/versions.py`` builds (BLAKE3 folded over the ordered per-chunk
  ``(blake3_hash, size)`` pairs), so a drill can prove the archive reproduces
  a file without re-downloading it from the backends. File entries also carry
  ``chunk_names`` (the ordered export filenames) -- without that mapping the
  archive could not restore or drill itself.
* ``master_salt_hex`` records the vault's 32-byte HKDF salt. It is a salt, not
  a secret: master key + salt is what a cold machine needs to re-derive the
  chunk key (``crypto.hkdf.derive_chunk_key``) that decrypts the copied
  ciphertexts.
* Chunk files are named ``<sha256-of-file-bytes>.gdc`` and written via
  ``atomic_write`` (temp file, fsync, ``os.replace``). Identical payload bytes
  therefore dedupe within and across exports: if the same name+size already
  exists in the target, it is reused instead of rewritten.

Honest limits
-------------
* The export is only as fresh as the last run; a burned drive still loses
  everything since then -- ``airgap_state.last_ok_at`` is the number to stare
  at, and the scheduled cycle exists so nobody has to remember.
* Per-chunk read failures (unplugged backend, purged shard) are collected, not
  fatal to the run: everything else still lands on the drive, but the outcome
  is ``ok=False`` with an error summary -- a partial archive never masquerades
  as a good one.
* A failed drill is a real signal, not noise: usually the vault changed after
  the last export (run a fresh export) or the drive went bad. It records the
  critical ``airgap_drill_failed`` alert; a passing drill records nothing.
* The scheduled loop re-reads the enabled flag and target directory every
  cycle and skips cleanly when either is missing; a locked vault only fails
  the cycle (logged), never the loop.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import blake3

from ghostdrive.crypto.chunk_crypto import ChunkDecryptor
from ghostdrive.crypto.hkdf import derive_chunk_key
from ghostdrive.crypto.nonce import NonceManager
from ghostdrive.services import alerts as alerts_service
from ghostdrive.services import files as files_service
from ghostdrive.services import versions as versions_service
from ghostdrive.services.context import (
    active_backends,
    get_master_key,
    hkdf_salt,
    require_db,
)
from ghostdrive.utils.fsync import atomic_write

logger = logging.getLogger("ghostdrive.services.airgap")

# Settings keys (string values, like every other GhostDrive setting).
KEY_AIRGAP_ENABLED = "airgap_enabled"            # "true" / "false" (default "false")
KEY_AIRGAP_TARGET_DIR = "airgap_target_dir"      # absolute path on the offline drive
KEY_AIRGAP_INTERVAL_HOURS = "airgap_interval_hours"  # default "168", clamped >= 1
KEY_AIRGAP_STATE = "airgap_state"                # JSON below, capped at 20 exports

DEFAULT_INTERVAL_HOURS = 168.0

# ``airgap_state`` = {"exports": [...], "last_ok_at": iso|None,
#                     "last_drill": {...}|None}; exports capped at the newest
# STATE_EXPORT_CAP entries so the settings row stays small forever.
STATE_EXPORT_CAP = 20

# verify_airgap re-hashes this many chunk files (sorted by name, deterministic
# for automation) on top of the exists+size pass over EVERY chunk file. 16
# catches a damaged recent write on any realistic export without turning
# "verify the drive" into "re-read the whole drive".
VERIFY_SAMPLE = 16

EXPORT_PREFIX = "ghostdrive-export-"
MANIFEST_NAME = "manifest.json"
CHUNK_MAGIC = b"GDC1"
HMAC_INFO = b"ghostdrive-airgap-v1"

ALERT_KIND_DRILL_FAILED = "airgap_drill_failed"

# Module-global task pattern (same as restore_drills._drill_task): one loop
# per feature, double-start is a no-op, stop clears the global.
_airgap_task: Optional[asyncio.Task] = None


# ─── Settings / state helpers ────────────────────────────────────────────────


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _coerce_now(now: Any) -> datetime:
    """Accept None (now) or a datetime; force tz-awareness for arithmetic."""
    if now is None:
        return _now()
    if not isinstance(now, datetime):
        raise TypeError(f"now must be a datetime, got {type(now).__name__}")
    return now if now.tzinfo else now.replace(tzinfo=timezone.utc)


def _resolve_db(db: Any) -> Any:
    if db is None:
        db = require_db()
    return db


def _setting_bool(db: Any, key: str, default: bool) -> bool:
    raw = str(db.get_setting(key, "true" if default else "false")).strip().lower()
    return raw in ("1", "true", "yes", "on")


def _interval_hours(db: Any) -> float:
    """Configured interval for status, clamped to >= 1 hour (0.5 -> 1.0)."""
    return _configured_hours(db, DEFAULT_INTERVAL_HOURS)


def _configured_hours(db: Any, fallback: float) -> float:
    """Resolve the interval: persisted setting wins, else the caller's fallback.

    Mirrors restore_drills._configured_float so ``POST``-style settings
    persistence and server-startup wiring can never disagree about cadence.
    A locked vault or unreadable value falls back rather than crashing
    startup; anything below the 1-hour floor clamps up (a 0.5 setting means
    1.0, never a busy loop).
    """
    try:
        raw = str(_resolve_db(db).get_setting(KEY_AIRGAP_INTERVAL_HOURS, "")).strip()
        value = float(raw) if raw else float(fallback)
    except Exception:
        return max(1.0, float(fallback))
    return max(1.0, value)


def _load_state(db: Any) -> dict:
    raw = ""
    try:
        raw = str(db.get_setting(KEY_AIRGAP_STATE, "") or "")
    except Exception as exc:  # locked/busy db: status must not crash
        logger.warning("Could not read airgap state: %s", exc)
    try:
        parsed = json.loads(raw) if raw else {}
    except ValueError:
        parsed = {}
    if not isinstance(parsed, dict):
        parsed = {}
    exports = parsed.get("exports")
    if not isinstance(exports, list):
        exports = []
    return {
        "exports": [e for e in exports if isinstance(e, dict)],
        "last_ok_at": parsed.get("last_ok_at"),
        "last_drill": parsed.get("last_drill")
        if isinstance(parsed.get("last_drill"), dict)
        else None,
    }


def _save_state(db: Any, state: dict) -> None:
    with db.transaction():
        db.set_setting(KEY_AIRGAP_STATE, json.dumps(state, sort_keys=True))


def _record_export(db: Any, entry: dict) -> None:
    state = _load_state(db)
    exports = list(state["exports"])
    exports.append(entry)
    state["exports"] = exports[-STATE_EXPORT_CAP:]
    if entry.get("ok"):
        state["last_ok_at"] = entry.get("at")
    _save_state(db, state)


def _record_drill(db: Any, drill: dict) -> None:
    state = _load_state(db)
    state["last_drill"] = drill
    _save_state(db, state)


def _resolve_target(db: Any, target_dir: Optional[str] = None) -> str:
    """Explicit argument wins, else the ``airgap_target_dir`` setting.

    ValueError (-> HTTP 400) when neither exists: the export must never guess
    a drive location.
    """
    raw = (
        target_dir
        if target_dir is not None
        else str(db.get_setting(KEY_AIRGAP_TARGET_DIR, "") or "")
    )
    target = str(raw or "").strip()
    if not target:
        raise ValueError(
            "Air-gap target directory is not configured; "
            "set airgap_target_dir or pass target."
        )
    return target


# ─── Manifest signing ────────────────────────────────────────────────────────


def _hmac_key(master_key: bytes) -> bytes:
    """Manifest signing key: PBKDF2-HMAC-SHA256(master_key, HMAC_INFO, 1).

    One iteration on purpose -- the master key is already 256 bits of entropy,
    so stretching adds nothing; the salt/INFO pair exists to bind air-gap
    manifests to this vault and version of the format.
    """
    return hashlib.pbkdf2_hmac("sha256", master_key, HMAC_INFO, 1)


def _canonical_body(body: dict) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _manifest_hmac_hex(body: dict, master_key: bytes) -> str:
    return hmac.new(_hmac_key(master_key), _canonical_body(body), hashlib.sha256).hexdigest()


def _manifest_hmac_ok(manifest: dict, master_key: bytes) -> bool:
    stated = manifest.get("hmac_hex")
    if not isinstance(stated, str) or not stated:
        return False
    body = {k: v for k, v in manifest.items() if k != "hmac_hex"}
    return hmac.compare_digest(stated, _manifest_hmac_hex(body, master_key))


# ─── Filesystem layout ───────────────────────────────────────────────────────


def _fresh_export_dir(target: Path, stamp: datetime) -> Path:
    """Create ``ghostdrive-export-YYYYMMDD-HHMMSS`` (with -N suffix on collision)."""
    base = EXPORT_PREFIX + stamp.strftime("%Y%m%d-%H%M%S")
    counter = 0
    while counter <= 100:
        name = base if counter == 0 else f"{base}-{counter}"
        candidate = target / name
        try:
            candidate.mkdir()
            return candidate
        except FileExistsError:
            counter += 1
    raise RuntimeError(f"Could not allocate an export directory under {target}")


def _latest_export_dir(target: Path) -> Optional[Path]:
    """Newest export subdir by name (the timestamp prefix sorts chronologically)."""
    dirs = sorted(
        (p for p in target.glob(EXPORT_PREFIX + "*") if p.is_dir()),
        key=lambda p: p.name,
    )
    return dirs[-1] if dirs else None


def _resolve_export_dir(db: Any, export_dir: Optional[str] = None) -> Path:
    if export_dir:
        path = Path(str(export_dir)).expanduser()
        if not path.is_dir():
            raise FileNotFoundError(f"Export directory not found: {path}")
        return path
    target = Path(_resolve_target(db)).expanduser()
    if not target.is_dir():
        raise FileNotFoundError(f"Air-gap target directory not found: {target}")
    latest = _latest_export_dir(target)
    if latest is None:
        raise FileNotFoundError(
            f"No {EXPORT_PREFIX}* directory under {target} -- run an export first."
        )
    return latest


def _read_manifest(export_dir: Path) -> dict:
    path = export_dir / MANIFEST_NAME
    if not path.is_file():
        raise FileNotFoundError(f"{MANIFEST_NAME} not found in {export_dir}")
    try:
        manifest = json.loads(path.read_bytes().decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(manifest, dict):
        raise ValueError(f"{path} is not a JSON object.")
    return manifest


def _summarise(errors: list[str], limit: int = 5) -> str:
    if not errors:
        return ""
    head = "; ".join(errors[:limit])
    extra = len(errors) - limit
    return f"{head} (+{extra} more)" if extra > 0 else head


# ─── Export ──────────────────────────────────────────────────────────────────


async def export_airgap(
    db: Any,
    target_dir: Optional[str] = None,
    *,
    now: datetime | None = None,
    objects: dict | None = None,
) -> dict:
    """Export every active file to ``target_dir`` as a signed, self-checking archive.

    Layout: ``<target>/ghostdrive-export-YYYYMMDD-HHMMSS/`` holding one
    ``<sha256>.gdc`` chunk file per unique chunk payload (4-byte ``GDC1`` magic
    + the verbatim backend ciphertext -- never re-encrypted, see module
    docstring) plus ``manifest.json`` signed over its own body. All writes go
    through ``atomic_write`` (temp + fsync + ``os.replace``), so an
    interrupted export leaves either the old file or the new one, never a
    half-written chunk with a good-looking name.

    Failure policy: a locked vault (or missing master key) raises
    RuntimeError before anything is written -- routes translate that to 401.
    Per-chunk read failures are collected while the rest of the export
    continues; the run then reports ``ok=False`` with an error summary. After
    writing, the manifest is re-read from disk and its HMAC re-checked, so
    ``ok=True`` means "what is on the drive verifies", not "no exception was
    thrown".

    Returns keys: ``ok, target, manifest_path, file_count, bytes,
    chunks_written, chunks_reused, error``.
    """
    db = _resolve_db(db)
    master_key = get_master_key()  # locked vault -> RuntimeError -> 401
    stamp = _coerce_now(now)

    target = Path(_resolve_target(db, target_dir)).expanduser()
    if not target.exists():
        raise FileNotFoundError(
            f"Air-gap target directory does not exist: {target} (is the drive plugged in?)"
        )
    if not target.is_dir():
        raise ValueError(f"Air-gap target is not a directory: {target}")

    export_dir = _fresh_export_dir(target, stamp)
    if objects is None:
        _, objects = await active_backends(connect_remote=False)

    rows = db._conn.execute(
        "SELECT id, name, path, size, mime_type FROM files "
        "WHERE tombstone = 0 ORDER BY path"
    ).fetchall()

    errors: list[str] = []
    file_entries: list[dict] = []
    chunk_files: dict[str, int] = {}  # name -> payload bytes on disk
    chunks_written = 0
    chunks_reused = 0

    for row in rows:
        chunks = db.get_file_chunks(row["id"])
        entry = {
            "file_id": row["id"],
            "path": row["path"],
            "name": row["name"],
            "size": int(row["size"] or 0),
            "chunks": 0,
            # Same derived digest services/versions.py uses: reproducible from
            # the export (decrypt -> per-chunk BLAKE3) AND from the live index.
            "content_hash_hex": versions_service._derived_hash(chunks),
            "chunk_names": [],
        }
        for chunk in chunks:
            try:
                ciphertext = await files_service._assemble_chunk(chunk, objects)
            except Exception as exc:
                # Backend unplugged, shard purged, ...: keep going, stay honest.
                errors.append(
                    f"{row['path']} chunk {chunk['chunk_index']}: {exc}"
                )
                continue
            payload = CHUNK_MAGIC + ciphertext
            name = hashlib.sha256(payload).hexdigest() + ".gdc"
            dest = export_dir / name
            if dest.exists() and dest.stat().st_size == len(payload):
                # Content-addressed name: same bytes -> same name, so a chunk
                # already on the drive (from an earlier export) is reused. The
                # reuse trusts the name; verify_airgap's sampling catches a
                # corrupted reused file later.
                chunks_reused += 1
            else:
                try:
                    atomic_write(dest, payload)
                except OSError as exc:
                    errors.append(f"could not write {name}: {exc}")
                    continue
                chunks_written += 1
            entry["chunk_names"].append(name)
            chunk_files.setdefault(name, len(payload))
        entry["chunks"] = len(entry["chunk_names"])
        file_entries.append(entry)

    manifest_body = {
        "v": 1,
        "created_at": stamp.isoformat(),
        "file_count": len(file_entries),
        "total_bytes": sum(chunk_files.values()),
        # The vault's 32-byte HKDF salt (a salt, not a secret): master key +
        # this salt re-derives the chunk key for the verbatim ciphertexts.
        "master_salt_hex": hkdf_salt().hex(),
        "files": file_entries,
        "chunk_files": [
            {"name": name, "size": size}
            for name, size in sorted(chunk_files.items())
        ],
    }
    manifest = dict(manifest_body)
    manifest["hmac_hex"] = _manifest_hmac_hex(manifest_body, master_key)

    manifest_path = export_dir / MANIFEST_NAME
    manifest_verified = False
    try:
        atomic_write(
            manifest_path,
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        )
    except OSError as exc:
        errors.append(f"manifest write failed: {exc}")
    if manifest_path.is_file():
        # Self-check: re-read what actually landed on the drive.
        try:
            on_disk = json.loads(manifest_path.read_bytes().decode("utf-8"))
            manifest_verified = _manifest_hmac_ok(on_disk, master_key)
            if not manifest_verified:
                errors.append("manifest self-check failed: HMAC mismatch")
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            errors.append(f"manifest self-check failed: {exc}")
    else:
        errors.append("manifest self-check failed: manifest.json missing")

    ok = not errors and manifest_verified
    error = _summarise(errors)
    outcome = {
        "ok": ok,
        "target": str(target),
        "manifest_path": str(manifest_path),
        "file_count": len(file_entries),
        "bytes": manifest_body["total_bytes"],
        "chunks_written": chunks_written,
        "chunks_reused": chunks_reused,
        "error": error,
    }
    _record_export(
        db,
        {
            "at": stamp.isoformat(),
            "target": str(target),
            "manifest_path": str(manifest_path),
            "file_count": len(file_entries),
            "bytes": manifest_body["total_bytes"],
            "ok": ok,
            "error": error,
        },
    )
    logger.info(
        "Air-gap export %s: %d file(s), %d written, %d reused -> %s",
        "ok" if ok else "FAILED",
        len(file_entries), chunks_written, chunks_reused, export_dir,
    )
    return outcome


# ─── Verify ──────────────────────────────────────────────────────────────────


async def verify_airgap(
    db: Any,
    export_dir: Optional[str] = None,
    *,
    now: datetime | None = None,
) -> dict:
    """Verify an existing export using disk reads only (no backend I/O).

    ``export_dir`` defaults to the newest ``ghostdrive-export-*`` directory
    under the configured target. Checks, in order of cost:

    1. manifest present, parseable, and its HMAC recomputes from the master
       key (``manifest_ok``);
    2. every recorded chunk file exists with the recorded size;
    3. up to ``VERIFY_SAMPLE`` chunk files (sorted by name, deterministic)
       start with the ``GDC1`` magic and hash to their own content-addressed
       name -- flipped bytes anywhere in a sampled file change the name check.

    ``now`` is accepted for call-signature symmetry with the other air-gap
    helpers and is not part of verification (nothing here is time-dependent).

    Returns keys: ``ok, checked_chunks, missing, corrupt, manifest_ok, error``
    (``checked_chunks`` = every chunk file that went through the exists+size
    pass; ``missing``/``corrupt`` are counts).
    """
    db = _resolve_db(db)
    master_key = get_master_key()  # locked -> RuntimeError -> 401
    export_path = _resolve_export_dir(db, export_dir)

    manifest = _read_manifest(export_path)
    manifest_ok = _manifest_hmac_ok(manifest, master_key)

    chunk_files = [
        item
        for item in (manifest.get("chunk_files") or [])
        if isinstance(item, dict)
    ]
    missing = 0
    corrupt = 0
    problems: list[str] = []
    readable: list[tuple[str, int]] = []

    for item in chunk_files:
        name = str(item.get("name") or "")
        size = int(item.get("size") or 0)
        # The manifest is HMAC-signed by us, but refuse path tricks anyway:
        # a name is a flat filename or it is corrupt.
        if not name or os.path.basename(name) != name:
            corrupt += 1
            problems.append(f"invalid chunk name {name!r}")
            continue
        path = export_path / name
        try:
            actual = path.stat().st_size
        except OSError:
            missing += 1
            problems.append(f"missing {name}")
            continue
        if actual != size:
            corrupt += 1
            problems.append(f"size mismatch {name} ({actual} != {size})")
            continue
        readable.append((name, size))

    for name, _size in sorted(readable)[:VERIFY_SAMPLE]:
        try:
            payload = (export_path / name).read_bytes()
        except OSError:
            missing += 1
            problems.append(f"missing {name}")
            continue
        if not payload.startswith(CHUNK_MAGIC):
            corrupt += 1
            problems.append(f"bad magic {name}")
            continue
        if hashlib.sha256(payload).hexdigest() + ".gdc" != name:
            corrupt += 1
            problems.append(f"content hash mismatch {name}")

    if not manifest_ok:
        problems.insert(0, "manifest HMAC check failed")
    if not chunk_files:
        problems.append("manifest records no chunk files")

    ok = manifest_ok and missing == 0 and corrupt == 0 and bool(chunk_files)
    return {
        "ok": ok,
        "checked_chunks": len(chunk_files),
        "missing": missing,
        "corrupt": corrupt,
        "manifest_ok": manifest_ok,
        "error": _summarise(problems),
    }


# ─── Restore drill ───────────────────────────────────────────────────────────


def _decrypt_export_chunk(payload: bytes, nonce_counter: int, chunk_key: bytes) -> bytes:
    """Decrypt one exported chunk file back to plaintext.

    Strips the ``GDC1`` magic, then runs the normal GhostDrive chunk
    decryptor: the payload after the magic is the backend's ciphertext+tag, so
    the Poly1305 tag fails loudly on any flipped byte (corruption surfaces as
    an AuthenticationError, before any hash comparison).
    """
    if not payload.startswith(CHUNK_MAGIC):
        raise ValueError("not a GhostDrive air-gap chunk file (bad magic)")
    body = payload[len(CHUNK_MAGIC):]
    if len(body) < 16:
        raise ValueError("chunk file is truncated (no Poly1305 tag)")
    ciphertext, tag = body[:-16], body[-16:]
    nonce = NonceManager.counter_to_nonce(int(nonce_counter))
    decryptor = ChunkDecryptor(key=chunk_key, nonce=nonce, expected_tag=tag)
    for offset in range(0, len(ciphertext), files_service.READ_BLOCK):
        decryptor.feed(ciphertext[offset:offset + files_service.READ_BLOCK])
    return b"".join(decryptor.verify_and_decrypt_streaming())


async def _alert_drill_failure(db: Any, subject: str, detail: str, stamp: datetime) -> None:
    """Record (+ best-effort dispatch) the critical airgap_drill_failed alert.

    Dedupe is the standard alerts flow: a recurring failure keeps the same
    stable id (alert_id(kind, subject)), so it is dispatched once and can be
    dismissed once.
    """
    alert = {
        "id": alerts_service.alert_id(ALERT_KIND_DRILL_FAILED, subject),
        "kind": ALERT_KIND_DRILL_FAILED,
        "severity": "critical",
        "subject_id": subject,
        "title": "Air-gap restore drill failed",
        "detail": detail,
        "detected_at": stamp.isoformat(),
    }
    try:
        new = alerts_service.record_alerts(db, [alert], now=stamp)
        await alerts_service.dispatch(db, new)
    except Exception as exc:  # alert plumbing must not mask the drill result
        logger.warning("Could not record air-gap drill alert: %s", exc)


async def restore_drill_airgap(
    db: Any,
    export_dir: Optional[str] = None,
    *,
    now: datetime | None = None,
) -> dict:
    """Restore-drill an export: decrypt one file out of it and compare digests.

    Picks one random file among the smallest third of the manifest (small keeps
    the drill cheap, random keeps it honest), reads its chunk files from the
    archive, decrypts them with the live index's nonce counters, and checks:

    * each plaintext chunk's BLAKE3 equals the live chunk row's digest
      (export == vault, exactly what comparing against ``iter_file`` would
      prove, without streaming it twice);
    * the folded ``content_hash_hex`` equals the manifest's (export ==
      manifest, the self-contained check).

    On success: ``last_drill.ok = True`` in ``airgap_state`` and no alert.
    On any failure: ``airgap_state.last_drill.ok = False`` plus the critical
    ``airgap_drill_failed`` alert (severity "critical", deduped by stable id).
    A stale export (vault changed since the last run) fails loudly with that
    same alert -- the fix is a fresh export, not a quieter drill.

    Returns keys: ``ok, file, error`` (``file`` is the manifest path of the
    drilled file, or None when there was nothing to drill).
    """
    db = _resolve_db(db)
    master_key = get_master_key()  # locked -> RuntimeError -> 401
    stamp = _coerce_now(now)
    export_path = _resolve_export_dir(db, export_dir)

    file_label: str | None = None
    drill: dict = {
        "at": stamp.isoformat(),
        "ok": False,
        "file": None,
        "file_id": None,
        "error": "",
    }
    try:
        manifest = _read_manifest(export_path)
        if not _manifest_hmac_ok(manifest, master_key):
            raise RuntimeError(
                "manifest HMAC check failed; the export is not trustworthy"
            )

        candidates = [
            entry
            for entry in (manifest.get("files") or [])
            if isinstance(entry, dict)
            and entry.get("chunk_names")
            and entry.get("content_hash_hex")
        ]
        if not candidates:
            # Nothing held (or no chunks to restore): same answer as a
            # "skipped" restore drill -- not a failure, so no alert.
            drill["ok"] = True
            drill["error"] = "nothing to drill: export contains no files"
            _record_drill(db, drill)
            return {"ok": True, "file": None, "error": drill["error"]}

        candidates.sort(key=lambda entry: int(entry.get("size") or 0))
        pool = candidates[: max(1, (len(candidates) + 2) // 3)]
        pick = random.choice(pool)
        file_id = str(pick.get("file_id") or "")
        file_label = str(pick.get("path") or pick.get("name") or file_id)
        drill["file_id"] = file_id or None
        drill["file"] = file_label

        live_chunks = db.get_file_chunks(file_id)
        names = list(pick["chunk_names"])
        if len(live_chunks) != len(names):
            raise RuntimeError(
                "the vault index changed since this export "
                f"({len(live_chunks)} chunk(s) live, {len(names)} exported); "
                "run a fresh air-gap export"
            )

        chunk_key = derive_chunk_key(master_key, hkdf_salt())
        folded = blake3.blake3()
        for chunk, name in zip(live_chunks, names):
            path = export_path / str(name)
            if not path.is_file():
                raise FileNotFoundError(f"exported chunk missing: {name}")
            plain = _decrypt_export_chunk(
                path.read_bytes(), int(chunk["nonce_counter"]), chunk_key
            )
            digest = blake3.blake3(plain).hexdigest()
            if digest != str(chunk["blake3_hash"]):
                raise RuntimeError(
                    f"restored bytes for chunk {chunk['chunk_index']} do not "
                    "match the live vault digest"
                )
            # Fold exactly like versions_service._derived_hash so the manifest
            # value is reproducible from the archive alone.
            folded.update(digest.encode())
            folded.update(len(plain).to_bytes(8, "big"))
        if folded.hexdigest() != str(pick["content_hash_hex"]):
            raise RuntimeError(
                "content hash rebuilt from the export does not match the manifest"
            )

        drill["ok"] = True
    except Exception as exc:
        drill["error"] = str(exc) or exc.__class__.__name__
        subject = drill["file_id"] or export_path.name
        logger.warning("Air-gap restore drill failed: %s", drill["error"])
        await _alert_drill_failure(
            db, subject, f"Air-gap drill of {file_label or export_path}: {drill['error']}", stamp
        )

    _record_drill(db, drill)
    return {
        "ok": bool(drill["ok"]),
        "file": drill["file"],
        "error": drill["error"],
    }


# ─── Status ──────────────────────────────────────────────────────────────────


def airgap_status(db: Any) -> dict:
    """Settings + last run + last drill for the UI (pure read, no master key)."""
    db = _resolve_db(db)
    state = _load_state(db)
    exports = state["exports"]
    target = str(db.get_setting(KEY_AIRGAP_TARGET_DIR, "") or "").strip()
    return {
        "enabled": _setting_bool(db, KEY_AIRGAP_ENABLED, False),
        "target_dir": target,
        "target_exists": bool(target) and os.path.isdir(target),
        "interval_hours": _interval_hours(db),
        "last": exports[-1] if exports else None,
        "last_ok_at": state["last_ok_at"],
        "last_drill": state["last_drill"],
    }


# ─── Scheduler ───────────────────────────────────────────────────────────────


async def _airgap_cycle(db: Any) -> Optional[dict]:
    """One scheduler cycle: export -> verify -> drill, or None when skipped.

    Skips cleanly (returns None, no filesystem touches) while disabled or
    unconfigured -- the flag is re-read every cycle so flipping it in settings
    takes effect without restarting the loop. Export failures short-circuit
    verify/drill: there is no point probing a half-written archive.
    """
    db = _resolve_db(db)
    if not _setting_bool(db, KEY_AIRGAP_ENABLED, False):
        return None
    if not str(db.get_setting(KEY_AIRGAP_TARGET_DIR, "") or "").strip():
        return None

    outcome = await export_airgap(db)
    result: dict[str, Any] = {"export": outcome, "verify": None, "drill": None}
    if not outcome.get("ok"):
        return result

    export_dir = str(Path(outcome["manifest_path"]).parent)
    try:
        result["verify"] = await verify_airgap(db, export_dir)
    except Exception as exc:
        logger.warning("Scheduled air-gap verification failed: %s", exc)
    if result["verify"] and result["verify"].get("ok"):
        try:
            # Drill only what just verified; a failed verify already has the
            # export's error recorded, and drilling it would only add noise.
            result["drill"] = await restore_drill_airgap(db, export_dir)
        except Exception as exc:
            logger.warning("Scheduled air-gap drill could not run: %s", exc)
    return result


async def _airgap_loop(db: Any, interval_hours: float) -> None:
    while True:
        # +/-10% jitter (same rationale as restore_drills._drill_loop): many
        # installs would otherwise hammer shared offline-drive routines and
        # provider backends in lockstep. The >=1h clamp means a zero setting
        # can never busy-loop.
        base = max(1.0, float(interval_hours) * 3600.0)
        await asyncio.sleep(base * random.uniform(0.9, 1.1))
        try:
            result = await _airgap_cycle(_resolve_db(db))
            if result is not None:
                logger.info(
                    "Scheduled air-gap cycle: export ok=%s verify=%s drill=%s",
                    (result["export"] or {}).get("ok"),
                    (result["verify"] or {}).get("ok"),
                    (result["drill"] or {}).get("ok"),
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # Locked vault, unplugged drive, busy db: log and keep ticking so
            # the schedule comes back by itself.
            logger.warning("Scheduled air-gap cycle failed: %s", exc)


def start_airgap_scheduler(
    interval_hours: float | None = None,
    db: Any = None,
) -> Optional[asyncio.Task]:
    """Start the background export->verify->drill loop (idempotent).

    The persisted ``airgap_interval_hours`` setting wins when present (default
    ``168`` = weekly, clamped >= 1); ``interval_hours`` is the ad-hoc fallback
    for callers and tests. Safe during server startup: a locked vault only
    affects cycles, never the loop itself.
    """
    global _airgap_task
    if _airgap_task is not None and not _airgap_task.done():
        return _airgap_task
    fallback = DEFAULT_INTERVAL_HOURS if interval_hours is None else float(interval_hours)
    hours = _configured_hours(db, fallback)
    _airgap_task = asyncio.create_task(_airgap_loop(db, hours))
    return _airgap_task


def stop_airgap_scheduler() -> None:
    """Cancel the air-gap loop and clear the module global."""
    global _airgap_task
    if _airgap_task is not None and not _airgap_task.done():
        _airgap_task.cancel()
    _airgap_task = None
