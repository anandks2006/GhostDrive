"""
tests/test_chaos.py -- Deterministic chaos / fault-injection suite for the
GhostDrive durability machinery (two-phase commit, healing, scrub, repair).

Philosophy
----------
1. **Deterministic fault points, never wall-clock races.** Faults are injected
   at exact call counts ("raise on shard 3", "fail the first heal attempt
   only") or gated on ``asyncio.Event`` objects. No test sleeps hoping things
   settle; every wait is event-driven with a failure timeout as a safety net.
2. **No real sockets.** Every backend is the in-process ``_FakeBackend``
   double below: it captures uploaded shards, serves them back on download,
   and raises whatever its fault hook tells it to raise.
3. **Assertions follow the documented semantics** of
   ``ghostdrive/pipeline/upload.py`` (pending intent -> stream -> confirm |
   fail+restore), ``ghostdrive/pipeline/healing.py`` (trickle heal,
   fail+restore), ``ghostdrive/services/resilience.py`` (scrub/repair) and
   ``ghostdrive/database/db.py`` (transaction + startup scan contract).
4. **xfail-never-silently-pass.** When a scenario exposes a genuine bug in
   production code this suite does not own, the test is written as
   ``@pytest.mark.xfail(strict=True, reason="<file:line root cause>")``.
   The test may not be weakened into a green test, and -- because it is
   strict -- it may not accidentally pass either. Every xfail in this file is
   listed in the suite report with its production root cause.
5. Helpers at module top are **copied** (not imported) from
   ``tests/test_pipeline.py`` and ``tests/test_durability.py`` so this file
   can evolve independently of them.

Run:
    py -m pytest tests/test_chaos.py -q --no-header -p no:cacheprovider
"""

import asyncio
import errno
import math
import threading
import time
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from zfec.easyfec import Encoder

from ghostdrive.crypto.nonce import NonceManager
from ghostdrive.database.db import GhostDriveDB
from ghostdrive.exceptions import BackendConnectionError, BackendNotFoundError, ChunkError
from ghostdrive.pipeline.chunker import ChunkDescriptor
from ghostdrive.pipeline.healing import HealthDaemon, HealingQueue, verify_chunk_location
from ghostdrive.pipeline.quota import QuotaManager
from ghostdrive.pipeline.upload import ChunkUploader
from ghostdrive.services.hostility import detect_withholding
from ghostdrive.web.state import state

# ── Constants ────────────────────────────────────────────────────────────────

MASTER_KEY = bytes(range(32))
HKDF_SALT = bytes(range(32, 64))
LEDGER_KEY = bytes(range(32))
GENESIS_SEED = bytes(range(32, 64))

# Erasure sizing for a 1024-byte chunk under the hard 4+2 floor:
#   shard bytes = ceil((size + 16-byte Poly1305 tag) / k=4)
SHARD_BYTES_1024 = math.ceil((1024 + 16) / 4)          # == 260
ERASURE_RESERVED_1024 = 6 * SHARD_BYTES_1024           # all 6 shards reserved up-front


# ── Helpers (copied from tests/test_pipeline.py / tests/test_durability.py) ──

def _make_db(tmp_path: Path, name: str = "chaos.db") -> GhostDriveDB:
    db = GhostDriveDB(
        path=tmp_path / name,
        ledger_key=bytes(range(32)),
        genesis_seed=bytes(range(32, 64)),
        master_key=bytes(range(32)),
    )
    db.open()
    return db


def _reopen_db(tmp_path: Path, name: str = "chaos.db") -> GhostDriveDB:
    """A *fresh* GhostDriveDB instance on an existing file (process restart)."""
    db = GhostDriveDB(
        path=tmp_path / name,
        ledger_key=bytes(range(32)),
        genesis_seed=bytes(range(32, 64)),
        master_key=bytes(range(32)),
    )
    db.open()
    return db


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _backend(db, backend_type="telegram", priority=1, quota_limit=1024 ** 3) -> str:
    bid = str(uuid.uuid4())
    db._conn.execute("BEGIN")
    db._conn.execute(
        """INSERT INTO backends
           (id, type, credentials_ref, status, priority, quota_used, quota_limit, quota_reserved)
           VALUES (?, ?, 'ref:test', 'healthy', ?, 0, ?, 0)""",
        (bid, backend_type, priority, quota_limit),
    )
    db._conn.execute("COMMIT")
    return bid


def _seed_file(db, tier="IMPORTANT", size=1024, name="payload.bin") -> str:
    file_id = str(uuid.uuid4())
    now = _now()
    with db.transaction():
        db.insert_file({
            "id": file_id, "name": name, "path": f"/{name}",
            "size": size, "mime_type": "application/octet-stream", "tier": tier,
            "created_at": now, "modified_at": now,
            "version": 1, "version_of": None,
            "tombstone": 0, "tombstone_at": None,
        })
    return file_id


def _seed_chunk(
    db,
    file_id,
    *,
    chunk_index: int = 0,
    size: int = 128,
    sub_block_count: int = 6,
    nonce_counter: int = 1,
    erasure: tuple | None = None,
) -> str:
    chunk_id = str(uuid.uuid4())
    cols = (
        "id, file_id, chunk_index, total_chunks, blake3_hash, size, "
        "nonce_counter, sub_block_count, is_manifest, ref_count"
    )
    vals = [chunk_id, file_id, chunk_index, 1, "0" * 64, size, nonce_counter, sub_block_count, 0, 1]
    if erasure is not None:
        k, n, padlen = erasure
        cols += ", erasure_k, erasure_n, erasure_padlen"
        vals += [k, n, padlen]
    marks = ", ".join("?" for _ in vals)
    with db.transaction():
        db._conn.execute(f"INSERT INTO chunks ({cols}) VALUES ({marks})", vals)
    return chunk_id


def _seed_location(db, chunk_id, sub_block_index, backend_id, status="confirmed",
                   reference_id=None, quota_reserved=0) -> None:
    with db.transaction():
        db._conn.execute(
            """INSERT INTO chunk_locations
               (chunk_id, sub_block_index, backend_id, reference_id, url_type,
                upload_date, status, quota_reserved)
               VALUES (?, ?, ?, ?, 'permanent', ?, ?, ?)""",
            (chunk_id, sub_block_index, backend_id,
             reference_id if reference_id is not None else f"ref-{sub_block_index}",
             _now(), status, quota_reserved),
        )


def _write_source(tmp_path: Path, size: int, name: str = "payload.bin") -> Path:
    p = tmp_path / name
    p.write_bytes(b"G" * size)
    return p


def _descriptor(size: int, index: int = 0, total: int = 1) -> ChunkDescriptor:
    return ChunkDescriptor(
        chunk_index=index, offset=0, size=size, total_chunks=total, is_manifest=False,
    )


def _quota(db, bid) -> tuple[int, int]:
    row = db._conn.execute(
        "SELECT quota_used, quota_reserved FROM backends WHERE id = ?", (bid,)
    ).fetchone()
    return int(row["quota_used"]), int(row["quota_reserved"])


def _status_counts(db, chunk_id: str | None = None) -> dict:
    sql = "SELECT status, COUNT(*) AS c FROM chunk_locations"
    params: tuple = ()
    if chunk_id is not None:
        sql += " WHERE chunk_id = ?"
        params = (chunk_id,)
    sql += " GROUP BY status"
    return {r["status"]: r["c"] for r in db._conn.execute(sql, params).fetchall()}


def _pending_count(db, chunk_id: str | None = None) -> int:
    if chunk_id is None:
        row = db._conn.execute(
            "SELECT COUNT(*) AS c FROM chunk_locations WHERE status = 'pending'"
        ).fetchone()
    else:
        row = db._conn.execute(
            "SELECT COUNT(*) AS c FROM chunk_locations WHERE status = 'pending' AND chunk_id = ?",
            (chunk_id,),
        ).fetchone()
    return int(row["c"])


def _chunk_row(db, chunk_id: str):
    return db._conn.execute("SELECT * FROM chunks WHERE id = ?", (chunk_id,)).fetchone()


def _loc_row(db, chunk_id: str, sub_block_index: int):
    return db._conn.execute(
        """SELECT cl.*, b.type AS backend_type FROM chunk_locations cl
           JOIN backends b ON cl.backend_id = b.id
           WHERE cl.chunk_id = ? AND cl.sub_block_index = ?
           ORDER BY cl.backend_id ASC""",
        (chunk_id, sub_block_index),
    ).fetchone()


def _km() -> SimpleNamespace:
    """Key material stub shaped like KeystoreManager for verify/heal paths."""
    return SimpleNamespace(master_key=MASTER_KEY, hkdf_salt=HKDF_SALT, is_unlocked=True)


def _make_uploader(db, backend, active_backends, nonce_dir: Path):
    nm = NonceManager(data_dir=nonce_dir)
    uploader = ChunkUploader(
        db=db,
        backend=backend,
        master_key=MASTER_KEY,
        hkdf_salt=HKDF_SALT,
        nonce_manager=nm,
        active_backends=active_backends,
    )
    return uploader, nm


class _FakeBackend:
    """In-process backend double: captures uploaded shards, serves them back.

    Deterministic fault hooks:
      * ``upload_fault(sub_block_index, attempt_number)`` returns an Exception
        to raise (or None to proceed).
      * ``download_hook(reference_id)`` returns the payload to serve, or raises
        (e.g. a 404 for a withholding backend).
    Tests with mid-stream faults replace ``upload`` outright.
    """

    def __init__(self, backend_id: str, backend_type: str, *, sub_block_bytes: int | None = None):
        self.id = backend_id
        self.type = backend_type
        self._connected = True
        self.is_cold_storage = False
        self.shards: dict[str, bytes] = {}
        self.upload_calls: list[int] = []
        self.uploaded_refs: list[tuple[int, str]] = []
        self.download_calls: list[str] = []
        self.delete_calls: list[str] = []
        self.upload_fault = None
        self.download_hook = None
        if sub_block_bytes is not None:
            self.sub_block_bytes = sub_block_bytes

    async def connect(self):
        self._connected = True

    async def upload(self, stream, chunk_id, sub_block_index):
        self.upload_calls.append(sub_block_index)
        if self.upload_fault is not None:
            exc = self.upload_fault(sub_block_index, self.upload_calls.count(sub_block_index))
            if exc is not None:
                raise exc
        data = bytearray()
        async for block in stream:
            data.extend(block)
        ref = f"ref-{self.type}-{sub_block_index}-{len(self.upload_calls)}"
        self.shards[ref] = bytes(data)
        self.uploaded_refs.append((sub_block_index, ref))
        return ref

    async def download(self, reference_id):
        self.download_calls.append(reference_id)
        if self.download_hook is not None:
            payload = self.download_hook(reference_id)  # may raise (404)
            yield payload
            return
        if reference_id in self.shards:
            yield self.shards[reference_id]
            return
        raise BackendNotFoundError(f"{reference_id} not found")

    async def delete(self, reference_id):
        self.delete_calls.append(reference_id)
        self.shards.pop(reference_id, None)
        return True


class _FakeDecryptor:
    """Stands in for ChaCha20-Poly1305 in heal-path tests whose seeded mirror
    bytes are not real ciphertext. Verification integrity is exercised
    separately with the real decryptor in TestCorruptedShard."""

    def __init__(self, *args, **kwargs):
        pass

    def feed(self, data):
        pass

    def verify_and_decrypt_streaming(self):
        return iter([b"plain"])


async def _upload_erasure_chunk(tmp_path, db, backends, tier="IMPORTANT", size=1024):
    """Upload one erasure-coded chunk through the REAL pipeline.

    Returns ``(chunk_id, file_id, uploader, nonce_manager)``. ``backends[0]``
    is the primary backend passed to ChunkUploader.
    """
    file_id = _seed_file(db, tier=tier, size=size, name=f"payload-{uuid.uuid4().hex[:6]}.bin")
    active = {}
    for b in backends:
        active[b.id] = b
        active[b.type] = b
    uploader, nm = _make_uploader(db, backends[0], active, tmp_path / "nonces")
    source = _write_source(tmp_path, size, name=f"src-{uuid.uuid4().hex[:6]}.bin")
    chunk_id = await uploader.upload_chunk(
        path=source,
        descriptor=_descriptor(size),
        file_id=file_id,
        mime_type="application/octet-stream",
    )
    return chunk_id, file_id, uploader, nm


# ═════════════════════════════════════════════════════════════════════════════
# Scenario 1 -- backend death mid-upload (one shard of six dies)
# ═════════════════════════════════════════════════════════════════════════════

class TestBackendDeathMidUpload:
    """Backend dies on shard 3 of 6 during an erasure (4+2) upload.

    Intended semantics (upload.py §9.6 / §5.6): the shard is retried with
    backoff, then the whole chunk fails -- already-uploaded shards are deleted
    remotely, EVERY location is marked failed, quota_reserved is fully
    restored, and the nonce counter stays advanced exactly once (never reused).
    The fan-out gathers ALL shard I/O before re-raising the lowest-index
    failure (upload.py:476-496), so sibling shards run to completion first.
    """

    @pytest.mark.asyncio
    async def test_backend_death_on_shard_three_fails_cleanly(self, tmp_path):
        db = _make_db(tmp_path)
        bid = _backend(db, "telegram")
        file_id = _seed_file(db, tier="IMPORTANT", size=1024)
        backend = _FakeBackend(bid, "telegram")

        # Fault: sub-block 3 dies on every attempt (pipeline retries 3x).
        def die_on_shard_three(sub_block_index, attempt):
            if sub_block_index == 3:
                return BackendConnectionError("backend died mid-upload (shard 3 of 6)")
            return None

        backend.upload_fault = die_on_shard_three

        # Observe quota at the exact moment the first shard hits the wire.
        mid_quota: dict = {}
        inner_upload = backend.upload

        async def watching_upload(stream, chunk_id, sub_block_index):
            if sub_block_index == 0 and "q" not in mid_quota:
                mid_quota["q"] = _quota(db, bid)
            return await inner_upload(stream, chunk_id, sub_block_index)

        backend.upload = watching_upload

        uploader, nm = _make_uploader(
            db, backend, {bid: backend, "telegram": backend}, tmp_path / "nonces"
        )
        source = _write_source(tmp_path, 1024)

        with patch("asyncio.sleep", new_callable=AsyncMock) as fake_sleep:
            with pytest.raises(BackendConnectionError):
                await uploader.upload_chunk(
                    path=source, descriptor=_descriptor(1024),
                    file_id=file_id, mime_type="application/octet-stream",
                )
            # Bounded retries: delay after attempts 0,1,2 -- never on the final raise.
            assert fake_sleep.call_count == 3

        chunk_rows = db._conn.execute(
            "SELECT id, nonce_counter FROM chunks WHERE file_id = ?", (file_id,)
        ).fetchall()
        assert len(chunk_rows) == 1
        chunk_id = chunk_rows[0]["id"]

        # Mid-flight: all six shards reserved, nothing counted as used yet.
        assert mid_quota["q"] == (0, ERASURE_RESERVED_1024)

        # Nine upload attempts: shards 0,1,2,4,5 once each (the fan-out
        # gathers every sibling shard before the chunk can fail), shard 3
        # four times (3 bounded retries + the final raising attempt).
        assert backend.upload_calls == [0, 1, 2, 3, 3, 3, 3, 4, 5]

        # Every shard that reached the wire was deleted remotely on failure.
        assert sorted(idx for idx, _ in backend.uploaded_refs) == [0, 1, 2, 4, 5]
        assert backend.delete_calls == [ref for _, ref in backend.uploaded_refs]

        # Quota never leaks in either direction.
        assert _quota(db, bid) == (0, 0)

        # Row bookkeeping: 6 failed intents, zero pending, zero confirmed.
        assert _status_counts(db, chunk_id) == {"failed": 6}
        assert _pending_count(db, chunk_id) == 0
        row = db._conn.execute(
            "SELECT SUM(quota_reserved) AS s FROM chunk_locations WHERE chunk_id = ?",
            (chunk_id,),
        ).fetchone()
        assert int(row["s"] or 0) == 0  # per-row reservations cleared too

        # Nonce advanced EXACTLY once -- persisted counter and chunk row agree.
        assert nm.peek_counter() == 1
        assert int(chunk_rows[0]["nonce_counter"]) == 1

        db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Scenario 2 -- every backend dies during one chunk
# ═════════════════════════════════════════════════════════════════════════════

class TestAllBackendsDead:
    """Death on ALL candidate backends during a chunk: the upload must raise
    cleanly with zero orphaned chunk_locations rows, every backend's
    quota_reserved fully restored, and no chunk location confirmed."""

    @pytest.mark.asyncio
    async def test_total_backend_death_leaves_no_orphans(self, tmp_path):
        db = _make_db(tmp_path)
        b_ids = [
            _backend(db, "telegram", priority=100),
            _backend(db, "discord", priority=90),
            _backend(db, "s3", priority=80),
        ]
        types = ("telegram", "discord", "s3")
        backends = {bid: _FakeBackend(bid, typ) for bid, typ in zip(b_ids, types)}
        for b in backends.values():
            b.upload_fault = lambda idx, attempt: BackendConnectionError("total backend death")

        active = {}
        for bid, b in backends.items():
            active[bid] = b
            active[b.type] = b

        primary = backends[b_ids[0]]
        mid_quota: dict = {}
        inner_upload = primary.upload

        async def watching_upload(stream, chunk_id, sub_block_index):
            if "q" not in mid_quota:
                mid_quota["q"] = {b: _quota(db, bid) for b, bid in zip(types, b_ids)}
            return await inner_upload(stream, chunk_id, sub_block_index)

        primary.upload = watching_upload

        file_id = _seed_file(db, tier="CRITICAL", size=1024)
        uploader, nm = _make_uploader(db, primary, active, tmp_path / "nonces")
        source = _write_source(tmp_path, 1024)

        with patch("asyncio.sleep", new_callable=AsyncMock):
            with pytest.raises(BackendConnectionError):
                await uploader.upload_chunk(
                    path=source, descriptor=_descriptor(1024),
                    file_id=file_id, mime_type="application/octet-stream",
                )

        chunk_id = db._conn.execute(
            "SELECT id FROM chunks WHERE file_id = ?", (file_id,)
        ).fetchone()["id"]

        # 6 shards round-robin over 3 failure domains -> exactly 2 reserved per
        # backend, observed at the first wire attempt (all reservations landed
        # in one transaction before any I/O).
        assert mid_quota["q"] == {
            "telegram": (0, 2 * SHARD_BYTES_1024),
            "discord": (0, 2 * SHARD_BYTES_1024),
            "s3": (0, 2 * SHARD_BYTES_1024),
        }

        # Everything restored on every backend; nothing confirmed anywhere.
        for bid in b_ids:
            assert _quota(db, bid) == (0, 0), f"quota leaked on {bid[:8]}"
        assert _status_counts(db, chunk_id) == {"failed": 6}
        assert _pending_count(db, chunk_id) == 0

        # Every shard died after its 4 bounded attempts: the fan-out gathers
        # ALL shard I/O before re-raising the lowest-index failure
        # (upload.py:476-496), so each backend saw both of its round-robin
        # shards retried (tg: 0+3, discord: 1+4, s3: 2+5). Nothing was ever
        # confirmed, so no remote deletes anywhere.
        assert primary.upload_calls == [0, 0, 0, 0, 3, 3, 3, 3]
        assert backends[b_ids[1]].upload_calls == [1, 1, 1, 1, 4, 4, 4, 4]
        assert backends[b_ids[2]].upload_calls == [2, 2, 2, 2, 5, 5, 5, 5]
        for b in backends.values():
            assert b.delete_calls == []

        # Nonce advanced exactly once despite the total failure.
        assert nm.peek_counter() == 1
        assert int(_chunk_row(db, chunk_id)["nonce_counter"]) == 1

        db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Scenario 3 -- cancellation at various await points (spec §5.7)
# ═════════════════════════════════════════════════════════════════════════════

class TestCancelledMidUpload:
    """asyncio.CancelledError at four different await points.

    No quota, intent, or nonce leak at ANY of them:
      a) during the BLAKE3 await (BEFORE the reserve transaction) -- nothing
         must exist afterwards;
      b) right after the nonce/intent transaction (first await of the stream
         read) -- cleanup must restore everything;
      c) during backend connect() before the first shard;
      d) mid-upload after shard 0 already reached the backend -- §5.7 requires
         remote delete of the confirmed sub-block.
    """

    async def _run(self, tmp_path, monkeypatch, backend, bid=None, patch_target=None, patch_value=None):
        db = _make_db(tmp_path)
        bid = bid or _backend(db, "telegram")
        backend.id = bid
        file_id = _seed_file(db, tier="IMPORTANT", size=1024)
        if patch_target is not None:
            monkeypatch.setattr(patch_target, patch_value)
        uploader, nm = _make_uploader(
            db, backend, {bid: backend, "telegram": backend}, tmp_path / "nonces"
        )
        source = _write_source(tmp_path, 1024)
        with pytest.raises(asyncio.CancelledError):
            await uploader.upload_chunk(
                path=source, descriptor=_descriptor(1024),
                file_id=file_id, mime_type="application/octet-stream",
            )
        return db, nm, file_id

    @pytest.mark.asyncio
    async def test_cancelled_during_blake3_before_reserve_leaves_nothing(self, tmp_path, monkeypatch):
        """Cancellation lands BEFORE quota/intent/nonce exist -> nothing to clean."""
        backend = _FakeBackend("unused", "telegram")

        def cancelled_blake3(*args, **kwargs):
            raise asyncio.CancelledError()

        db, nm, file_id = await self._run(
            tmp_path, monkeypatch, backend,
            patch_target="ghostdrive.pipeline.upload._compute_blake3_chunk",
            patch_value=cancelled_blake3,
        )

        assert db._conn.execute("SELECT COUNT(*) AS c FROM chunks").fetchone()["c"] == 0
        assert db._conn.execute("SELECT COUNT(*) AS c FROM chunk_locations").fetchone()["c"] == 0
        assert _quota(db, backend.id) == (0, 0)
        assert nm.peek_counter() == 0  # counter file never written
        db.close()

    @pytest.mark.asyncio
    async def test_cancelled_right_after_nonce_txn_restores_everything(self, tmp_path, monkeypatch):
        """Cancellation at the first await AFTER the reserve+intent+nonce txn
        (the erasure path reads the whole stream before any upload)."""
        backend = _FakeBackend("unused", "telegram")

        async def dying_stream(*args, **kwargs):
            yield b"\x00" * 65536
            raise asyncio.CancelledError()

        db, nm, file_id = await self._run(
            tmp_path, monkeypatch, backend,
            patch_target="ghostdrive.pipeline.upload._encrypted_chunk_stream",
            patch_value=dying_stream,
        )
        chunk_id = db._conn.execute(
            "SELECT id FROM chunks WHERE file_id = ?", (file_id,)
        ).fetchone()["id"]

        assert _status_counts(db, chunk_id) == {"cancelled": 6}
        assert _pending_count(db, chunk_id) == 0
        assert _quota(db, backend.id) == (0, 0)
        assert backend.upload_calls == []   # died before any I/O
        assert backend.delete_calls == []
        assert nm.peek_counter() == 1       # nonce advanced once, never reused
        assert int(_chunk_row(db, chunk_id)["nonce_counter"]) == 1
        db.close()

    @pytest.mark.asyncio
    async def test_cancelled_during_connect_restores_everything(self, tmp_path):
        backend = _FakeBackend("unused", "telegram")
        backend._connected = False
        backend.connect = AsyncMock(side_effect=asyncio.CancelledError())

        db, nm, file_id = await self._run(tmp_path, None, backend)
        chunk_id = db._conn.execute(
            "SELECT id FROM chunks WHERE file_id = ?", (file_id,)
        ).fetchone()["id"]

        assert _status_counts(db, chunk_id) == {"cancelled": 6}
        assert _pending_count(db, chunk_id) == 0
        assert _quota(db, backend.id) == (0, 0)
        assert backend.upload_calls == []
        assert nm.peek_counter() == 1
        db.close()

    @pytest.mark.asyncio
    async def test_cancelled_mid_upload_deletes_confirmed_shards(self, tmp_path):
        """Shard 1 raises CancelledError while the fan-out is in flight: §5.7
        requires backend.delete() for EVERY sub-block that reached the wire
        and 'cancelled' rows for all six."""
        backend = _FakeBackend("unused", "telegram")

        def cancel_on_second(sub_block_index, attempt):
            if sub_block_index == 1:
                return asyncio.CancelledError()
            return None

        backend.upload_fault = cancel_on_second

        db, nm, file_id = await self._run(tmp_path, None, backend)
        chunk_id = db._conn.execute(
            "SELECT id FROM chunks WHERE file_id = ?", (file_id,)
        ).fetchone()["id"]

        # The fan-out gathers all shard I/O before the CancelledError
        # propagates (upload.py:476-496), so every shard hit the wire; the
        # five that completed were then deleted remotely (spec §5.7), and
        # shard 1 stored no reference because it raised before consuming
        # the stream.
        assert backend.upload_calls == [0, 1, 2, 3, 4, 5]
        assert sorted(idx for idx, _ in backend.uploaded_refs) == [0, 2, 3, 4, 5]
        assert backend.delete_calls == [ref for _, ref in backend.uploaded_refs]
        assert backend.shards == {}  # remote copies cleaned up

        assert _status_counts(db, chunk_id) == {"cancelled": 6}
        assert _pending_count(db, chunk_id) == 0
        assert _quota(db, backend.id) == (0, 0)
        assert nm.peek_counter() == 1
        db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Scenario 4 -- network drop during heal
# ═════════════════════════════════════════════════════════════════════════════

def _seed_healable_chunk(db, *, tier="CRITICAL", size=100, with_failed_target=False):
    """One chunk with a confirmed mirror on Telegram; Discord (optionally with a
    pre-existing FAILED row) is the only other healthy backend."""
    tg = _backend(db, "telegram", priority=100)
    dc = _backend(db, "discord", priority=90)
    file_id = _seed_file(db, tier=tier, size=size)
    chunk_id = _seed_chunk(db, file_id, size=size, sub_block_count=1)
    _seed_location(db, chunk_id, 0, tg, status="confirmed", reference_id="ref-tg-0")
    if with_failed_target:
        _seed_location(db, chunk_id, 0, dc, status="failed", reference_id="", quota_reserved=0)
    return tg, dc, file_id, chunk_id


def _make_queue(db, active_backends):
    main_view = MagicMock()
    main_view.active_uploads = 0
    return HealingQueue(
        db=db, active_backends=active_backends, km=_km(), main_view=main_view
    )


class TestHealingNetworkDrop:
    """HealingQueue under a flaky target: fail-once-then-succeed reaches
    eventual consistency; an always-failing target gets exactly one bounded
    attempt per trickle step (no spin, no quota leak, chunk never killed)."""

    @pytest.mark.asyncio
    async def test_network_drop_heals_on_second_attempt(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path)
        tg, dc, file_id, chunk_id = _seed_healable_chunk(db)
        tg_b = _FakeBackend(tg, "telegram")
        dc_b = _FakeBackend(dc, "discord")
        # The confirmed source shard healing downloads ("ref-tg-0").
        tg_b.shards["ref-tg-0"] = b"\x00" * 32

        # Drop exactly the FIRST heal attempt; succeed afterwards.
        attempts = {"n": 0}

        def drop_first(idx, attempt):
            attempts["n"] += 1
            if attempts["n"] == 1:
                return BackendConnectionError("network drop during heal")
            return None

        dc_b.upload_fault = drop_first
        mid_quota: list = []
        inner_upload = dc_b.upload

        async def watching_upload(stream, chunk_id, sub_block_index):
            mid_quota.append(_quota(db, dc))
            return await inner_upload(stream, chunk_id, sub_block_index)

        dc_b.upload = watching_upload

        monkeypatch.setattr("ghostdrive.pipeline.healing.ChunkDecryptor", _FakeDecryptor)
        queue = _make_queue(db, {tg: tg_b, dc: dc_b, "telegram": tg_b, "discord": dc_b})

        # --- attempt 1: network drop -> fail + restore, nothing dangling -----
        await queue.perform_healing_step()
        loc = db._conn.execute(
            "SELECT * FROM chunk_locations WHERE chunk_id = ? AND backend_id = ?",
            (chunk_id, dc),
        ).fetchone()
        assert loc["status"] == "failed"
        assert int(loc["quota_reserved"]) == 0
        assert _quota(db, dc) == (0, 0)          # reserve rolled back exactly
        assert _quota(db, tg) == (0, 0)          # source untouched
        assert _pending_count(db) == 0           # no dangling intent
        assert queue._active_healing_backends == set()  # guard released

        # --- attempt 2: heals -> eventual consistency ------------------------
        await queue.perform_healing_step()
        loc = db._conn.execute(
            "SELECT * FROM chunk_locations WHERE chunk_id = ? AND backend_id = ?",
            (chunk_id, dc),
        ).fetchone()
        assert loc["status"] == "confirmed"
        assert loc["reference_id"].startswith("ref-discord-0-")
        assert _quota(db, dc) == (100, 0)        # reserved moved to used once
        assert mid_quota == [(0, 100), (0, 100)]  # reserved during each attempt

        # One attempt per step (2 total), one row per (chunk, target).
        assert dc_b.upload_calls == [0, 0]
        rows = db._conn.execute(
            "SELECT COUNT(*) AS c FROM chunk_locations WHERE chunk_id = ? AND backend_id = ?",
            (chunk_id, dc),
        ).fetchone()
        assert rows["c"] == 1
        # Source mirror still confirmed throughout.
        assert _status_counts(db, chunk_id) == {"confirmed": 2}
        db.close()

    @pytest.mark.asyncio
    async def test_always_failing_heal_target_is_bounded_and_never_leaks(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path)
        tg, dc, file_id, chunk_id = _seed_healable_chunk(db)
        tg_b = _FakeBackend(tg, "telegram")
        dc_b = _FakeBackend(dc, "discord")
        # The confirmed source shard healing downloads ("ref-tg-0").
        tg_b.shards["ref-tg-0"] = b"\x00" * 32
        dc_b.upload_fault = lambda idx, attempt: BackendConnectionError("target is permanently down")

        monkeypatch.setattr("ghostdrive.pipeline.healing.ChunkDecryptor", _FakeDecryptor)
        queue = _make_queue(db, {tg: tg_b, dc: dc_b, "telegram": tg_b, "discord": dc_b})

        # Bounded: 3 trickle iterations, each makes EXACTLY ONE upload attempt
        # (the heal path has no internal retry loop -- it cannot spin).
        for step in range(3):
            await queue.perform_healing_step()
            assert dc_b.upload_calls == [0] * (step + 1)
            assert _quota(db, dc) == (0, 0)             # no leak after any round
            assert _pending_count(db) == 0              # no dangling intents
            assert queue._active_healing_backends == set()

        loc = db._conn.execute(
            "SELECT * FROM chunk_locations WHERE chunk_id = ? AND backend_id = ?",
            (chunk_id, dc),
        ).fetchone()
        assert loc["status"] == "failed"
        # The chunk is NEVER marked dead: the source mirror stays confirmed.
        assert _status_counts(db, chunk_id) == {"confirmed": 1, "failed": 1}
        db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Scenario 5 -- corrupted shard
# ═════════════════════════════════════════════════════════════════════════════

class TestCorruptedShard:
    """Flipped bytes in one shard of a real 4+2 erasure chunk."""

    @pytest.mark.asyncio
    async def test_flipped_data_shard_detected_and_flagged_by_scrub(self, tmp_path):
        db = _make_db(tmp_path)
        bid = _backend(db, "telegram")
        b = _FakeBackend(bid, "telegram")
        chunk_id, file_id, uploader, nm = await _upload_erasure_chunk(
            tmp_path, db, [b], tier="CRITICAL", size=1024
        )
        assert _status_counts(db, chunk_id) == {"confirmed": 6}

        # Flip one byte in shard 0 -- a DATA shard the 4-of-6 decoder consumes.
        loc0 = _loc_row(db, chunk_id, 0)
        ref0 = loc0["reference_id"]
        corrupted = bytearray(b.shards[ref0])
        corrupted[10] ^= 0xFF
        b.shards[ref0] = bytes(corrupted)

        # Verify/decode path detects it: the Poly1305 tag no longer matches.
        res = await verify_chunk_location(db, dict(loc0), _km(), {bid: b, "telegram": b})
        assert res == "auth_failed"

        # Scrub records the failure against THIS location and flags it...
        daemon = HealthDaemon(
            db=db, active_backends={bid: b, "telegram": b}, km=_km(),
            notifications=MagicMock(), main_view=MagicMock(),
        )
        await daemon._record_verification_result(dict(loc0), res)

        logs = db._conn.execute(
            "SELECT * FROM integrity_log WHERE chunk_id = ?", (chunk_id,)
        ).fetchall()
        assert len(logs) == 1
        assert logs[0]["result"] == "auth_failed"
        assert logs[0]["backend_id"] == bid

        # ...but the chunk is NOT permanently dead: the other five mirrors are
        # untouched and still cover the 4-of-6 recovery threshold.
        counts = _status_counts(db, chunk_id)
        assert counts == {"confirmed": 5, "failed": 1}
        assert db._conn.execute(
            "SELECT tombstone FROM files WHERE id = ?", (file_id,)
        ).fetchone()["tombstone"] == 0
        db.close()

    @pytest.mark.asyncio
    async def test_corrupted_parity_shard_is_detected(self, tmp_path):
        db = _make_db(tmp_path)
        bid = _backend(db, "telegram")
        b = _FakeBackend(bid, "telegram")
        chunk_id, file_id, uploader, nm = await _upload_erasure_chunk(
            tmp_path, db, [b], tier="CRITICAL", size=1024
        )

        loc4 = _loc_row(db, chunk_id, 4)
        corrupted = bytearray(b.shards[loc4["reference_id"]])
        corrupted[10] ^= 0xFF
        b.shards[loc4["reference_id"]] = bytes(corrupted)

        res = await verify_chunk_location(db, dict(loc4), _km(), {bid: b, "telegram": b})
        assert res != "ok", (
            "a byte-flipped parity shard must not verify as 'ok'"
        )
        db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Scenario 6 -- withholding backend under scrub
# ═════════════════════════════════════════════════════════════════════════════

class TestWithholdingBackendUnderScrub:
    """One backend 404s everything while its peers serve normally."""

    async def _setup(self, tmp_path):
        db = _make_db(tmp_path)
        ids = [
            _backend(db, "telegram", priority=100),
            _backend(db, "discord", priority=90),
            _backend(db, "s3", priority=80),
        ]
        fb = {
            ids[0]: _FakeBackend(ids[0], "telegram"),
            ids[1]: _FakeBackend(ids[1], "discord"),
            ids[2]: _FakeBackend(ids[2], "s3"),
        }
        chunk_id, file_id, uploader, nm = await _upload_erasure_chunk(
            tmp_path, db, [fb[ids[0]], fb[ids[1]], fb[ids[2]]],
            tier="IMPORTANT", size=1024,
        )
        # The discord backend turns hostile: denies every read with a 404.
        def deny(_reference_id):
            raise Exception("404 Not Found: message not found")

        fb[ids[1]].download_hook = deny
        active = {}
        for bid, obj in fb.items():
            active[bid] = obj
            active[obj.type] = obj
        return db, ids, fb, active, chunk_id

    @pytest.mark.asyncio
    async def test_scrub_never_marks_the_chunk_permanently_dead(self, tmp_path):
        """A location is exonerated only by its OWN backend's bytes, so the
        withholding backend's two denied locations fail and are flagged for
        healing -- but the chunk is never marked permanently dead: the four
        locations its peers serve verify, and 4+2 reconstruction still needs
        only those four shards."""
        db, ids, fb, active, chunk_id = await self._setup(tmp_path)
        km = _km()
        daemon = HealthDaemon(
            db=db, active_backends=active, km=km,
            notifications=MagicMock(), main_view=MagicMock(),
        )

        results = {}
        for sub in range(6):
            loc = dict(_loc_row(db, chunk_id, sub))
            res = await verify_chunk_location(db, loc, km, active)
            results[sub] = res
            await daemon._record_verification_result(loc, res)

        # The withholding backend can no longer hide behind its peers: the
        # discord-held shards (round-robin indexes 1 and 4) must be fetched
        # from discord itself to verify those locations, so they are
        # attributed to it as not_found. The four locations whose backends
        # serve their shards verify 'ok'.
        assert results == {
            0: "ok", 1: "not_found", 2: "ok", 3: "ok", 4: "not_found", 5: "ok",
        }

        # Chunk is alive -- only the two denied locations are flagged failed
        # (heal targets), nothing tombstoned, and the four surviving shards
        # still cover the 4-of-6 recovery threshold.
        assert _status_counts(db, chunk_id) == {"confirmed": 4, "failed": 2}
        db.close()

    @pytest.mark.asyncio
    async def test_detect_withholding_flags_backend_from_integrity_log(self, tmp_path):
        """hostility.detect_withholding correlates integrity_log rows: a backend
        that fails chunks its peers served is flagged 'withholding'."""
        db = _make_db(tmp_path)
        b_tg = _backend(db, "telegram", priority=100)
        b_dc = _backend(db, "discord", priority=90)
        b_s3 = _backend(db, "s3", priority=80)
        file_id = _seed_file(db, tier="CRITICAL", size=100)
        # Six distinct chunks: discord denies all of them, peers serve all.
        for i in range(6):
            cid = _seed_chunk(db, file_id, chunk_index=i, size=100, sub_block_count=6)
            db.insert_integrity_log(str(uuid.uuid4()), cid, b_dc, "not_found")
            db.insert_integrity_log(str(uuid.uuid4()), cid, b_tg, "ok")
            db.insert_integrity_log(str(uuid.uuid4()), cid, b_s3, "ok")

        report = detect_withholding(db)

        verdicts = {r["backend_id"]: r["verdict"] for r in report["backends"]}
        assert verdicts[b_dc] == "withholding"
        assert verdicts[b_tg] == "ok"
        assert verdicts[b_s3] == "ok"
        assert report["flagged"] == [{"backend_id": b_dc, "verdict": "withholding"}]
        db.close()

    @pytest.mark.asyncio
    async def test_denied_shard_is_attributed_to_the_denying_backend(self, tmp_path):
        db, ids, fb, active, chunk_id = await self._setup(tmp_path)
        # Location of the withholding (discord) backend.
        loc = next(
            dict(_loc_row(db, chunk_id, sub))
            for sub in range(6)
            if _loc_row(db, chunk_id, sub)["backend_id"] == ids[1]
        )
        res = await verify_chunk_location(db, loc, _km(), active)
        assert res == "not_found", (
            "the backend that denied its own shards must not verify as 'ok'"
        )
        db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Scenario 7 -- SQLite contention
# ═════════════════════════════════════════════════════════════════════════════

class TestSQLiteContention:
    """Concurrent quota transactions: interleaved asyncio tasks on two
    connections, two writer threads through the production connection model
    (one shared connection serialised by GhostDriveDB's RLock), and a directed
    two-connection write-lock exclusion (BEGIN IMMEDIATE) -- totals must be
    exact and no exception may escape."""

    @pytest.mark.asyncio
    async def test_interleaved_quota_tasks_on_two_connections_stay_consistent(self, tmp_path):
        db1 = _make_db(tmp_path, "shared.db")
        db2 = _reopen_db(tmp_path, "shared.db")
        try:
            bid = _backend(db1, "telegram", quota_limit=10 ** 9)
            q1, q2 = QuotaManager(db1), QuotaManager(db2)

            async def reserve_loop(qm, db, count, size):
                for _ in range(count):
                    with db.transaction():
                        qm.reserve(bid, size)
                    await asyncio.sleep(0)  # yield -> interleave with the other task

            # Phase 1: both tasks reserve concurrently (20x7 + 20x5 = 240).
            await asyncio.gather(
                reserve_loop(q1, db1, 20, 7),
                reserve_loop(q2, db2, 20, 5),
            )
            assert _quota(db1, bid) == (0, 240)
            assert _quota(db2, bid) == (0, 240)  # both connections agree

            async def confirm_loop(qm, db, count, size):
                for _ in range(count):
                    with db.transaction():
                        qm.confirm(bid, size)
                    await asyncio.sleep(0)

            async def restore_loop(qm, db, count, size):
                for _ in range(count):
                    with db.transaction():
                        qm.restore(bid, size)
                    await asyncio.sleep(0)

            # Phase 2: confirm one stream while restoring the other.
            await asyncio.gather(
                confirm_loop(q1, db1, 20, 7),
                restore_loop(q2, db2, 20, 5),
            )
            assert _quota(db1, bid) == (140, 0)
            assert _quota(db2, bid) == (140, 0)
        finally:
            db1.close()
            db2.close()

    def test_concurrent_writer_threads_never_corrupt_quota_totals(self, tmp_path):
        """Two writer threads through ONE shared connection -- the production
        model: check_same_thread=False plus GhostDriveDB's per-instance
        RLock, which _Transaction holds across BEGIN..COMMIT. Totals must be
        exact (400 confirmed, 400 restored) with zero exceptions, no matter
        how the GIL interleaves the two loops."""
        db = _make_db(tmp_path, "threaded.db")
        bid = _backend(db, "telegram", quota_limit=10 ** 9)

        errors: list = []
        barrier = threading.Barrier(2, timeout=10)

        def worker(final_op):
            qm = QuotaManager(db)
            try:
                barrier.wait()
                for _ in range(40):
                    with db.transaction():
                        qm.reserve(bid, 10)
                for _ in range(40):
                    with db.transaction():
                        final_op(qm)
            except Exception:  # noqa: BLE001 - collected for assertion
                errors.append(traceback.format_exc())

        t1 = threading.Thread(target=worker, args=(lambda qm: qm.confirm(bid, 10),))
        t2 = threading.Thread(target=worker, args=(lambda qm: qm.restore(bid, 10),))
        t1.start()
        t2.start()
        t1.join(timeout=30)
        t2.join(timeout=30)

        assert not t1.is_alive() and not t2.is_alive(), "writer threads deadlocked"
        assert errors == [], f"transactions raised under contention: {errors}"

        try:
            # Each thread deposited 400; thread 1's 400 confirmed (reserved ->
            # used), thread 2's 400 restored. Interleaving cannot change that:
            # every withdrawal is preceded by its own deposits, so the
            # MAX(0, ...) clamp never fires.
            assert _quota(db, bid) == (400, 0)
        finally:
            db.close()

    def test_stale_snapshot_write_survives_competing_commit(self, tmp_path):
        """Same two-connection race as the original xfail, under the FIXED
        contract: db1's transaction now takes the write lock up front
        (BEGIN IMMEDIATE, ghostdrive/database/db.py _Transaction.__enter__),
        so db2's competing commit can no longer land between reserve_quota's
        SELECT and its UPDATE -- instead it must WAIT (busy_timeout + the
        BEGIN-retry loop) for db1 to commit. Both writes must still be
        visible at the end."""
        db1 = _make_db(tmp_path, "snap.db")
        db2 = _reopen_db(tmp_path, "snap.db")
        try:
            bid = _backend(db1, "telegram", quota_limit=10 ** 9)

            competing: dict = {}

            def _competing_commit():
                # Runs in another thread: with BEGIN IMMEDIATE on db1 this
                # blocks on the writer lock instead of committing into
                # db1's read snapshot.
                try:
                    with db2.transaction():
                        db2._conn.execute(
                            "UPDATE backends SET quota_used = quota_used + 7 WHERE id = ?",
                            (bid,),
                        )
                    competing["done"] = True
                except Exception as exc:  # noqa: BLE001 - collected for assertion
                    competing["error"] = exc

            with db1.transaction():
                # Mirrors reserve_quota's first statement.
                db1._conn.execute(
                    "SELECT quota_used FROM backends WHERE id = ?", (bid,)
                ).fetchone()
                # The competing connection tries to commit a newer version
                # WHILE db1's transaction is open. It must block on the write
                # lock -- 0.25s is far below the 5000ms busy_timeout, so it
                # cannot time out here, and nothing else in this thread needs
                # to progress for db1 to commit.
                t = threading.Thread(target=_competing_commit)
                t.start()
                time.sleep(0.25)
                assert competing.get("done") is None, (
                    "BEGIN IMMEDIATE did not exclude the competing writer"
                )
                # The real production code path writes under the same
                # transaction: with the old deferred BEGIN this raised
                # OperationalError('database is locked') (SQLITE_BUSY_SNAPSHOT
                # at the SELECT->UPDATE upgrade); with BEGIN IMMEDIATE the
                # snapshot cannot go stale.
                QuotaManager(db1).reserve(bid, 10)

            # db1 committed: the parked writer must now acquire the lock and
            # commit (bounded by its own BEGIN retry loop + busy_timeout).
            t.join(timeout=30)
            assert not t.is_alive(), "competing writer deadlocked"
            assert competing.get("error") is None, competing.get("error")
            assert competing.get("done") is True

            # Desired semantics: both committed writes are visible.
            assert _quota(db1, bid) == (7, 10)
        finally:
            db1.close()
            db2.close()


# ═════════════════════════════════════════════════════════════════════════════
# Scenario 8 -- disk-full (ENOSPC) mid-stream
# ═════════════════════════════════════════════════════════════════════════════

class TestDiskFullMidStream:
    """OSError(ENOSPC) from the backend mid-stream: same guarantees as a
    network death -- ChunkError out, everything restored."""

    @pytest.mark.asyncio
    async def test_enospc_mid_stream_restores_quota_exactly(self, tmp_path):
        db = _make_db(tmp_path)
        bid = _backend(db, "telegram")
        file_id = _seed_file(db, tier="DISPOSABLE", size=4096)
        # 4096+16 encrypted bytes split into 512-byte sub-blocks -> 9 intents.
        backend = _FakeBackend(bid, "telegram", sub_block_bytes=512)

        async def dying_upload(stream, chunk_id, sub_block_index):
            backend.upload_calls.append(sub_block_index)
            if sub_block_index == 2:
                # Consume part of the payload, THEN the disk fills up.
                await stream.__anext__()
                raise OSError(errno.ENOSPC, "No space left on device")
            data = bytearray()
            async for block in stream:
                data.extend(block)
            ref = f"ref-telegram-{sub_block_index}-{len(backend.upload_calls)}"
            backend.shards[ref] = bytes(data)
            backend.uploaded_refs.append((sub_block_index, ref))
            return ref

        mid_quota: dict = {}
        inner = dying_upload

        async def watching_upload(stream, chunk_id, sub_block_index):
            if sub_block_index == 0 and "q" not in mid_quota:
                mid_quota["q"] = _quota(db, bid)
            return await inner(stream, chunk_id, sub_block_index)

        backend.upload = watching_upload

        uploader, nm = _make_uploader(db, backend, {bid: backend}, tmp_path / "nonces")
        source = _write_source(tmp_path, 4096)

        with pytest.raises(ChunkError) as exc_info:
            await uploader.upload_chunk(
                path=source, descriptor=_descriptor(4096),
                file_id=file_id, mime_type="application/octet-stream",
            )
        # The original OSError is preserved as the cause (no swallowing).
        assert isinstance(exc_info.value.__cause__, OSError)
        assert exc_info.value.__cause__.errno == errno.ENOSPC

        chunk_id = db._conn.execute(
            "SELECT id FROM chunks WHERE file_id = ?", (file_id,)
        ).fetchone()["id"]

        # Mid-flight: all 9 sub-block reservations were held (4096 + 16 tag).
        assert mid_quota["q"] == (0, 4096 + 16)

        # Sub-blocks 0 and 1 reached the wire -> deleted remotely on failure.
        assert [idx for idx, _ in backend.uploaded_refs] == [0, 1]
        assert backend.delete_calls == [ref for _, ref in backend.uploaded_refs]

        # Exact restore: nothing used, nothing reserved, nothing pending.
        assert _quota(db, bid) == (0, 0)
        assert _status_counts(db, chunk_id) == {"failed": 9}
        assert _pending_count(db, chunk_id) == 0

        # Nonce advanced exactly once despite the disk failure.
        assert nm.peek_counter() == 1
        assert int(_chunk_row(db, chunk_id)["nonce_counter"]) == 1
        db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Scenario 9 -- two-phase commit crash recovery
# ═════════════════════════════════════════════════════════════════════════════

class TestCrashRecovery:
    """Process dies after the pending intent + quota reservation commit but
    before confirm: what does a fresh process see?"""

    def _crash_with_pending_intent(self, tmp_path):
        db = _make_db(tmp_path, "crash.db")
        bid = _backend(db, "telegram")
        file_id = _seed_file(db, tier="IMPORTANT", size=1024)
        chunk_id = _seed_chunk(db, file_id, size=1024, sub_block_count=6)
        qm = QuotaManager(db)
        with db.transaction():
            qm.reserve(bid, 100)
            db.insert_chunk_location_pending({
                "chunk_id": chunk_id, "sub_block_index": 0, "backend_id": bid,
                "reference_id": "", "url_type": "permanent",
                "upload_date": _now(), "last_verified": None,
                "quota_reserved": 100,
            })
        db.close()  # <-- process death: intent committed, never confirmed
        return bid, chunk_id

    def test_pending_intent_is_settled_on_reopen(self, tmp_path):
        """After restart the spec §5.6 startup scan settles the intent: the
        row survives as 'cancelled' (audit trail) and its reservation is
        released -- nothing dangles and no quota leaks across the crash."""
        bid, chunk_id = self._crash_with_pending_intent(tmp_path)
        db = _reopen_db(tmp_path, "crash.db")
        try:
            pending = db.pending_chunk_locations()
            assert pending == [], "startup left a pending intent dangling"
            row = db._conn.execute(
                "SELECT status, quota_reserved FROM chunk_locations WHERE chunk_id = ?",
                (chunk_id,),
            ).fetchone()
            assert row["status"] == "cancelled"
            assert int(row["quota_reserved"]) == 0
            assert _quota(db, bid) == (0, 0)
        finally:
            db.close()

    def test_startup_resolver_settles_dangling_intent(self, tmp_path):
        bid, chunk_id = self._crash_with_pending_intent(tmp_path)
        db = _reopen_db(tmp_path, "crash.db")
        try:
            # Intended semantics: on boot the pending intent is resolved
            # (confirmed if the remote object exists, otherwise failed) and the
            # reservation released.
            remaining = db.pending_chunk_locations()
            assert remaining == [], (
                f"startup left {len(remaining)} pending intent(s) dangling"
            )
            assert _quota(db, bid) == (0, 0), "reserved quota never released"
        finally:
            db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Scenario 10 -- repair during concurrent scrub (healing INSERT idempotency)
# ═════════════════════════════════════════════════════════════════════════════

class TestRepairDuringConcurrentScrub:
    """Two repairs of the same missing shard racing each other: the
    chunk_locations insert must be idempotent (upsert under the PK), never
    producing duplicate shard rows."""

    def _seed_erasure_layout(self, db):
        """4+2 chunk with shards 0-4 confirmed across three domains; shard 5
        missing. A fourth idle backend exists as a repair target."""
        b_ids = [
            _backend(db, "telegram", priority=100),
            _backend(db, "discord", priority=90),
            _backend(db, "s3", priority=80),
            _backend(db, "nas", priority=50),
        ]
        fakes = {
            b_ids[0]: _FakeBackend(b_ids[0], "telegram"),
            b_ids[1]: _FakeBackend(b_ids[1], "discord"),
            b_ids[2]: _FakeBackend(b_ids[2], "s3"),
            b_ids[3]: _FakeBackend(b_ids[3], "nas"),
        }
        file_id = _seed_file(db, tier="CRITICAL", size=4096)
        chunk_id = _seed_chunk(
            db, file_id, size=4096, sub_block_count=6, erasure=(4, 6, 0)
        )
        # Real Reed-Solomon shards of a real payload.
        shards = Encoder(4, 6).encode(b"C" * 4096)
        layout = [(0, b_ids[0]), (1, b_ids[0]), (2, b_ids[1]),
                  (3, b_ids[1]), (4, b_ids[2])]
        for sub, bid in layout:
            ref = f"ref-seed-{sub}"
            fakes[bid].shards[ref] = shards[sub]
            _seed_location(db, chunk_id, sub, bid, status="confirmed", reference_id=ref)
        return b_ids, fakes, file_id, chunk_id

    def _patch_state(self, monkeypatch, db):
        monkeypatch.setattr(state, "db", db)
        monkeypatch.setattr(state, "km", _km())

    @pytest.mark.asyncio
    async def test_concurrent_repairs_do_not_duplicate_shard_rows(self, tmp_path, monkeypatch):
        from ghostdrive.services.resilience import repair_chunk

        db = _make_db(tmp_path)
        b_ids, fakes, file_id, chunk_id = self._seed_erasure_layout(db)
        self._patch_state(monkeypatch, db)

        # The target backend's upload is gated: repair #1 parks MID-upload.
        target = fakes[b_ids[3]]
        uploaded: list = []
        first_in_flight = asyncio.Event()
        release_first = asyncio.Event()

        async def gated_upload(stream, chunk_id, sub_block_index):
            uploaded.append(sub_block_index)
            if len(uploaded) == 1:
                first_in_flight.set()
                await release_first.wait()
            return f"ref-repair-{sub_block_index}-{len(uploaded)}"

        target.upload = gated_upload
        objects = dict(fakes)

        repair_one = asyncio.create_task(repair_chunk(chunk_id, objects))
        await asyncio.wait_for(first_in_flight.wait(), timeout=5)

        # Repair #2 runs fully while #1 is parked inside the target's upload.
        repair_two = await asyncio.wait_for(repair_chunk(chunk_id, objects), timeout=5)

        release_first.set()
        repair_one_result = await asyncio.wait_for(repair_one, timeout=5)

        assert repair_one_result["repaired"] == 1
        assert repair_two["repaired"] == 1

        # Exactly ONE row for the repaired shard -- the pending INSERT is
        # idempotent under the race (upsert on (chunk, sub_index, backend)).
        rows = db._conn.execute(
            "SELECT * FROM chunk_locations WHERE chunk_id = ? AND sub_block_index = 5",
            (chunk_id,),
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["backend_id"] == b_ids[3]
        assert rows[0]["status"] == "confirmed"
        assert int(rows[0]["quota_reserved"]) == 0

        # No duplicate confirmed copies of ANY shard index, no pending leftovers.
        dupes = db._conn.execute(
            """SELECT sub_block_index, COUNT(*) AS c FROM chunk_locations
               WHERE chunk_id = ? AND status = 'confirmed'
               GROUP BY sub_block_index HAVING COUNT(*) > 1""",
            (chunk_id,),
        ).fetchall()
        assert dupes == []
        assert _status_counts(db, chunk_id) == {"confirmed": 6}
        assert _pending_count(db, chunk_id) == 0
        db.close()

    @pytest.mark.asyncio
    async def test_healing_upsert_overwrites_preexisting_failed_row(self, tmp_path, monkeypatch):
        """The healing INSERT was converted to an upsert so a backend with a
        FAILED row can be healed back to. Verify the upsert holds: exactly one
        row survives, no PRIMARY KEY violation."""
        monkeypatch.setattr("ghostdrive.pipeline.healing.ChunkDecryptor", _FakeDecryptor)
        db = _make_db(tmp_path)
        tg, dc, file_id, chunk_id = _seed_healable_chunk(db, with_failed_target=True)
        tg_b = _FakeBackend(tg, "telegram")
        dc_b = _FakeBackend(dc, "discord")
        # The confirmed source shard healing downloads ("ref-tg-0").
        tg_b.shards["ref-tg-0"] = b"\x00" * 32
        mid_quota: list = []
        inner = dc_b.upload

        async def watching_upload(stream, chunk_id, sub_block_index):
            mid_quota.append(_quota(db, dc))
            return await inner(stream, chunk_id, sub_block_index)

        dc_b.upload = watching_upload

        queue = _make_queue(db, {tg: tg_b, dc: dc_b, "telegram": tg_b, "discord": dc_b})
        await queue.perform_healing_step()

        rows = db._conn.execute(
            "SELECT * FROM chunk_locations WHERE chunk_id = ? AND backend_id = ?",
            (chunk_id, dc),
        ).fetchall()
        assert len(rows) == 1                     # upsert, not a second row
        assert rows[0]["status"] == "confirmed"
        assert rows[0]["reference_id"].startswith("ref-discord-0-")
        assert mid_quota == [(0, 100)]             # reserved while in flight
        assert _quota(db, dc) == (100, 0)          # confirmed exactly once
        assert _status_counts(db, chunk_id) == {"confirmed": 2}
        db.close()
