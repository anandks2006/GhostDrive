"""
tests/test_parallel_upload.py -- Concurrency guarantees for the erasure shard
fan-out in ghostdrive/pipeline/upload.py.

The erasure path used to write its n shards strictly sequentially. It now fans
them out with asyncio.gather under a politeness semaphore while ALL database
bookkeeping (confirm/fail, quota, HMAC chain) stays in the main task after
gather. These tests pin down that contract:

  * shard writes overlap (>1 in flight) and never exceed the semaphore bound
  * all-success final DB state: n confirmed locations, quota_used sums,
    erasure_k/n correct, HMAC chain intact, decode still works
  * one flaky backend (transient failure -> retry succeeds): final state is
    identical to the all-success run and decode still works
  * one persistently failing shard: the OLD sequential failure semantics are
    preserved exactly (all locations failed, uploaded shards deleted, quota
    restored, exception re-raised -- the chunk row is kept)
  * the non-erasure path is untouched: sub-blocks still write strictly one at
    a time with correct rows/quota

Helpers/harness are copied from tests/test_pipeline.py (not imported) and
extended with a shared in-flight concurrency tracker.
"""

import asyncio
import math
import os
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from ghostdrive.crypto.nonce import NonceManager
from ghostdrive.database.db import GhostDriveDB
from ghostdrive.exceptions import BackendConnectionError
from ghostdrive.pipeline.chunker import ChunkDescriptor
from ghostdrive.pipeline.healing import verify_chunk_location
from ghostdrive.pipeline.upload import (
    _MAX_PARALLEL_SHARD_WRITES,
    ChunkUploader,
)

# Captured at import time so the tests can patch asyncio.sleep (retry backoff)
# without breaking the yielding behaviour their mocks rely on.
_REAL_SLEEP = asyncio.sleep


async def _fast_sleep(_delay, *args, **kwargs):
    """Drop-in asyncio.sleep() that yields ONCE instead of waiting out the
    retry backoff.

    Keeps retry tests fast while preserving a suspension point: a plain
    AsyncMock would never yield, silently serialising the fan-out and hiding
    concurrency bugs from the assertions."""
    await _REAL_SLEEP(0)


# ── Helpers (copied from tests/test_pipeline.py, then extended) ───────────────

def _make_db(tmp_path: Path) -> GhostDriveDB:
    db = GhostDriveDB(
        path=tmp_path / "test.db",
        ledger_key=bytes(range(32)),
        genesis_seed=bytes(range(32, 64)),
        master_key=bytes(range(32)),
    )
    db.open()
    return db


def _insert_file(db, path_str: str, size: int, tier: str) -> str:
    file_id = str(uuid.uuid4())
    now = "2024-01-01T00:00:00+00:00"
    with db.transaction():
        db.insert_file({
            "id": file_id,
            "name": path_str.rsplit("/", 1)[-1],
            "path": path_str,
            "size": size,
            "mime_type": "application/octet-stream",
            "tier": tier,
            "created_at": now,
            "modified_at": now,
            "version": 1,
            "version_of": None,
            "tombstone": 0,
            "tombstone_at": None,
        })
    return file_id


def _insert_nas_backend(db, host: str, priority: int = 1) -> str:
    """One NAS row per failure domain: distinct ``host`` -> distinct
    ``nas:<host>`` failure domain (see durability.backend_failure_domain)."""
    backend_id = str(uuid.uuid4())
    with db.transaction():
        db._conn.execute(
            """INSERT INTO backends
               (id, type, credentials_ref, status, priority,
                quota_used, quota_limit, quota_reserved)
               VALUES (?, 'nas', ?, 'healthy', ?, 0, ?, 0)""",
            (backend_id, host, priority, 1024 * 1024 * 1024),
        )
    return backend_id


# ── Concurrency-recording backend harness ─────────────────────────────────────

class _ConcurrencyTracker:
    """Counts upload() calls in flight across ALL backend mocks at once."""

    def __init__(self) -> None:
        self.in_flight = 0
        self.max_in_flight = 0

    def enter(self) -> None:
        self.in_flight += 1
        if self.in_flight > self.max_in_flight:
            self.max_in_flight = self.in_flight

    def exit(self) -> None:
        self.in_flight -= 1


class _ShardBackend:
    """Hand-rolled NAS backend mock (deliberately not MagicMock).

    backend_failure_domain() reads ``.host`` to derive the failure domain, and
    upload.py consults ``_connected`` -- a MagicMock would auto-create truthy
    child attributes for anything this class forgot to define, which is how
    eight rows collapse into one domain (see the comment in
    tests/test_adaptive_coding.py). Explicit attributes keep it deterministic.

    ``fail_attempts`` makes the first N upload attempts raise
    BackendConnectionError (a "flaky" backend that the retry loop can absorb).
    """

    def __init__(
        self,
        backend_id: str,
        host: str,
        tracker: _ConcurrencyTracker,
        upload_delay: float = 0.01,
        fail_attempts: int = 0,
    ) -> None:
        self.id = backend_id
        self.type = "nas"
        self.host = host
        self._connected = True
        self._tracker = tracker
        self._upload_delay = upload_delay
        self._fail_attempts = fail_attempts
        self.upload_calls = 0
        self.stored: dict[str, bytes] = {}
        self.deleted: list[str] = []

    async def connect(self) -> None:
        self._connected = True

    async def upload(self, stream, chunk_id: str, sub_block_index: int) -> str:
        self.upload_calls += 1
        self._tracker.enter()
        try:
            # Suspend while "in flight" so sibling shard tasks can overlap.
            # Without an await here the mock would run to completion without
            # ever yielding and the fan-out could never be observed.
            await asyncio.sleep(self._upload_delay)
            if self.upload_calls <= self._fail_attempts:
                raise BackendConnectionError(f"flaky backend {self.host}")
            data = bytearray()
            async for block in stream:
                data.extend(block)
            reference_id = f"ref-{sub_block_index}"
            self.stored[reference_id] = bytes(data)
            return reference_id
        finally:
            self._tracker.exit()

    async def delete(self, reference_id: str) -> bool:
        self.deleted.append(reference_id)
        self.stored.pop(reference_id, None)
        return True

    async def download(self, reference_id: str):
        if reference_id not in self.stored:
            raise Exception("Shard not found")
        yield self.stored[reference_id]


def _setup_erasure(tmp_path, *, n_backends=8, tier="CRITICAL",
                   fail_host=None, fail_attempts=0) -> SimpleNamespace:
    """CRITICAL file spread over ``n_backends`` distinct NAS failure domains.

    With 8 domains + tier CRITICAL the adaptive planner picks (4, 8) -> 8
    shards; each shard lands on its own backend (one shard per domain per
    round), so per-backend upload_calls is exactly the number of attempts for
    that one shard.
    """
    db = _make_db(tmp_path)
    tracker = _ConcurrencyTracker()
    backend_ids: list[str] = []
    mocks: dict[str, _ShardBackend] = {}
    active_backends: dict[str, _ShardBackend] = {}
    for i in range(n_backends):
        host = f"nas-{i}"
        backend_id = _insert_nas_backend(db, host)
        mock = _ShardBackend(
            backend_id, host, tracker,
            fail_attempts=(fail_attempts if host == fail_host else 0),
        )
        backend_ids.append(backend_id)
        mocks[backend_id] = mock
        active_backends[backend_id] = mock

    payload = os.urandom(1024)
    file_path = tmp_path / "source.bin"
    file_path.write_bytes(payload)
    descriptor = ChunkDescriptor(
        chunk_index=0, offset=0, size=len(payload),
        total_chunks=1, is_manifest=False,
    )
    file_id = _insert_file(db, "/source.bin", len(payload), tier)

    uploader = ChunkUploader(
        db=db,
        backend=mocks[backend_ids[0]],
        master_key=bytes(range(32)),
        hkdf_salt=bytes(range(32, 64)),
        nonce_manager=NonceManager(data_dir=tmp_path),
        active_backends=active_backends,
    )
    return SimpleNamespace(
        db=db, tracker=tracker, mocks=mocks, active_backends=active_backends,
        backend_ids=backend_ids, file_path=file_path, descriptor=descriptor,
        file_id=file_id, uploader=uploader, payload=payload,
    )


def _locations(db, chunk_id):
    return db._conn.execute(
        """SELECT sub_block_index, backend_id, reference_id, status, quota_reserved
           FROM chunk_locations WHERE chunk_id = ? ORDER BY sub_block_index""",
        (chunk_id,),
    ).fetchall()


def _key_manager() -> MagicMock:
    km = MagicMock()
    km.master_key = bytes(range(32))
    km.hkdf_salt = bytes(range(32, 64))
    return km


def _assert_fully_confirmed(ctx, chunk_id, n_shards: int, shard_bytes: int):
    """Assertions that must hold for ANY all-success erasure upload run,
    sequential or parallel -- the final state the change had to preserve."""
    locs = _locations(ctx.db, chunk_id)
    assert len(locs) == n_shards
    assert all(loc["status"] == "confirmed" for loc in locs)
    assert all(loc["quota_reserved"] == 0 for loc in locs)
    # One location per shard index, each with the reference its mock returned.
    assert sorted(loc["sub_block_index"] for loc in locs) == list(range(n_shards))
    assert all(loc["reference_id"] == f"ref-{loc['sub_block_index']}" for loc in locs)
    # Exactly one shard per backend row (one shard per failure domain).
    assert {loc["backend_id"] for loc in locs} == set(ctx.backend_ids)

    # quota: every byte reserved up front is now accounted as used, once.
    total_used = 0
    for backend_id in ctx.backend_ids:
        row = ctx.db._conn.execute(
            "SELECT quota_used, quota_reserved FROM backends WHERE id = ?",
            (backend_id,),
        ).fetchone()
        assert row["quota_used"] == shard_bytes
        assert row["quota_reserved"] == 0
        total_used += row["quota_used"]
    assert total_used == n_shards * shard_bytes


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestParallelErasureUpload:
    @pytest.mark.asyncio
    async def test_shard_writes_run_concurrently_within_bound(self, tmp_path):
        ctx = _setup_erasure(tmp_path, n_backends=8)
        chunk_id = await ctx.uploader.upload_chunk(
            path=ctx.file_path, descriptor=ctx.descriptor,
            file_id=ctx.file_id, mime_type="application/octet-stream",
        )

        # The fan-out must actually overlap: with 6-8 shards across distinct
        # failure domains more than one upload is in flight at some point.
        assert ctx.tracker.max_in_flight > 1, "shard writes did not overlap"
        # ... but never above the semaphore politeness bound.
        assert ctx.tracker.max_in_flight <= _MAX_PARALLEL_SHARD_WRITES

        # Every shard written exactly once, all confirmed.
        assert sum(m.upload_calls for m in ctx.mocks.values()) == 8
        shard_bytes = math.ceil((len(ctx.payload) + 16) / 4)
        _assert_fully_confirmed(ctx, chunk_id, 8, shard_bytes)
        ctx.db.close()

    @pytest.mark.asyncio
    async def test_all_success_state_is_identical_to_sequential(self, tmp_path):
        ctx = _setup_erasure(tmp_path, n_backends=8)
        chunk_id = await ctx.uploader.upload_chunk(
            path=ctx.file_path, descriptor=ctx.descriptor,
            file_id=ctx.file_id, mime_type="application/octet-stream",
        )

        # Adaptive coding: CRITICAL over 8 domains -> 4+4.
        chunk_row = ctx.db._conn.execute(
            "SELECT sub_block_count, erasure_k, erasure_n, erasure_padlen FROM chunks WHERE id = ?",
            (chunk_id,),
        ).fetchone()
        assert chunk_row is not None
        assert chunk_row["erasure_k"] == 4
        assert chunk_row["erasure_n"] == 8
        assert chunk_row["erasure_padlen"] == 0
        assert chunk_row["sub_block_count"] == 8  # n + padlen * 10

        shard_bytes = math.ceil((len(ctx.payload) + 16) / 4)
        _assert_fully_confirmed(ctx, chunk_id, 8, shard_bytes)

        # The HMAC ledger must still replay cleanly after concurrent I/O --
        # the confirm writes were done sequentially, in shard-index order.
        assert ctx.db.verify_hmac_chain() is True

        # End-to-end: download + erasure decode still works.
        loc_row = ctx.db._conn.execute(
            "SELECT * FROM chunk_locations WHERE chunk_id = ? LIMIT 1", (chunk_id,)
        ).fetchone()
        res = await verify_chunk_location(ctx.db, loc_row, _key_manager(), ctx.active_backends)
        assert res == "ok"
        ctx.db.close()

    @pytest.mark.asyncio
    async def test_one_flaky_backend_final_state_unchanged(self, tmp_path):
        """One shard fails its first attempt, retry succeeds -> the chunk must
        end in the SAME state as an all-success run, and decode must work."""
        ctx = _setup_erasure(
            tmp_path, n_backends=8, fail_host="nas-3", fail_attempts=1
        )
        with patch("asyncio.sleep", _fast_sleep):
            chunk_id = await ctx.uploader.upload_chunk(
                path=ctx.file_path, descriptor=ctx.descriptor,
                file_id=ctx.file_id, mime_type="application/octet-stream",
            )

        flaky = next(m for m in ctx.mocks.values() if m.host == "nas-3")
        healthy = [m for m in ctx.mocks.values() if m.host != "nas-3"]
        assert flaky.upload_calls == 2   # 1 transient failure + 1 retry success
        assert all(m.upload_calls == 1 for m in healthy)

        # Identical final state to the all-success run: 8 confirmed, quota sums.
        shard_bytes = math.ceil((len(ctx.payload) + 16) / 4)
        _assert_fully_confirmed(ctx, chunk_id, 8, shard_bytes)

        # Download/decode still works with the recovered shard.
        loc_row = ctx.db._conn.execute(
            "SELECT * FROM chunk_locations WHERE chunk_id = ? LIMIT 1", (chunk_id,)
        ).fetchone()
        res = await verify_chunk_location(ctx.db, loc_row, _key_manager(), ctx.active_backends)
        assert res == "ok"
        ctx.db.close()

    @pytest.mark.asyncio
    async def test_one_persistent_shard_failure_keeps_old_failure_semantics(self, tmp_path):
        """A shard that fails all retry attempts must reproduce the sequential
        run's outcome EXACTLY: all locations failed (no partial tolerance in
        the current design), shards that already reached a backend deleted,
        quota fully restored, chunk row kept, exception re-raised."""
        ctx = _setup_erasure(
            tmp_path, n_backends=8, fail_host="nas-2", fail_attempts=4
        )
        with patch("asyncio.sleep", _fast_sleep), pytest.raises(BackendConnectionError):
            await ctx.uploader.upload_chunk(
                path=ctx.file_path, descriptor=ctx.descriptor,
                file_id=ctx.file_id, mime_type="application/octet-stream",
            )

        # Retries really happened on the failing backend (4 attempts total).
        failing = next(m for m in ctx.mocks.values() if m.host == "nas-2")
        assert failing.upload_calls == 4
        healthy = [m for m in ctx.mocks.values() if m.host != "nas-2"]
        assert all(m.upload_calls == 1 for m in healthy)

        # Chunk row survives (two-phase commit record), as it did before.
        assert ctx.db._conn.execute("SELECT COUNT(*) FROM chunks").fetchone()[0] == 1

        # ALL locations failed -- not just the bad shard -- and none hold a
        # reservation, matching the old sequential failure handlers.
        chunk_row_id = ctx.db._conn.execute("SELECT id FROM chunks").fetchone()["id"]
        locs = _locations(ctx.db, chunk_row_id)
        assert len(locs) == 8
        assert all(loc["status"] == "failed" for loc in locs)
        assert all(loc["quota_reserved"] == 0 for loc in locs)

        # Quota fully restored on every backend (used AND reserved back to 0).
        for backend_id in ctx.backend_ids:
            row = ctx.db._conn.execute(
                "SELECT quota_used, quota_reserved FROM backends WHERE id = ?",
                (backend_id,),
            ).fetchone()
            assert row["quota_used"] == 0
            assert row["quota_reserved"] == 0

        # The 7 shards that DID reach a backend were deleted again (best
        # effort), so nothing orphaned remains -- same as sequential.
        assert all(len(m.deleted) == 1 for m in healthy)
        assert failing.deleted == []
        assert sum(len(m.stored) for m in ctx.mocks.values()) == 0
        ctx.db.close()


class TestNonErasurePathUnchanged:
    @pytest.mark.asyncio
    async def test_sub_blocks_stay_sequential_and_correct(self, tmp_path):
        """DISPOSABLE chunks never fan out: their sub-blocks all target one
        backend, so the path must keep writing them one at a time."""
        db = _make_db(tmp_path)
        tracker = _ConcurrencyTracker()
        backend_id = _insert_nas_backend(db, "nas-0")
        mock = _ShardBackend(backend_id, "nas-0", tracker)
        mock.sub_block_bytes = 512  # force several sub-blocks from a small file

        payload = os.urandom(1500)  # incompressible: cipher is 1:1 + 16-byte tag
        file_path = tmp_path / "source.bin"
        file_path.write_bytes(payload)
        descriptor = ChunkDescriptor(
            chunk_index=0, offset=0, size=len(payload),
            total_chunks=1, is_manifest=False,
        )
        file_id = _insert_file(db, "/source.bin", len(payload), "DISPOSABLE")

        uploader = ChunkUploader(
            db=db,
            backend=mock,
            master_key=bytes(range(32)),
            hkdf_salt=bytes(range(32, 64)),
            nonce_manager=NonceManager(data_dir=tmp_path / "nm"),
            active_backends={backend_id: mock, "nas": mock},
        )
        chunk_id = await uploader.upload_chunk(
            path=file_path, descriptor=descriptor,
            file_id=file_id, mime_type="application/octet-stream",
        )

        expected_sub_blocks = math.ceil((len(payload) + 16) / mock.sub_block_bytes)
        assert expected_sub_blocks > 1  # the test would be vacuous otherwise

        # Exactly sequential: never more than one sub-block write in flight.
        assert tracker.max_in_flight == 1
        assert mock.upload_calls == expected_sub_blocks

        # Not erasure-coded (defaults are 0 for legacy/plain chunks).
        chunk_row = db._conn.execute(
            "SELECT sub_block_count, erasure_k, erasure_n FROM chunks WHERE id = ?",
            (chunk_id,),
        ).fetchone()
        assert chunk_row["sub_block_count"] == expected_sub_blocks
        assert chunk_row["erasure_k"] == 0
        assert chunk_row["erasure_n"] == 0

        locs = _locations(db, chunk_id)
        assert len(locs) == expected_sub_blocks
        assert all(loc["status"] == "confirmed" for loc in locs)
        assert sorted(loc["sub_block_index"] for loc in locs) == list(range(expected_sub_blocks))
        assert all(loc["reference_id"] == f"ref-{loc['sub_block_index']}" for loc in locs)

        # Quota: reserved = actual encrypted size (1500 + 16), now all used.
        row = db._conn.execute(
            "SELECT quota_used, quota_reserved FROM backends WHERE id = ?",
            (backend_id,),
        ).fetchone()
        assert row["quota_used"] == len(payload) + 16
        assert row["quota_reserved"] == 0

        # Download + verify path still works for the plain (non-erasure) layout.
        loc_row = db._conn.execute(
            "SELECT * FROM chunk_locations WHERE chunk_id = ? LIMIT 1", (chunk_id,)
        ).fetchone()
        res = await verify_chunk_location(db, loc_row, _key_manager(), {backend_id: mock, "nas": mock})
        assert res == "ok"
        db.close()
