"""
test_retention_window.py -- Repair-window scheduling, repair bandwidth capping,
stale chunk-location retention (prune + duplicate rebalance), and the
HealingQueue window/exclusion gating those services feed.
"""

import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from ghostdrive.database.db import GhostDriveDB
from ghostdrive.pipeline.healing import HealingQueue
from ghostdrive.services import maintenance_window
from ghostdrive.services import retention
from ghostdrive.utils.bandwidth_throttle import UPLOAD_LIMITER


# ── DB helpers copied (not imported) from tests/test_durability.py ──────────
# Extended with optional parameters this suite needs: fixed backend ids for
# deterministic tiebreaks, explicit upload dates for cutoff math, and erasure
# parameters for shard-size estimates.


def _make_db(tmp_path: Path) -> GhostDriveDB:
    db = GhostDriveDB(
        path=tmp_path / "retention.db",
        ledger_key=bytes(range(32)),
        genesis_seed=bytes(range(32, 64)),
        master_key=bytes(range(32)),
    )
    db.open()
    return db


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _backend(
    db,
    backend_type: str = "local",
    credentials_ref: str = "ref:test",
    backend_id: str | None = None,
    **overrides,
) -> str:
    backend_id = backend_id or str(uuid.uuid4())
    values = {
        "id": backend_id,
        "type": backend_type,
        "credentials_ref": credentials_ref,
        "status": "healthy",
        "priority": 100,
        "quota_used": 0,
        "quota_limit": 1024 ** 3,
        "quota_reserved": 0,
    }
    values.update(overrides)
    columns = ", ".join(values)
    marks = ", ".join("?" for _ in values)
    db._conn.execute("BEGIN")
    db._conn.execute(
        f"INSERT INTO backends ({columns}) VALUES ({marks})", tuple(values.values())
    )
    db._conn.execute("COMMIT")
    return backend_id


def _file(db, tier: str = "CRITICAL") -> str:
    file_id = str(uuid.uuid4())
    now = _now()
    db._conn.execute("BEGIN")
    db._conn.execute(
        """INSERT INTO files (id, name, path, size, mime_type, tier, created_at, modified_at)
           VALUES (?, 'test.bin', '/tmp/test.bin', 128, 'application/octet-stream', ?, ?, ?)""",
        (file_id, tier, now, now),
    )
    db._conn.execute("COMMIT")
    return file_id


def _chunk(db, file_id: str, sub_block_count: int = 1, **overrides) -> str:
    chunk_id = str(uuid.uuid4())
    values = {
        "id": chunk_id,
        "file_id": file_id,
        "chunk_index": 0,
        "total_chunks": 1,
        "blake3_hash": "0" * 64,
        "size": 128,
        "nonce_counter": 1,
        "sub_block_count": sub_block_count,
    }
    values.update(overrides)
    columns = ", ".join(values)
    marks = ", ".join("?" for _ in values)
    db._conn.execute("BEGIN")
    db._conn.execute(
        f"INSERT INTO chunks ({columns}) VALUES ({marks})", tuple(values.values())
    )
    db._conn.execute("COMMIT")
    return chunk_id


def _location(
    db,
    chunk_id: str,
    backend_id: str,
    sub_block_index: int,
    status: str = "confirmed",
    upload_date: str | None = None,
    quota_reserved: int = 0,
) -> None:
    db._conn.execute("BEGIN")
    db._conn.execute(
        """INSERT INTO chunk_locations
           (chunk_id, sub_block_index, backend_id, reference_id, upload_date,
            status, quota_reserved)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (chunk_id, sub_block_index, backend_id, f"ref-{sub_block_index}",
         upload_date or _now(), status, quota_reserved),
    )
    db._conn.execute("COMMIT")


def _set_window(db, enabled: bool, start: str, end: str, bandwidth_kbps: int = 0) -> None:
    with db.transaction():
        db.set_setting(maintenance_window.KEY_ENABLED, "true" if enabled else "false")
        db.set_setting(maintenance_window.KEY_START, start)
        db.set_setting(maintenance_window.KEY_END, end)
        db.set_setting(maintenance_window.KEY_BANDWIDTH, str(bandwidth_kbps))


# ── parse_hhmm ───────────────────────────────────────────────────────────────

class TestParseHHMM:
    def test_valid_times(self):
        assert maintenance_window.parse_hhmm("02:00") == (2, 0)
        assert maintenance_window.parse_hhmm("23:59") == (23, 59)
        assert maintenance_window.parse_hhmm("00:00") == (0, 0)
        assert maintenance_window.parse_hhmm(" 07:30 ") == (7, 30)

    @pytest.mark.parametrize("value", ["25:00", "12:60", "ab:cd", "02:00:00", "02-00", "2", ":", "1:2:3"])
    def test_invalid_times_raise(self, value):
        with pytest.raises(ValueError):
            maintenance_window.parse_hhmm(value)

    def test_empty_falls_back_to_default(self):
        assert maintenance_window.parse_hhmm("", default=(2, 0)) == (2, 0)
        assert maintenance_window.parse_hhmm(None, default=(6, 30)) == (6, 30)
        assert maintenance_window.parse_hhmm("   ", default=(0, 0)) == (0, 0)

    def test_empty_without_default_raises(self):
        with pytest.raises(ValueError):
            maintenance_window.parse_hhmm("")
        with pytest.raises(ValueError):
            maintenance_window.parse_hhmm(None)


# ── is_within_window ─────────────────────────────────────────────────────────

class TestWithinWindow:
    # All datetimes are explicit; nothing here reads the wall clock.
    def test_mid_window_is_inside(self):
        now = datetime(2026, 3, 1, 4, 30)
        assert maintenance_window.is_within_window(now, (2, 0), (6, 0)) is True

    def test_boundaries(self):
        assert maintenance_window.is_within_window(datetime(2026, 3, 1, 2, 0), (2, 0), (6, 0)) is True
        assert maintenance_window.is_within_window(datetime(2026, 3, 1, 1, 59), (2, 0), (6, 0)) is False
        assert maintenance_window.is_within_window(datetime(2026, 3, 1, 6, 0), (2, 0), (6, 0)) is False

    def test_overnight_window_spans_midnight(self):
        # 23:00 -> 01:00 crosses midnight.
        assert maintenance_window.is_within_window(datetime(2026, 3, 1, 0, 30), (23, 0), (1, 0)) is True
        assert maintenance_window.is_within_window(datetime(2026, 3, 1, 23, 30), (23, 0), (1, 0)) is True
        assert maintenance_window.is_within_window(datetime(2026, 3, 1, 12, 0), (23, 0), (1, 0)) is False
        assert maintenance_window.is_within_window(datetime(2026, 3, 1, 1, 0), (23, 0), (1, 0)) is False

    def test_equal_start_and_end_is_always_closed(self):
        for hour in (0, 6, 12, 23):
            assert maintenance_window.is_within_window(
                datetime(2026, 3, 1, hour, 30), (6, 0), (6, 0)
            ) is False


# ── is_repair_allowed / repair_window_status ────────────────────────────────

class TestRepairAllowed:
    def test_disabled_by_default(self, tmp_path):
        db = _make_db(tmp_path)
        assert maintenance_window.is_repair_allowed(db) == (True, "window_disabled")

    def test_enabled_and_inside_window(self, tmp_path):
        db = _make_db(tmp_path)
        _set_window(db, True, "02:00", "06:00")
        allowed, reason = maintenance_window.is_repair_allowed(
            db, now=datetime(2026, 3, 1, 3, 0)
        )
        assert (allowed, reason) == (True, "within_window")

    def test_enabled_and_outside_window(self, tmp_path):
        db = _make_db(tmp_path)
        _set_window(db, True, "02:00", "06:00")
        allowed, reason = maintenance_window.is_repair_allowed(
            db, now=datetime(2026, 3, 1, 12, 0)
        )
        assert (allowed, reason) == (False, "outside_window")


class TestWindowStatus:
    def test_disabled_status(self, tmp_path):
        db = _make_db(tmp_path)
        status = maintenance_window.repair_window_status(db, now=datetime(2026, 3, 1, 3, 0))
        assert set(status) == {
            "enabled", "start", "end", "open", "next_open_at", "repair_bandwidth_kbps",
        }
        assert status["enabled"] is False
        assert status["open"] is False
        assert status["next_open_at"] is None

    def test_enabled_status_computes_next_open(self, tmp_path):
        db = _make_db(tmp_path)
        _set_window(db, True, "02:00", "06:00", bandwidth_kbps=512)
        # 12:00 is outside the window; the next opening is 02:00 next day.
        status = maintenance_window.repair_window_status(db, now=datetime(2026, 3, 1, 12, 0))
        assert status["enabled"] is True
        assert status["start"] == "02:00"
        assert status["end"] == "06:00"
        assert status["open"] is False
        assert status["repair_bandwidth_kbps"] == 512
        assert status["next_open_at"] == datetime(2026, 3, 2, 2, 0).isoformat()

    def test_enabled_and_open_now(self, tmp_path):
        db = _make_db(tmp_path)
        _set_window(db, True, "02:00", "06:00")
        status = maintenance_window.repair_window_status(db, now=datetime(2026, 3, 1, 3, 0))
        assert status["open"] is True


# ── background_bandwidth_scope ───────────────────────────────────────────────

class TestBandwidthScope:
    @pytest.fixture(autouse=True)
    def _reset_limiter(self):
        UPLOAD_LIMITER.rate_limit = 0
        yield
        UPLOAD_LIMITER.rate_limit = 0

    @pytest.mark.asyncio
    async def test_caps_and_restores_rate(self, tmp_path):
        db = _make_db(tmp_path)
        _set_window(db, True, "02:00", "06:00", bandwidth_kbps=512)
        assert UPLOAD_LIMITER.rate_limit == 0
        async with maintenance_window.background_bandwidth_scope(db):
            assert UPLOAD_LIMITER.rate_limit == 512 * 1024
        assert UPLOAD_LIMITER.rate_limit == 0

    @pytest.mark.asyncio
    async def test_restores_rate_on_exception(self, tmp_path):
        db = _make_db(tmp_path)
        _set_window(db, True, "02:00", "06:00", bandwidth_kbps=512)
        with pytest.raises(RuntimeError, match="heal failed"):
            async with maintenance_window.background_bandwidth_scope(db):
                assert UPLOAD_LIMITER.rate_limit == 512 * 1024
                raise RuntimeError("heal failed")
        assert UPLOAD_LIMITER.rate_limit == 0

    @pytest.mark.asyncio
    async def test_zero_cap_is_noop(self, tmp_path):
        db = _make_db(tmp_path)
        _set_window(db, True, "02:00", "06:00", bandwidth_kbps=0)
        async with maintenance_window.background_bandwidth_scope(db):
            assert UPLOAD_LIMITER.rate_limit == 0
        assert UPLOAD_LIMITER.rate_limit == 0


# ── retention: counts and pruning ────────────────────────────────────────────

NOW = datetime(2026, 3, 10, 12, 0, tzinfo=timezone.utc)


def _seed_stale_rows(db) -> None:
    """One dead row past the cutoff, one fresh (kept), one stale pending with
    reserved quota, and one orphaned location whose chunk row is missing."""
    _backend(db, "local", backend_id="b-1", quota_reserved=1000)
    _backend(db, "local", backend_id="b-2")
    file_id = _file(db)
    chunk_id = _chunk(db, file_id)

    old = (NOW - timedelta(days=10)).isoformat()
    fresh = (NOW - timedelta(days=1)).isoformat()
    two_days = (NOW - timedelta(days=2)).isoformat()

    _location(db, chunk_id, "b-1", 0, "failed", upload_date=old)
    _location(db, chunk_id, "b-2", 1, "failed", upload_date=fresh)
    _location(db, chunk_id, "b-1", 2, "pending", upload_date=two_days, quota_reserved=1000)

    # FKs are ON in this schema, but orphans are exactly the rows that got in
    # while they were off (legacy DBs / manual tampering) — seed one by
    # temporarily disabling enforcement.
    db._conn.execute("PRAGMA foreign_keys = OFF")
    _location(db, "chunk-gone", "b-2", 0, "confirmed", upload_date=old)
    db._conn.execute("PRAGMA foreign_keys = ON")


class TestStaleCounts:
    def test_counts_only_stale_rows(self, tmp_path):
        db = _make_db(tmp_path)
        _seed_stale_rows(db)
        counts = retention.stale_location_counts(db, older_than_days=7, now=NOW)
        assert counts == {
            "failed_cancelled": 1,   # 10-day-old failed row only; fresh one kept
            "stale_pending": 1,      # pending older than 24h
            "orphaned": 1,           # chunk-gone location
            "duplicate_confirmed": 0,
        }

    def test_counts_duplicate_confirmed_groups(self, tmp_path):
        db = _make_db(tmp_path)
        _backend(db, "local", backend_id="b-1")
        _backend(db, "local", backend_id="b-2")
        file_id = _file(db)
        chunk_id = _chunk(db, file_id)
        stamp = NOW.isoformat()
        _location(db, chunk_id, "b-1", 0, "confirmed", upload_date=stamp)
        _location(db, chunk_id, "b-2", 0, "confirmed", upload_date=stamp)
        counts = retention.stale_location_counts(db, now=NOW)
        assert counts["duplicate_confirmed"] == 1


class TestPrune:
    def test_prune_removes_stale_and_restores_quota(self, tmp_path):
        db = _make_db(tmp_path)
        _seed_stale_rows(db)

        res = retention.prune_stale_locations(db, older_than_days=7, now=NOW)
        assert res == {
            "failed_cancelled": 1,
            "stale_pending": 1,
            "orphaned": 1,
            "pruned": 3,
            "quota_released_bytes": 1000,
        }

        with db.transaction():
            rows = db._conn.execute(
                "SELECT backend_id, status FROM chunk_locations ORDER BY backend_id, sub_block_index"
            ).fetchall()
            backend = db._conn.execute(
                "SELECT quota_reserved FROM backends WHERE id = 'b-1'"
            ).fetchone()

        # Only the fresh failed row survives.
        assert [(r["backend_id"], r["status"]) for r in rows] == [("b-2", "failed")]
        # The stale pending row's reservation went back to its backend.
        assert backend["quota_reserved"] == 0

        # Second run is a no-op.
        res2 = retention.prune_stale_locations(db, older_than_days=7, now=NOW)
        assert res2["pruned"] == 0
        assert res2["quota_released_bytes"] == 0


# ── retention: duplicate confirmed rebalance ─────────────────────────────────

class TestDeduplicateConfirmed:
    def _seed_duplicates(self, db, loser_quota_used: int = 0, a_status: str = "healthy"):
        """Two confirmed copies of shard 0 on healthy backends with identical
        verification timestamps, so the tiebreak falls through to the
        lexicographically smallest backend_id -> 'a-backend' wins."""
        _backend(db, "local", backend_id="a-backend", status=a_status)
        _backend(db, "local", backend_id="b-backend", quota_used=loser_quota_used)
        file_id = _file(db)
        chunk_id = _chunk(
            db, file_id, sub_block_count=4, size=1024,
            erasure_k=4, erasure_n=6, erasure_padlen=0,
        )
        stamp = "2026-03-01T00:00:00+00:00"
        _location(db, chunk_id, "a-backend", 0, "confirmed", upload_date=stamp)
        _location(db, chunk_id, "b-backend", 0, "confirmed", upload_date=stamp)
        return chunk_id

    def _confirmed_backends(self, db, chunk_id):
        with db.transaction():
            return [
                r["backend_id"]
                for r in db._conn.execute(
                    "SELECT backend_id FROM chunk_locations "
                    "WHERE chunk_id = ? AND status = 'confirmed' ORDER BY backend_id",
                    (chunk_id,),
                ).fetchall()
            ]

    @pytest.mark.asyncio
    async def test_index_only_cleanup(self, tmp_path):
        db = _make_db(tmp_path)
        chunk_id = self._seed_duplicates(db)

        res = await retention.deduplicate_confirmed_locations(db, objects=None)
        assert res["groups"] == 1
        assert res["removed"] == 1
        assert res["quota_released_bytes"] == 0  # index-only: no quota math
        assert res["errors"] == []

        # Determinism rule: identical timestamps, same priority -> smallest id.
        assert self._confirmed_backends(db, chunk_id) == ["a-backend"]

        # Index-only cleanup must not touch backend accounting.
        with db.transaction():
            used = {
                r["id"]: r["quota_used"]
                for r in db._conn.execute("SELECT id, quota_used FROM backends").fetchall()
            }
        assert used == {"a-backend": 0, "b-backend": 0}

    @pytest.mark.asyncio
    async def test_remote_delete_releases_quota(self, tmp_path):
        db = _make_db(tmp_path)
        # Shard estimate is ceil((size + 16) / k) = ceil(1040 / 4) = 260.
        chunk_id = self._seed_duplicates(db, loser_quota_used=1000)

        loser_obj = MagicMock()
        loser_obj.delete = AsyncMock(return_value=True)
        objects = {"a-backend": MagicMock(), "b-backend": loser_obj}

        res = await retention.deduplicate_confirmed_locations(db, objects)
        assert res == {"groups": 1, "removed": 1, "quota_released_bytes": 260, "errors": []}

        loser_obj.delete.assert_awaited_once_with("ref-0")
        with db.transaction():
            backend = db._conn.execute(
                "SELECT quota_used FROM backends WHERE id = 'b-backend'"
            ).fetchone()
        assert backend["quota_used"] == 1000 - 260
        assert self._confirmed_backends(db, chunk_id) == ["a-backend"]

    @pytest.mark.asyncio
    async def test_failed_remote_delete_keeps_quota(self, tmp_path):
        db = _make_db(tmp_path)
        chunk_id = self._seed_duplicates(db, loser_quota_used=1000)

        loser_obj = MagicMock()
        loser_obj.delete = AsyncMock(side_effect=RuntimeError("403 gone wrong"))
        objects = {"a-backend": MagicMock(), "b-backend": loser_obj}

        res = await retention.deduplicate_confirmed_locations(db, objects)
        # Row still goes away, but quota is only released on a successful delete.
        assert res["removed"] == 1
        assert res["quota_released_bytes"] == 0
        assert len(res["errors"]) == 1
        with db.transaction():
            backend = db._conn.execute(
                "SELECT quota_used FROM backends WHERE id = 'b-backend'"
            ).fetchone()
        assert backend["quota_used"] == 1000
        assert self._confirmed_backends(db, chunk_id) == ["a-backend"]

    @pytest.mark.asyncio
    async def test_healthy_backend_beats_smaller_id(self, tmp_path):
        db = _make_db(tmp_path)
        # a-backend is degraded: even with the smaller id it loses to the
        # healthy b-backend (preference 1 dominates tiebreak 4).
        chunk_id = self._seed_duplicates(db, a_status="degraded")

        res = await retention.deduplicate_confirmed_locations(db, objects=None)
        assert res["removed"] == 1
        assert self._confirmed_backends(db, chunk_id) == ["b-backend"]


# ── HealingQueue gating ──────────────────────────────────────────────────────

@pytest.fixture
def healing_db(tmp_path) -> GhostDriveDB:
    return _make_db(tmp_path)


def _patched_sleep(monkeypatch, stop_after: int):
    """Replace asyncio.sleep so the loop's startup sleep passes but a later
    sleep cancels the coroutine — exercising exactly one loop body."""
    real_sleep = asyncio.sleep
    calls = {"n": 0}

    async def fake_sleep(delay):
        calls["n"] += 1
        if calls["n"] >= stop_after:
            raise asyncio.CancelledError()
        await real_sleep(0)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)


def _make_queue(db) -> HealingQueue:
    main_view = MagicMock()
    main_view.active_uploads = 0
    return HealingQueue(
        db=db,
        active_backends={},
        km=SimpleNamespace(master_key=b"\x00" * 32, hkdf_salt=b"\x01" * 32),
        main_view=main_view,
        loop_interval=0.01,
    )


class TestHealingWindowGate:
    @pytest.mark.asyncio
    async def test_loop_skips_step_when_window_closed(self, healing_db, monkeypatch):
        queue = _make_queue(healing_db)
        queue._running = True
        _patched_sleep(monkeypatch, stop_after=2)
        monkeypatch.setattr(
            maintenance_window, "is_repair_allowed",
            lambda db=None, now=None: (False, "outside_window"),
        )

        with patch.object(queue, "perform_healing_step", AsyncMock()) as step:
            with pytest.raises(asyncio.CancelledError):
                await queue._run_loop()
            step.assert_not_called()

    @pytest.mark.asyncio
    async def test_loop_runs_step_when_allowed(self, healing_db, monkeypatch):
        queue = _make_queue(healing_db)
        queue._running = True
        _patched_sleep(monkeypatch, stop_after=2)
        # No monkeypatch of is_repair_allowed: default settings leave the
        # window disabled, which allows repairs around the clock.

        with patch.object(queue, "perform_healing_step", AsyncMock()) as step:
            with pytest.raises(asyncio.CancelledError):
                await queue._run_loop()
            step.assert_called_once()

    @pytest.mark.asyncio
    async def test_closed_window_setting_blocks_the_gate(self, healing_db, monkeypatch):
        """End-to-end gate check with real settings: an enabled window that
        does not contain 'now' short-circuits the loop before
        perform_healing_step. is_repair_allowed is only told *which* clock
        reading to use, so the check stays deterministic while the persisted
        settings are exercised for real."""
        queue = _make_queue(healing_db)
        queue._running = True
        _set_window(healing_db, True, "02:00", "06:00")
        _patched_sleep(monkeypatch, stop_after=2)

        real_check = maintenance_window.is_repair_allowed
        monkeypatch.setattr(
            maintenance_window, "is_repair_allowed",
            lambda db=None, now=None: real_check(db, now=datetime(2026, 3, 1, 12, 0)),
        )

        with patch.object(queue, "perform_healing_step", AsyncMock()) as step:
            with pytest.raises(asyncio.CancelledError):
                await queue._run_loop()
            step.assert_not_called()


class TestHealingRetryAfterFailure:
    @pytest.mark.asyncio
    async def test_failed_backend_is_healable_again(self, healing_db):
        """A chunk with a confirmed copy on a-backend and a *failed* row on
        b-backend must now heal back to b-backend. Before this change the
        candidate query excluded any backend with ANY location row, so the
        failed row blocked the retry forever. The test drives
        perform_healing_step end-to-end; the pending-row INSERT it triggers is
        an upsert, so the old failed row is overwritten instead of tripping
        the (chunk_id, sub_block_index, backend_id) primary key."""
        db = healing_db
        _backend(db, "telegram", backend_id="a-backend")
        _backend(db, "discord", backend_id="b-backend")
        file_id = _file(db, "CRITICAL")
        chunk_id = _chunk(db, file_id, sub_block_count=1, size=100)
        stamp = "2026-03-01T00:00:00+00:00"
        _location(db, chunk_id, "a-backend", 0, "confirmed", upload_date=stamp)
        _location(db, chunk_id, "b-backend", 0, "failed", upload_date=stamp)

        mock_a = MagicMock()
        mock_a.id = "a-backend"
        mock_a.type = "telegram"
        mock_a.connect = AsyncMock()

        async def download_gen(ref_id):
            yield b"\x00" * 32

        mock_a.download = MagicMock(side_effect=download_gen)

        mock_b = MagicMock()
        mock_b.id = "b-backend"
        mock_b.type = "discord"
        mock_b.connect = AsyncMock()
        mock_b.upload = AsyncMock(return_value="ref-b-new")

        queue = HealingQueue(
            db=db,
            active_backends={"a-backend": mock_a, "b-backend": mock_b},
            km=SimpleNamespace(master_key=b"\x00" * 32, hkdf_salt=b"\x01" * 32),
            main_view=MagicMock(active_uploads=0),
        )

        with patch("ghostdrive.pipeline.healing.ChunkDecryptor") as mock_decrypt_cls:
            mock_decrypt = MagicMock()
            mock_decrypt.verify_and_decrypt_streaming.return_value = [b"plain"]
            mock_decrypt_cls.return_value = mock_decrypt

            await queue.perform_healing_step()

        mock_b.upload.assert_called_once()
        with db.transaction():
            rows = db._conn.execute(
                "SELECT status, reference_id FROM chunk_locations "
                "WHERE chunk_id = ? AND backend_id = 'b-backend'",
                (chunk_id,),
            ).fetchall()
        assert len(rows) == 1  # the failed row was upserted, not duplicated
        assert rows[0]["status"] == "confirmed"
        assert rows[0]["reference_id"] == "ref-b-new"


# ── web routes ───────────────────────────────────────────────────────────────

PASSPHRASE = "correct horse battery staple"


@pytest.fixture
def client(tmp_path):
    """Fresh unlocked vault in a temp dir (function-scoped: these tests lock it).
    Pattern copied from tests/test_recovery_api.py."""
    from ghostdrive.web.server import app
    from ghostdrive.web.state import state

    state.clean_shutdown()
    state.app_data_dir = tmp_path
    state.keystore_path = tmp_path / "keystore.json"
    state.db_path = tmp_path / "ghostdrive.db"

    client = TestClient(app)
    res = client.post("/api/auth/setup", json={"passphrase": PASSPHRASE})
    assert res.status_code == 200, res.text

    yield client

    state.clean_shutdown()


class TestRepairWindowRoutes:
    def test_get_defaults(self, client):
        res = client.get("/api/resilience/repair-window")
        assert res.status_code == 200
        data = res.json()
        assert data["enabled"] is False
        assert data["start"] == "02:00"
        assert data["end"] == "06:00"
        assert data["open"] is False
        assert data["next_open_at"] is None
        assert data["repair_bandwidth_kbps"] == 0

    def test_post_roundtrip(self, client):
        res = client.post("/api/resilience/repair-window", json={
            "enabled": True, "start": "22:00", "end": "06:00", "bandwidth_kbps": 512,
        })
        assert res.status_code == 200, res.text
        data = res.json()
        assert data["enabled"] is True
        assert data["start"] == "22:00"
        assert data["end"] == "06:00"
        assert data["repair_bandwidth_kbps"] == 512
        assert data["next_open_at"] is not None

        # Persisted: a fresh GET reflects the same configuration.
        again = client.get("/api/resilience/repair-window").json()
        assert again["enabled"] is True
        assert again["start"] == "22:00"
        assert again["repair_bandwidth_kbps"] == 512

    def test_post_rejects_bad_start(self, client):
        res = client.post("/api/resilience/repair-window", json={
            "enabled": True, "start": "99:00", "end": "06:00", "bandwidth_kbps": 0,
        })
        assert res.status_code == 400

    def test_post_rejects_garbage_end(self, client):
        res = client.post("/api/resilience/repair-window", json={
            "enabled": True, "start": "02:00", "end": "banana", "bandwidth_kbps": 0,
        })
        assert res.status_code == 400


class TestRetentionRoutes:
    def test_status_returns_zero_counts(self, client):
        res = client.get("/api/resilience/retention/status?older_than_days=7")
        assert res.status_code == 200
        data = res.json()
        assert data == {
            "failed_cancelled": 0,
            "stale_pending": 0,
            "orphaned": 0,
            "duplicate_confirmed": 0,
        }

    def test_prune_on_empty_db_is_noop(self, client):
        res = client.post("/api/resilience/retention/prune", json={})
        assert res.status_code == 200
        assert res.json()["pruned"] == 0
