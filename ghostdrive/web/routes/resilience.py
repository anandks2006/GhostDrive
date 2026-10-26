"""
resilience.py -- Integrity scrub runner, chunk repair, and erasure coding health routes.
"""

import logging
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ghostdrive.services import durability
from ghostdrive.services import maintenance_window
from ghostdrive.services import resilience as resilience_service
from ghostdrive.services import retention
from ghostdrive.services import snapshots
from ghostdrive.services.context import require_db

logger = logging.getLogger("ghostdrive_web.resilience")

router = APIRouter(prefix="/api/resilience", tags=["resilience"])


class ScrubTriggerRequest(BaseModel):
    tier: str = "ALL"
    auto_repair: bool = True


class DurabilityContractRequest(BaseModel):
    required_domain_losses: int = 2
    requires_offsite: bool = False
    requires_restore_proof: bool = False
    preset: str | None = None


class WhatIfRequest(BaseModel):
    lost_domain_ids: list[str] = []
    lost_backend_ids: list[str] = []


class SnapshotCreateRequest(BaseModel):
    pass


class SnapshotVerifyRequest(BaseModel):
    snapshot_id: str | None = None


class SnapshotRestoreRequest(BaseModel):
    snapshot_id: str | None = None
    destination: str | None = None


def _http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, FileNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, ValueError):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, RuntimeError) and "locked" in str(exc).lower():
        return HTTPException(status_code=401, detail=str(exc))
    logger.exception("Resilience operation failed: %s", exc)
    return HTTPException(status_code=500, detail=str(exc))


@router.get("/status")
def get_resilience_status() -> dict:
    """Returns chunk integrity health score, recent scrub results, and zfec parameters."""
    try:
        return resilience_service.status()
    except Exception as exc:
        raise _http_error(exc)


@router.get("/contract")
def get_durability_contract() -> dict:
    try:
        return durability.contract_from_settings(require_db())
    except Exception as exc:
        raise _http_error(exc)


@router.post("/contract")
def set_durability_contract(req: DurabilityContractRequest) -> dict:
    try:
        db = require_db()
        if req.preset:
            preset = durability.contract_preset(req.preset)
            required = preset["required_domain_losses"]
            offsite = preset["requires_offsite"]
            restore_proof = preset["requires_restore_proof"]
        else:
            required = req.required_domain_losses
            offsite = req.requires_offsite
            restore_proof = req.requires_restore_proof
        contract = durability.save_contract(
            db, required, offsite, requires_restore_proof=restore_proof
        )
        return {
            "status": "success",
            "contract": contract,
            "worst_case": durability.audit_readiness(db, contract=contract),
        }
    except Exception as exc:
        raise _http_error(exc)


@router.get("/contract/presets")
def get_contract_presets() -> dict:
    return {
        "presets": [
            {"name": name, **values}
            for name, values in durability.CONTRACT_PRESETS.items()
        ]
    }


@router.post("/what-if")
def what_if(req: WhatIfRequest) -> dict:
    try:
        return durability.simulate_domain_losses(
            require_db(),
            lost_domain_ids=req.lost_domain_ids,
            lost_backend_ids=req.lost_backend_ids,
        )
    except Exception as exc:
        raise _http_error(exc)


@router.post("/recovery/confirm")
def confirm_recovery_saved() -> dict:
    try:
        confirmed_at = durability.confirm_recovery_saved(require_db())
        return {"status": "success", "confirmed_at": confirmed_at}
    except Exception as exc:
        raise _http_error(exc)


@router.get("/snapshots")
def list_snapshots() -> dict:
    try:
        db = require_db()
        return {
            "snapshots": snapshots.list_snapshots(db),
            "latest_drill": snapshots.latest_drill(db),
        }
    except Exception as exc:
        raise _http_error(exc)


@router.post("/snapshots")
async def create_snapshot(req: SnapshotCreateRequest | None = None) -> dict:
    try:
        return await snapshots.create_snapshot(require_db())
    except Exception as exc:
        raise _http_error(exc)


@router.post("/snapshots/verify")
async def verify_snapshot(req: SnapshotVerifyRequest | None = None) -> dict:
    try:
        return await snapshots.verify_snapshot(
            require_db(), snapshot_id=req.snapshot_id if req else None
        )
    except Exception as exc:
        raise _http_error(exc)


@router.post("/snapshots/restore")
async def restore_snapshot(req: SnapshotRestoreRequest | None = None) -> dict:
    try:
        from ghostdrive.web.state import state

        destination = (
            Path(req.destination)
            if req and req.destination
            else Path(state.app_data_dir) / "recovered-index.db"
        )
        raw, meta = await snapshots.restore_latest_bytes(
            require_db(), snapshot_id=req.snapshot_id if req else None
        )
        written = snapshots.write_restored_index(raw, destination)
        return {
            "status": "success",
            "snapshot_id": meta["snapshot_id"],
            "snapshot_at": meta["snapshot_at"],
            "destination": str(written),
            "size": len(raw),
        }
    except Exception as exc:
        raise _http_error(exc)


@router.post("/drill")
async def run_restore_drill() -> dict:
    try:
        return await snapshots.run_restore_drill(require_db())
    except Exception as exc:
        raise _http_error(exc)


@router.post("/evacuate")
async def evacuate_at_risk() -> dict:
    try:
        return await resilience_service.evacuate_at_risk()
    except Exception as exc:
        raise _http_error(exc)


@router.get("/drill/latest")
def latest_restore_drill() -> dict:
    try:
        return {"drill": snapshots.latest_drill(require_db())}
    except Exception as exc:
        raise _http_error(exc)


@router.post("/scrub/start")
async def trigger_scrub(req: ScrubTriggerRequest) -> dict:
    """Triggers background chunk checksum scrub and auto-repair queue."""
    try:
        return await resilience_service.start_scrub(req.tier, req.auto_repair)
    except Exception as exc:
        raise _http_error(exc)


@router.post("/repair/chunk/{chunk_id}")
async def repair_chunk(chunk_id: str) -> dict:
    try:
        result = await resilience_service.repair_chunk(chunk_id)
        result.setdefault("status", "success")
        return result
    except Exception as exc:
        raise _http_error(exc)


class RepairWindowRequest(BaseModel):
    enabled: bool
    start: str = "02:00"
    end: str = "06:00"
    bandwidth_kbps: int = 0


class RetentionPruneRequest(BaseModel):
    older_than_days: int = 7


class RetentionRebalanceRequest(BaseModel):
    limit: int = 50


@router.get("/repair-window")
def get_repair_window() -> dict:
    """Returns the configured repair window, whether it is open, and the cap."""
    try:
        return maintenance_window.repair_window_status(require_db())
    except Exception as exc:
        raise _http_error(exc)


@router.post("/repair-window")
def update_repair_window(req: RepairWindowRequest) -> dict:
    """Persists the repair window settings and returns the updated status."""
    try:
        db = require_db()
        # Validate explicitly so garbage times surface as 400, not 500.
        start = maintenance_window.parse_hhmm(req.start)
        end = maintenance_window.parse_hhmm(req.end)
        with db.transaction():
            db.set_setting(maintenance_window.KEY_ENABLED, "true" if req.enabled else "false")
            db.set_setting(maintenance_window.KEY_START, f"{start[0]:02d}:{start[1]:02d}")
            db.set_setting(maintenance_window.KEY_END, f"{end[0]:02d}:{end[1]:02d}")
            db.set_setting(
                maintenance_window.KEY_BANDWIDTH, str(max(0, int(req.bandwidth_kbps)))
            )
        return maintenance_window.repair_window_status(db)
    except Exception as exc:
        raise _http_error(exc)


@router.get("/retention/status")
def retention_status(older_than_days: int = 7) -> dict:
    """Counts of stale/orphaned/duplicate chunk_locations retention would prune."""
    try:
        return retention.stale_location_counts(require_db(), older_than_days=older_than_days)
    except Exception as exc:
        raise _http_error(exc)


@router.post("/retention/prune")
def prune_retention(req: RetentionPruneRequest | None = None) -> dict:
    """Deletes stale failed/cancelled/pending/orphaned chunk_locations rows."""
    try:
        days = req.older_than_days if req else 7
        return retention.prune_stale_locations(require_db(), older_than_days=days)
    except Exception as exc:
        raise _http_error(exc)


@router.post("/retention/rebalance")
async def rebalance_retention(req: RetentionRebalanceRequest | None = None) -> dict:
    """Collapses duplicate confirmed shard copies, deleting redundant remote objects."""
    try:
        db = require_db()
        # Local-only backends: rebalancing must not trigger remote provider
        # connections just to delete a duplicate row.
        from ghostdrive.services.context import active_backends

        _, objects = await active_backends(connect_remote=False)
        limit = req.limit if req else 50
        return await retention.deduplicate_confirmed_locations(db, objects, limit=limit)
    except Exception as exc:
        raise _http_error(exc)
