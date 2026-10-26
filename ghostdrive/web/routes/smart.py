"""
smart.py -- Smart engine controls, auto-tiering policy, and thermal backpressure settings.
"""

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ghostdrive.services import smart as smart_service

logger = logging.getLogger("ghostdrive_web.smart")

router = APIRouter(prefix="/api/smart", tags=["smart"])


class SmartEngineConfig(BaseModel):
    background_sync: bool = True
    auto_tiering_enabled: bool = True
    auto_tiering_days_unused: int = 30
    thermal_throttling_enabled: bool = True
    max_cpu_percent_cap: int = 80
    bandwidth_limit_kbps: int = 0
    battery_saver_pause: bool = True


@router.get("/config")
def get_smart_config() -> dict:
    try:
        cfg = smart_service.load_config()
        return {**cfg, "thermal_state": smart_service.thermal_state(cfg)}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/config")
def update_smart_config(cfg: SmartEngineConfig) -> dict:
    try:
        saved = smart_service.save_config(cfg.model_dump())
        return {
            "status": "success",
            "config": saved,
            "thermal_state": smart_service.thermal_state(saved),
            "message": "Smart engine configuration updated and applied.",
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
