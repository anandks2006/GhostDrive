"""
telemetry.py -- Live WebSocket telemetry streaming and bandwidth monitoring routes.
"""

import asyncio
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ghostdrive.services.telemetry import meter, system_stats
from ghostdrive.web.state import state

logger = logging.getLogger("ghostdrive_web.telemetry")

router = APIRouter(prefix="/api/telemetry", tags=["telemetry"])


def _snapshot() -> dict:
    sample = meter.sample()
    stats = system_stats()
    return {
        "upload_speed_kbps": sample["upload_speed_kbps"],
        "download_speed_kbps": sample["download_speed_kbps"],
        "active_threads": stats["active_threads"],
        "cpu_usage_percent": stats["cpu_usage_percent"],
        "ram_usage_mb": stats["ram_usage_mb"],
        "active_uploads": len(state.active_uploads),
        "active_downloads": len(state.active_downloads),
        "log_message": sample["last_message"],
    }


@router.get("/stats")
def get_telemetry_stats() -> dict:
    return _snapshot()


@router.websocket("/ws")
async def websocket_telemetry_stream(websocket: WebSocket):
    await websocket.accept()
    state.telemetry_clients.add(websocket)
    try:
        while True:
            payload = {"type": "telemetry_tick", **_snapshot()}
            await websocket.send_json(payload)
            await asyncio.sleep(1.0)
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.debug("Telemetry websocket closed: %s", exc)
    finally:
        state.telemetry_clients.discard(websocket)
