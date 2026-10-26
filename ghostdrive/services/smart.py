"""Smart engine configuration: persistence and real throttle application."""

from __future__ import annotations

import json
import logging

import psutil

from ghostdrive.utils.bandwidth_throttle import DOWNLOAD_LIMITER, UPLOAD_LIMITER

logger = logging.getLogger("ghostdrive.services.smart")

SETTINGS_KEY = "smart_config"

DEFAULTS = {
    "background_sync": True,
    "auto_tiering_enabled": True,
    "auto_tiering_days_unused": 30,
    "thermal_throttling_enabled": True,
    "max_cpu_percent_cap": 80,
    "bandwidth_limit_kbps": 0,
    "battery_saver_pause": True,
}


def load_config(db=None) -> dict:
    cfg = dict(DEFAULTS)
    if db is None:
        from ghostdrive.services.context import require_db
        db = require_db()
    try:
        raw = db.get_setting(SETTINGS_KEY, "")
        if raw:
            stored = json.loads(raw)
            if isinstance(stored, dict):
                cfg.update({k: stored[k] for k in DEFAULTS if k in stored})
    except Exception as exc:
        logger.warning("Could not load smart config: %s", exc)
    return cfg


def save_config(cfg: dict, db=None) -> dict:
    if db is None:
        from ghostdrive.services.context import require_db
        db = require_db()
    merged = dict(DEFAULTS)
    merged.update({k: cfg[k] for k in DEFAULTS if k in cfg})
    with db.transaction():
        db.set_setting(SETTINGS_KEY, json.dumps(merged))
    apply_config(merged)
    return merged


def apply_config(cfg: dict) -> None:
    limit_bytes = max(0, int(cfg.get("bandwidth_limit_kbps") or 0)) * 1024
    UPLOAD_LIMITER.set_rate_limit(limit_bytes)
    DOWNLOAD_LIMITER.set_rate_limit(limit_bytes)


def apply_saved() -> None:
    try:
        apply_config(load_config())
    except Exception as exc:
        logger.debug("Smart config could not be applied at unlock: %s", exc)


def thermal_state(cfg: dict) -> dict:
    cpu_percent = psutil.cpu_percent(interval=0.1)
    temp_c = 0.0
    available = False
    try:
        sensors = psutil.sensors_temperatures() or {}
        for name in ("coretemp", "k10temp", "cpu_thermal", "acpitz"):
            if sensors.get(name):
                temp_c = float(sensors[name][0].current)
                available = True
                break
        if not available:
            for readings in sensors.values():
                if readings:
                    temp_c = float(readings[0].current)
                    available = True
                    break
    except Exception:
        pass

    thermal_throttling = bool(cfg.get("thermal_throttling_enabled", True))
    cap = int(cfg.get("max_cpu_percent_cap") or 80)
    throttling_active = thermal_throttling and (
        (available and temp_c >= 80.0) or cpu_percent >= cap
    )
    factor = 1.0
    if throttling_active:
        factor = max(0.25, min(1.0, cap / max(cpu_percent, 1.0)))

    battery_paused = False
    if cfg.get("battery_saver_pause", True):
        try:
            battery = psutil.sensors_battery()
            if battery is not None and not battery.power_plugged:
                battery_paused = True
                factor = min(factor, 0.5)
        except Exception:
            pass

    return {
        "cpu_temp_celsius": round(temp_c, 1) if available else None,
        "temperature_available": available,
        "cpu_usage_percent": cpu_percent,
        "throttling_active": throttling_active,
        "battery_paused": battery_paused,
        "current_backpressure_factor": round(factor, 2),
    }
