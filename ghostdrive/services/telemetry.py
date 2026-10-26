"""Real transfer measurements for the live telemetry panel."""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Deque

import psutil


class TransferMeter:
    """Counts bytes in each direction and derives a smoothed KB/s rate."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._upload_bytes = 0
        self._download_bytes = 0
        self._last_upload_bytes = 0
        self._last_download_bytes = 0
        self._last_sample = time.monotonic()
        self._upload_kbps = 0.0
        self._download_kbps = 0.0
        self._events: Deque[str] = deque(maxlen=200)
        self._last_message = "Idle - waiting for transfers."

    def record_upload(self, nbytes: int) -> None:
        with self._lock:
            self._upload_bytes += max(0, int(nbytes))

    def record_download(self, nbytes: int) -> None:
        with self._lock:
            self._download_bytes += max(0, int(nbytes))

    def status(self, message: str) -> None:
        with self._lock:
            stamp = time.strftime("%H:%M:%S")
            self._last_message = message
            self._events.append(f"[{stamp}] {message}")

    @property
    def last_message(self) -> str:
        with self._lock:
            return self._last_message

    @property
    def events(self) -> list[str]:
        with self._lock:
            return list(self._events)

    def sample(self) -> dict:
        with self._lock:
            now = time.monotonic()
            elapsed = max(now - self._last_sample, 0.001)
            up_delta = self._upload_bytes - self._last_upload_bytes
            down_delta = self._download_bytes - self._last_download_bytes
            # Light exponential smoothing avoids a jittery 0 / spike readout.
            self._upload_kbps = 0.6 * (up_delta / 1024 / elapsed) + 0.4 * self._upload_kbps
            self._download_kbps = 0.6 * (down_delta / 1024 / elapsed) + 0.4 * self._download_kbps
            self._last_upload_bytes = self._upload_bytes
            self._last_download_bytes = self._download_bytes
            self._last_sample = now
            return {
                "upload_speed_kbps": round(self._upload_kbps, 2),
                "download_speed_kbps": round(self._download_kbps, 2),
                "last_message": self._last_message,
            }


meter = TransferMeter()


def system_stats() -> dict:
    mem = psutil.virtual_memory()
    return {
        "active_threads": threading.active_count(),
        "cpu_usage_percent": psutil.cpu_percent(interval=None),
        "ram_usage_mb": round(mem.used / (1024 * 1024), 2),
    }
