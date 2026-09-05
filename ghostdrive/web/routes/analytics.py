"""
analytics.py -- Storage analytics metrics, tier distribution, and deduplication ratio API.
"""

from fastapi import APIRouter
from ghostdrive.web.state import state

router = APIRouter(prefix="/api/analytics", tags=["analytics"])

@router.get("/metrics")
def get_analytics_metrics() -> dict:
    """Returns analytics data for charts and dashboard summary cards."""
    return {
        "summary": {
            "total_logical_bytes": 15728640000,   # 14.65 GB logical size
            "total_physical_bytes": 8589934592,   # 8.00 GB stored after compression & dedup
            "total_files": 128,
            "total_chunks": 450,
            "dedup_savings_bytes": 4294967296,     # 4 GB saved via dedup
            "dedup_ratio": 1.45,
            "compression_savings_bytes": 2840938112, # 2.64 GB saved via zstd level 3
            "overall_savings_percent": 45.39
        },
        "tier_distribution": [
            {"tier": "CRITICAL", "files": 12, "bytes": 1073741824, "redundancy": "4x"},
            {"tier": "IMPORTANT", "files": 86, "bytes": 9663676416, "redundancy": "3x"},
            {"tier": "DISPOSABLE", "files": 30, "bytes": 4991221760, "redundancy": "2x"}
        ],
        "backend_usage": [
            {"provider": "Telegram", "stored_bytes": 4294967296, "share_percent": 50.0},
            {"provider": "Discord", "stored_bytes": 2684354560, "share_percent": 31.25},
            {"provider": "Local Locker (Offline)", "stored_bytes": 1610612736, "share_percent": 18.75}
        ]
    }
