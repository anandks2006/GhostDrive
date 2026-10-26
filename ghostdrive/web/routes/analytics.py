"""
analytics.py -- Storage analytics metrics, tier distribution, and deduplication ratio API.
"""

from fastapi import APIRouter, HTTPException

from ghostdrive.services import analytics as analytics_service

router = APIRouter(prefix="/api/analytics", tags=["analytics"])


@router.get("/metrics")
def get_analytics_metrics() -> dict:
    """Returns analytics data for charts and dashboard summary cards."""
    try:
        return analytics_service.metrics()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
