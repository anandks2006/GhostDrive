"""Storage analytics derived from the live database."""

from __future__ import annotations

from ghostdrive.services.context import require_db

_TIER_ORDER = ("CRITICAL", "IMPORTANT", "DISPOSABLE")
_TIER_REDUNDANCY = {"CRITICAL": "RS 4+2", "IMPORTANT": "RS 4+2", "DISPOSABLE": "single copy"}


def metrics() -> dict:
    db = require_db()
    summary = db.get_analytics_summary()
    raw = db.get_storage_analytics()

    tier_rows = {row["tier"]: row for row in raw["tier_usage"]}
    tier_distribution = []
    for tier in _TIER_ORDER:
        row = tier_rows.get(tier)
        tier_distribution.append({
            "tier": tier,
            "files": int(row["count"]) if row else 0,
            "bytes": int(row["total_size"] or 0) if row else 0,
            "redundancy": _TIER_REDUNDANCY[tier],
        })

    total_physical = summary["physical_bytes"]
    logical = summary["logical_bytes"]
    dedup_savings = summary["dedup_savings_bytes"]
    compression_savings = 0  # uploads encrypt the original bytes (zstd reserved for future use)
    overall_savings = dedup_savings + compression_savings
    unique_logical = max(logical - dedup_savings, 1)
    dedup_ratio = round(logical / unique_logical, 3) if logical else 1.0

    backends = db.list_backends()
    total_used = sum(int(row["quota_used"] or 0) for row in backends)
    backend_usage = []
    for row in backends:
        used = int(row["quota_used"] or 0)
        backend_usage.append({
            "provider": row["type"].replace("_", " ").title(),
            "backend_id": row["id"],
            "stored_bytes": used,
            "quota_bytes": int(row["quota_limit"] or 0),
            "share_percent": round((used / total_used) * 100, 2) if total_used else 0.0,
        })

    return {
        "summary": {
            "total_logical_bytes": logical,
            "total_physical_bytes": total_physical,
            "total_files": summary["file_count"],
            "total_chunks": summary["chunk_count"],
            "dedup_savings_bytes": dedup_savings,
            "dedup_ratio": dedup_ratio,
            "compression_savings_bytes": compression_savings,
            "overall_savings_percent": round(
                (overall_savings / logical) * 100, 2
            ) if logical else 0.0,
        },
        "tier_distribution": tier_distribution,
        "backend_usage": backend_usage,
        "upload_history": raw["upload_history"],
        "type_groups": raw["type_groups"],
    }
