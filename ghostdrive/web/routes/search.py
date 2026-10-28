"""
search.py -- Local content search API (decrypt-at-query-time, no index at rest).

``POST /api/search/content`` runs the vault's content search: file texts are
decrypted per query into a bounded in-memory cache (see
services/content_search.py for the threat model — the deleted plaintext-FTS
module is the anti-pattern this replaces).  ``GET /api/search/content/cache``
exposes cache introspection for the UI.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ghostdrive.services import content_search as search_service

logger = logging.getLogger("ghostdrive_web.search")

router = APIRouter(prefix="/api/search", tags=["search"])


class ContentSearchRequest(BaseModel):
    query: str
    limit: int = 50
    max_file_mb: int = 2
    max_files: int = 400


def _http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, FileNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, ValueError):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, RuntimeError) and "locked" in str(exc).lower():
        return HTTPException(status_code=401, detail=str(exc))
    logger.exception("Content search failed: %s", exc)
    return HTTPException(status_code=500, detail=str(exc))


@router.post("/content")
async def search_content(req: ContentSearchRequest) -> dict:
    """Search file contents (decrypted at query time); newest files first."""
    try:
        return await search_service.search_content(
            req.query,
            limit=max(1, min(int(req.limit), 200)),
            max_file_bytes=max(1, min(int(req.max_file_mb), 50)) * 1024 * 1024,
            max_files=max(1, min(int(req.max_files), 2000)),
        )
    except Exception as exc:
        raise _http_error(exc)


@router.get("/content/cache")
def search_cache() -> dict:
    """Retained cache size (decoded text is RAM-only and wipeable)."""
    return search_service.search_cache_stats()
