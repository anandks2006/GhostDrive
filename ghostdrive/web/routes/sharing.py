"""
sharing.py -- Shared media, public links generator, access expiration, and link revocation API.
"""

from typing import Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/sharing", tags=["sharing"])

class CreateShareLinkRequest(BaseModel):
    file_id: str
    recipient_alias: Optional[str] = "public"
    ttl_hours: int = 72
    require_passcode: bool = False

@router.get("/links")
def list_shared_links() -> dict:
    return {
        "shared_links": [
            {
                "link_id": "share_88192a",
                "file_id": "file_a7b8c9",
                "filename": "ML_Model_Checkpoint_v2.pt",
                "size": 524288000,
                "created_at": "2026-09-03 14:20:00",
                "expires_at": "2026-09-06 14:20:00",
                "access_count": 3,
                "url": "http://127.0.0.1:8000/s/share_88192a"
            }
        ]
    }

@router.post("/create")
def create_share_link(req: CreateShareLinkRequest) -> dict:
    link_id = f"share_{req.file_id[-6:]}"
    url = f"http://127.0.0.1:8000/s/{link_id}"
    return {
        "status": "success",
        "link_id": link_id,
        "url": url,
        "ttl_hours": req.ttl_hours,
        "message": "Share link created successfully."
    }

@router.delete("/revoke/{link_id}")
def revoke_share_link(link_id: str) -> dict:
    return {
        "status": "success",
        "link_id": link_id,
        "message": f"Share link {link_id} has been revoked."
    }
