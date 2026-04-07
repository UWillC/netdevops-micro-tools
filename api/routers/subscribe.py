"""
Subscribe endpoint — proxy to MailerLite API.
Keeps API key on server side (never exposed to frontend).
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr
import httpx
import os

router = APIRouter()

MAILERLITE_API_URL = "https://connect.mailerlite.com/api"
MAILERLITE_API_KEY = os.getenv("MAILERLITE_API_KEY", "")
GATED_TOOLS_GROUP_ID = "184092079999157302"


class SubscribeRequest(BaseModel):
    email: EmailStr


@router.post("/subscribe")
async def subscribe(req: SubscribeRequest):
    """Add email to MailerLite 'Gated Tools' group."""
    if not MAILERLITE_API_KEY:
        # Fallback: accept email even without MailerLite key (dev mode)
        return {"success": True, "message": "Subscribed (dev mode)"}

    headers = {
        "Authorization": f"Bearer {MAILERLITE_API_KEY}",
        "Content-Type": "application/json",
    }

    payload = {
        "email": req.email,
        "groups": [GATED_TOOLS_GROUP_ID],
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{MAILERLITE_API_URL}/subscribers",
                json=payload,
                headers=headers,
            )

        # MailerLite returns 200 (existing) or 201 (new)
        if resp.status_code in (200, 201):
            return {"success": True, "message": "Subscribed"}

        # 422 = validation error (bad email format etc.)
        if resp.status_code == 422:
            return {"success": False, "message": "Invalid email"}

        # Other errors — still unlock locally, just log
        return {"success": True, "message": "Subscribed (partial)"}

    except Exception:
        # Network error — still return success so user isn't blocked
        return {"success": True, "message": "Subscribed (offline)"}
