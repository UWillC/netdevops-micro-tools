"""
Subscribe endpoint — proxy to MailerLite API.
Keeps API key on server side (never exposed to frontend).

BETA-A (2026-10-05): a successful subscribe also returns a signed beta token
(api/beta.py) for the MailerLite subscriber id. The answer has the same shape
for a new and an existing address. POST /api/beta/token is the read-only
backfill for browsers unlocked before tokens existed: it looks the address up
and never creates a subscriber or touches its groups.
"""

from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel, EmailStr
import httpx
import os
from urllib.parse import quote

from api import beta

router = APIRouter()

MAILERLITE_API_URL = "https://connect.mailerlite.com/api"
MAILERLITE_API_KEY = os.getenv("MAILERLITE_API_KEY", "")
GATED_TOOLS_GROUP_ID = "184092079999157302"


class SubscribeRequest(BaseModel):
    email: EmailStr


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=10.0)


def _subscriber_id(resp) -> Optional[str]:
    try:
        sid = (resp.json() or {}).get("data", {}).get("id")
    except Exception:
        return None
    return str(sid) if sid is not None else None


def _ok(message: str, token: Optional[str]) -> dict:
    return {"success": True, "message": message, "token": token}


@router.post("/subscribe")
async def subscribe(req: SubscribeRequest):
    """Add email to MailerLite 'Gated Tools' group; return a beta token when configured."""
    if not MAILERLITE_API_KEY:
        # Fallback: accept email even without MailerLite key (dev mode)
        return _ok("Subscribed (dev mode)", None)

    headers = {
        "Authorization": f"Bearer {MAILERLITE_API_KEY}",
        "Content-Type": "application/json",
    }

    # No status, no resubscribe flag: an address that unsubscribed stays unsubscribed.
    payload = {
        "email": req.email,
        "groups": [GATED_TOOLS_GROUP_ID],
    }

    try:
        async with _client() as client:
            resp = await client.post(
                f"{MAILERLITE_API_URL}/subscribers",
                json=payload,
                headers=headers,
            )

        # MailerLite returns 200 (existing) or 201 (new); same answer for both
        if resp.status_code in (200, 201):
            return _ok("Subscribed", beta.issue_token(_subscriber_id(resp)))

        # 422 = validation error (bad email format etc.)
        if resp.status_code == 422:
            return {"success": False, "message": "Invalid email", "token": None}

        # Other errors — still unlock locally, just log
        return _ok("Subscribed (partial)", None)

    except Exception:
        # Network error — still return success so user isn't blocked
        return _ok("Subscribed (offline)", None)


@router.post("/beta/token")
async def beta_token(req: SubscribeRequest):
    """Read-only backfill: token for an existing Gated Tools subscriber.

    Never creates, updates or regroups anyone. An unknown address, and a member
    whose id is outside [BETA_ID_MIN, BETA_ID_MAX] (FIX-5a), gets a decoy token
    of the same shape (no enumeration); it is dropped later on a 404. No id
    range configured (FIX-5b) = no token for anyone, like a missing secret.
    Rate-limited with /api/subscribe's budget (api/rate_limit.py PATH_LIMITS).
    """
    if not MAILERLITE_API_KEY or beta.current_secret() is None or beta.id_range() is None:
        return {"token": None}

    headers = {"Authorization": f"Bearer {MAILERLITE_API_KEY}", "Accept": "application/json"}
    sid = None
    try:
        async with _client() as client:
            resp = await client.get(
                f"{MAILERLITE_API_URL}/subscribers/{quote(req.email, safe='@')}",
                headers=headers,
            )
        if resp.status_code == 200:
            data = (resp.json() or {}).get("data") or {}
            groups = data.get("groups")
            if groups is None:
                print("[WARN] beta backfill: lookup answer has no groups; token not issued")
            elif any(str(g.get("id")) == GATED_TOOLS_GROUP_ID for g in groups if isinstance(g, dict)):
                sid = str(data.get("id")) if data.get("id") is not None else None
        elif resp.status_code != 404:
            print(f"[WARN] beta backfill: lookup failed status={resp.status_code}")
    except Exception as exc:
        print(f"[WARN] beta backfill: lookup error {type(exc).__name__}")

    # FIX-5a: a real token only inside the frozen decoy range; anyone else
    # (e.g. joined after BETA_ID_MAX) takes the decoy path, same shape.
    if not (sid and beta.in_backfill_range(sid)):
        sid = beta.decoy_subscriber_id(req.email)
    token = beta.issue_token(sid)
    return {"token": token}
