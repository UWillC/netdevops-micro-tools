"""
KEV Watch API (KW-01.2, 2026-09-27).

GET /api/kev/watch?days=14&vendors=Cisco,Fortinet
CVEs added to the CISA KEV catalog in the last `days` days for the given vendors.

Source is only services.kev_catalog: no new fetch path, same TTL, cache and
offline switch. Every response says which catalog it came from and when that
copy was fetched. When CISA cannot be reached the last good copy is served with
`catalog.stale = true` and its real fetch date, so an old copy is never read as
"no new listings". With no catalog at all the answer is 503, never an empty
table.

Free module, like the threat feed: no auth on the API.
"""

import datetime
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query

from services import kev_catalog

router = APIRouter()

MAX_VENDORS = 20
MAX_VENDOR_LEN = 64


def _today() -> datetime.date:
    """UTC date; a seam for tests."""
    return datetime.datetime.now(datetime.timezone.utc).date()


def _parse_vendors(raw: Optional[str]) -> List[str]:
    """Comma-separated vendor names; blank or missing -> watch_vendors()."""
    if raw is None or not raw.strip():
        return kev_catalog.watch_vendors()
    seen = {}
    for part in raw.split(","):
        name = part.strip()
        if not name:
            continue
        if len(name) > MAX_VENDOR_LEN:
            raise HTTPException(status_code=422,
                                detail=f"Vendor name longer than {MAX_VENDOR_LEN} characters.")
        seen.setdefault(name.lower(), name)
    if not seen:
        return kev_catalog.watch_vendors()
    if len(seen) > MAX_VENDORS:
        raise HTTPException(status_code=422, detail=f"At most {MAX_VENDORS} vendors per request.")
    return list(seen.values())


@router.get("/kev/watch")
def kev_watch(
    days: int = Query(14, ge=1, le=90, description="Window in days (1-90), inclusive."),
    vendors: Optional[str] = Query(
        None, description="Comma-separated KEV vendorProject names; default: server watch list."),
):
    """New CISA KEV listings for the chosen vendors, with catalog provenance."""
    vendor_list = _parse_vendors(vendors)
    if not kev_catalog.load_kev_index():
        raise HTTPException(
            status_code=503,
            detail="CISA KEV catalog unavailable: no live copy and no cached copy. "
                   "Try again later; this is not an empty result.",
        )
    items = kev_catalog.recent_additions(days, vendors=vendor_list, today=_today())
    return {
        "items": items,
        "count": len(items),
        "days": days,
        "vendors": vendor_list,
        "catalog": kev_catalog.catalog_status(),
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
