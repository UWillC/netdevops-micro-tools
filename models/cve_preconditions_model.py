"""
Curated CVE preconditions data model (XCUT-001 Phase 3).

Hand-curated per-CVE annotations about what exploitability conditions an
attacker needs satisfied. Consumed by the correlation engine (Phase 4) to
decide whether device-specific findings (CIS audit failures, config gaps)
elevate or confirm a given CVE's real-world risk on a given device.

Schema stability: field names are part of the on-disk JSON contract.
Never rename, only add optional fields with defaults.
"""

from typing import List, Optional

from pydantic import BaseModel, Field


class CVEPreconditionDetail(BaseModel):
    """The 'preconditions' object inside a curated CVE JSON file."""

    # Conditions that MUST be true for exploitation to work at all.
    # If any required condition is not satisfied → CVE is not exploitable
    # on this device (correlation engine downgrades to MITIGATED).
    required: List[str] = Field(default_factory=list)

    # Conditions that, if true, make the exploit work WITHOUT authentication.
    # When all satisfied, correlation engine bumps effective CVSS to
    # `effective_cvss_when_unauth` (typically 9.8 for RCE, 7.5 for DoS).
    sufficient_for_unauthenticated: List[str] = Field(default_factory=list)

    # Free-text explanation cited in UI tooltip. Operators read this to
    # understand WHY the score changed — transparency is the point.
    rationale: str = ""


class CVEPreconditions(BaseModel):
    """One curated record, keyed by cve_id in the loader."""

    cve_id: str
    preconditions: CVEPreconditionDetail

    # Effective CVSS to apply when all unauth conditions hold. None means
    # "no effective override" (the CVE's native CVSS is already the real
    # risk — still worth correlating for confirmation).
    effective_cvss_when_unauth: Optional[float] = None

    # Curation metadata — purely for audit trail / transparency. Not used
    # by the correlation engine.
    last_curated: str  # ISO date (YYYY-MM-DD)
    curator: str = "initial"
    notes: Optional[str] = None
