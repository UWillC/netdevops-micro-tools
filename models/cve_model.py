from pydantic import BaseModel, Field
from typing import Dict, List, Optional


class CVEAffectedRange(BaseModel):
    min: str
    max: str


class CVEFirstFixed(BaseModel):
    """First fixed version keyed by ProductFamily enum value.

    Flat map: {"ios-xe": "17.9.4a", "ios": "15.2(7)E8", "asa": "9.18.4"}

    CVE-006 Phase 3. Populated by _parse_advisory from PSIRT advisory-detail
    endpoint (`firstFixed` per productName). Multi-family advisories carry
    one fix version per affected family path — e.g. CVE-2025-20363 is
    unauth on ASA, auth on IOS XE, with different fix versions per family.
    Single scalar `CVEEntry.fixed_in` loses this distinction.
    """
    fixes: Dict[str, str] = Field(default_factory=dict)


class CVEKevStatus(BaseModel):
    """CISA Known Exploited Vulnerabilities catalog status.

    ISE-01 (2026-09-18). Presence of this block means the CVE was in the KEV
    catalog when the record was written. `catalog_version` pins which snapshot
    that was, so a stale record is recognisable instead of being trusted: KEV
    is append-mostly but due dates and notes do change.

    `due_date` is the US federal remediation deadline (BOD 22-01 and successors).
    It is not a vendor deadline and carries no obligation outside FCEB agencies,
    but it is the sharpest public signal that a CVE is being exploited now.
    """

    date_added: str            # ISO date, KEV `dateAdded`
    due_date: str              # ISO date, KEV `dueDate`
    catalog_version: Optional[str] = None   # e.g. "2026.09.16"
    directive: Optional[str] = None         # e.g. "BOD 26-04"


class CVEEntry(BaseModel):
    cve_id: str
    title: str
    severity: str  # critical/high/medium/low

    platforms: List[str] = Field(default_factory=list)
    affected: CVEAffectedRange

    fixed_in: Optional[str] = None
    tags: List[str] = Field(default_factory=list)

    description: str
    workaround: Optional[str] = None
    advisory_url: Optional[str] = None

    confidence: str = "demo"  # demo | validated | partial

    # v0.3+ metadata (optional, SaaS-ready)
    source: Optional[str] = None  # local-json | cisco | nvd | tenable
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cwe: Optional[str] = None
    published: Optional[str] = None
    last_modified: Optional[str] = None
    references: List[str] = Field(default_factory=list)

    # v0.6.16 — CVE-007 severity transparency:
    # Cisco SIR (Security Impact Rating) is a separate scale from CVSS.
    # When the curated `severity` field was sourced from Cisco SIR, store it
    # here so the UI can display CVSS-bucket as primary and Cisco SIR as a
    # secondary tag. `None` means no explicit Cisco SIR was recorded.
    cisco_sir: Optional[str] = None

    # v0.6.16 — CVE-010 bundled-publication:
    # Cisco publishes semi-annual bundles in March and September. Operators
    # patching one bundle item usually want to patch the rest in the same
    # bundle. None for non-bundled advisories.
    bundle: Optional[str] = None  # e.g. "2025-09", "2025-03"

    # v0.6.24 (CVE-003 Phase 3) — canonical platform family taxonomy.
    # Populated by _parse_advisory via normalize_cisco_product_names() on new
    # PSIRT imports. Values are ProductFamily enum string values ("ios-xe",
    # "ios", "nx-os", ...). Empty list on legacy local-json records (matcher
    # falls back to `platforms` field for those).
    product_families: List[str] = Field(default_factory=list)

    # v0.6.24 (CVE-003 Phase 3) — raw PSIRT productNames (first 50 entries,
    # truncated for storage). Display / debugging only — matching MUST use
    # product_families + affected.min/max, never this field directly.
    affected_versions_raw: List[str] = Field(default_factory=list)

    # v0.6.24 (CVE-006 Phase 3) — per-family first-fixed version. Populated
    # by PSIRT advisory-detail fetch. When present, matcher prefers the
    # family-specific fix over the scalar `fixed_in` field. None on legacy
    # local-json records — matcher falls back to `fixed_in` + `affected.max`.
    first_fixed_version: Optional[CVEFirstFixed] = None

    # ISE-01 (2026-09-18) — CISA KEV status. Populated only for records whose
    # CVE is in the KEV catalog. None means "not in KEV as of the last import",
    # NOT "not exploited" — absence of evidence only.
    kev: Optional[CVEKevStatus] = None
