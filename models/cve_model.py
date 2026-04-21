from pydantic import BaseModel, Field
from typing import List, Optional


class CVEAffectedRange(BaseModel):
    min: str
    max: str


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
