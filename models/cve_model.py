from pydantic import BaseModel, Field
from typing import Dict, List, Optional


class CVEAffectedRange(BaseModel):
    min: str
    max: str


class CVEFirstFixed(BaseModel):
    """First fixed version, keyed by a fix *path*.

    A path is either a ProductFamily enum value, or that value plus a release
    train when the product is fixed per train:

        {"ios-xe": "17.9.4a", "ios": "15.2(7)E8", "asa": "9.18.4"}
        {"ise-3.3": "3.3 Patch 12", "ise-3.4": "3.4 Patch 7"}

    The train form (CVE-007, 2026-09-18) exists because one fix per family
    cannot express ISE: every fix belongs to family `ise`, yet Cisco ships a
    different patch level on each train, and "3.4 Patch 7" says nothing about
    3.3. Use `fix_for()` rather than indexing `fixes` directly — it resolves
    the train form first and falls back to the bare family.

    CVE-006 Phase 3. Populated by _parse_advisory from PSIRT advisory-detail
    endpoint (`firstFixed` per productName). Multi-family advisories carry
    one fix version per affected family path — e.g. CVE-2025-20363 is
    unauth on ASA, auth on IOS XE, with different fix versions per family.
    Single scalar `CVEEntry.fixed_in` loses this distinction.
    """
    fixes: Dict[str, str] = Field(default_factory=dict)

    def fix_for(self, family: str, train: Optional[str] = None) -> Optional[str]:
        """Fix on `family`, preferring the `family-train` path when given."""
        if train:
            hit = self.fixes.get("%s-%s" % (family, train))
            if hit:
                return hit
        return self.fixes.get(family)

    def trains(self, family: str) -> List[str]:
        """Release trains that carry an explicit fix for `family`, sorted."""
        prefix = family + "-"
        return sorted(k[len(prefix):] for k in self.fixes if k.startswith(prefix))


class CVEBundledInfo(BaseModel):
    """Marks a CVE that stands for a *class* of defects, not a single bug.

    CVE-007 (2026-09-18). Since July 2026 Cisco discloses on a fixed cadence
    (1st and 3rd Wednesday, seven-day advance notice) and, in hardening
    releases, assigns one CVE per CWE category instead of one per defect.
    Russ Smoak, blogs.cisco.com, 2026-06-02: "Assessing security risk
    CVE-by-CVE and applying point mitigations is no longer fit for purpose."

    Consequence for every consumer of a record carrying this block: it cannot
    be mitigated on its own and has no meaningful "is this one bug reachable
    in my config" answer. The unit of remediation is the hardened release.

    Not to be confused with `CVEEntry.bundle` (CVE-010), which marks a same-day
    *publication* bundle of otherwise ordinary advisories.
    """

    advisory_id: str                      # e.g. "cisco-sa-hardening-ise-XU5EwX5T"
    # Every CWE category the hardening release covers, across all its CVEs.
    cwe_categories: List[str] = Field(default_factory=list)
    # Every CVE in the same hardening release (this one included).
    sibling_cves: List[str] = Field(default_factory=list)
    # True when len(cves) == len(cwe) on the source advisory — the structural
    # signature of "one CVE per CWE category". False means the advisory matched
    # on id/title only and deserves a second look.
    one_cve_per_cwe: bool = True


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

    # MATCH-01 (2026-09-18) — Cisco's complete Known Affected release list for
    # this advisory, per software family: {"ios-xe": ["17.9.4", …], "ios": […]}.
    # When the queried family has a list, the matcher uses exact membership and
    # ignores `affected.min/max`, which on PSIRT imports is a 0.0.0–999
    # placeholder that matches every version. `affected_versions_raw` above is
    # the display-only first-50 slice of the same data and must not be matched on.
    known_affected: Dict[str, List[str]] = Field(default_factory=dict)
    # Date the list was read from Cisco (ISO). A release absent from the list
    # is "not listed as of this date", not proof about later releases.
    known_affected_as_of: Optional[str] = None

    # CVE-007 (2026-09-18) — set when this CVE is a Cisco hardening-release
    # CVE, i.e. a CWE category rather than a single defect. None = ordinary CVE.
    bundled: Optional[CVEBundledInfo] = None
