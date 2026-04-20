"""
Platform taxonomy for CVE matching.

Post-CTO-memo 2026-04-19: the cisco-psirt-import feed tags every advisory
with "IOS XE" regardless of the advisory's actual affected products, leading
to systemic false positives (SSM On-Prem, CUCM, ASA, RV Series CVEs all
showing up for IOS XE queries) and false negatives (ASA/RV queries return
nothing or wrong content).

Until the importer is refactored to preserve advisory.affected_products
(CTO memo P0.1, estimated 3-5 days), this module provides a DATA-LAYER
fix: detect the true product family from the CVE title/description and
let the matcher enforce per-family strict matching.

Reference: projects/netdevops/cve-analyzer-cto-memo-2026-04-19.md
"""

from enum import Enum
from typing import List, Optional, Tuple


# -----------------------------
# Product family taxonomy
# -----------------------------
class ProductFamily(str, Enum):
    IOS = "ios"                   # IOS classic (12.x, 15.x)
    IOS_XE = "ios-xe"             # IOS XE (3.x, 16.x, 17.x) — Catalyst, ISR, ASR routers
    IOS_XE_SDWAN = "ios-xe-sdwan" # cEdge / Catalyst SD-WAN (autonomous IOS XE in SD-WAN mode)
    IOS_XE_WLC = "ios-xe-wlc"     # Catalyst 9800 WLC
    IOS_XR = "ios-xr"             # ASR 9000, NCS, 8000 series
    NX_OS = "nx-os"               # Nexus switches
    ASA = "asa"                   # Adaptive Security Appliance
    FTD = "ftd"                   # Firepower Threat Defense
    FXOS = "fxos"                 # Firepower OS (underlying)
    RV_SERIES = "rv-series"       # Small Business RV320, RV325, RV340 etc.
    MERAKI = "meraki"             # Meraki dashboard / MS / MR / MX
    AP_SOFTWARE = "ap-software"   # Access Point firmware
    CUCM = "cucm"                 # Unified Communications Manager
    UCCX = "uccx"                 # Unified Contact Center
    WEBEX = "webex"               # Webex Meetings / Teams
    FINESSE = "finesse"           # Contact Center Finesse
    SSM_ON_PREM = "ssm-on-prem"   # Smart Software Manager On-Prem
    DNA_CENTER = "dna-center"     # DNA Center / Catalyst Center
    ISE = "ise"                   # Identity Services Engine
    UNKNOWN = "unknown"            # Could not be determined from title/description


# -----------------------------
# Title → family detection
# -----------------------------
# Order matters: more specific patterns first (longer substrings match before shorter).
# Tuple: (list_of_trigger_substrings, family)
_TITLE_PATTERNS: List[Tuple[List[str], ProductFamily]] = [
    # --- Non-IOS-XE products that PSIRT importer mislabels ---
    (["smart software manager on-prem", "ssm on-prem", "ssm on prem"], ProductFamily.SSM_ON_PREM),
    (["unified communications manager"], ProductFamily.CUCM),
    (["unified contact center"], ProductFamily.UCCX),
    (["cisco finesse"], ProductFamily.FINESSE),
    (["cisco webex"], ProductFamily.WEBEX),
    (["meraki"], ProductFamily.MERAKI),
    (["access point software"], ProductFamily.AP_SOFTWARE),
    (["dna center", "catalyst center"], ProductFamily.DNA_CENTER),
    (["identity services engine", "cisco ise"], ProductFamily.ISE),

    # --- Firewall / security platforms ---
    (["firepower threat defense", "cisco ftd"], ProductFamily.FTD),
    (["firepower extensible operating system", "cisco fxos"], ProductFamily.FXOS),
    (["adaptive security appliance", "cisco asa software", "cisco secure firewall asa", "cisco asa "], ProductFamily.ASA),

    # --- Small business / SOHO ---
    (["small business rv", "rv series", "rv320", "rv325", "rv340", "rv345", "rv042", "rv082", "rv016", "rv215w"], ProductFamily.RV_SERIES),

    # --- Network OS (more specific first) ---
    (["cisco ios xe sd-wan", "cisco ios-xe sd-wan", "catalyst sd-wan"], ProductFamily.IOS_XE_SDWAN),
    (["catalyst 9800", "ios xe wireless controller"], ProductFamily.IOS_XE_WLC),
    (["cisco ios xr", "ios-xr"], ProductFamily.IOS_XR),
    (["cisco nx-os", "cisco nexus", "nx-os software"], ProductFamily.NX_OS),

    # IOS / IOS XE need care: shared advisories e.g. "Cisco IOS and IOS XE Software"
    # are detected separately via detect_all_families().
]


def _title_contains(text: str, trigger: str) -> bool:
    """Case-insensitive substring match."""
    return trigger.lower() in text.lower()


def detect_primary_family(title: str, description: str = "") -> ProductFamily:
    """
    Detect the PRIMARY product family from a CVE title (fallback: description).

    Returns UNKNOWN if title doesn't unambiguously identify a family.
    IOS / IOS XE are handled specially because shared advisories ("Cisco IOS,
    IOS XE, and IOS XR Software...") span multiple families — use
    detect_all_families() for that case.
    """
    if not title:
        return ProductFamily.UNKNOWN

    combined = title + " " + (description[:500] if description else "")

    # Check non-IOS-XE product patterns first (they dominate when present)
    for triggers, family in _TITLE_PATTERNS:
        for trigger in triggers:
            if _title_contains(combined, trigger):
                return family

    # IOS / IOS XE detection (distinguishable by order in title)
    low = combined.lower()
    has_ios_xe = "ios xe" in low or "ios-xe" in low
    has_ios_classic = (
        "cisco ios " in low or
        "cisco ios software" in low or
        ("ios" in low and not has_ios_xe and "ios-xe" not in low)
    )

    if has_ios_xe and has_ios_classic:
        # Shared — prefer IOS_XE as primary (most common use case)
        return ProductFamily.IOS_XE
    if has_ios_xe:
        return ProductFamily.IOS_XE
    if has_ios_classic:
        return ProductFamily.IOS

    return ProductFamily.UNKNOWN


def detect_all_families(title: str, description: str = "") -> List[ProductFamily]:
    """
    Return ALL product families mentioned in the title (for shared advisories).

    Example: "Cisco IOS, IOS XE, and IOS XR Software LLDP Buffer Overflow"
    → [IOS, IOS_XE, IOS_XR]
    """
    if not title:
        return []

    combined = (title + " " + (description[:500] if description else "")).lower()
    families: List[ProductFamily] = []

    # Check each non-generic pattern
    for triggers, family in _TITLE_PATTERNS:
        for trigger in triggers:
            if trigger.lower() in combined:
                if family not in families:
                    families.append(family)
                break  # one match per family is enough

    # IOS / IOS XE / IOS XR
    if "ios xr" in combined or "ios-xr" in combined:
        if ProductFamily.IOS_XR not in families:
            families.append(ProductFamily.IOS_XR)
    if "ios xe" in combined or "ios-xe" in combined:
        if ProductFamily.IOS_XE not in families:
            families.append(ProductFamily.IOS_XE)
    # IOS classic: tricky because "ios" appears in "ios xe" too. Only count if
    # we find "cisco ios " (with trailing space) or "ios software" not preceded
    # by XE/XR.
    if "cisco ios software" in combined and ProductFamily.IOS not in families:
        families.append(ProductFamily.IOS)
    elif ("cisco ios " in combined and
          " and " in combined and
          ("ios xe" in combined or "ios xr" in combined) and
          ProductFamily.IOS not in families):
        # "Cisco IOS, IOS XE, and ..." pattern → IOS classic too
        families.append(ProductFamily.IOS)

    return families


# -----------------------------
# User input → family normalization
# -----------------------------
# Map user-facing platform strings (case-insensitive exact match or substring)
# to the ProductFamily they represent.
_USER_INPUT_ALIASES: List[Tuple[List[str], ProductFamily]] = [
    (["cisco asa", "adaptive security appliance", "cisco secure firewall asa", "asa software"], ProductFamily.ASA),
    (["cisco ftd", "firepower threat defense"], ProductFamily.FTD),
    (["cisco fxos", "firepower extensible"], ProductFamily.FXOS),
    (["cisco ios xe sd-wan", "catalyst sd-wan", "cedge"], ProductFamily.IOS_XE_SDWAN),
    (["catalyst 9800", "ios xe wireless"], ProductFamily.IOS_XE_WLC),
    (["cisco ios xr", "ios-xr", "ios xr"], ProductFamily.IOS_XR),
    (["cisco nx-os", "nexus", "nx-os"], ProductFamily.NX_OS),
    (["small business rv", "rv series", "rv320", "rv325", "rv340", "rv345", "rv042", "rv016"], ProductFamily.RV_SERIES),
    (["meraki"], ProductFamily.MERAKI),
    (["access point software", "aironet", "catalyst 9100", "catalyst 9115", "catalyst 9120"], ProductFamily.AP_SOFTWARE),
    (["cucm", "unified communications manager"], ProductFamily.CUCM),
    (["uccx", "unified contact center"], ProductFamily.UCCX),
    (["webex"], ProductFamily.WEBEX),
    (["finesse"], ProductFamily.FINESSE),
    (["ssm on-prem", "ssm on prem", "smart software manager"], ProductFamily.SSM_ON_PREM),
    (["dna center", "catalyst center"], ProductFamily.DNA_CENTER),
    (["ise", "identity services engine"], ProductFamily.ISE),
    # IOS XE must be LAST among IOS-family entries (most specific first)
    (["cisco ios xe", "ios-xe software", "ios xe software", "ios xe"], ProductFamily.IOS_XE),
    (["cisco ios software", "cisco ios "], ProductFamily.IOS),
]


def normalize_user_platform(user_input: str) -> Optional[ProductFamily]:
    """
    Map a user-facing platform string to the canonical ProductFamily.

    Returns None if the input cannot be recognized (caller should fall back
    to legacy fuzzy matching to avoid breaking existing queries).

    Examples:
      "Cisco ASA"            → ProductFamily.ASA
      "Cisco IOS XE"          → ProductFamily.IOS_XE
      "IOS XE"                → ProductFamily.IOS_XE
      "Cisco RV320"           → ProductFamily.RV_SERIES
      "ISR4451-X"             → None (hardware model, caller keeps legacy)
    """
    if not user_input:
        return None

    low = user_input.strip().lower()

    for triggers, family in _USER_INPUT_ALIASES:
        for trigger in triggers:
            if trigger.lower() in low:
                return family

    return None


# -----------------------------
# Compatibility matrix
# -----------------------------
# If user queries family X, which CVE title families should also be treated
# as IN-SCOPE (shared advisories), and which are strictly OUT-OF-SCOPE?
_IN_SCOPE: dict = {
    ProductFamily.IOS:        {ProductFamily.IOS, ProductFamily.IOS_XE, ProductFamily.IOS_XR, ProductFamily.UNKNOWN},
    ProductFamily.IOS_XE:     {ProductFamily.IOS_XE, ProductFamily.IOS, ProductFamily.IOS_XR, ProductFamily.IOS_XE_SDWAN, ProductFamily.IOS_XE_WLC, ProductFamily.UNKNOWN},
    ProductFamily.IOS_XE_SDWAN: {ProductFamily.IOS_XE_SDWAN, ProductFamily.IOS_XE, ProductFamily.UNKNOWN},
    ProductFamily.IOS_XE_WLC: {ProductFamily.IOS_XE_WLC, ProductFamily.IOS_XE, ProductFamily.UNKNOWN},
    ProductFamily.IOS_XR:     {ProductFamily.IOS_XR, ProductFamily.IOS, ProductFamily.IOS_XE, ProductFamily.UNKNOWN},
    ProductFamily.NX_OS:      {ProductFamily.NX_OS, ProductFamily.UNKNOWN},
    ProductFamily.ASA:        {ProductFamily.ASA, ProductFamily.FTD, ProductFamily.FXOS, ProductFamily.UNKNOWN},
    ProductFamily.FTD:        {ProductFamily.FTD, ProductFamily.ASA, ProductFamily.FXOS, ProductFamily.UNKNOWN},
    ProductFamily.FXOS:       {ProductFamily.FXOS, ProductFamily.ASA, ProductFamily.FTD, ProductFamily.UNKNOWN},
    ProductFamily.RV_SERIES:  {ProductFamily.RV_SERIES, ProductFamily.UNKNOWN},
    ProductFamily.MERAKI:     {ProductFamily.MERAKI, ProductFamily.UNKNOWN},
    ProductFamily.AP_SOFTWARE:{ProductFamily.AP_SOFTWARE, ProductFamily.UNKNOWN},
    ProductFamily.CUCM:       {ProductFamily.CUCM, ProductFamily.UCCX, ProductFamily.FINESSE, ProductFamily.UNKNOWN},
    ProductFamily.UCCX:       {ProductFamily.UCCX, ProductFamily.CUCM, ProductFamily.FINESSE, ProductFamily.UNKNOWN},
    ProductFamily.WEBEX:      {ProductFamily.WEBEX, ProductFamily.UNKNOWN},
    ProductFamily.FINESSE:    {ProductFamily.FINESSE, ProductFamily.CUCM, ProductFamily.UCCX, ProductFamily.UNKNOWN},
    ProductFamily.SSM_ON_PREM:{ProductFamily.SSM_ON_PREM, ProductFamily.UNKNOWN},
    ProductFamily.DNA_CENTER: {ProductFamily.DNA_CENTER, ProductFamily.UNKNOWN},
    ProductFamily.ISE:        {ProductFamily.ISE, ProductFamily.UNKNOWN},
    ProductFamily.UNKNOWN:    set(),  # unknown target accepts nothing strict
}


def is_cve_in_scope_for_query(query_family: ProductFamily, cve_families: List[ProductFamily]) -> bool:
    """
    Decide whether a CVE's detected families are in-scope for a user query family.

    Rules:
    - If CVE has NO detected families (all UNKNOWN), fall back to legacy matching
      (caller's responsibility — we return True here to not hide potentially-relevant CVEs).
    - Otherwise, at least one of the CVE's families must be in the query's in-scope set.
    """
    if not cve_families:
        return True  # no signal — don't exclude

    in_scope = _IN_SCOPE.get(query_family, set())
    if not in_scope:
        return True  # query family unknown — fall back to legacy

    return any(fam in in_scope for fam in cve_families)
