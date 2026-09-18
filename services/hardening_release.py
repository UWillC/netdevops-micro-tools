"""
Cisco hardening-release detection (CVE-007, 2026-09-18).

Since July 2026 Cisco discloses on a fixed cadence — the 1st and 3rd Wednesday
of each month, with seven days of advance notice — and in *hardening releases*
no longer assigns one CVE per defect. Each CVE covers many fixes inside a single
CWE category. Russ Smoak, blogs.cisco.com, 2026-06-02:

    "Assessing security risk CVE-by-CVE and applying point mitigations is no
     longer fit for purpose."

Why this module exists: the whole engine was built on "one CVE = one
vulnerability = one fixed version". A hardening-release CVE breaks all three.
It is a category, it has no per-defect exploit path to reason about, and its
remediation is "be on the hardened release", not a point mitigation.

The signature is machine-readable. It was verified on 2026-09-18 against the
seven hardening advisories then obtainable from PSIRT:

    cisco-sa-hardening-iosxe-V8NMuMZJ       2026-08-05   7 CVE / 7 CWE
    cisco-sa-hardening-crosswork-UzDTU9Vh   2026-08-19   4 CVE / 4 CWE
    cisco-sa-hardening-iosxr-qg64NcM        2026-09-02   7 CVE / 7 CWE
    cisco-sa-hardening-esa-dfCrfXkm         2026-09-14   5 CVE / 5 CWE
    cisco-sa-hardening-ise-XU5EwX5T         2026-09-16   6 CVE / 6 CWE
    cisco-sa-hardening-ndw1-psFvnrg         2026-09-16   6 CVE / 6 CWE
    cisco-sa-hardening-asaftdfmc-uvpPROhN   2026-09-16   8 CVE / 8 CWE

In every one: advisoryId starts with "cisco-sa-hardening-", the title contains
"Hardening Release", and len(cves) == len(cwe).

This module has no dependency on the engine or the providers, so importers,
the engine and the API can all use it without import cycles.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from models.cve_model import CVEBundledInfo

HARDENING_ID_PREFIX = "cisco-sa-hardening-"
_HARDENING_TITLE_RE = re.compile(r"hardening\s+release", re.IGNORECASE)
_ADVISORY_ID_IN_URL_RE = re.compile(r"(cisco-sa-[A-Za-z0-9-]+)")


def is_hardening_advisory(adv: Dict[str, Any]) -> bool:
    """True when a raw PSIRT advisory dict is a hardening release."""
    adv_id = (adv.get("advisoryId") or "").lower()
    if adv_id.startswith(HARDENING_ID_PREFIX):
        return True
    return bool(_HARDENING_TITLE_RE.search(adv.get("advisoryTitle") or ""))


def bundled_info_from_advisory(adv: Dict[str, Any]) -> Optional[CVEBundledInfo]:
    """Build the `bundled` block for every CVE of a hardening advisory.

    Returns None for an ordinary advisory. Note what is deliberately NOT
    derived here: which CWE belongs to which CVE. PSIRT returns `cves` and
    `cwe` as two independently sorted lists, so positions do not correspond;
    the per-CVE CWE has to come from NVD. We record the full category list
    and leave the per-CVE field alone.
    """
    if not is_hardening_advisory(adv):
        return None
    cves = [c for c in (adv.get("cves") or []) if isinstance(c, str) and c.startswith("CVE-")]
    cwes = [c for c in (adv.get("cwe") or []) if isinstance(c, str) and c.startswith("CWE-")]
    return CVEBundledInfo(
        advisory_id=adv.get("advisoryId") or "",
        cwe_categories=sorted(set(cwes)),
        sibling_cves=sorted(set(cves)),
        one_cve_per_cwe=bool(cves) and len(set(cves)) == len(set(cwes)),
    )


def advisory_id_from_url(url: Optional[str]) -> Optional[str]:
    """Extract 'cisco-sa-…' from a Cisco advisory URL."""
    m = _ADVISORY_ID_IN_URL_RE.search(url or "")
    return m.group(1) if m else None


def is_bundled_cve(cve: Any) -> bool:
    """True when a CVEEntry stands for a CWE class in a hardening release.

    Order of evidence, strongest first: the typed `bundled` block (set at
    import time from the advisory itself), then the `bundled-cve` tag, then the
    advisory URL, then the title. The weaker signals keep records imported
    before CVE-007 detectable without a re-import.
    """
    if getattr(cve, "bundled", None) is not None:
        return True
    tags = [t.lower() for t in (getattr(cve, "tags", None) or [])]
    if "bundled-cve" in tags:
        return True
    adv_id = advisory_id_from_url(getattr(cve, "advisory_url", None)) or ""
    if adv_id.lower().startswith(HARDENING_ID_PREFIX):
        return True
    return bool(_HARDENING_TITLE_RE.search(getattr(cve, "title", "") or ""))
