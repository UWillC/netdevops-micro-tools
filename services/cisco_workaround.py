"""
Cisco's own Workarounds section, copied verbatim from the advisory's CSAF document.

Why (C1 MITIG-AUDIT, 2026-09-25): 7 of 10 hand-written mitigations for KEV-listed CVEs
disagreed with Cisco - "workarounds" where Cisco says there are none, and the one mitigation
Cisco does publish missing (e.g. the SNMP view excluding cafSessionMethodsInfoEntry for
CVE-2025-20352). The tool now shows Cisco's text first; our steps are labelled as ours.
"""

import json
import re
import urllib.request
from datetime import date
from typing import Optional, Tuple

CSAF_URL = ("https://sec.cloudapps.cisco.com/security/center/contentjson/"
            "CiscoSecurityAdvisory/{sa}/csaf/{sa}.json")

_SA_RE = re.compile(r"(cisco-sa-[A-Za-z0-9-]+)")


def advisory_id(url_or_id: Optional[str]) -> Optional[str]:
    """cisco-sa-... id from an advisory URL (or the id itself)."""
    if not url_or_id:
        return None
    m = _SA_RE.search(url_or_id)
    return m.group(1) if m else None


_POSITIVE_WA = re.compile(
    r"there (?:is|are) (?:a |two |several )?workarounds? that address"
    r"|there is a workaround|to work around|as a workaround")
_DISCLAIMER = re.compile(
    r"while (?:this|these) (?:mitigations?|workarounds?)[^.]*(?:has|have) been deployed.*$")


def classify(text: str) -> str:
    """none | mitigation | workaround | unknown, from Cisco's own wording.

    "none" only when nothing is left besides the "no workarounds" sentence and Cisco's
    standard disclaimer - "no workarounds, but if you do not use feature X, disable it"
    is a mitigation, and showing it as "none" would hide Cisco's advice.
    """
    t = " ".join(text.split()).lower()
    if not t:
        return "unknown"
    if _POSITIVE_WA.search(t):
        return "workaround"
    body = _DISCLAIMER.sub("", t)
    if "no workaround" not in body:
        first = body.split(". ", 1)[0]
        return "mitigation" if "mitigat" in first else "workaround"
    rest = " ".join(x for x in re.split(r"(?<=\.)\s+", body) if "no workaround" not in x)
    return "none" if len(rest.strip()) < 20 else "mitigation"


def extract(csaf: dict) -> Optional[str]:
    """The advisory's Workarounds note, verbatim (None when the document has none)."""
    notes = (csaf.get("document") or {}).get("notes") or []
    parts = [n.get("text", "").strip() for n in notes
             if "workaround" in (n.get("title") or "").lower() and n.get("text")]
    return "\n\n".join(parts) or None


def csaf_cves(csaf: dict) -> list:
    """CVE ids the advisory itself lists (CSAF `vulnerabilities[].cve`), sorted."""
    return sorted({v.get("cve") for v in csaf.get("vulnerabilities") or [] if v.get("cve")})


def build(csaf: dict, sa: str, fetched: Optional[str] = None) -> Optional[dict]:
    text = extract(csaf)
    if text is None:
        return None
    return {
        "status": classify(text),
        "text": text,
        "source": CSAF_URL.format(sa=sa),
        "fetched": fetched or date.today().isoformat(),
        # MITIG-WRONG-CVE (2026-09-27): which CVEs this text is about, so a record whose
        # advisory does not list its own CVE is detectable offline (test_mitig_advisory_cve).
        "cves": csaf_cves(csaf),
    }


def _get_csaf(sa: str, timeout: int) -> dict:
    req = urllib.request.Request(CSAF_URL.format(sa=sa),
                                 headers={"User-Agent": "netdevops-micro-tools"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _fetch_checked(url_or_id: Optional[str], cve_id: Optional[str],
                   timeout: int = 20) -> Tuple[Optional[dict], bool]:
    """(record or None, rejected).

    Importer gate (MITIG-WRONG-CVE, 2026-09-27): three hand-written records pointed at an
    advisory for a different CVE, so Cisco's text and our steps described the wrong bug.
    rejected=True only when Cisco's CSAF was read and does NOT list cve_id: the caller must
    not write the mitigation. A network failure is not a rejection (record None, False).
    """
    sa = advisory_id(url_or_id)
    if not sa:
        return None, False
    try:
        csaf = _get_csaf(sa, timeout)
    except Exception as e:  # noqa: BLE001 - a missing section must never break an import
        print(f"cisco_workaround: {sa}: {type(e).__name__}: {str(e)[:120]}")
        return None, False
    listed = csaf_cves(csaf)
    if cve_id and cve_id.upper() not in listed:
        print(f"cisco_workaround: REJECTED {cve_id}: {sa} does not list it "
              f"(lists {', '.join(listed) or 'no CVE'})")
        return None, True
    return build(csaf, sa), False


def fetch_checked(url_or_id: Optional[str], cve_id: Optional[str],
                  timeout: int = 20) -> Tuple[Optional[dict], bool]:
    """Importer entry point; see _fetch_checked."""
    return _fetch_checked(url_or_id, cve_id, timeout)


def fetch(url_or_id: Optional[str], timeout: int = 20) -> Optional[dict]:
    """Network fetch + build, no CVE check. Any failure = None (UI says 'not checked')."""
    return _fetch_checked(url_or_id, None, timeout)[0]
