"""
First-fixed releases for Cisco ISE, read from an advisory's Fixed Software table
(ISE-04, 2026-09-18).

Why this exists. For ISE the Known Affected list (services.known_affected) says
WHETHER a release is affected. It does not say what to upgrade to: Cisco fixes
ISE per train, and a train in Software Maintenance or past End of Software
Maintenance may get no fix at all. That information lives only in the advisory's
Fixed Software table, which PSIRT's JSON API does not expose but the CVRF XML
does.

"Next patch after the last affected one" would be a tempting shortcut and would
be wrong in exactly the cases that matter: on an EoSM train there is no next
patch, and on 3.1 / 3.2 a Medium advisory is never back-ported. So the table is
read, not inferred.

Table text as it appears in CVRF, flattened, footnote digits glued to the train:

    3.01 and earlier Migrate to fixed release. 3.12 3.1 Patch 12 3.22 3.2 Patch 11
    3.3 3.3 Patch 12 3.4 3.4 Patch 7 3.53 3.5 Patch 4
    3.1 and earlier Not vulnerable 3.2 3.2 Patch 11 …
    3.4 3.4 Patch 7 3.4 Patch 7 3.4 Patch 7 3.5 3.5 Patch 3 3.5 Patch 4 3.5 Patch 4

Rows that do not fit are skipped. An unparsed table yields {} — "unknown", which
callers must not confuse with "no fix exists".
"""

from __future__ import annotations

import re
import urllib.request
import xml.etree.ElementTree as ET
from typing import Dict, Optional

MIGRATE = "migrate"   # Cisco: "Migrate to (a) fixed release" — no fix on this train

_ROW_RE = re.compile(
    r"(?<![\d.])(?P<train>\d\.\d)\d?\s+"
    r"(?P<earlier>and earlier\s+)?"
    r"(?P<fix>Migrate to (?:a )?fixed release\.?"
    r"|Not vulnerable\.?"
    r"|(?:\d\.\d Patch \d+\s*)+)",
    re.IGNORECASE,
)
_PATCH_RE = re.compile(r"(\d\.\d) Patch (\d+)", re.IGNORECASE)
_HEADER_RE = re.compile(r"First Fixed Release", re.IGNORECASE)


def parse_ise_fixed_table(text: str) -> Dict[str, str]:
    """{"3.4": "3.4 Patch 7", "3.0": "migrate"} from flattened Fixed Software text.

    "Not vulnerable" rows produce no entry (the Known Affected list already
    excludes those releases). When a row has several fixes — one column per CVE —
    the highest patch is kept, since anything lower leaves a CVE open.
    """
    if not text:
        return {}
    m = _HEADER_RE.search(text)
    body = text[m.end():] if m else text
    out: Dict[str, str] = {}
    for row in _ROW_RE.finditer(body):
        train = row.group("train")
        fix = row.group("fix").strip()
        low = fix.lower()
        if low.startswith("not vulnerable"):
            continue
        if low.startswith("migrate"):
            out.setdefault(train, MIGRATE)
            if row.group("earlier"):
                # "3.0 and earlier — Migrate": applies to every older train too.
                out.setdefault("<" + train, MIGRATE)
            continue
        patches = [int(p) for t, p in _PATCH_RE.findall(fix) if t == train]
        if patches:
            out[train] = "%s Patch %d" % (train, max(patches))
    return out


def fixes_as_paths(table: Dict[str, str]) -> Dict[str, str]:
    """{"3.4": …} -> {"ise-3.4": …}, the CVEFirstFixed key form."""
    return {"ise-" + train: fix for train, fix in table.items()}


def _flatten(elem) -> str:
    return re.sub(r"\s+", " ", "".join(elem.itertext())).strip()


def fixed_software_text_from_cvrf(xml_text: str) -> str:
    """The "Fixed Software" note of a CVRF document, flattened; "" if absent."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return ""
    for note in root.iter():
        if note.tag.endswith("}Note") and (note.get("Title") or "").strip().lower() == "fixed software":
            return _flatten(note)
    return ""


def vulnerabilities_from_cvrf(xml_text: str) -> Dict[str, Dict[str, object]]:
    """{cve_id: {"title", "cvss", "vector"}} — the per-CVE facts of an advisory.

    PSIRT's JSON gives one `cvssBaseScore` per ADVISORY, which is the maximum
    across its CVEs. "Cisco Identity Services Engine Vulnerabilities" is 10.0 as
    an advisory, but of its six CVEs one is 10.0 and the rest are 7.6, 7.2, 4.9,
    4.9 and 4.9. Stamping the advisory score on each would repeat, for CVSS, the
    mistake `cwe_list[0]` made for CWE. CVRF carries the real per-CVE values.
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {}
    out: Dict[str, Dict[str, object]] = {}
    for vuln in root.iter():
        if not vuln.tag.endswith("}Vulnerability"):
            continue
        rec: Dict[str, object] = {}
        cve_id = None
        for ch in vuln.iter():
            tag = ch.tag.rsplit("}", 1)[-1]
            text = (ch.text or "").strip()
            if tag == "CVE" and text.startswith("CVE-"):
                cve_id = text.upper()
            elif tag == "Title" and "title" not in rec and text:
                rec["title"] = text
            elif tag == "BaseScoreV3" and "cvss" not in rec:
                try:
                    rec["cvss"] = float(text)
                except ValueError:
                    pass
            elif tag == "VectorV3" and "vector" not in rec and text:
                rec["vector"] = text
        if cve_id:
            out[cve_id] = rec
    return out


_EXPLOITED_RE = re.compile(r"\bis aware of (?:active|attempted|continued|ongoing)? ?exploitation", re.IGNORECASE)


def exploitation_confirmed_in_cvrf(xml_text: str) -> bool:
    """True only for an affirmative PSIRT statement of exploitation.

    The common text is "is NOT aware of any public announcements or malicious
    use", so this matches the affirmative phrasing and nothing looser.
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return False
    for note in root.iter():
        if note.tag.endswith("}Note") and "exploitation" in (note.get("Title") or "").lower():
            text = _flatten(note)
            return bool(_EXPLOITED_RE.search(text)) and "not aware of" not in text.lower()
    return False


def fetch_cvrf(cvrf_url: Optional[str], timeout_seconds: int = 8) -> str:
    """Raw CVRF XML, or "" on any failure. Only Cisco's advisory host is contacted."""
    if not cvrf_url or not cvrf_url.startswith("https://sec.cloudapps.cisco.com/"):
        return ""
    try:
        req = urllib.request.Request(cvrf_url, headers={"User-Agent": "netdevops-micro-tools"})
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return ""


def ise_advisory_details(xml_text: str) -> Dict[str, object]:
    """Everything the ISE importer needs from one CVRF document."""
    return {
        "fixes": fixes_as_paths(parse_ise_fixed_table(fixed_software_text_from_cvrf(xml_text))),
        "vulnerabilities": vulnerabilities_from_cvrf(xml_text),
        "exploited": exploitation_confirmed_in_cvrf(xml_text),
    }


def fetch_ise_fixes(cvrf_url: Optional[str], timeout_seconds: int = 8) -> Dict[str, str]:
    """Fix paths for one advisory, or {} on any failure. Never raises."""
    return ise_advisory_details(fetch_cvrf(cvrf_url, timeout_seconds))["fixes"]  # type: ignore[return-value]
