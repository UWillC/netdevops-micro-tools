"""
PREVIEW-01, version of 22.11 (CEO repo projects/netdevops/specs/2026-11-20_podglad-bez-konta.md,
AC-6, AC-18, AC-19; user decision 21.11 "full change plan for the one most dangerous finding").

The preview answer carries ONE finding with a change plan. Everything here is a
projection of data that already exists: the full analysis (api.routers.cve.run_analysis),
the reviewed mitigation files (services.mitigation_service.get_mitigation_for_platform)
and the Cisco-sourced rollback templates (cve_rollback/rollback_templates.json).
Nothing is generated; a gap is said out loud ("No reviewed steps ...").

AC-6 in the JSON, not only in the UI: the answer names exactly one CVE id. Cisco's own
texts often name sibling CVEs of a bundled advisory ("these vulnerabilities ..."), so
any other CVE id inside a text is replaced by OTHER_CVE, and a link that names another
CVE is dropped.
"""

import json
import re
from pathlib import Path
from typing import List, Literal, Optional
from urllib.parse import urlparse

from pydantic import BaseModel

from services.cve_engine import DEFAULT_DATA_DIR, data_dir_for_platform
from services.mitigation_service import get_mitigation_service

ROLLBACK_FILE = Path(__file__).resolve().parent.parent / "cve_rollback" / "rollback_templates.json"

CVE_ID = re.compile(r"CVE-\d{4}-\d+", re.I)
# @ciso P5: also catch loose spellings ("CVE 2023 20273", "cve_2023_20273", "CVE-2023–20273").
CVE_LOOSE = re.compile(r"CVE[\s_\-\u2010-\u2015]*(\d{4})[\s_\-\u2010-\u2015]*(\d{4,})", re.I)
# @ciso P2: the whole link is checked by one strict pattern (no userinfo, no backslash,
# no percent-encoding, host = cisco.com / cisa.gov or a subdomain), not by urlparse alone.
LINK_RE = re.compile(r"^https://(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*(?:cisco\.com|cisa\.gov)"
                     r"(?:/[A-Za-z0-9._~!$&'()*+,;=:/?#\-]*)?$", re.I)
OTHER_CVE = "[another CVE, listed in the full report]"
# Links we pass on: Cisco and CISA pages over https only.
LINK_HOSTS = ("cisco.com", "cisa.gov")

SEVERE = ("critical", "high")

TITLES = {
    "applies": "Does this apply to you",
    "workaround": "Workaround (Cisco advisory)",
    "target": "Target release",
    "upgrade": "Upgrade",
    "verify": "Verify",
    "sources": "Sources",
    "rollback": "Rollback",
}
HEADER_UNCERTAIN = "Needs confirmation on your device"
MSG_NO_STEPS = "No reviewed steps for this CVE yet. See the Cisco advisory."  # copy v1 (@cmo 22.11)
# AC-19 v24.11 (copy section 9, draft @pm, @cmo final): sections 2 and 5 of the fallback,
# no link; the advisory link stays in sections 1, 4 and 6 only.
MSG_NO_STEPS_SEE_1 = "No reviewed steps for this CVE yet. Use the Cisco advisory linked in section 1."
MSG_NO_WORKAROUND = "Cisco lists no workaround for this vulnerability. Upgrade is the fix."
MSG_UNKNOWN_WORKAROUND = "Cisco's workaround section is not in our data yet, see the Cisco advisory."
MSG_UPGRADE_LINK = "Get the target release from Cisco Software Download; the advisory lists the fixed releases."
MSG_NO_TARGET = "No upgrade path computed for this release, see the full report."
MSG_ROLLBACK_FALLBACK = "Rollback: follow Cisco's upgrade guide for {family}."
LABEL_OUR_STEPS = "Our steps, checked against Cisco's text on {date}"
LABEL_OUR_ACL = "Our ACL, checked against Cisco's text on {date}"
LINK_FULL_TEXT = "Read Cisco's full text"   # user decision 23.11 (1)
LABEL_CISCO_EXCERPT = "Excerpt from Cisco's advisory"   # user decision 23.11 ("2 tak", PREVIEW-INTRO-01)
LABEL_APPLICABILITY = "Applicability"
LABEL_VULNERABLE_IF = "Vulnerable if"
LABEL_EXPECTED = "Expected"
# Cisco's texts paste links as ["https://..."]; the preview drops them (the advisory link stays).
RAW_LINK = re.compile(r'\s*\[\s*"https?://[^"\]]*"\s*\]')
PARAGRAPH_BREAK = re.compile(r"\n[ \t]*\n")
# PREVIEW-INTRO-01: a first paragraph that is only Cisco's "no workarounds" sentence, or that
# ends with a colon ("... do the following:"), takes the next paragraph with it, within limits
# so the card does not grow back to the full text.
# PREVIEW-INTRO-02 (user 23.11 "3 tak"): the same rule for the positive intro sentences
# ("There is a workaround ...", "There are workarounds ...", "... and a mitigation ...").
INTRO_ONLY = re.compile(r"^There (?:(?:are|is) no workarounds?|is a workaround(?: and a mitigation)?"
                        r"|are workarounds) that address(?:es)? "
                        r"(?:this|these) vulnerabilit(?:y|ies)\.?$", re.I)
EXCERPT_MAX_PARAS = 2
EXCERPT_MAX_CHARS = 900
SENTENCE_END = re.compile(r"[.!?](?=\s)")
SENTENCE_END_OR_EOS = re.compile(r"[.!?](?=\s|$)")
ELLIPSIS = "\u2026"
TRAIN_TEXT = {"same": "same train", "change": "train change",
              "migration": "migration to a supported train"}


class PlanLink(BaseModel):
    label: str
    url: str


class PlanBlock(BaseModel):
    label: Optional[str] = None
    text: Optional[str] = None
    commands: List[str] = []


class PlanSection(BaseModel):
    id: Literal["applies", "workaround", "target", "upgrade", "verify", "sources", "rollback"]
    title: str
    source: str           # one word: where the section comes from
    blocks: List[PlanBlock] = []
    links: List[PlanLink] = []


class TopFinding(BaseModel):
    cve_id: str
    title: str
    severity: str
    cvss: Optional[float] = None
    kev: bool = False
    published: Optional[str] = None
    needs_confirmation: bool = False
    header: Optional[str] = None
    plan: List[PlanSection]


# ------------------------------------------------------------------ AC-18

def is_severe(c) -> bool:
    return (c.severity or "").lower() in SEVERE


def pick_top(matched, uncertain_ids) -> Optional[object]:
    """The one finding the preview explains. AC-18 v24.11: the pool is every Critical/High
    match plus every KEV match of any severity (the KEV warning and the plan must name the
    same vulnerability); Medium/Low without KEV never compete. Order: (1) in KEV,
    (2) highest CVSS, (3) newest advisory publication, (4) CVE id ascending. Uncertain
    matches compete only when there is no certain one in the pool."""
    severe = [c for c in matched or [] if is_severe(c) or c.kev is not None]
    if not severe:
        return None
    uncertain = set(uncertain_ids or [])
    pool = [c for c in severe if c.cve_id not in uncertain] or severe
    # Stable sorts, least significant key first: id ascending, then newest
    # publication date, then KEV and highest CVSS (unknown CVSS counts as lowest).
    pool = sorted(pool, key=lambda c: c.cve_id.upper())
    pool = sorted(pool, key=lambda c: (c.published or "")[:10], reverse=True)
    pool = sorted(pool, key=lambda c: (c.kev is None, -(c.cvss_score if c.cvss_score is not None else -1.0)))
    return pool[0]


def count_more_findings(critical: int, high: int, top) -> Optional[int]:
    """AC-18 v24.11: Critical/High findings other than `top_finding` (a Medium/Low KEV
    pick is not one of them). None without a plan."""
    if top is None:
        return None
    n = critical + high - (1 if top.severity.lower() in SEVERE else 0)
    return max(n, 0)


# ------------------------------------------------------------------ AC-6 scrubbing

def _scrub(text: Optional[str], own_id: str) -> Optional[str]:
    if text is None:
        return None
    own = own_id.upper()
    return CVE_LOOSE.sub(lambda m: m.group(0) if f"CVE-{m.group(1)}-{m.group(2)}" == own else OTHER_CVE,
                         str(text))


def _link(label: str, url: Optional[str], own_id: str) -> Optional[PlanLink]:
    if not url or not isinstance(url, str):
        return None
    url = url.strip()
    if not LINK_RE.match(url) or "@" in url or "\\" in url or "%" in url:
        return None
    host = (urlparse(url).hostname or "").lower()
    if not any(host == h or host.endswith("." + h) for h in LINK_HOSTS):
        return None
    if any(f"CVE-{a}-{b}" != own_id.upper() for a, b in CVE_LOOSE.findall(url)):
        return None
    return PlanLink(label=label, url=url)


def _needs_next(paragraph: str) -> bool:
    return paragraph.endswith(":") or bool(INTRO_ONLY.match(paragraph))


def _drop_colon_sentence(paragraph: str) -> str:
    """'... received. The following is an example:' -> '... received.' ('' if nothing is left)."""
    ends = list(SENTENCE_END.finditer(paragraph))
    return paragraph[:ends[-1].end()].rstrip() if ends else ""


def _cap(excerpt: str, limit: int) -> str:
    """@ciso W2 (v0.7.21 review): hard length limit. Cut at the last sentence end within
    the limit; with no sentence end there, cut at a word boundary and add an ellipsis."""
    if len(excerpt) <= limit:
        return excerpt
    ends = [m.end() for m in SENTENCE_END_OR_EOS.finditer(excerpt[:limit])]
    if ends:
        return excerpt[:ends[-1]].rstrip()
    head = excerpt[:limit - len(ELLIPSIS)]
    space = max(head.rfind(" "), head.rfind("\n"))
    return (head[:space] if space > 0 else head).rstrip() + ELLIPSIS


def cisco_excerpt(text: Optional[str], own_id: Optional[str] = None):
    """User decision 23.11 (1): the preview shows the start of a Cisco text, without the
    raw ["https://..."] links; the rest stays behind "Read Cisco's full text".
    PREVIEW-INTRO-01 (user 23.11 "2 tak"): a first paragraph that ends with a colon or is
    only "There are no workarounds ..." (PREVIEW-INTRO-02, user 23.11 "3 tak": or "There is
    a workaround ...", "There are workarounds ...") takes the next one (at most EXCERPT_MAX_PARAS,
    EXCERPT_MAX_CHARS). An excerpt that still ends with a colon loses that last sentence.
    @ciso W2: the result is never longer than EXCERPT_MAX_CHARS, measured after the AC-6
    scrub when own_id is given (OTHER_CVE is longer than a CVE id; the scrub is idempotent).
    Returns (excerpt, shortened)."""
    if not text:
        return text, False
    full = str(text).replace("\r\n", "\n").replace("\r", "\n").strip()
    raw = [p.strip() for p in PARAGRAPH_BREAK.split(full) if p.strip()] or [full]
    paras = [q for q in (RAW_LINK.sub("", p).strip() for p in raw) if q]
    if not paras:
        return "", True
    take = [paras[0]]
    while (len(take) < min(EXCERPT_MAX_PARAS, len(paras)) and _needs_next(take[-1])
           and sum(map(len, take)) + len(paras[len(take)]) <= EXCERPT_MAX_CHARS):
        take.append(paras[len(take)])
    if take[-1].endswith(":"):
        cut = _drop_colon_sentence(take[-1])
        if cut:
            take[-1] = cut
        elif len(take) > 1:
            take.pop()
    excerpt = "\n\n".join(take)
    if own_id:
        excerpt = _scrub(excerpt, own_id)
    capped = _cap(excerpt, EXCERPT_MAX_CHARS)
    return capped, capped != excerpt or len(take) < len(raw) or excerpt != "\n\n".join(raw)


def _block(own_id: str, label=None, text=None, commands=None) -> PlanBlock:
    return PlanBlock(label=label, text=_scrub(text, own_id),
                     commands=[_scrub(c, own_id) for c in (commands or [])])


# ------------------------------------------------------------------ rollback (T14)

_rollback_cache: Optional[dict] = None


def rollback_data() -> dict:
    global _rollback_cache
    if _rollback_cache is None:
        _rollback_cache = json.loads(ROLLBACK_FILE.read_text(encoding="utf-8"))
    return _rollback_cache


def rollback_section(platform: str, own_id: str) -> PlanSection:
    data = rollback_data()
    by_id = {f["id"]: f for f in data["families"]}
    blocks, links = [], []
    for fid in data["platforms"].get(platform, []):
        fam = by_id[fid]
        link = _link(f"Cisco: {fam['source_title']}", fam["source"], own_id)
        if link and link.url not in {l.url for l in links}:
            links.append(link)
        if not fam["steps"]:
            blocks.append(_block(own_id, label=fam["label"],
                                 text=MSG_ROLLBACK_FALLBACK.format(family=fam["label"])))
            continue
        for step in fam["steps"]:
            blocks.append(_block(own_id, label=fam["label"], text=step["text"],
                                 commands=step["commands"]))
    return PlanSection(id="rollback", title=TITLES["rollback"], source="Cisco",
                       blocks=blocks, links=links)


# ------------------------------------------------------------------ AC-19

def _mitigation(cve_id: str, platform: str, version: str):
    """Reuse the Mitigation Advisor lookup. Its applicability check runs on the IOS XE
    dataset only, so for other families it is asked without device context (the
    preview already knows the CVE matched, from the engine of the right family)."""
    svc = get_mitigation_service()
    if data_dir_for_platform(platform) == DEFAULT_DATA_DIR:
        return svc.get_mitigation_for_platform(cve_id, platform, version)
    return svc.get_mitigation_for_platform(cve_id)


def build_top_finding(full, platform: str, version: str, upgrade, data_as_of: Optional[str],
                      eol: bool) -> Optional[TopFinding]:
    """`full` = run_analysis() answer, `upgrade` = the PreviewUpgrade the counts show
    (same target as AC-4 and the full report, AC-5)."""
    top = pick_top(full.matched, full.coverage_uncertain)
    if top is None:
        return None
    cid = top.cve_id
    uncertain = cid in set(full.coverage_uncertain or [])
    resp = _mitigation(cid, platform, version)
    m = resp.mitigation if resp.found else None
    advisory = _link("Cisco advisory", (m.cisco_psirt if m else None) or top.advisory_url, cid)
    adv_links = [advisory] if advisory else []

    def no_steps(sid: str) -> PlanSection:
        # AC-19 v24.11: the advisory link only in section 1 (plus 4 and 6), not 5 times.
        if sid == "applies":
            return PlanSection(id=sid, title=TITLES[sid], source="Cisco",
                               blocks=[PlanBlock(text=MSG_NO_STEPS)], links=adv_links)
        # @ciso R2 24.11: no link in section 1 = do not send people there.
        return PlanSection(id=sid, title=TITLES[sid], source="Cisco",
                           blocks=[PlanBlock(text=MSG_NO_STEPS_SEE_1 if adv_links else MSG_NO_STEPS)])

    # 1. Does this apply to you
    if m:
        blocks = [_block(cid, text=m.detection.description, commands=m.detection.commands),
                  _block(cid, label=LABEL_VULNERABLE_IF, text=m.detection.vulnerable_if)]
        if resp.applicability_reason:
            blocks.append(_block(cid, label=LABEL_APPLICABILITY, text=resp.applicability_reason))
        applies = PlanSection(id="applies", title=TITLES["applies"], source="NetDevOps", blocks=blocks)
    else:
        applies = no_steps("applies")

    # 2. Workaround: Cisco's text 1:1, ours under it only when reviewed.
    if m:
        cw = m.cisco_workaround
        blocks, wk_links = [], adv_links
        if cw is None or cw.status == "unknown":
            blocks.append(PlanBlock(text=MSG_UNKNOWN_WORKAROUND))
        elif cw.status == "none":
            blocks.append(PlanBlock(text=MSG_NO_WORKAROUND))
        else:
            excerpt, shortened = cisco_excerpt(cw.text, cid)
            blocks.append(_block(cid, label=LABEL_CISCO_EXCERPT if shortened else f"Cisco: {cw.status}",
                                 text=excerpt))
            full_text = _link(LINK_FULL_TEXT, advisory.url, cid) if (shortened and advisory) else None
            if full_text:
                wk_links = [full_text]
        if m.steps_reviewed:
            for step in m.workaround_steps:
                blocks.append(_block(cid, label=LABEL_OUR_STEPS.format(date=m.steps_reviewed),
                                     text=step.description, commands=step.commands))
            if m.acl_mitigation:
                blocks.append(_block(cid, label=LABEL_OUR_ACL.format(date=m.steps_reviewed),
                                     text=m.acl_mitigation.description,
                                     commands=m.acl_mitigation.commands))
        # cw.source is the machine-readable CSAF file; people get the advisory page.
        workaround = PlanSection(id="workaround", title=TITLES["workaround"], source="Cisco",
                                 blocks=blocks, links=wk_links)
    else:
        workaround = no_steps("workaround")

    # 6. Sources
    src_links = list(adv_links)
    if m:
        cisa = _link("CISA alert", m.cisa_alert, cid)
        if cisa:
            src_links.append(cisa)
    sources = PlanSection(id="sources", title=TITLES["sources"], source="Cisco",
                          blocks=[PlanBlock(text=f"Data as of {data_as_of}.")] if data_as_of else [],
                          links=src_links)

    if eol:   # AC-18: EoL = no upgrade steps, only 1, 2 and 6
        plan = [applies, workaround, sources]
    else:
        # 3. Target release (same value as the counts and the full report)
        if upgrade is not None and upgrade.target:
            train = TRAIN_TEXT.get(upgrade.train or "", "")
            text = (f"{upgrade.target}" + (f" ({train})" if train else "")
                    + f". Critical/High left at target: {upgrade.critical_high_left}.")
            target = PlanSection(id="target", title=TITLES["target"],
                                 source="Cisco" if upgrade.source == "cisco" else "Dataset",
                                 blocks=[PlanBlock(text=text)])
        else:
            target = PlanSection(id="target", title=TITLES["target"],
                                 source="Cisco" if (upgrade and upgrade.source == "cisco") else "Dataset",
                                 blocks=[PlanBlock(text=(upgrade.note if upgrade and upgrade.note
                                                         else MSG_NO_TARGET))])
        # 4. Upgrade. User decision 23.11 (3): only the target computed for all findings;
        # the per-CVE notes (mitigation file `upgrade_path`) stay in the full report.
        up_blocks = [PlanBlock(text=MSG_UPGRADE_LINK)]
        if upgrade is not None and upgrade.target:
            up_blocks.insert(0, PlanBlock(label=TITLES["target"], text=upgrade.target))
        up = PlanSection(id="upgrade", title=TITLES["upgrade"], source="Cisco",
                         blocks=up_blocks, links=adv_links)
        # 5. Verify
        if m:
            verify = PlanSection(id="verify", title=TITLES["verify"], source="NetDevOps", blocks=[
                _block(cid, text=m.verification.description, commands=m.verification.commands),
                _block(cid, label=LABEL_EXPECTED, text=m.verification.expected_output)])
        else:
            verify = no_steps("verify")
        plan = [applies, workaround, target, up, verify, sources, rollback_section(platform, cid)]

    cvss = top.cvss_score
    return TopFinding(
        cve_id=cid, title=_scrub(top.title, cid), severity=(top.severity or "").capitalize(),
        cvss=cvss, kev=top.kev is not None, published=(top.published or "")[:10] or None,
        needs_confirmation=uncertain, header=HEADER_UNCERTAIN if uncertain else None, plan=plan)
