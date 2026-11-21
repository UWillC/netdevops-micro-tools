"""
PREVIEW-01 "Check your release, no email" (spec 2026-11-20, CEO repo
projects/netdevops/specs/2026-11-20_podglad-bez-konta.md).

POST /analyze/cve/preview answers with counts only: Critical / High / Medium /
Low, KEV, the upgrade target with its train flag, and the date of the data. It
is a PROJECTION of the full analysis (api.routers.cve.run_analysis), never a
second engine, so the numbers cannot drift from the report behind the gate
(AC-5). Everything that lets someone act without the report stays out of the
JSON, not only out of the UI (AC-6): CVE and advisory ids, per-CVE cards,
CVSS/SIR, descriptions, mitigations, KEV ids and due dates, the list of what
remains at the target, the full provenance block, exports.

The e-mail gate is a value gate, not access control (the full analyzer answers
anyone who posts to it). What this endpoint protects is cost: CPU on Render and
the openVuln quota. Hence:
  - feature flag PREVIEW_ENABLED, default off -> 404 (T5);
  - per-IP 5/min + 30/h in api/rate_limit.py PATH_LIMITS (AC-14);
  - input rejected before the engine: platform from the analyzer's list,
    release <= 64 characters with a digit and a narrow character set (AC-3/9/10/15);
  - a global budget of uncached openVuln queries (10/min, 60/h), independent of IP
    (AC-16). Over budget the preview still answers, with the dataset's own
    upgrade check and "Cisco check unavailable right now" (AC-13).

Unknown release (AC-11): a release on no Known Affected list of its family is
asked of openVuln (IOS XE / IOS only, the per-release query we already use). A
404 / NO_DATA_FOUND, or no answer at all while nothing Critical/High matched,
is NOT EVALUATED, never "0 Critical / 0 High".

Logging (T8, AC-17): one line per answer, state and family from a fixed list.
No IP, no release, no free text.
"""

import re
import threading
import time
from collections import deque
from typing import Callable, Literal, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from api.routers import cve as cve_router
from services import cisco_software_checker as csc
from services.known_affected import version_is_listed

router = APIRouter()

PREVIEW_PATH = "/analyze/cve/preview"
MAX_PREVIEW_VERSION_LENGTH = 64

# Value of the CVE Analyzer <select> (web/index.html) -> log family (T8).
PLATFORMS = {
    "IOS XE": "ios-xe",
    "IOS": "ios",
    "NX-OS": "nx-os",
    "ISE": "ise",
    "Catalyst SD-WAN Manager": "sdwan",
    "Catalyst SD-WAN Controller": "sdwan",
    "Catalyst SD-WAN Validator": "sdwan",
}
FORMAT_HINTS = {
    "IOS XE": "Write the release as the device prints it, e.g. 17.9.4a.",
    "IOS": "Write the release as the device prints it, e.g. 15.2(7)E8.",
    "NX-OS": "Write the release as the device prints it, e.g. 10.2(6).",
    "ISE": "Write the release with its patch, e.g. 3.4 Patch 5.",
    "Catalyst SD-WAN Manager": "Write the release as the controller prints it, e.g. 20.12.5.",
    "Catalyst SD-WAN Controller": "Write the release as the controller prints it, e.g. 20.12.5.",
    "Catalyst SD-WAN Validator": "Write the release as the controller prints it, e.g. 20.12.5.",
}
# What a release, or a pasted `show version` line, is made of. Anything else is
# rejected before the engine (AC-10), with no echo of the value.
_RELEASE_CHARS = re.compile(r"^[A-Za-z0-9 .,:()_/+\-]+$")

MSG_EMPTY = "Enter a software release."
MSG_NOT_RELEASE = "This does not look like a Cisco release."
MSG_PLATFORM = "Choose a platform from the list."

NOTE_UNKNOWN = ("NOT EVALUATED: we have no data for this release. An empty result means "
                "not checked, not not vulnerable.")
NOTE_UNCONFIRMED = " Cisco's own release list could not be confirmed right now."
NOTE_SYNCING = "Dataset is syncing, try again in a minute."
# @ciso W1: the engine's own NOT EVALUATED notes can name CVE ids (SD-WAN), so
# the preview never passes them through.
NOTE_NOT_EVALUATED = ("NOT EVALUATED: our dataset cannot evaluate this release on this platform. "
                      "An empty result means not checked, not not vulnerable.")
NOTE_CLEAN = ("Our dataset covers Cisco PSIRT advisories; it is not a full scan of your "
              "device.")
NOTE_EOL = "Hardware replacement required, no software fix path."
NOTE_NO_PATH = "No upgrade path computed for this release, see the full report."
NOTE_CISCO_DOWN = "Cisco check unavailable right now."
SOURCES = "Cisco PSIRT advisories (openVuln API), CISA KEV catalog"

SEVERE = ("Critical", "High")

# AC-16: uncached openVuln QUERIES started from the preview, all callers together
# (@ciso W2: one pass is up to 4 queries, so the budget counts queries), with a
# per-minute sub-limit so a burst cannot spend the hour at once.
OPENVULN_CAP = ((10, 60), (60, 60 * 60))


def enabled() -> bool:
    return cve_router._env_true("PREVIEW_ENABLED")


class OpenVulnBudget:
    """Sliding-window count of uncached openVuln queries made for the preview."""

    def __init__(self, cap=OPENVULN_CAP, clock: Callable[[], float] = time.monotonic):
        self.limits = tuple(cap)
        self._horizon = max(w for _, w in self.limits)
        self._clock = clock
        self._spent = deque()
        self._lock = threading.Lock()

    def take(self) -> bool:
        now = self._clock()
        with self._lock:
            while self._spent and self._spent[0] <= now - self._horizon:
                self._spent.popleft()
            for max_count, window in self.limits:
                if sum(1 for t in self._spent if t > now - window) >= max_count:
                    return False
            self._spent.append(now)
            return True


budget = OpenVulnBudget()


class _RequestGate:
    """live_gate for one preview request: every uncached query costs one unit."""

    def __init__(self):
        self.denied = False

    def __call__(self) -> bool:
        if self.denied:
            return False
        if budget.take():   # module global: tests swap the budget
            return True
        self.denied = True
        print("INFO preview openvuln_cap_hit")
        return False


class CVEPreviewRequest(BaseModel):
    platform: str
    version: str


class PreviewUpgrade(BaseModel):
    source: Literal["cisco", "dataset"]
    target: Optional[str] = None
    # "same" train, train "change", or "migration" (ISE train without a fix)
    train: Optional[Literal["same", "change", "migration"]] = None
    critical_high_left: Optional[int] = None
    note: Optional[str] = None


class CVEPreviewResponse(BaseModel):
    state: Literal["findings", "clean", "eol", "unknown", "not_evaluated"]
    interpreted_as: Optional[str] = None
    critical: Optional[int] = None
    high: Optional[int] = None
    medium: Optional[int] = None
    low: Optional[int] = None
    kev: Optional[int] = None
    need_confirmation: Optional[int] = None
    upgrade: Optional[PreviewUpgrade] = None
    upgrade_note: Optional[str] = None
    eol_note: Optional[str] = None
    note: Optional[str] = None
    format_hint: Optional[str] = None
    data_as_of: Optional[str] = None
    sources: str = SOURCES


def _log(state: str, platform: Optional[str]) -> None:
    print(f"INFO preview state={state} family={PLATFORMS.get(platform or '', 'other')}")


def _reject(detail: str, platform: Optional[str]):
    _log("invalid", platform)
    raise HTTPException(status_code=400, detail=detail)


def validate(req: CVEPreviewRequest) -> str:
    """The release to analyse, or 400 without echoing anything the caller sent."""
    platform = req.platform if req.platform in PLATFORMS else None
    if platform is None:
        _reject(MSG_PLATFORM, None)
    version = req.version or ""
    if len(version) > MAX_PREVIEW_VERSION_LENGTH:   # before strip: no work on a long value
        _reject(MSG_NOT_RELEASE, platform)
    version = version.strip()
    if not version:
        _reject(MSG_EMPTY, platform)
    if not _RELEASE_CHARS.match(version) or not re.search(r"\d", version):
        _reject(MSG_NOT_RELEASE, platform)
    return version


def _display_version(platform: str, version: str) -> str:
    v = version
    if v.lower().startswith(platform.lower() + " "):
        v = v[len(platform) + 1:].strip()
    return f"{platform} {v}"


def _train_keys(engine) -> set:
    """major.minor trains named in the dataset's fix tables (families without KA lists)."""
    trains = set()
    for c in engine.cves:
        ffv = getattr(c, "first_fixed_version", None)
        fixes = getattr(ffv, "fixes", None) or (ffv.get("fixes") if isinstance(ffv, dict) else None) or {}
        for key in fixes:
            m = re.search(r"-(\d+\.\d+)$", str(key))
            if m:
                trains.add(m.group(1))
    return trains


def release_listed(engine, version: str) -> bool:
    """Does our dataset name this release anywhere (Known Affected list or fix-table train)?"""
    family = getattr(engine, "known_affected_family", None)
    if family:
        listed = {v for c in engine.cves for v in ((c.known_affected or {}).get(family) or [])}
        return version_is_listed(version, listed, family)
    m = re.match(r"^\s*(\d+)\.(\d+)", version or "")
    return bool(m) and f"{int(m.group(1))}.{int(m.group(2))}" in _train_keys(engine)


def data_as_of(provenance: dict) -> Optional[str]:
    dates = [s.get("last_refreshed") for s in (provenance or {}).get("sources") or []
             if s.get("available") and s.get("last_refreshed")]
    return max(dates)[:10] if dates else None


def project_upgrade(full) -> Optional[PreviewUpgrade]:
    """Target + train flag + Critical/High left. Cisco's path first, the dataset check second."""
    cp = full.cisco_upgrade_path
    if cp:
        if cp.get("target"):
            left = sum(1 for r in cp.get("remaining") or [] if r.get("sir") in SEVERE)
            return PreviewUpgrade(source="cisco", target=cp["target"],
                                  train="same" if cp.get("same_train") else "change",
                                  critical_high_left=left)
        if cp.get("same_train") is True:
            note = ("Cisco names a first fixed release on your train that its API cannot "
                    "check yet. The full report names it.")
        else:
            note = ("No release on your train clears every Critical/High advisory (Cisco). "
                    "Plan a train change; the full report lists what blocks it.")
        return PreviewUpgrade(source="cisco", note=note)
    utc = full.upgrade_target_check
    if utc:
        if utc.get("target"):
            kind = {"same-train": "same", "train-change": "change",
                    "migration": "migration"}.get(utc.get("kind"))
            return PreviewUpgrade(source="dataset", target=utc["target"], train=kind,
                                  critical_high_left=len(utc.get("critical_high") or []))
        return PreviewUpgrade(source="dataset",
                              note="No newer train in our dataset closes every known CVE. "
                                   "See the full report.")
    return None


def preview_target(full) -> Optional[str]:
    """The target the preview shows, picked from a full response (AC-5 parity)."""
    up = project_upgrade(full)
    return up.target if up else None


@router.post("/cve/preview", response_model=CVEPreviewResponse)
def analyze_cve_preview(req: CVEPreviewRequest):
    if not enabled():
        raise HTTPException(status_code=404, detail="Not Found")
    version = validate(req)
    platform = req.platform

    gate = _RequestGate()
    out: dict = {}
    full = cve_router.run_analysis(
        cve_router.CVEAnalyzeRequest(platform=platform, version=version, include_suggestions=True),
        live_gate=gate, engine_out=out)
    engine, bare = out.get("engine"), out.get("version", version)
    eff_platform = out.get("platform", platform)
    base = dict(interpreted_as=_display_version(platform, bare),
                data_as_of=data_as_of(full.provenance))

    # AC-12: platform not covered, or the dataset is being synchronised.
    if (full.coverage_note or "").startswith("NOT EVALUATED") or full.dataset_syncing:
        _log("not_evaluated", platform)
        return CVEPreviewResponse(
            state="not_evaluated",
            note=NOTE_SYNCING if full.dataset_syncing else NOTE_NOT_EVALUATED,
            format_hint=None if full.dataset_syncing else FORMAT_HINTS[platform], **base)

    s = full.summary or {}
    crit, high = int(s.get("critical", 0)), int(s.get("high", 0))

    # AC-11: a release nobody knows is NOT EVALUATED, never 0 / 0.
    ostype = cve_router._openvuln_ostype(eff_platform, bare)
    if engine is not None and not release_listed(engine, bare):
        cisco_known = csc.release_known(ostype, bare, live_gate=gate) if ostype else None
        if cisco_known is False or (cisco_known is None and crit + high == 0):
            _log("unknown", platform)
            return CVEPreviewResponse(
                state="unknown",
                note=NOTE_UNKNOWN + (NOTE_UNCONFIRMED if cisco_known is None else ""),
                format_hint=FORMAT_HINTS[platform], **base)

    uncertain = set(full.coverage_uncertain or [])
    counts = dict(
        critical=crit, high=high,
        medium=int(s.get("medium", 0)), low=int(s.get("low", 0)),
        kev=sum(1 for c in full.matched if c.kev is not None),
        need_confirmation=sum(1 for c in full.matched
                              if c.cve_id in uncertain
                              and (c.severity or "").lower() in ("critical", "high")),
    )

    eol = bool(full.eol_status and full.eol_status.get("is_eol"))
    if eol:
        _log("eol", platform)
        return CVEPreviewResponse(state="eol", eol_note=NOTE_EOL, **counts, **base)

    upgrade = project_upgrade(full)
    upgrade_note = None
    if upgrade is None:
        upgrade_note = NOTE_NO_PATH
    if (ostype and full.matched and full.cisco_upgrade_path is None
            and csc.cached_result(ostype, bare) is None):
        # AC-13: openVuln offline, over its time budget, or over the AC-16 budget.
        upgrade_note = NOTE_CISCO_DOWN if upgrade else f"{NOTE_CISCO_DOWN} {NOTE_NO_PATH}"

    state = "findings" if crit + high else "clean"
    _log(state, platform)
    return CVEPreviewResponse(
        state=state, upgrade=upgrade, upgrade_note=upgrade_note,
        note=NOTE_CLEAN if state == "clean" else None, **counts, **base)
