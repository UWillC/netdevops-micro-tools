"""
ACL Lint + What-if Trace endpoint (ACL-01.3, 2026-10-28).

Spec: CEO repo projects/netdevops/spec_acl-01_v0_2026-10-22.md, sections 3-5.
Engines: services/acl_engine.py (parser + trace, ACL-01.1),
services/acl_lint.py (lint L01-L11/P01, ACL-01.2),
services/acl_packets.py (auto-packets from rule edges, ACL-01.3).

Endpoint:
  POST /tools/acl/analyze - parse a pasted IPv4 ACL, lint it, build the
  auto-packet table and (optionally) trace one packet.

The paste is untrusted text. The endpoint reads it as data only: no eval, no
regex built from the input, nothing written to disk, nothing logged. Size is
capped BEFORE parsing (characters and lines) and the rule count right after
parsing, before the lint (indexed, near-linear up to MAX_RULES). A rejected paste is not echoed back (pydantic's own
max_length error would return the whole input, hence the manual check).
Errors are short sentences, never a stack trace.

Schema errors (@ciso N2, ACL-01.4, 2026-10-28): FastAPI's default 422 copies
each offending value into an ``input`` field, so a 50 000-character
``trace.src`` (or a non-string ``config_text``) came back whole. For this path
api/main.py routes RequestValidationError to ``validation_error_body`` below,
which keeps only ``type``, ``loc`` and ``msg`` (no ``input``, no ``ctx``, no
``url``), at most MAX_SCHEMA_ERRORS entries with short strings. The ACL-01.3
report said the pydantic 422 carried "short fields, no config_text": that was
wrong before this change. The per-IP POST limit in
api/rate_limit.py applies, with a stricter path limit for this endpoint
(10/min and 120/h, @ciso W1 2026-10-28).

Concurrency (@ciso W2, 2026-10-28): one analysis costs ~0.4 s of CPU locally
(~1 s on Render), in the single uvicorn process every tool shares. A per-IP
limit does not stop a few addresses at once, so at most MAX_CONCURRENT analyses
run at a time; a request that finds no free slot is refused at once with 503,
Retry-After and a fixed sentence, never queued. The handler is a plain ``def``:
FastAPI runs it in the anyio worker thread pool, not on the event loop, so the
slot is a ``threading.BoundedSemaphore`` (an ``asyncio.Semaphore`` is bound to
the loop and not thread-safe). ``acquire(blocking=False)`` never waits, and the
slot is released in ``finally`` on every exit (200, 413, 422). Pydantic's own
422 fires before the handler runs, so it never takes a slot.

Response size (@ciso W3, 2026-10-28): every ACL adds up to MAX_PACKETS_PER_ACL
auto-packets plus its own summary and lint lines, so the ACL count is capped
together with the rule count (MAX_ACLS). The lint findings still scale with the
rules, so the serialized response is also capped (MAX_RESPONSE_BYTES, 413).
"""

import threading

from typing import Any, Dict, List, Optional, Union

from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel, Field

from services.acl_engine import STATUS_OK, Packet, parse_acls, trace
from services.acl_lint import lint
from services.acl_packets import auto_packets

router = APIRouter()

ENGINE_VERSION = "acl-01.4"
ANALYZE_PATH = "/tools/acl/analyze"

# Schema-error body (@ciso N2): bounded whatever the request holds.
MAX_SCHEMA_ERRORS = 10
_MAX_LOC_PART = 40
_MAX_MSG = 160

# Spec section 5: < 200 ms for an ACL of up to 500 lines. The cap is twice that,
# so a `show run` excerpt with some non-ACL lines around the ACL still fits.
MAX_CHARS = 100_000
MAX_LINES = 1_000
# The lint finds overlapping earlier rules through a per-ACL index (near-linear
# up to this cap; the cost grows faster above ~1000 rules), so the rule count is
# capped on its own: 500 = the size the spec's timing target names. Raising it
# needs a new worst-case measurement on Render (@ciso W4b, 2026-10-28).
MAX_RULES = 500
# Response size grows with the ACL count (auto-packets per ACL, names repeated in
# every row): 50 ACLs cut the 500-ACL worst case (~1.1 MB) early, before the lint.
MAX_ACLS = 50
# Measured 2026-10-28: 50 ACLs x 10 overlapping rules with long names still give
# ~0.7 MB (lint findings ~0.4 KB each, up to ~1.6 per rule), so the ACL cap alone
# does not hold the @ciso W3 bound. Backstop: the serialized response is refused
# with 413 above this size. Clients that omit Accept-Encoding would get any
# compression undone, so a hard cap is the only bound on transfer.
MAX_RESPONSE_BYTES = 300_000

# At most this many analyses at once, process-wide (@ciso W2). Non-blocking.
MAX_CONCURRENT = 2
BUSY_RETRY_AFTER = 5  # seconds
BUSY_MESSAGE = "ACL analysis is busy right now. Try again in a few seconds."
_slots = threading.BoundedSemaphore(MAX_CONCURRENT)


class TraceRequest(BaseModel):
    acl: Optional[str] = Field(default=None, max_length=64,
                               description="ACL name or number; optional when the paste holds one ACL")
    src: str = Field(..., max_length=15, description="Source IPv4 address")
    dst: Optional[str] = Field(default=None, max_length=15,
                               description="Destination IPv4 address (required for an extended ACL)")
    protocol: Optional[Union[int, str]] = Field(
        default=None, description="tcp | udp | icmp | 0-255 (required for an extended ACL)")
    src_port: Optional[int] = Field(default=None, ge=0, le=65535)
    dst_port: Optional[int] = Field(default=None, ge=0, le=65535)
    established: bool = Field(default=False, description="Packet belongs to an established TCP session")


class AclAnalyzeRequest(BaseModel):
    config_text: str = Field(..., description="IPv4 ACLs as pasted from show run, a template or a change file")
    trace: Optional[TraceRequest] = Field(default=None, description="One what-if packet to trace")
    auto_packets: bool = Field(default=True, description="Build the auto-packet table from rule edges")


class AclSummary(BaseModel):
    acl: str
    type: str
    forms: List[str]
    rules: int
    evaluated_rules: int


class AclAnalyzeResponse(BaseModel):
    engine: str
    acls: List[AclSummary]
    lint: Dict[str, Any]
    auto_packets: List[Dict[str, Any]]
    trace: Optional[Dict[str, Any]] = None


def validation_error_body(errors: List[Dict[str, Any]]) -> Dict[str, Any]:
    """422 body for a schema error on this endpoint, without the offending value.

    ``errors`` is ``RequestValidationError.errors()``. Every entry loses
    ``input`` / ``ctx`` / ``url``; ``loc`` parts and ``msg`` are cut short, and
    the list is capped, so the body stays small for any request.
    """
    out = []
    for err in errors[:MAX_SCHEMA_ERRORS]:
        loc = [part if isinstance(part, int) else str(part)[:_MAX_LOC_PART]
               for part in err.get("loc", ())][:6]
        out.append({"type": str(err.get("type", ""))[:_MAX_LOC_PART],
                    "loc": loc,
                    "msg": str(err.get("msg", ""))[:_MAX_MSG]})
    return {"detail": out}


def _check_size(text: str) -> None:
    if len(text) > MAX_CHARS:
        raise HTTPException(status_code=413,
                            detail="Paste too large: at most %d characters." % MAX_CHARS)
    # The parser splits with str.splitlines(), which also breaks on \r, \v, \f,
    # \x1c-\x1e, \x85, \u2028, \u2029: count the same way, or a paste joined
    # with \r would pass a \n count and reach the parser with 3x more rules.
    if len(text.splitlines()) > MAX_LINES:
        raise HTTPException(status_code=413,
                            detail="Paste too large: at most %d lines." % MAX_LINES)
    if not text.strip():
        raise HTTPException(status_code=422, detail="Paste at least one ACL.")


def _protocol(value: Union[int, str, None]) -> Union[int, str, None]:
    if isinstance(value, str):
        value = value.strip().lower()
        if len(value) > 4:
            raise HTTPException(status_code=422,
                                detail="Packet protocol must be tcp, udp, icmp or 0-255.")
    return value


def _run_trace(parsed, req: TraceRequest) -> Dict[str, Any]:
    name = req.acl
    if name is None:
        if len(parsed.acls) != 1:
            raise HTTPException(status_code=422,
                                detail="Name the ACL to trace: the paste holds %d ACLs." % len(parsed.acls))
        name = next(iter(parsed.acls))
    if name not in parsed.acls:
        raise HTTPException(status_code=422, detail="ACL to trace was not found in the paste.")
    packet = Packet(src=req.src.strip(), dst=req.dst.strip() if req.dst else None,
                    protocol=_protocol(req.protocol), src_port=req.src_port,
                    dst_port=req.dst_port, established=req.established)
    try:
        return trace(parsed, name, packet)
    except ValueError as exc:
        # Messages come from services/acl_engine.py (fixed sentences, no input echoed).
        raise HTTPException(status_code=422, detail="Invalid packet: %s." % exc)


@router.post("/acl/analyze", response_model=AclAnalyzeResponse)
def analyze_acl(req: AclAnalyzeRequest):
    """Lint a pasted IPv4 ACL, trace edge packets, optionally trace one packet."""
    if not _slots.acquire(blocking=False):
        raise HTTPException(status_code=503, detail=BUSY_MESSAGE,
                            headers={"Retry-After": str(BUSY_RETRY_AFTER)})
    try:
        return _analyze(req)
    finally:
        _slots.release()


def _analyze(req: AclAnalyzeRequest) -> Response:
    _check_size(req.config_text)
    parsed = parse_acls(req.config_text)
    if len(parsed.acls) > MAX_ACLS:
        raise HTTPException(status_code=413,
                            detail="Too many ACLs: at most %d per request (the paste has %d)." % (MAX_ACLS, len(parsed.acls)))
    rule_count = sum(1 for acl in parsed.acls.values() for e in acl.entries if e.kind == "rule")
    if rule_count > MAX_RULES:
        raise HTTPException(status_code=413,
                            detail="Too many ACL rules: at most %d per request (the paste has %d)." % (MAX_RULES, rule_count))
    summaries = []
    for acl in parsed.acls.values():
        rules = [e for e in acl.entries if e.kind == "rule"]
        summaries.append(AclSummary(
            acl=acl.name, type=acl.acl_type, forms=list(acl.forms), rules=len(rules),
            evaluated_rules=sum(1 for e in rules if e.status == STATUS_OK and e.rule is not None)))
    traced = _run_trace(parsed, req.trace) if req.trace is not None else None
    linted = lint(parsed)
    payload = AclAnalyzeResponse(
        engine=ENGINE_VERSION,
        acls=summaries,
        lint=linted,
        # Rules with a lint finding get their edge packets first (user, 28.10).
        auto_packets=auto_packets(parsed, lint_result=linted) if req.auto_packets else [],
        trace=traced,
    ).model_dump_json().encode("utf-8")
    if len(payload) > MAX_RESPONSE_BYTES:
        raise HTTPException(status_code=413,
                            detail="Result too large: split the paste into fewer ACLs or rules per request.")
    return Response(content=payload, media_type="application/json")
