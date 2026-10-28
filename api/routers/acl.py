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
parsing, before the lint, which compares rule pairs (O(n^2)). A rejected paste is not echoed back (pydantic's own
max_length error would return the whole input, hence the manual check).
Errors are short sentences, never a stack trace. The per-IP POST limit in
api/rate_limit.py applies like on every other tool.
"""

from typing import Any, Dict, List, Optional, Union

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from services.acl_engine import STATUS_OK, Packet, parse_acls, trace
from services.acl_lint import lint
from services.acl_packets import auto_packets

router = APIRouter()

ENGINE_VERSION = "acl-01.3"

# Spec section 5: < 200 ms for an ACL of up to 500 lines. The cap is twice that,
# so a `show run` excerpt with some non-ACL lines around the ACL still fits.
MAX_CHARS = 100_000
MAX_LINES = 1_000
# The lint compares every rule with the rules above it (O(n^2) in rules), so the
# rule count is capped on its own: 500 = the size the spec's timing target names.
MAX_RULES = 500


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
    _check_size(req.config_text)
    parsed = parse_acls(req.config_text)
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
    return AclAnalyzeResponse(
        engine=ENGINE_VERSION,
        acls=summaries,
        lint=lint(parsed),
        auto_packets=auto_packets(parsed) if req.auto_packets else [],
        trace=traced,
    )
