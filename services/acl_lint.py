"""
Cisco IOS / IOS-XE IPv4 ACL lint (ACL-01.2, 2026-10-27).

Second increment of ACL-01 "ACL Lint + What-if Trace". A library only: no API
endpoint, no UI. Spec: CEO repo projects/netdevops/spec_acl-01_v0_2026-10-22.md
sections 2 (rule containment) and 3 (lint catalogue L01-L11, P01). Input is the
model built by ``services.acl_engine.parse_acls``.

Containment (spec section 2), valid also for non-contiguous wildcards:
address set B is inside A  <=>  (wcB & ~wcA) == 0 and (addrA & ~wcA) == (addrB & ~wcA).
NOTE: spec v0 section 2 prints the first term as ``(wcA & ~wcB) == 0``, which has
the roles swapped (it would say ``any`` does not contain a host). Every bit that
A fixes (wcA = 0) must also be fixed in B (wcB = 0), hence ``wcB & ~wcA``.
Rule A contains rule B when it does so on every dimension: protocol (``ip``
contains everything), src/dst address, src/dst ports (interval sets), and
``established`` (A without the flag contains B with it; not the other way).

Order of evaluation = order of ``Acl.entries`` after Q2 sorting (sequence
numbers), never the order of lines in the pasted text.

Per later rule B at most one of L01/L02/L03 is reported, chosen by the FIRST
earlier rule A that contains B (that rule is the one that takes B's traffic):
identical to B except log/seq -> L03, other action -> L01, same action -> L02.

L10 is a heuristic (Q3, user 2026-10-26): it runs only when the paste holds at
least 2 ACLs and its message says so.

Each finding: id, level, line (the line it is about), lines (all lines involved),
quote (each involved line as pasted, without indentation), effect (one sentence:
what happens to traffic), proposal (never applied automatically).

Deterministic: the same input gives byte-identical JSON.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from services.acl_engine import (
    STATUS_OK,
    STATUS_P01,
    Acl,
    AddressSpec,
    ParseResult,
    PortSpec,
    Rule,
    _ANY_WC,
    _ip_str,
)

LINT_VERSION = "acl-01.2"

LEVEL_ERROR = "ERROR"
LEVEL_WARN = "WARN"
LEVEL_INFO = "INFO"

LEVELS = {
    "L01": LEVEL_ERROR, "L02": LEVEL_WARN, "L03": LEVEL_WARN, "L04": LEVEL_WARN,
    "L05": LEVEL_INFO, "L06": LEVEL_ERROR, "L07": LEVEL_INFO, "L08": LEVEL_WARN,
    "L09": LEVEL_INFO, "L10": LEVEL_INFO, "L11": LEVEL_INFO, "P01": LEVEL_ERROR,
}

_M32 = 0xFFFFFFFF
_FULL_PORTS: Tuple[Tuple[int, int], ...] = ((0, 65535),)
_PORT_PROTOCOLS = (6, 17)


# ---------------------------------------------------------------- containment


def address_contains(a: AddressSpec, b: AddressSpec) -> bool:
    """Spec section 2: set(b) is a subset of set(a)."""
    return (b.wildcard & ~a.wildcard & _M32) == 0 and \
        (a.address & ~a.wildcard & _M32) == (b.address & ~a.wildcard & _M32)


def address_intersects(a: AddressSpec, b: AddressSpec) -> bool:
    """Some IP is in both: bits fixed in both must agree."""
    fixed = ~a.wildcard & ~b.wildcard & _M32
    return (a.address & fixed) == (b.address & fixed)


def _merge(intervals: Tuple[Tuple[int, int], ...]) -> Tuple[Tuple[int, int], ...]:
    out: List[List[int]] = []
    for lo, hi in sorted(intervals):
        if out and lo <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], hi)
        else:
            out.append([lo, hi])
    return tuple((lo, hi) for lo, hi in out)


def _ports(spec: Optional[PortSpec]) -> Tuple[Tuple[int, int], ...]:
    """Interval set of a port condition; no condition = every port."""
    return _FULL_PORTS if spec is None else _merge(spec.intervals)


def ports_contain(a: Tuple[Tuple[int, int], ...], b: Tuple[Tuple[int, int], ...]) -> bool:
    """Every interval of b lies inside one interval of a (a is merged, so gaps are real)."""
    return all(any(alo <= lo and hi <= ahi for alo, ahi in a) for lo, hi in b)


def ports_intersect(a: Tuple[Tuple[int, int], ...], b: Tuple[Tuple[int, int], ...]) -> bool:
    return any(lo <= bhi and blo <= hi for lo, hi in a for blo, bhi in b)


def _proto_contains(a: Rule, b: Rule) -> bool:
    return a.protocol_number is None or a.protocol_number == b.protocol_number


def _proto_intersects(a: Rule, b: Rule) -> bool:
    return a.protocol_number is None or b.protocol_number is None or \
        a.protocol_number == b.protocol_number


def _ports_relevant(a: Rule, b: Rule) -> bool:
    """Ports only matter when both sides are about a port protocol."""
    return a.protocol_number in _PORT_PROTOCOLS or b.protocol_number in _PORT_PROTOCOLS


def rule_contains(a: Rule, b: Rule) -> bool:
    """Spec section 2: every packet matched by b is matched by a."""
    if not _proto_contains(a, b):
        return False
    if not address_contains(a.src, b.src) or not address_contains(a.dst, b.dst):
        return False
    if _ports_relevant(a, b):
        if not ports_contain(_ports(a.src_ports), _ports(b.src_ports)):
            return False
        if not ports_contain(_ports(a.dst_ports), _ports(b.dst_ports)):
            return False
    if a.established and not b.established:
        return False
    return True


def rules_intersect(a: Rule, b: Rule) -> bool:
    """Some packet is matched by both (established never separates: a packet can have it)."""
    if not _proto_intersects(a, b):
        return False
    if not address_intersects(a.src, b.src) or not address_intersects(a.dst, b.dst):
        return False
    if _ports_relevant(a, b):
        if not ports_intersect(_ports(a.src_ports), _ports(b.src_ports)):
            return False
        if not ports_intersect(_ports(a.dst_ports), _ports(b.dst_ports)):
            return False
    return True


def rules_identical(a: Rule, b: Rule) -> bool:
    """Same action and same match (log and seq ignored): L03."""
    return a.action == b.action and rule_contains(a, b) and rule_contains(b, a)


# ---------------------------------------------------------------- helpers


def _is_catch_all(rule: Rule) -> bool:
    """`ip any any` (standard: `any`) with no ports and no established."""
    return (rule.protocol_number is None and rule.src.wildcard == _ANY_WC and
            rule.dst.wildcard == _ANY_WC and rule.src_ports is None and
            rule.dst_ports is None and not rule.established)


def _non_contiguous(wc: int) -> bool:
    return wc not in (0, _ANY_WC) and (wc & (wc + 1)) != 0


def _finding(fid: str, entries: List[Any], effect: str, proposal: str) -> Dict[str, Any]:
    """``entries[0]`` is the line the finding is about; the rest are context lines."""
    lines = [e.line for e in entries]
    return {
        "id": fid,
        "level": LEVELS[fid],
        "line": lines[0],
        "lines": lines,
        "quote": [e.text for e in entries],
        "effect": effect,
        "proposal": proposal,
    }


def _verb(action: str) -> str:
    return "permits" if action == "permit" else "denies"


# ---------------------------------------------------------------- checks


def _check_shadow(rules: List[Any], findings: List[Dict[str, Any]]) -> None:
    """L01 / L02 / L03 (first containing earlier rule decides) and L11."""
    for j, b in enumerate(rules):
        rb = b.rule
        container = next((a for a in rules[:j] if rule_contains(a.rule, rb)), None)
        if container is not None:
            ra = container.rule
            if rules_identical(ra, rb):
                if ra.log != rb.log and rb.log:
                    effect = ("The %s on line %d never logs: line %d matches exactly the same traffic first."
                              % (rb.log, b.line, container.line))
                    proposal = "Remove line %d; if logging is wanted, add %s to line %d." % (
                        b.line, rb.log, container.line)
                elif ra.log != rb.log:
                    effect = ("Line %d duplicates line %d (only log differs) and never matches."
                              % (b.line, container.line))
                    proposal = "Remove line %d." % b.line
                else:
                    effect = "Line %d duplicates line %d and never matches." % (b.line, container.line)
                    proposal = "Remove line %d." % b.line
                findings.append(_finding("L03", [b, container], effect, proposal))
            elif ra.action != rb.action:
                effect = ("Line %d never matches: line %d %s all of its traffic first, so the intended %s never happens."
                          % (b.line, container.line, _verb(ra.action), rb.action))
                proposal = ("Move line %d above line %d, or remove it if line %d is the intended behaviour."
                            % (b.line, container.line, container.line))
                findings.append(_finding("L01", [b, container], effect, proposal))
            else:
                effect = ("Line %d never matches: line %d already %s all of its traffic."
                          % (b.line, container.line, _verb(ra.action)))
                proposal = "Remove line %d; it changes nothing." % b.line
                findings.append(_finding("L02", [b, container], effect, proposal))
            continue
        for a in rules[:j]:
            ra = a.rule
            if ra.action == rb.action or not rules_intersect(ra, rb) or rule_contains(rb, ra):
                continue
            effect = ("Lines %d and %d overlap partially with different actions: for the shared traffic line %d wins (%s), the rest reaches line %d (%s)."
                      % (a.line, b.line, a.line, ra.action, b.line, rb.action))
            proposal = "Confirm the order is intended; split the rules if it is not."
            findings.append(_finding("L11", [b, a], effect, proposal))
            break


def _check_addresses(entry: Any, acl_type: str, findings: List[Dict[str, Any]]) -> None:
    """L04 host bits under the wildcard, L05 non-contiguous wildcard."""
    rule = entry.rule
    sides = [("src", rule.src)] + ([("dst", rule.dst)] if acl_type == "extended" else [])
    for side, addr in sides:
        if addr.original_address is None or addr.wildcard in (0, _ANY_WC):
            continue
        orig = addr.original_address
        try:
            orig_int = int.from_bytes(bytes(int(p) for p in orig.split(".")), "big")
        except ValueError:
            continue
        stored = "%s %s" % (_ip_str(addr.address), _ip_str(addr.wildcard))
        if orig_int & addr.wildcard:
            effect = ("IOS will store %s `%s` as `%s` (confirmed on IOS XE 16.12.13, standard and extended), "
                      "so it matches the whole range, not only %s." % (side, addr.original, stored, orig))
            proposal = "If one host was meant, use `host %s`; otherwise write `%s`." % (orig, stored)
            findings.append(_finding("L04", [entry], effect, proposal))
        if _non_contiguous(addr.wildcard):
            effect = ("Wildcard %s on %s is non-contiguous: it matches every address with the same fixed bits as %s. "
                      "Legal, but easy to misread." % (_ip_str(addr.wildcard), side, _ip_str(addr.address)))
            proposal = "Keep it only if intentional; add a remark that explains the pattern."
            findings.append(_finding("L05", [entry], effect, proposal))


def _check_log_on_wide_permit(entry: Any, acl_type: str, findings: List[Dict[str, Any]]) -> None:
    """L08. Standard ACL: only src counts (its dst is implicit, not written by the user)."""
    rule = entry.rule
    if rule.action != "permit" or rule.log is None:
        return
    wide = [s for s, a in (("src", rule.src), ("dst", rule.dst))
            if a.wildcard == _ANY_WC and (s == "src" or acl_type == "extended")]
    if not wide:
        return
    effect = ("Every packet this permit matches is logged; with `any` on %s that can mean a high log volume and CPU load."
              % " and ".join(wide))
    proposal = "Remove %s, or narrow the rule." % rule.log
    findings.append(_finding("L08", [entry], effect, proposal))


def _check_order(acl: Acl, rule_entries: List[Any], findings: List[Dict[str, Any]]) -> None:
    """L06 catch-all not last, L07 no explicit logged deny at the end."""
    all_rule_lines = [e for e in acl.entries if e.kind == "rule"]
    for e in rule_entries:
        if _is_catch_all(e.rule) and e is not all_rule_lines[-1]:
            effect = "Every rule below line %d is unreachable: this rule matches all traffic." % e.line
            proposal = "Move it to the end of the ACL, or narrow it."
            findings.append(_finding("L06", [e], effect, proposal))

    if not all_rule_lines:
        return
    last = all_rule_lines[-1]
    if last.status != STATUS_OK:
        return  # the last rule was not evaluated: cannot tell what reaches the implicit deny
    rule = last.rule
    if _is_catch_all(rule) and (rule.action == "permit" or rule.log is not None):
        return  # nothing reaches the implicit deny, or the explicit deny already logs
    explicit = "deny any log" if acl.acl_type == "standard" else "deny ip any any log"
    if _is_catch_all(rule):
        effect = "Line %d drops the remaining traffic but logs nothing." % last.line
        proposal = "Add log: `%s`." % explicit
    else:
        effect = "Traffic not matched by any rule is dropped by the implicit deny, and nothing is logged."
        proposal = "Add `%s` as the last rule." % explicit
    findings.append(_finding("L07", [last], effect, proposal))


def _check_remarks(acl: Acl, findings: List[Dict[str, Any]]) -> None:
    """L09: remark at the end, or followed by another remark before any rule."""
    entries = acl.entries
    for i, e in enumerate(entries):
        if e.kind != "remark":
            continue
        nxt = next((x for x in entries[i + 1:] if x.kind in ("rule", "remark")), None)
        if nxt is None:
            effect = "Remark at the end of the ACL describes no rule; it has no effect on traffic."
        elif nxt.kind == "remark":
            effect = "Remark is followed by another remark (line %d), not by a rule; it has no effect on traffic." % nxt.line
        else:
            continue
        proposal = "Remove it, or move it above the rule it describes."
        findings.append(_finding("L09", [e], effect, proposal))


def _check_established_pairs(parsed: ParseResult, findings_by_acl: Dict[str, List[Dict[str, Any]]]) -> None:
    """L10 heuristic (Q3): only with >= 2 ACLs in the paste."""
    acls = list(parsed.acls.values())
    if len(acls) < 2:
        return
    for acl in acls:
        others = [e for o in acls if o is not acl for e in o.entries
                  if e.kind == "rule" and e.status == STATUS_OK and e.rule is not None]
        for e in acl.entries:
            if e.kind != "rule" or e.status != STATUS_OK or e.rule is None:
                continue
            rule = e.rule
            if not rule.established or rule.src_ports is None:
                continue
            want = _ports(rule.src_ports)
            paired = any(
                o.rule.action == "permit" and o.rule.protocol_number in (None, 6) and
                ports_intersect(_ports(o.rule.dst_ports), want)
                for o in others)
            if paired:
                continue
            effect = ("Heuristic: line %d lets return TCP traffic from src %s (established), but no other ACL in this paste "
                      "permits that port as destination; the outgoing half may be missing, or sit in an ACL that was not pasted."
                      % (e.line, rule.src_ports.original))
            proposal = "Check the ACL for the other direction (heuristic finding, not a verified error)."
            findings_by_acl[acl.name].append(_finding("L10", [e], effect, proposal))


# ---------------------------------------------------------------- entry point


def lint(parsed: ParseResult) -> Dict[str, Any]:
    """Run the v0 lint catalogue over every ACL in ``parsed``."""
    findings_by_acl: Dict[str, List[Dict[str, Any]]] = {}
    not_evaluated_by_acl: Dict[str, List[Dict[str, Any]]] = {}
    for acl in parsed.acls.values():
        findings: List[Dict[str, Any]] = []
        not_eval: List[Dict[str, Any]] = []
        rules = []
        for e in acl.entries:
            if e.status == STATUS_P01:
                findings.append(_finding("P01", [e], "Line is not evaluated: %s." % e.reason,
                                         "Fix the line; the trace and the lint skip it until then."))
                continue
            if e.status != STATUS_OK:
                not_eval.append({"line": e.line, "text": e.text, "reason": e.reason})
                continue
            if e.kind == "rule" and e.rule is not None:
                rules.append(e)
        _check_shadow(rules, findings)
        for e in rules:
            _check_addresses(e, acl.acl_type, findings)
            _check_log_on_wide_permit(e, acl.acl_type, findings)
        _check_order(acl, rules, findings)
        _check_remarks(acl, findings)
        findings_by_acl[acl.name] = findings
        not_evaluated_by_acl[acl.name] = not_eval
    _check_established_pairs(parsed, findings_by_acl)

    out_acls = []
    totals = {LEVEL_ERROR: 0, LEVEL_WARN: 0, LEVEL_INFO: 0}
    for acl in parsed.acls.values():
        fs = sorted(findings_by_acl[acl.name], key=lambda f: (f["line"], f["id"], f["lines"]))
        for f in fs:
            totals[f["level"]] += 1
        out_acls.append({"acl": acl.name, "type": acl.acl_type, "findings": fs,
                         "not_evaluated": not_evaluated_by_acl[acl.name]})
    return {
        "engine": LINT_VERSION,
        "acls": out_acls,
        "not_evaluated": list(parsed.not_evaluated),
        "totals": totals,
    }


def lint_json(parsed: ParseResult) -> str:
    return json.dumps(lint(parsed), sort_keys=True, ensure_ascii=False)
