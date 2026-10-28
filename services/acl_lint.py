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
from functools import lru_cache
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


# Pure function of an immutable tuple. Cached since ACL-01.3, when _check_shadow
# still called it for every rule pair; since W4 (2026-10-28) the shadow index
# calls it once per rule and field, the pairwise helpers remain for tests and
# single comparisons. Bounded size, so a hostile paste cannot grow it without limit.
@lru_cache(maxsize=4096)
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


# ---------------------------------------------------------------- shadow index
#
# _check_shadow needs, for every rule b, the FIRST earlier rule that contains b
# (L01/L02/L03) and, if there is none, the first earlier rule with the other
# action that overlaps b without being inside it (L11). Comparing every pair is
# O(n^2) calls of rule_contains: ~350 ms locally (~1.6-1.8 s on Render) for 500
# rules that differ only in the last field (@ciso W4, 2026-10-28).
#
# The index answers the same three questions for all earlier rules at once, as
# Python ints used as bitsets over rule positions (bit i = rules[i]):
#   contain(b) = rules a with rule_contains(a, b)
#   overlap(b) = rules a with rules_intersect(a, b)
#   inside(b)  = rules a with rule_contains(b, a)
# Each field is answered separately and the answers are ANDed; the lowest set bit
# below b's position is the first such earlier rule. Exact, not a heuristic: the
# same set algebra as the pairwise functions above (tests/test_acl_lint_index.py
# compares both on fixtures and random ACLs).
#   protocol, established: a handful of masks.
#   addresses: bit-sliced, 32 bit positions x (wildcard / fixed 0 / fixed 1)
#     masks, so non-contiguous wildcards cost the same as prefixes.
#   ports: the port line is cut into segments at every interval edge used by any
#     rule; per segment, the mask of rules covering it; range AND / range OR over
#     segments from sparse tables in O(1) per interval.
# Cost: O(n * 32) for addresses, O(S log S) for S <= 4n + 2 port segments, plus
# a few int operations per rule; answers are cached per distinct field value.


def _low_index(mask: int) -> int:
    return (mask & -mask).bit_length() - 1


class _PortIndex:
    """Interval sets of one port field (src or dst) of every rule, as bitsets.

    ``masks`` accepts only sets whose edges were known at build time: the sets
    themselves plus ``queries`` (a segment must lie wholly inside or outside).
    """

    def __init__(self, sets: List[Tuple[Tuple[int, int], ...]], all_mask: int,
                 queries: Tuple[Tuple[Tuple[int, int], ...], ...] = ()):
        self.all = all_mask
        edges = [iv for s in list(sets) + list(queries) for iv in s]
        points = sorted({0, 65536} | {lo for lo, _ in edges} | {hi + 1 for _, hi in edges})
        self.pos = {p: k for k, p in enumerate(points)}
        nseg = len(points) - 1  # segment k = ports points[k] .. points[k + 1] - 1
        self.nseg = nseg
        toggle = [0] * (nseg + 1)
        for i, s in enumerate(sets):  # merged intervals are disjoint: XOR on/off per rule
            bit = 1 << i
            for lo, hi in s:
                toggle[self.pos[lo]] ^= bit
                toggle[self.pos[hi + 1]] ^= bit
        cover: List[int] = []
        acc = 0
        for k in range(nseg):
            acc ^= toggle[k]
            cover.append(acc)
        self.and_t = [cover]
        self.or_t = [cover]
        width = 1
        while width * 2 <= nseg:
            pa, po = self.and_t[-1], self.or_t[-1]
            self.and_t.append([pa[k] & pa[k + width] for k in range(nseg - 2 * width + 1)])
            self.or_t.append([po[k] | po[k + width] for k in range(nseg - 2 * width + 1)])
            width *= 2
        self.cache: Dict[Tuple[Tuple[int, int], ...], Tuple[int, int, int]] = {}

    def _and(self, lo: int, hi: int) -> int:
        j = (hi - lo + 1).bit_length() - 1
        t = self.and_t[j]
        return t[lo] & t[hi - (1 << j) + 1]

    def _or(self, lo: int, hi: int) -> int:
        j = (hi - lo + 1).bit_length() - 1
        t = self.or_t[j]
        return t[lo] | t[hi - (1 << j) + 1]

    def masks(self, s: Tuple[Tuple[int, int], ...]) -> Tuple[int, int, int]:
        """(rules whose set contains s, rules whose set meets s, rules whose set is inside s)."""
        hit = self.cache.get(s)
        if hit is not None:
            return hit
        contain, overlap, outside = self.all, 0, 0
        start = 0
        for lo, hi in s:
            a, b = self.pos[lo], self.pos[hi + 1] - 1
            contain &= self._and(a, b)
            overlap |= self._or(a, b)
            if a > start:
                outside |= self._or(start, a - 1)
            start = b + 1
        if start < self.nseg:
            outside |= self._or(start, self.nseg - 1)
        hit = (contain, overlap, self.all & ~outside)
        self.cache[s] = hit
        return hit


class _AddrIndex:
    """Address/wildcard of one field (src or dst) of every rule, bit-sliced."""

    def __init__(self, specs: List[AddressSpec], all_mask: int):
        self.all = all_mask
        wild = [0] * 32
        zero = [0] * 32
        one = [0] * 32
        for i, a in enumerate(specs):
            bit = 1 << i
            for k in range(32):
                b = 1 << k
                if a.wildcard & b:
                    wild[k] |= bit
                elif a.address & b:
                    one[k] |= bit
                else:
                    zero[k] |= bit
        self.wild, self.zero, self.one = wild, zero, one
        self.cache: Dict[Tuple[int, int], Tuple[int, int, int]] = {}

    def masks(self, a: AddressSpec) -> Tuple[int, int, int]:
        """(rules containing a, rules meeting a, rules inside a); same algebra as address_contains/intersects."""
        key = (a.address, a.wildcard)
        hit = self.cache.get(key)
        if hit is not None:
            return hit
        contain = overlap = inside = self.all
        for k in range(32):
            b = 1 << k
            w = self.wild[k]
            if a.wildcard & b:
                contain &= w  # a leaves the bit open: a container must leave it open too
            else:
                same = self.one[k] if a.address & b else self.zero[k]
                contain &= w | same
                overlap &= w | same
                inside &= same
        hit = (contain, overlap, inside)
        self.cache[key] = hit
        return hit


class _ShadowIndex:
    """Bitset answers of rule_contains / rules_intersect against every rule of one ACL."""

    def __init__(self, rules: List[Rule]):
        n = len(rules)
        self.all = full = (1 << n) - 1
        self.by_proto: Dict[Optional[int], int] = {}
        self.port_proto = 0
        self.established = 0
        self.by_action: Dict[str, int] = {}
        for i, r in enumerate(rules):
            bit = 1 << i
            self.by_proto[r.protocol_number] = self.by_proto.get(r.protocol_number, 0) | bit
            self.by_action[r.action] = self.by_action.get(r.action, 0) | bit
            if r.protocol_number in _PORT_PROTOCOLS:
                self.port_proto |= bit
            if r.established:
                self.established |= bit
        self.ip = self.by_proto.get(None, 0)
        self.src = _AddrIndex([r.src for r in rules], full)
        self.dst = _AddrIndex([r.dst for r in rules], full)
        self.src_ports = _PortIndex([_ports(r.src_ports) for r in rules], full)
        self.dst_ports = _PortIndex([_ports(r.dst_ports) for r in rules], full)

    def masks(self, r: Rule) -> Tuple[int, int, int]:
        """(contain, overlap, inside) bitsets for rule r; see the section comment."""
        full = self.all
        p = r.protocol_number
        if p is None:
            contain, overlap, inside = self.ip, full, full
        else:
            same = self.by_proto.get(p, 0)
            contain, overlap, inside = self.ip | same, self.ip | same, same
        if r.established:
            inside &= self.established
        else:
            contain &= full & ~self.established
        for index, value in ((self.src, r.src), (self.dst, r.dst)):
            c, o, i = index.masks(value)
            contain &= c
            overlap &= o
            inside &= i
        # Ports matter only for pairs where one side is tcp/udp (_ports_relevant).
        ignore = 0 if p in _PORT_PROTOCOLS else full & ~self.port_proto
        for index, spec in ((self.src_ports, r.src_ports), (self.dst_ports, r.dst_ports)):
            c, o, i = index.masks(_ports(spec))
            contain &= c | ignore
            overlap &= o | ignore
            inside &= i | ignore
        return contain, overlap, inside


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
    """L01 / L02 / L03 (first containing earlier rule decides) and L11.

    Same result as comparing b with every earlier rule in order (see the shadow
    index section above), without the O(n^2) pairwise calls.
    """
    index = _ShadowIndex([e.rule for e in rules])
    for j, b in enumerate(rules):
        rb = b.rule
        earlier = (1 << j) - 1
        contain, overlap, inside = index.masks(rb)
        hit = contain & earlier
        container = rules[_low_index(hit)] if hit else None
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
        # First earlier rule with the other action that overlaps b and is not inside b.
        hit = overlap & ~inside & earlier & ~index.by_action.get(rb.action, 0)
        if hit:
            a = rules[_low_index(hit)]
            ra = a.rule
            effect = ("Lines %d and %d overlap partially with different actions: for the shared traffic line %d wins (%s), the rest reaches line %d (%s)."
                      % (a.line, b.line, a.line, ra.action, b.line, rb.action))
            proposal = "Confirm the order is intended; split the rules if it is not."
            findings.append(_finding("L11", [b, a], effect, proposal))


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
    """L09: remark with no rule after it (at the end of the ACL).

    A block of consecutive remarks above a rule is a multi-line comment, not a
    finding (dogfooding 2026-10-28: the old "remark followed by remark" case
    flagged every heading above its description).
    """
    entries = acl.entries
    for i, e in enumerate(entries):
        if e.kind != "remark":
            continue
        if any(x.kind == "rule" for x in entries[i + 1:]):
            continue
        effect = "Remark at the end of the ACL describes no rule; it has no effect on traffic."
        proposal = "Remove it, or move it above the rule it describes."
        findings.append(_finding("L09", [e], effect, proposal))


def _check_established_pairs(parsed: ParseResult, findings_by_acl: Dict[str, List[Dict[str, Any]]]) -> None:
    """L10 heuristic (Q3): only with >= 2 ACLs in the paste."""
    acls = list(parsed.acls.values())
    if len(acls) < 2:
        return
    # A rule is paired when a permit (ip or tcp) rule of ANOTHER ACL has dst ports
    # that meet its src ports. Instead of scanning every other rule per candidate
    # (O(n * m), ~120 ms locally for 2 x 250 rules), one port index over all
    # possible partners of all ACLs; bit i = partners[i], acl_bits = their ACL.
    partners: List[Rule] = []
    acl_bits: Dict[str, int] = {}
    wanted = set()
    for acl in acls:
        for e in acl.entries:
            if e.kind != "rule" or e.status != STATUS_OK or e.rule is None:
                continue
            if e.rule.action == "permit" and e.rule.protocol_number in (None, 6):
                acl_bits[acl.name] = acl_bits.get(acl.name, 0) | (1 << len(partners))
                partners.append(e.rule)
            if e.rule.established and e.rule.src_ports is not None:
                wanted.add(_ports(e.rule.src_ports))
    if not wanted:
        return
    index = _PortIndex([_ports(r.dst_ports) for r in partners], (1 << len(partners)) - 1,
                       tuple(sorted(wanted)))
    for acl in acls:
        for e in acl.entries:
            if e.kind != "rule" or e.status != STATUS_OK or e.rule is None:
                continue
            rule = e.rule
            if not rule.established or rule.src_ports is None:
                continue
            _, overlap, _ = index.masks(_ports(rule.src_ports))
            if overlap & ~acl_bits.get(acl.name, 0):
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
