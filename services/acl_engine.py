"""
Cisco IOS / IOS-XE IPv4 ACL parser and what-if trace engine (ACL-01.1, 2026-10-26).

Scope: the first increment of ACL-01 "ACL Lint + What-if Trace". A library only:
no API endpoint, no UI, no lint. Spec: CEO repo
projects/netdevops/spec_acl-01_v0_2026-10-22.md (sections 1, 2, 4, 6, Annex A).

What it does:

1. ``parse_acls(text)`` reads a paste (``show run`` excerpt, change file, template)
   and builds one model per ACL. Accepted forms: numbered standard (1-99,
   1300-1999) and extended (100-199, 2000-2699), named standard/extended with
   optional sequence numbers, and a numbered ACL printed in named form
   (``ip access-list standard 99`` + `` 10 permit ...``). The last one is how
   IOS XE 16.12.13 prints numbered ACLs in ``show run`` (user lab, WS-C3850-48T,
   2026-10-22), so both forms of the same number in one paste are ONE ACL.
2. ``trace(parsed, acl_name, packet)`` walks the ACL top-down; the first matching
   rule wins; no match is the implicit deny. Result follows spec section 4:
   ``{acl, verdict, matched_line, implicit_deny, path:[{line, matched, reason}]}``
   plus ``unevaluated_lines`` (see below).

Rules this module never breaks:

- No line inside an ACL is skipped silently. Anything outside the v0 grammar
  (object-group, IPv6, VRF, time-range, fragments, reflect/evaluate, ICMP types,
  dscp/tos/precedence, unknown keywords) gets status NOT_EVALUATED with a reason.
  Lines that are known to be invalid (port in a standard ACL, ``established``
  on a non-TCP rule, port name outside Annex A or from the other protocol's
  table, malformed address) get P01 with the line number.
- Cisco behaviour is not guessed. Where the spec is silent, the line is marked
  NOT_EVALUATED rather than interpreted. A trace over an ACL with such lines
  lists them in ``unevaluated_lines``: the verdict holds only if none of them
  would have matched first.
- Addresses are stored normalized (``addr & ~wildcard``, which is what IOS
  writes back, lab 2026-10-22) AND as written, so the L04 lint in ACL-01.2 has
  the original to read.
- Deterministic output: the same input gives byte-identical JSON.

Ordering (Q2, user 2026-10-26): entries without a sequence number get 10, 20, ...
in paste order (one counter per ACL, shared by both forms), then the ACL is
sorted by sequence number; ties keep paste order. Identical rules from both
forms are kept (they are an L03 matter for ACL-01.2).

``line`` everywhere = 1-based line number in the pasted text.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union

ENGINE_VERSION = "acl-01.1"

STATUS_OK = "OK"
STATUS_NOT_EVALUATED = "NOT_EVALUATED"
STATUS_P01 = "P01"

PROTO_NUMBERS = {"tcp": 6, "udp": 17, "icmp": 1}

# Annex A (spec 2026-10-22). TCP: names and numbers from Cisco IOS XE REST API
# ACL reference. UDP: names from Cisco "Transit Access Control Lists", numbers
# from IANA ([VERIFY] on a lab with `permit udp any any eq ?`).
TCP_PORT_NAMES: Dict[str, int] = {
    "bgp": 179, "chargen": 19, "cmd": 514, "daytime": 13, "discard": 9,
    "domain": 53, "echo": 7, "exec": 512, "finger": 79, "ftp": 21,
    "ftp-data": 20, "gopher": 70, "hostname": 101, "ident": 113, "irc": 194,
    "klogin": 543, "kshell": 544, "login": 513, "lpd": 515, "msrpc": 135,
    "nntp": 119, "pim-auto-rp": 496, "pop2": 109, "pop3": 110, "smtp": 25,
    "sunrpc": 111, "tacacs": 49, "talk": 517, "telnet": 23, "time": 37,
    "uucp": 540, "whois": 43, "www": 80,
}
UDP_PORT_NAMES: Dict[str, int] = {
    "biff": 512, "bootpc": 68, "bootps": 67, "discard": 9, "dnsix": 195,
    "domain": 53, "echo": 7, "isakmp": 500, "mobile-ip": 434, "nameserver": 42,
    "netbios-dgm": 138, "netbios-ns": 137, "netbios-ss": 139, "ntp": 123,
    "pim-auto-rp": 496, "rip": 520, "snmp": 161, "snmptrap": 162, "sunrpc": 111,
    "syslog": 514, "tacacs": 49, "talk": 517, "tftp": 69, "time": 37,
    "who": 513, "xdmcp": 177,
}
PORT_NAMES = {"tcp": TCP_PORT_NAMES, "udp": UDP_PORT_NAMES}

PORT_OPS = ("eq", "neq", "lt", "gt", "range")
LOG_FLAGS = ("log", "log-input")

# Keywords that put a line outside the v0 grammar (spec section 1).
OUT_OF_V0_KEYWORDS = {
    "object-group": "object-group is outside v0",
    "fragments": "fragments is outside v0",
    "reflect": "reflexive ACL (reflect) is outside v0",
    "evaluate": "reflexive ACL (evaluate) is outside v0",
    "time-range": "time-range is outside v0",
    "dscp": "dscp is outside v0",
    "tos": "tos is outside v0",
    "precedence": "precedence is outside v0",
    "vrf": "VRF is outside v0",
}

STANDARD_RANGES = ((1, 99), (1300, 1999))
EXTENDED_RANGES = ((100, 199), (2000, 2699))

_ANY_WC = 0xFFFFFFFF


class LineResult(Exception):
    """Internal: a line ends as NOT_EVALUATED or P01 with a reason."""

    def __init__(self, status: str, reason: str):
        super().__init__(reason)
        self.status = status
        self.reason = reason


def _not_eval(reason: str) -> LineResult:
    return LineResult(STATUS_NOT_EVALUATED, reason)


def _p01(reason: str) -> LineResult:
    return LineResult(STATUS_P01, reason)


# ---------------------------------------------------------------- model


@dataclass(frozen=True)
class AddressSpec:
    """Address + wildcard. ``address`` is normalized (addr & ~wildcard)."""

    address: int
    wildcard: int
    original: str  # as written: "any", "host 10.1.1.5", "10.1.1.5 0.0.0.255", "10.1.1.5"
    original_address: Optional[str]  # as written; None for "any"

    def contains(self, ip: int) -> bool:
        mask = ~self.wildcard & 0xFFFFFFFF
        return (ip & mask) == self.address

    def describe(self) -> str:
        if self.wildcard == _ANY_WC:
            return "any"
        if self.wildcard == 0:
            return "host " + _ip_str(self.address)
        return _ip_str(self.address) + " " + _ip_str(self.wildcard)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": _ip_str(self.address),
            "wildcard": _ip_str(self.wildcard),
            "original": self.original,
            "original_address": self.original_address,
        }


ANY_ADDRESS = AddressSpec(0, _ANY_WC, "any", None)


@dataclass(frozen=True)
class PortSpec:
    """Port condition as a set of closed intervals in 0-65535."""

    original: str  # "eq www", "range 1000 2000"
    intervals: Tuple[Tuple[int, int], ...]

    def contains(self, port: int) -> bool:
        return any(lo <= port <= hi for lo, hi in self.intervals)

    def to_dict(self) -> Dict[str, Any]:
        return {"original": self.original, "intervals": [list(i) for i in self.intervals]}


@dataclass(frozen=True)
class Rule:
    """One ACE (spec section 2). Standard ACL: only ``src``, the rest = any."""

    action: str  # permit | deny
    protocol: str  # "ip", "tcp", "udp", "icmp" or the number as written
    protocol_number: Optional[int]  # None = ip (all protocols)
    src: AddressSpec
    src_ports: Optional[PortSpec]
    dst: AddressSpec
    dst_ports: Optional[PortSpec]
    established: bool
    log: Optional[str]  # None | "log" | "log-input"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "protocol": self.protocol,
            "protocol_number": self.protocol_number,
            "src": self.src.to_dict(),
            "src_ports": self.src_ports.to_dict() if self.src_ports else None,
            "dst": self.dst.to_dict(),
            "dst_ports": self.dst_ports.to_dict() if self.dst_ports else None,
            "established": self.established,
            "log": self.log,
        }


@dataclass
class Entry:
    """One line inside an ACL: a rule, a remark, or a line that was not evaluated."""

    line: int
    text: str
    kind: str  # rule | remark | other
    status: str  # OK | NOT_EVALUATED | P01
    seq: Optional[int] = None
    explicit_seq: bool = False
    form: str = "numbered"  # numbered | named
    rule: Optional[Rule] = None
    remark: Optional[str] = None
    reason: Optional[str] = None
    _block: int = 0
    _order: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "line": self.line,
            "seq": self.seq,
            "form": self.form,
            "kind": self.kind,
            "status": self.status,
            "text": self.text,
            "rule": self.rule.to_dict() if self.rule else None,
            "remark": self.remark,
            "reason": self.reason,
        }


@dataclass
class Acl:
    name: str
    acl_type: str  # standard | extended
    forms: List[str] = field(default_factory=list)
    entries: List[Entry] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type": self.acl_type,
            "forms": list(self.forms),
            "entries": [e.to_dict() for e in self.entries],
        }


@dataclass
class ParseResult:
    acls: Dict[str, Acl] = field(default_factory=dict)  # insertion order = first appearance
    # ACL-related lines outside any evaluable ACL (ipv6 access-list, object-group
    # definitions, unknown access-list numbers, header conflicts ...).
    not_evaluated: List[Dict[str, Any]] = field(default_factory=list)
    # Line numbers of non-ACL config in the paste (interface, hostname, ...).
    other_lines: List[int] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "engine": ENGINE_VERSION,
            "acls": [a.to_dict() for a in self.acls.values()],
            "not_evaluated": list(self.not_evaluated),
            "other_lines": list(self.other_lines),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, ensure_ascii=False)


# ---------------------------------------------------------------- helpers


def _ip_str(value: int) -> str:
    return str(ipaddress.IPv4Address(value))


def _parse_ipv4(token: str) -> Optional[int]:
    try:
        return int(ipaddress.IPv4Address(token))
    except (ipaddress.AddressValueError, ValueError):
        return None


def _looks_ipv4(token: str) -> bool:
    return token.count(".") == 3 and all(p.isdigit() for p in token.split("."))


def _numbered_type(number: int) -> Optional[str]:
    for lo, hi in STANDARD_RANGES:
        if lo <= number <= hi:
            return "standard"
    for lo, hi in EXTENDED_RANGES:
        if lo <= number <= hi:
            return "extended"
    return None


def _parse_address(tokens: List[str], i: int, standard: bool) -> Tuple[AddressSpec, int]:
    """Parse ``any`` | ``host A`` | ``A W`` | (standard only) ``A`` alone = host."""
    if i >= len(tokens):
        raise _p01("address missing")
    tok = tokens[i]
    if tok == "any":
        return ANY_ADDRESS, i + 1
    if tok == "host":
        if i + 1 >= len(tokens):
            raise _p01("address missing after 'host'")
        ip = _parse_ipv4(tokens[i + 1])
        if ip is None:
            if ":" in tokens[i + 1]:
                raise _not_eval("IPv6 is outside v0")
            raise _p01("invalid host address '%s'" % tokens[i + 1])
        return AddressSpec(ip, 0, "host " + tokens[i + 1], tokens[i + 1]), i + 2
    if ":" in tok:
        raise _not_eval("IPv6 is outside v0")
    ip = _parse_ipv4(tok)
    if ip is None:
        if _looks_ipv4(tok):
            raise _p01("invalid address '%s'" % tok)
        raise _not_eval("unknown token '%s' where an address was expected" % tok)
    nxt = tokens[i + 1] if i + 1 < len(tokens) else None
    if nxt is not None and _looks_ipv4(nxt):
        wc = _parse_ipv4(nxt)
        if wc is None:
            raise _p01("invalid wildcard '%s'" % nxt)
        norm = ip & (~wc & 0xFFFFFFFF)
        return AddressSpec(norm, wc, tok + " " + nxt, tok), i + 2
    if standard:
        return AddressSpec(ip, 0, tok, tok), i + 1
    raise _p01("wildcard missing after address '%s'" % tok)


def _parse_port_value(token: str, proto: str) -> int:
    if token.isdigit():
        value = int(token)
        if value > 65535:
            raise _p01("port %s out of range 0-65535" % token)
        return value
    names = PORT_NAMES[proto]
    if token in names:
        return names[token]
    other = "udp" if proto == "tcp" else "tcp"
    if token in PORT_NAMES[other]:
        raise _p01("port name '%s' is a %s name, not valid for %s" % (token, other.upper(), proto.upper()))
    raise _p01("port name '%s' is not in the %s port table (Annex A)" % (token, proto.upper()))


def _parse_ports(tokens: List[str], i: int, proto: Optional[str]) -> Tuple[Optional[PortSpec], int]:
    if i >= len(tokens) or tokens[i] not in PORT_OPS:
        return None, i
    op = tokens[i]
    if proto not in PORT_NAMES:
        raise _p01("port operator '%s' is valid only for tcp/udp" % op)
    if op == "range":
        if i + 2 >= len(tokens):
            raise _p01("range needs two ports")
        lo = _parse_port_value(tokens[i + 1], proto)
        hi = _parse_port_value(tokens[i + 2], proto)
        if lo > hi:
            # IOS behaviour for a reversed range is not verified: do not guess.
            raise _not_eval("range %s %s has low > high; IOS behaviour not verified" % (tokens[i + 1], tokens[i + 2]))
        return PortSpec(" ".join(tokens[i:i + 3]), ((lo, hi),)), i + 3
    if i + 1 >= len(tokens):
        raise _p01("port missing after '%s'" % op)
    p = _parse_port_value(tokens[i + 1], proto)
    if op == "eq":
        intervals: List[Tuple[int, int]] = [(p, p)]
    elif op == "neq":
        intervals = [iv for iv in ((0, p - 1), (p + 1, 65535)) if iv[0] <= iv[1]]
    elif op == "lt":
        intervals = [(0, p - 1)] if p > 0 else []
    else:  # gt
        intervals = [(p + 1, 65535)] if p < 65535 else []
    return PortSpec(op + " " + tokens[i + 1], tuple(intervals)), i + 2


def _parse_flags(tokens: List[str], i: int, proto: Optional[str], standard: bool) -> Tuple[bool, Optional[str]]:
    established = False
    log: Optional[str] = None
    while i < len(tokens):
        tok = tokens[i]
        if tok == "established":
            if standard:
                raise _p01("'established' in a standard ACL")
            if proto != "tcp":
                raise _p01("'established' is valid only for tcp (rule protocol: %s)" % proto)
            established = True
        elif tok in LOG_FLAGS:
            if log is not None:
                raise _not_eval("more than one log flag")
            log = tok
        elif tok in PORT_OPS and standard:
            raise _p01("port in a standard ACL")
        else:
            # e.g. `log <cookie>`, ICMP type, multi-port `eq 80 443`: not in v0 grammar.
            if proto == "icmp":
                raise _not_eval("ICMP type/code '%s' is outside v0" % tok)
            raise _not_eval("token '%s' is outside the v0 grammar" % tok)
        i += 1
    return established, log


def parse_rule(body: List[str], acl_type: str) -> Rule:
    """Parse tokens after the ACL name/number/seq: ``permit|deny ...``.

    Raises LineResult for NOT_EVALUATED / P01.
    """
    for tok in body:
        if tok in OUT_OF_V0_KEYWORDS:
            raise _not_eval(OUT_OF_V0_KEYWORDS[tok])
    action = body[0]
    standard = acl_type == "standard"
    i = 1
    if standard:
        src, i = _parse_address(body, i, standard=True)
        if i < len(body) and body[i] in PORT_OPS:
            raise _p01("port in a standard ACL")
        established, log = _parse_flags(body, i, None, standard=True)
        return Rule(action, "ip", None, src, None, ANY_ADDRESS, None, established, log)

    if i >= len(body):
        raise _p01("protocol missing")
    proto_tok = body[i]
    if proto_tok == "ip":
        proto, number = "ip", None
    elif proto_tok in PROTO_NUMBERS:
        proto, number = proto_tok, PROTO_NUMBERS[proto_tok]
    elif proto_tok.isdigit():
        number = int(proto_tok)
        if number > 255:
            raise _p01("protocol number %s out of range 0-255" % proto_tok)
        proto = proto_tok
    else:
        raise _not_eval("protocol '%s' is outside v0 (ip|tcp|udp|icmp|0-255)" % proto_tok)
    i += 1
    port_proto = proto if proto in PORT_NAMES else None
    src, i = _parse_address(body, i, standard=False)
    if i < len(body) and body[i] in PORT_OPS and port_proto is None:
        raise _p01("port operator '%s' is valid only for tcp/udp" % body[i])
    src_ports, i = _parse_ports(body, i, port_proto)
    dst, i = _parse_address(body, i, standard=False)
    if i < len(body) and body[i] in PORT_OPS and port_proto is None:
        raise _p01("port operator '%s' is valid only for tcp/udp" % body[i])
    dst_ports, i = _parse_ports(body, i, port_proto)
    established, log = _parse_flags(body, i, proto, standard=False)
    return Rule(action, proto, number, src, src_ports, dst, dst_ports, established, log)


# ---------------------------------------------------------------- parser


class _Parser:
    def __init__(self) -> None:
        self.result = ParseResult()
        self.order = 0
        self.block = 0
        self.ctx: Optional[Dict[str, Any]] = None  # current named block

    def _next_order(self) -> int:
        self.order += 1
        return self.order

    def _top_not_eval(self, line_no: int, text: str, reason: str) -> None:
        self.result.not_evaluated.append({"line": line_no, "text": text, "reason": reason})

    def _get_acl(self, name: str, acl_type: str, form: str) -> Acl:
        acl = self.result.acls.get(name)
        if acl is None:
            acl = Acl(name, acl_type)
            self.result.acls[name] = acl
        if form not in acl.forms:
            acl.forms.append(form)
        return acl

    def _add_entry(self, acl: Acl, entry: Entry) -> None:
        entry._order = self._next_order()
        acl.entries.append(entry)

    def _entry_from_body(self, line_no: int, text: str, body: List[str], acl_type: str,
                         form: str, seq: Optional[int], block: int) -> Entry:
        entry = Entry(line=line_no, text=text, kind="rule", status=STATUS_OK, seq=seq,
                      explicit_seq=seq is not None, form=form, _block=block)
        if not body:
            entry.kind, entry.status, entry.reason = "other", STATUS_P01, "empty entry"
            return entry
        head = body[0]
        if head == "remark":
            entry.kind = "remark"
            entry.remark = text.split("remark", 1)[1].strip()
            return entry
        if head not in ("permit", "deny"):
            entry.kind = "other"
            if head in OUT_OF_V0_KEYWORDS:
                entry.status, entry.reason = STATUS_NOT_EVALUATED, OUT_OF_V0_KEYWORDS[head]
            else:
                entry.status = STATUS_NOT_EVALUATED
                entry.reason = "entry '%s' is outside the v0 grammar" % head
            return entry
        try:
            entry.rule = parse_rule(body, acl_type)
        except LineResult as exc:
            entry.status, entry.reason = exc.status, exc.reason
        return entry

    def feed(self, line_no: int, raw: str) -> None:
        text = raw.rstrip()
        stripped = text.strip()
        if not stripped or stripped.startswith("!"):
            if stripped.startswith("!"):
                self.ctx = None
            return
        tokens = stripped.split()
        indented = text[:1].isspace()
        first = tokens[0]

        if first == "access-list":
            self.ctx = None
            self._numbered(line_no, stripped, tokens)
            return
        if first == "ip" and len(tokens) >= 2 and tokens[1] == "access-list":
            self.ctx = None
            self._named_header(line_no, stripped, tokens)
            return
        if first in ("ipv6", "mac", "object-group") and not indented:
            self.ctx = {"unsupported": True, "reason": self._unsupported_reason(tokens)}
            self._top_not_eval(line_no, stripped, self.ctx["reason"])
            return

        if self.ctx is not None:
            is_entry = indented or first.isdigit() or first in ("permit", "deny", "remark")
            if first == "exit" and not indented:
                self.ctx = None
                return
            if is_entry:
                if self.ctx.get("unsupported"):
                    self._top_not_eval(line_no, stripped, self.ctx["reason"])
                    return
                self._named_entry(line_no, stripped, tokens)
                return
            self.ctx = None
        self.result.other_lines.append(line_no)

    @staticmethod
    def _unsupported_reason(tokens: List[str]) -> str:
        if tokens[0] == "ipv6":
            return "IPv6 ACL is outside v0"
        if tokens[0] == "mac":
            return "MAC ACL is outside v0"
        return "object-group definition is outside v0"

    def _numbered(self, line_no: int, stripped: str, tokens: List[str]) -> None:
        if len(tokens) < 3 or not tokens[1].isdigit():
            self._top_not_eval(line_no, stripped, "access-list form outside v0 (expected access-list <number> ...)")
            return
        number = int(tokens[1])
        acl_type = _numbered_type(number)
        if acl_type is None:
            self._top_not_eval(line_no, stripped, "ACL number %d is outside the IPv4 standard/extended ranges" % number)
            return
        name = tokens[1]
        existing = self.result.acls.get(name)
        if existing is not None and existing.acl_type != acl_type:
            self._top_not_eval(line_no, stripped, "ACL %s already declared as %s" % (name, existing.acl_type))
            return
        acl = self._get_acl(name, acl_type, "numbered")
        entry = self._entry_from_body(line_no, stripped, tokens[2:], acl_type, "numbered", None, block=0)
        self._add_entry(acl, entry)

    def _named_header(self, line_no: int, stripped: str, tokens: List[str]) -> None:
        if len(tokens) != 4 or tokens[2] not in ("standard", "extended"):
            reason = "ip access-list form outside v0 (expected ip access-list standard|extended <name>)"
            self.ctx = {"unsupported": True, "reason": reason}
            self._top_not_eval(line_no, stripped, reason)
            return
        acl_type, name = tokens[2], tokens[3]
        if name.isdigit():
            num_type = _numbered_type(int(name))
            if num_type != acl_type:
                # Spec: a numeric name takes the type of its number range. A mismatch
                # (or a number outside the ranges) is not described: do not guess.
                reason = "ACL %s declared %s, number range says %s; behaviour not verified" % (
                    name, acl_type, num_type or "no IPv4 range")
                self.ctx = {"unsupported": True, "reason": reason}
                self._top_not_eval(line_no, stripped, reason)
                return
        existing = self.result.acls.get(name)
        if existing is not None and existing.acl_type != acl_type:
            reason = "ACL %s already declared as %s" % (name, existing.acl_type)
            self.ctx = {"unsupported": True, "reason": reason}
            self._top_not_eval(line_no, stripped, reason)
            return
        self.block += 1
        self._get_acl(name, acl_type, "named")
        self.ctx = {"unsupported": False, "name": name, "type": acl_type, "block": self.block}

    def _named_entry(self, line_no: int, stripped: str, tokens: List[str]) -> None:
        acl = self.result.acls[self.ctx["name"]]
        seq: Optional[int] = None
        body = tokens
        if tokens[0].isdigit():
            seq = int(tokens[0])
            body = tokens[1:]
        entry = self._entry_from_body(line_no, stripped, body, self.ctx["type"], "named", seq,
                                      block=self.ctx["block"])
        self._add_entry(acl, entry)

    def finish(self) -> ParseResult:
        for acl in self.result.acls.values():
            _assign_order(acl)
        return self.result


def _assign_order(acl: Acl) -> None:
    """Q2: seq-less entries get 10, 20, ... in paste order; then sort by seq."""
    entries = sorted(acl.entries, key=lambda e: e._order)
    counter = 0
    for e in entries:
        # Only permit/deny lines (also those NOT_EVALUATED / P01) take a seq.
        if e.kind == "rule" and e.seq is None:
            counter += 1
            e.seq = counter * 10
    keys: Dict[int, Tuple[int, int]] = {}
    for idx, e in enumerate(entries):
        if e.seq is not None:  # rule, or remark/other with an explicit seq
            keys[id(e)] = (e.seq, e._order)
            continue
        # A remark (or other sub-command) without seq stays in front of the next
        # rule of the same block; a trailing one stays after the previous rule.
        nxt = next((x for x in entries[idx + 1:] if x._block == e._block and x.seq is not None), None)
        if nxt is not None:
            keys[id(e)] = (nxt.seq, e._order)
        else:
            prev = next((x for x in reversed(entries[:idx]) if x._block == e._block and x.seq is not None), None)
            keys[id(e)] = (prev.seq if prev else 0, e._order)
    acl.entries = sorted(entries, key=lambda e: keys[id(e)])


def parse_acls(text: str) -> ParseResult:
    """Parse every IPv4 ACL in ``text``. Never raises on content."""
    parser = _Parser()
    for line_no, raw in enumerate(text.splitlines(), start=1):
        parser.feed(line_no, raw)
    return parser.finish()


# ---------------------------------------------------------------- trace


@dataclass(frozen=True)
class Packet:
    src: str
    dst: Optional[str] = None
    protocol: Union[str, int, None] = None  # "tcp" | "udp" | "icmp" | 0-255
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    established: bool = False


def _packet_proto(packet: Packet) -> Tuple[Optional[str], Optional[int]]:
    p = packet.protocol
    if p is None:
        return None, None
    if isinstance(p, int):
        if not 0 <= p <= 255:
            raise ValueError("protocol number out of range 0-255")
        name = next((k for k, v in PROTO_NUMBERS.items() if v == p), None)
        return name, p
    p = str(p).lower()
    if p in PROTO_NUMBERS:
        return p, PROTO_NUMBERS[p]
    if p.isdigit():
        return _packet_proto(Packet(packet.src, protocol=int(p)))
    raise ValueError("packet protocol must be tcp, udp, icmp or 0-255")


def _check_port(value: Optional[int], label: str) -> None:
    if value is None:
        raise ValueError("%s is required for a tcp/udp packet" % label)
    if not 0 <= int(value) <= 65535:
        raise ValueError("%s out of range 0-65535" % label)


def _mismatch(rule: Rule, src: int, dst: Optional[int], pname: Optional[str], pnum: Optional[int],
              packet: Packet) -> Optional[str]:
    """First non-matching dimension (protocol, src, src port, dst, dst port, established)."""
    if rule.protocol_number is not None and rule.protocol_number != pnum:
        return "protocol %s ∉ %s" % (pname or pnum, rule.protocol)
    if not rule.src.contains(src):
        return "src %s ∉ %s" % (_ip_str(src), rule.src.describe())
    if rule.src_ports is not None and not rule.src_ports.contains(int(packet.src_port)):
        return "src port %d ∉ %s" % (int(packet.src_port), rule.src_ports.original)
    if dst is not None and not rule.dst.contains(dst):
        return "dst %s ∉ %s" % (_ip_str(dst), rule.dst.describe())
    if rule.dst_ports is not None and not rule.dst_ports.contains(int(packet.dst_port)):
        return "dst port %d ∉ %s" % (int(packet.dst_port), rule.dst_ports.original)
    if rule.established and not packet.established:
        return "established ∉ packet (not part of an established TCP session)"
    return None


def trace(parsed: ParseResult, acl_name: str, packet: Packet) -> Dict[str, Any]:
    """What-if trace (spec section 4). First matching rule wins; no match = implicit deny."""
    acl = parsed.acls.get(str(acl_name))
    if acl is None:
        raise KeyError("ACL %s not found" % acl_name)
    src_ip = _parse_ipv4(packet.src)
    if src_ip is None:
        raise ValueError("invalid src address")
    dst_ip: Optional[int] = None
    pname: Optional[str] = None
    pnum: Optional[int] = None
    if acl.acl_type == "extended":
        if packet.dst is None or _parse_ipv4(packet.dst) is None:
            raise ValueError("an extended ACL trace needs a valid dst address")
        dst_ip = _parse_ipv4(packet.dst)
        pname, pnum = _packet_proto(packet)
        if pnum is None:
            raise ValueError("an extended ACL trace needs a protocol")
        if pname in ("tcp", "udp"):
            _check_port(packet.src_port, "src port")
            _check_port(packet.dst_port, "dst port")
        if packet.established and pname != "tcp":
            raise ValueError("established applies only to tcp packets")

    path: List[Dict[str, Any]] = []
    unevaluated: List[int] = []
    for entry in acl.entries:
        if entry.kind == "remark":
            continue
        if entry.status != STATUS_OK or entry.rule is None:
            unevaluated.append(entry.line)
            path.append({"line": entry.line, "matched": False,
                         "reason": "%s: %s" % (entry.status, entry.reason)})
            continue
        reason = _mismatch(entry.rule, src_ip, dst_ip, pname, pnum, packet)
        if reason is None:
            path.append({"line": entry.line, "matched": True, "reason": "match"})
            return {"acl": acl.name, "verdict": entry.rule.action, "matched_line": entry.line,
                    "implicit_deny": False, "path": path, "unevaluated_lines": unevaluated}
        path.append({"line": entry.line, "matched": False, "reason": reason})
    return {"acl": acl.name, "verdict": "deny", "matched_line": None, "implicit_deny": True,
            "path": path, "unevaluated_lines": unevaluated}


def trace_json(parsed: ParseResult, acl_name: str, packet: Packet) -> str:
    return json.dumps(trace(parsed, acl_name, packet), sort_keys=True, ensure_ascii=False)
