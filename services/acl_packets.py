"""
Auto-packets for the ACL what-if trace (ACL-01.3, 2026-10-28).

Spec: CEO repo projects/netdevops/spec_acl-01_v0_2026-10-22.md section 4,
"Auto-pakiety": 5-10 packets built from the edges of the rules themselves
(exact port, port +/- 1, address on the wildcard boundary, first address
outside it), each with its trace result. The table answers "how will this ACL
be checked" without the user typing a single packet.

How packets are chosen (deterministic, no randomness):

1. For every evaluable rule (status OK) the module lists edge candidates, each
   built so that it differs from the rule on ONE dimension at most:
   ``hit`` (inside on every dimension), ``dst port`` just above / below the
   port condition, ``src`` / ``dst`` first address outside the wildcard set,
   ``src`` / ``dst`` last address inside the set (boundary), src port edges,
   and a non-established packet for an ``established`` rule.
2. Candidates are taken round-robin: first the ``hit`` of every rule in ACL
   order, then the next edge type for every rule, and so on, skipping a packet
   that is already in the table, until ``MAX_PACKETS_PER_ACL`` (10). A packet
   that another rule's edge produces again gets that rule in ``also_built_for``
   (only for rows already in the table): the ``hit`` packet of a shadowed rule
   is the same packet as the earlier rule's, and the row says so.
   A small ACL can give fewer than 5 distinct packets (a one-line standard ACL
   has at most 4 edges); the module never pads the table with packets that do
   not come from a rule edge.
3. Every packet is traced with ``services.acl_engine.trace``. Each row keeps
   the rule it was built from (``from_line``) and whether it was built inside
   or outside that rule (``relation``): a ``hit`` packet that lands on another
   line shows shadowing without reading the lint.

Placeholders where a rule leaves a value open (documented, not hidden):
``any`` is shown as a documentation address (RFC 5737: src 198.51.100.10,
dst 203.0.113.10); an ``ip`` rule is probed with TCP; an open source port is
49152 (first IANA dynamic port), an open destination port 443.

The output carries the verdict summary of each trace (verdict, matched_line,
implicit_deny, unevaluated_lines), not the full path: the full path of one
packet is what the single trace in the API returns.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from services.acl_engine import (
    STATUS_OK,
    Acl,
    AddressSpec,
    Packet,
    ParseResult,
    PortSpec,
    Rule,
    _ANY_WC,
    _ip_str,
    trace,
)

MAX_PACKETS_PER_ACL = 10

ANY_SRC_PLACEHOLDER = "198.51.100.10"  # RFC 5737 TEST-NET-2
ANY_DST_PLACEHOLDER = "203.0.113.10"   # RFC 5737 TEST-NET-3
DEFAULT_SRC_PORT = 49152               # first IANA dynamic/private port
DEFAULT_DST_PORT = 443
PROBE_PROTOCOL_FOR_IP = 6              # an `ip` rule is probed with TCP

_M32 = 0xFFFFFFFF
_PROTO_NAMES = {6: "tcp", 17: "udp", 1: "icmp"}

# Round-robin order of edge types (spec section 4 lists: exact port, port +/- 1,
# address on the wildcard boundary, first address outside it).
EDGE_ORDER = (
    "hit",
    "dst_port_above",
    "src_outside",
    "dst_outside",
    "src_last",
    "dst_last",
    "dst_port_below",
    "not_established",
    "src_port_above",
    "src_port_below",
    "dst_port_high",
)


# ---------------------------------------------------------------- edges


def _addr_inside(addr: AddressSpec, placeholder: str) -> Tuple[int, str]:
    if addr.wildcard == _ANY_WC:
        return int.from_bytes(bytes(int(p) for p in placeholder.split(".")), "big"), "any"
    return addr.address, addr.describe()


def _addr_last(addr: AddressSpec) -> Optional[int]:
    """Last address of the set (on the wildcard boundary); None for host/any."""
    if addr.wildcard in (0, _ANY_WC):
        return None
    return addr.address | addr.wildcard


def _addr_outside(addr: AddressSpec) -> Optional[int]:
    """First address outside the set: just above its last address, else just below its first."""
    if addr.wildcard == _ANY_WC:
        return None
    above = (addr.address | addr.wildcard) + 1
    if above <= _M32 and not addr.contains(above):
        return above
    below = addr.address - 1
    if below >= 0 and not addr.contains(below):
        return below
    return None


def _port_inside(spec: Optional[PortSpec], default: int) -> Optional[int]:
    """Representative port inside the condition (the exact port for `eq`)."""
    if spec is None:
        return default
    if not spec.intervals:
        return None  # e.g. `lt 0`: no port matches
    op = spec.original.split()[0]
    if op == "lt":
        return spec.intervals[-1][1]  # lt 1024 -> 1023 (the edge)
    return spec.intervals[-1][0]      # eq p -> p, neq p -> p+1, gt p -> p+1, range lo hi -> lo


def _port_edges(spec: Optional[PortSpec]) -> Dict[str, Optional[int]]:
    """``above`` / ``below``: first port outside the condition; ``high``: top of a range."""
    out: Dict[str, Optional[int]] = {"above": None, "below": None, "high": None}
    if spec is None or not spec.intervals:
        return out
    for lo, hi in spec.intervals:
        if out["above"] is None and hi + 1 <= 65535 and not spec.contains(hi + 1):
            out["above"] = hi + 1
        if out["below"] is None and lo - 1 >= 0 and not spec.contains(lo - 1):
            out["below"] = lo - 1
    lo, hi = spec.intervals[-1]
    if hi != lo and spec.original.split()[0] == "range":
        out["high"] = hi
    return out


def _rule_candidates(rule: Rule, acl_type: str) -> Dict[str, Tuple[Dict[str, Any], str, str]]:
    """Edge type -> (packet fields, relation to the rule, edge description)."""
    src_in, src_desc = _addr_inside(rule.src, ANY_SRC_PLACEHOLDER)
    if acl_type == "standard":
        cands: Dict[str, Tuple[Dict[str, Any], str, str]] = {}
        base = {"src": src_in, "dst": None, "protocol": None, "src_port": None,
                "dst_port": None, "established": False}
        cands["hit"] = (base, "inside", "src %s inside %s" % (_ip_str(src_in), src_desc))
        last = _addr_last(rule.src)
        if last is not None:
            cands["src_last"] = (dict(base, src=last), "inside",
                                 "src %s = last address of %s" % (_ip_str(last), src_desc))
        outside = _addr_outside(rule.src)
        if outside is not None:
            cands["src_outside"] = (dict(base, src=outside), "outside",
                                    "src %s = first address outside %s" % (_ip_str(outside), src_desc))
        return cands

    dst_in, dst_desc = _addr_inside(rule.dst, ANY_DST_PLACEHOLDER)
    pnum = rule.protocol_number if rule.protocol_number is not None else PROBE_PROTOCOL_FOR_IP
    has_ports = pnum in (6, 17)
    sport = _port_inside(rule.src_ports, DEFAULT_SRC_PORT) if has_ports else None
    dport = _port_inside(rule.dst_ports, DEFAULT_DST_PORT) if has_ports else None
    if has_ports and (sport is None or dport is None):
        return {}  # the rule matches no port at all: no edge to show
    base = {"src": src_in, "dst": dst_in, "protocol": pnum, "src_port": sport,
            "dst_port": dport, "established": rule.established}

    hit_parts = ["src %s" % _ip_str(src_in), "dst %s" % _ip_str(dst_in), _PROTO_NAMES.get(pnum, str(pnum))]
    if rule.dst_ports is not None:
        hit_parts.append("dst port %d (%s)" % (dport, rule.dst_ports.original))
    if rule.src_ports is not None:
        hit_parts.append("src port %d (%s)" % (sport, rule.src_ports.original))
    if rule.protocol_number is None:
        hit_parts.append("ip rule probed with tcp")
    cands = {"hit": (base, "inside", "inside on every field: " + ", ".join(hit_parts))}

    if has_ports:
        d = _port_edges(rule.dst_ports)
        if d["above"] is not None:
            cands["dst_port_above"] = (dict(base, dst_port=d["above"]), "outside",
                                       "dst port %d = just outside %s" % (d["above"], rule.dst_ports.original))
        if d["below"] is not None:
            cands["dst_port_below"] = (dict(base, dst_port=d["below"]), "outside",
                                       "dst port %d = just outside %s" % (d["below"], rule.dst_ports.original))
        if d["high"] is not None:
            cands["dst_port_high"] = (dict(base, dst_port=d["high"]), "inside",
                                      "dst port %d = top of %s" % (d["high"], rule.dst_ports.original))
        s = _port_edges(rule.src_ports)
        if s["above"] is not None:
            cands["src_port_above"] = (dict(base, src_port=s["above"]), "outside",
                                       "src port %d = just outside %s" % (s["above"], rule.src_ports.original))
        if s["below"] is not None:
            cands["src_port_below"] = (dict(base, src_port=s["below"]), "outside",
                                       "src port %d = just outside %s" % (s["below"], rule.src_ports.original))

    for side, addr, desc in (("src", rule.src, src_desc), ("dst", rule.dst, dst_desc)):
        outside = _addr_outside(addr)
        if outside is not None:
            cands[side + "_outside"] = (dict(base, **{side: outside}), "outside",
                                        "%s %s = first address outside %s" % (side, _ip_str(outside), desc))
        last = _addr_last(addr)
        if last is not None:
            cands[side + "_last"] = (dict(base, **{side: last}), "inside",
                                     "%s %s = last address of %s" % (side, _ip_str(last), desc))

    if rule.established:
        cands["not_established"] = (dict(base, established=False), "outside",
                                    "same packet without established (new TCP session)")
    return cands


# ---------------------------------------------------------------- selection


def _packet_out(fields: Dict[str, Any]) -> Dict[str, Any]:
    proto = fields["protocol"]
    return {
        "src": _ip_str(fields["src"]),
        "dst": _ip_str(fields["dst"]) if fields["dst"] is not None else None,
        "protocol": _PROTO_NAMES.get(proto, proto) if proto is not None else None,
        "src_port": fields["src_port"],
        "dst_port": fields["dst_port"],
        "established": fields["established"],
    }


def auto_packets_for_acl(parsed: ParseResult, acl: Acl,
                         limit: int = MAX_PACKETS_PER_ACL) -> List[Dict[str, Any]]:
    """Up to ``limit`` edge packets for one ACL, each with its trace verdict."""
    per_rule = [(e.line, _rule_candidates(e.rule, acl.acl_type))
                for e in acl.entries
                if e.kind == "rule" and e.status == STATUS_OK and e.rule is not None]
    rows: List[Dict[str, Any]] = []
    seen: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
    for edge in EDGE_ORDER:
        for line, cands in per_rule:
            if edge not in cands:
                continue
            fields, relation, why = cands[edge]
            pkt = _packet_out(fields)
            key = tuple(pkt[k] for k in ("src", "dst", "protocol", "src_port", "dst_port", "established"))
            if key in seen:
                # Same packet from another rule's edge (typically the `hit` of a rule
                # shadowed by an earlier one): no new row, but the link is kept.
                seen[key]["also_built_for"].append({"line": line, "edge": edge, "relation": relation})
                continue
            if len(rows) >= limit:
                continue
            result = trace(parsed, acl.name, Packet(**pkt))
            rows.append({
                "packet": pkt,
                "from_line": line,
                "edge": edge,
                "relation": relation,
                "why": why,
                "verdict": result["verdict"],
                "matched_line": result["matched_line"],
                "implicit_deny": result["implicit_deny"],
                "unevaluated_lines": result["unevaluated_lines"],
                "also_built_for": [],
            })
            seen[key] = rows[-1]
    return rows


def auto_packets(parsed: ParseResult, limit: int = MAX_PACKETS_PER_ACL) -> List[Dict[str, Any]]:
    """``[{acl, packets:[...]}]`` for every ACL in the paste, in paste order."""
    return [{"acl": acl.name, "packets": auto_packets_for_acl(parsed, acl, limit)}
            for acl in parsed.acls.values()]
