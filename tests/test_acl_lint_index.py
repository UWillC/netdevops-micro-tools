"""
Shadow / L10 index in services/acl_lint.py (@ciso W4, 2026-10-28): differential test.

The index replaces two pairwise scans (``_check_shadow``: every rule against
every earlier rule; ``_check_established_pairs``: every established rule against
every rule of the other ACLs). The pairwise versions are kept below VERBATIM
(as on main 297beff) as the reference. Every lint result must be byte-identical
(``lint_json``) with the reference on: the 21 lint fixtures, the hostile 500-rule
inputs from the @ciso review and the @cto search for a new worst case, and a
seeded random corpus built from small value pools (so containment, partial
overlap, non-contiguous wildcards, empty port sets and port edges 0/65535 occur
often). A second test checks the index bitsets against rule_contains /
rules_intersect for every ordered pair.
"""

import random
import statistics
import time

import pytest

from services import acl_lint
from services.acl_engine import STATUS_OK, parse_acls
from services.acl_lint import (
    _PortIndex,
    _ports,
    _ShadowIndex,
    _finding,
    _verb,
    lint,
    lint_json,
    ports_intersect,
    rule_contains,
    rules_identical,
    rules_intersect,
)
from tests.test_acl_lint import FIXTURES


# ---------------------------------------------------------------- reference (pairwise, main 297beff)


def _ref_check_shadow(rules, findings):
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


def _ref_check_established_pairs(parsed, findings_by_acl):
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


def _ref_lint_json(parsed, monkeypatch):
    with monkeypatch.context() as m:
        m.setattr(acl_lint, "_check_shadow", _ref_check_shadow)
        m.setattr(acl_lint, "_check_established_pairs", _ref_check_established_pairs)
        return lint_json(parsed)


# ---------------------------------------------------------------- corpus


def _acl(name, lines):
    return "ip access-list extended %s\n" % name + "".join(" %s\n" % l for l in lines)


def _act(i):
    return "permit" if i % 2 else "deny"


def _quad(r):
    return "%d.%d.%d.%d" % tuple(r.randrange(256) for _ in range(4))


def hostile_worst():
    """@ciso review 28.10: 500 rules that differ only in the last port, actions alternating."""
    return "ip access-list extended WORST\n" + "".join(
        " %s tcp any neq 5 any eq %d established\n" % (_act(i), i) for i in range(1, 501))


def hostile_range():
    return "ip access-list extended R\n" + "".join(
        " %s tcp any range 0 65535 any eq %d\n" % (_act(i), i) for i in range(1, 501))


def hostile_combo():
    """@cto 28.10, worst found against the index: every field distinct, non-contiguous wildcards,
    two port intervals on src, wide distinct ranges on dst (largest bitsets and sparse tables)."""
    r = random.Random(2)
    return _acl("C", ["%s tcp %s %s neq %d %s %s range %d %d%s" % (
        _act(i), _quad(r), _quad(r), 1000 + i, _quad(r), _quad(r), i, 65535 - 2 * i,
        " established" if i % 3 == 0 else "") for i in range(500)])


def hostile_port_segments():
    return _acl("PS", ["%s tcp any neq %d any range %d %d established" % (_act(i), 1000 + i, i, 65535 - i)
                       for i in range(500)])


def hostile_l11_chain():
    return _acl("O", ["%s tcp any range %d %d any" % (_act(i), i, i + 1000) for i in range(500)])


def hostile_l10_two_acls():
    return (_acl("IN", ["permit tcp any eq %d any established" % (1 + i) for i in range(250)]) +
            _acl("OUT", ["permit tcp any any eq %d" % (30000 + i) for i in range(250)]))


def hostile_l10_many():
    return (_acl("IN", ["permit tcp any range %d %d any established" % (i, 65535 - i) for i in range(499)]) +
            _acl("OUT", ["permit tcp any any lt 1"]))


def hostile_std_noncontig():
    r = random.Random(3)
    return "".join("access-list 10 %s %s %s\n" % (_act(i), _quad(r), _quad(r)) for i in range(500))


HOSTILE = [hostile_worst, hostile_range, hostile_combo, hostile_port_segments, hostile_l11_chain,
           hostile_l10_two_acls, hostile_l10_many, hostile_std_noncontig]

_ADDRS = ["any", "any", "host 10.0.0.1", "host 10.0.0.2", "10.0.0.0 0.0.0.255", "10.0.0.0 0.0.255.255",
          "10.0.1.0 0.0.0.255", "10.0.0.1 0.0.0.254", "10.0.0.0 0.255.0.255", "10.0.0.5 0.0.0.3",
          "0.0.0.0 255.255.255.254", "host 10.0.1.1", "10.0.0.0 0.0.0.1"]
_PORTS = ["", "", "", "eq 0", "eq 22", "eq 80", "eq 65535", "neq 22", "neq 0", "neq 65535", "lt 1",
          "lt 1024", "lt 0", "gt 1023", "gt 65534", "gt 65535", "range 0 65535", "range 20 80",
          "range 22 22", "range 80 443", "range 1024 65535", "eq www", "range 0 21"]
_PROTOS = ["ip", "ip", "tcp", "tcp", "tcp", "udp", "udp", "icmp", "6", "17", "47"]


def _random_rule(r, standard):
    action = r.choice(["permit", "deny"])
    log = r.choice(["", "", "", " log", " log-input"])
    if standard:
        return "%s %s%s" % (action, r.choice(_ADDRS), log)
    proto = r.choice(_PROTOS)
    ports = proto in ("tcp", "udp")
    sp = r.choice(_PORTS) if ports and r.random() < 0.4 else ""
    dp = r.choice(_PORTS) if ports else ""
    est = " established" if proto == "tcp" and r.random() < 0.3 else ""
    if r.random() < 0.02:
        est = " established"  # occasionally invalid (P01): must be skipped identically
    return "%s %s %s%s %s%s%s%s" % (action, proto, r.choice(_ADDRS), " " + sp if sp else "",
                                    r.choice(_ADDRS), " " + dp if dp else "", est, log)


def random_paste(seed):
    r = random.Random(seed)
    out = []
    for k in range(r.choice([1, 1, 2, 2, 3])):
        if r.random() < 0.2:
            num = r.choice([10, 11, 99])
            out.extend("access-list %d %s" % (num, _random_rule(r, True)) for _ in range(r.randint(1, 30)))
            continue
        out.append("ip access-list extended A%d" % k)
        n = r.randint(1, 40)
        seqs = r.sample(range(1, 1000), n) if r.random() < 0.3 else [10 * (i + 1) for i in range(n)]
        for s in seqs:
            if r.random() < 0.05:
                out.append(" remark x")
            out.append(" %d %s" % (s, _random_rule(r, False)))
    return "\n".join(out) + "\n"


RANDOM_SEEDS = range(1500)


# ---------------------------------------------------------------- tests


@pytest.mark.parametrize("name,paste,_expected", FIXTURES, ids=[f[0] for f in FIXTURES])
def test_fixtures_identical_to_pairwise(name, paste, _expected, monkeypatch):
    parsed = parse_acls(paste)
    assert lint_json(parsed) == _ref_lint_json(parsed, monkeypatch)


@pytest.mark.parametrize("gen", HOSTILE, ids=[g.__name__ for g in HOSTILE])
def test_hostile_identical_to_pairwise(gen, monkeypatch):
    parsed = parse_acls(gen())
    assert lint_json(parsed) == _ref_lint_json(parsed, monkeypatch)


def test_random_corpus_identical_to_pairwise(monkeypatch):
    findings = {}
    for seed in RANDOM_SEEDS:
        parsed = parse_acls(random_paste(seed))
        new = lint_json(parsed)
        assert new == _ref_lint_json(parsed, monkeypatch), "seed %d" % seed
        for acl in lint(parsed)["acls"]:
            for f in acl["findings"]:
                findings[f["id"]] = findings.get(f["id"], 0) + 1
    # The corpus must actually exercise every finding the index decides.
    for fid in ("L01", "L02", "L03", "L10", "L11"):
        assert findings.get(fid, 0) >= 20, findings


def test_index_bitsets_match_pairwise_functions():
    """contain / overlap / inside of every rule against every rule (not only the first hit)."""
    for seed in range(300):
        parsed = parse_acls(random_paste(10_000 + seed))
        for acl in parsed.acls.values():
            rules = [e.rule for e in acl.entries if e.status == STATUS_OK and e.rule is not None]
            if not rules:
                continue
            index = _ShadowIndex(rules)
            for rb in rules:
                contain, overlap, inside = index.masks(rb)
                for i, ra in enumerate(rules):
                    bit = (contain >> i) & 1, (overlap >> i) & 1, (inside >> i) & 1
                    assert bit == (rule_contains(ra, rb), rules_intersect(ra, rb), rule_contains(rb, ra)), \
                        (seed, ra, rb)


def test_port_index_all_interval_shapes():
    r = random.Random(7)
    edges = [0, 1, 2, 21, 22, 23, 80, 443, 1023, 1024, 65534, 65535]
    sets = []
    for _ in range(200):
        k = r.choice([0, 1, 1, 2, 3])
        pts = sorted(r.sample(edges, 2 * k)) if k else []
        sets.append(acl_lint._merge(tuple((pts[2 * i], pts[2 * i + 1]) for i in range(k))))
    sets.append(())
    sets.append(((0, 65535),))
    index = _PortIndex(sets, (1 << len(sets)) - 1)
    for b in sets:
        contain, overlap, inside = index.masks(b)
        for i, a in enumerate(sets):
            assert (contain >> i) & 1 == acl_lint.ports_contain(a, b)
            assert (overlap >> i) & 1 == ports_intersect(a, b)
            assert (inside >> i) & 1 == acl_lint.ports_contain(b, a)


@pytest.mark.parametrize("gen", [hostile_worst, hostile_range, hostile_combo], ids=["worst", "range", "combo"])
def test_hostile_500_rules_lint_fast(gen):
    """W4: the pairwise lint took ~350 ms locally on WORST; the index ~5-20 ms. Loose guard against O(n^2)."""
    parsed = parse_acls(gen())
    times = []
    for _ in range(3):
        start = time.perf_counter()
        lint(parsed)
        times.append((time.perf_counter() - start) * 1000)
    assert statistics.median(times) < 100, times
