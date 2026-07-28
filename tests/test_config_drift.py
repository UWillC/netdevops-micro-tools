"""
Config Drift v1.1 regression tests.

Fixtures come from the first real E2E test (2026-07-28): an access-switch
baseline config vs its hardened variant. The reference report from v1.0
flagged 5 classification weaknesses — these tests pin the v1.1 fixes:

1. Comment lines (! ...) are never sections and never produce warnings
2. Removed+added lines of the same command are paired as "modified"
3. Direction tags (hardening/degradation) exist and are sane
4. transport/exec-timeout notes are context-aware (aux is not VTY)
5. Drift score/section counts are not inflated by single-line globals
"""

from pathlib import Path

import pytest

from api.routers.config_drift import (
    DriftRequest,
    compare_configs,
    _parse_into_sections,
    _command_key,
    _security_weight,
    _expand_interface_range,
    GLOBAL_SECTION,
)

FIXTURES = Path(__file__).parent / "fixtures" / "config_drift"


@pytest.fixture(scope="module")
def baseline() -> str:
    return (FIXTURES / "access_switch_baseline.txt").read_text()


@pytest.fixture(scope="module")
def hardened() -> str:
    return (FIXTURES / "access_switch_hardened.txt").read_text()


@pytest.fixture(scope="module")
def report(baseline, hardened):
    return compare_configs(DriftRequest(config_a=baseline, config_b=hardened))


def _all_changes(report):
    for section in report.sections:
        for change in section.changes:
            yield section, change


# ----------------------------
# P1a: comments are never sections
# ----------------------------

class TestCommentsAreNotSections:
    def test_no_comment_sections_in_report(self, report):
        for section in report.sections:
            assert not section.title.lstrip().startswith("!"), (
                f"Comment line leaked as section: {section.title!r}"
            )

    def test_no_comment_lines_in_changes(self, report):
        for section, change in _all_changes(report):
            assert not change.line.lstrip().startswith("!"), (
                f"Comment line reported as drift: {change.line!r}"
            )

    def test_parser_drops_comments(self, baseline):
        sections = _parse_into_sections(baseline, ignore_cosmetic=True)
        for header, lines in sections.items():
            assert not header.lstrip().startswith("!")
            for line in lines:
                assert not line.lstrip().startswith("!")


# ----------------------------
# P1b: context-aware notes (aux is not VTY)
# ----------------------------

class TestContextAwareNotes:
    def test_aux_transport_not_reported_as_vty(self, report):
        aux_changes = [c for s, c in _all_changes(report)
                       if "line aux" in c.section]
        transport = [c for c in aux_changes if "transport" in c.line]
        assert transport, "Expected transport change under line aux 0"
        for change in transport:
            assert "VTY" not in (change.note or ""), (
                f"AUX transport flagged as VTY: {change.note!r}"
            )
            assert "AUX" in (change.note or "")

    def test_vty_changes_still_labeled_vty(self, report):
        vty_changes = [c for s, c in _all_changes(report)
                       if "line vty" in c.section and "exec-timeout" in c.line]
        assert vty_changes, "Expected exec-timeout change under line vty"
        for change in vty_changes:
            assert "VTY" in (change.note or "")


# ----------------------------
# P1c: no granularity inflation
# ----------------------------

class TestGranularity:
    def test_single_line_globals_grouped(self, baseline):
        sections = _parse_into_sections(baseline, ignore_cosmetic=True)
        # Single-line global commands must NOT be their own sections
        assert "ntp server [CORE_SW_IP_1] prefer" not in sections
        assert "logging buffered 64000 informational" not in sections
        assert any("ntp server" in l for l in sections[GLOBAL_SECTION])

    def test_real_blocks_are_sections(self, baseline):
        sections = _parse_into_sections(baseline, ignore_cosmetic=True)
        assert "tacacs server [ISE-1]" in sections
        assert "line vty 0 15" in sections
        assert "interface range GigabitEthernet1/0/1 - 40" in sections

    def test_logical_area_count_sane(self, report):
        # v1.0 reported 67 sections for ~13 logical change areas
        assert len(report.sections) <= 20, (
            f"Section inflation: {len(report.sections)} sections"
        )

    def test_order_independence(self, baseline):
        # Reorder two global lines — drift must stay zero
        reordered = baseline.replace(
            "no ip domain lookup\nip domain name [example.local]",
            "ip domain name [example.local]\nno ip domain lookup",
        )
        rep = compare_configs(DriftRequest(config_a=baseline, config_b=reordered))
        assert rep.drift_score == 0.0
        assert rep.total_added == 0 and rep.total_removed == 0 and rep.total_modified == 0

    def test_identical_configs_zero_drift(self, baseline):
        rep = compare_configs(DriftRequest(config_a=baseline, config_b=baseline))
        assert rep.drift_score == 0.0
        assert rep.summary == ["Configs are identical (no drift detected)."]


# ----------------------------
# P2: modified-line pairing
# ----------------------------

class TestModifiedPairing:
    def _find_modified(self, report, fragment):
        return [c for s, c in _all_changes(report)
                if c.change_type == "modified" and fragment in c.line]

    def test_username_scrypt_paired(self, report):
        mods = self._find_modified(report, "username [breakglass-admin]")
        assert len(mods) == 1, "username secret -> scrypt secret must be ONE modified entry"
        assert "algorithm-type scrypt" in mods[0].line
        assert mods[0].old_line and "algorithm-type" not in mods[0].old_line

    def test_logging_buffered_paired(self, report):
        mods = self._find_modified(report, "logging buffered 512000")
        assert len(mods) == 1
        assert "64000" in mods[0].old_line

    def test_ntp_server_keyed_paired(self, report):
        mods = self._find_modified(report, "ntp server [CORE_SW_IP_1]")
        assert len(mods) == 1
        assert "key 1" in mods[0].line
        assert "key" not in mods[0].old_line

    def test_snmp_community_disable_paired(self, report):
        mods = self._find_modified(report, "no snmp-server community")
        assert len(mods) == 1
        assert mods[0].old_line.startswith("snmp-server community")

    def test_command_keys(self):
        assert _command_key("username [x] privilege 15 secret [s]") == \
               _command_key("username [x] privilege 15 algorithm-type scrypt secret [s]")
        assert _command_key("ntp server [ip1] prefer") == _command_key("ntp server [ip1] key 1 prefer")
        assert _command_key("ntp server [ip1] prefer") != _command_key("ntp server [ip2]")
        assert _command_key("snmp-server community [c] RO [acl]") == \
               _command_key("no snmp-server community [c]")


# ----------------------------
# P4: direction heuristic
# ----------------------------

class TestDirection:
    def test_every_change_has_direction(self, report):
        for section, change in _all_changes(report):
            assert change.direction in ("hardening", "degradation", "neutral")

    def test_snmp_v2c_disable_is_hardening(self, report):
        mods = [c for s, c in _all_changes(report)
                if c.change_type == "modified" and "no snmp-server community" in c.line]
        assert mods and mods[0].direction == "hardening"

    def test_scrypt_upgrade_is_hardening(self, report):
        mods = [c for s, c in _all_changes(report)
                if c.change_type == "modified" and "scrypt" in c.line]
        assert mods and all(m.direction == "hardening" for m in mods)

    def test_removed_protection_is_degradation(self, baseline):
        # Strip port-security from the baseline -> degradation must be flagged
        stripped = baseline.replace(" switchport port-security\n", "")
        rep = compare_configs(DriftRequest(config_a=baseline, config_b=stripped))
        removed = [c for s in rep.sections for c in s.changes
                   if c.change_type == "removed" and "port-security" in c.line]
        assert removed
        assert all(c.direction == "degradation" for c in removed)

    def test_weights(self):
        assert _security_weight("no snmp-server community [c]") == 1
        assert _security_weight("snmp-server community [c] ro [acl]") == -1
        assert _security_weight("ip http server") == -1
        assert _security_weight("no ip http server") == 1
        assert _security_weight("clock timezone [UTC] 0") == 0

    def test_summary_has_direction_disclaimer(self, report):
        assert any("NOT a risk rating" in s for s in report.summary)


# ----------------------------
# Risk classification (round 2 fix: NTP is not AAA)
# ----------------------------

class TestRiskClassification:
    def test_ntp_lines_never_classified_as_aaa(self, report):
        ntp = [c for s, c in _all_changes(report)
               if c.line.strip().startswith("ntp ")]
        assert ntp, "Expected NTP changes in report"
        for change in ntp:
            assert "AAA" not in (change.note or ""), (
                f"NTP line misclassified as AAA: {change.line!r} -> {change.note!r}"
            )

    def test_ntp_keyed_server_is_warning_ntp(self, report):
        hits = [c for s, c in _all_changes(report)
                if "ntp server" in c.line and "key 1" in c.line]
        assert hits
        for change in hits:
            assert change.risk == "warning"
            assert "NTP" in (change.note or "")

    def test_tacacs_key_child_still_critical(self):
        a = "tacacs server ISE\n address ipv4 10.0.0.1\n"
        b = "tacacs server ISE\n address ipv4 10.0.0.1\n key SECRET123\n"
        rep = compare_configs(DriftRequest(config_a=a, config_b=b))
        added = [c for s in rep.sections for c in s.changes
                 if c.change_type == "added" and c.line.strip().startswith("key ")]
        assert added
        assert added[0].risk == "critical"
        assert "AAA" in added[0].note

    def test_fixture_critical_count_is_exactly_real(self, report):
        # Reference review 28.07: real CRITICALs = username, enable secret,
        # aaa authorization console, snmp community. NTP must not inflate this.
        criticals = [c for s, c in _all_changes(report) if c.risk == "critical"]
        assert len(criticals) == 4, (
            f"Expected 4 real CRITICALs, got {len(criticals)}: "
            f"{[c.line for c in criticals]}"
        )


# ----------------------------
# P5: reference detections from the real E2E test (trap coverage)
# ----------------------------

class TestReferenceDetections:
    def test_trap_removed_no_cdp_enable_detected(self, report):
        """v1.0 trap: 'no cdp enable' removed from user ports must be caught."""
        removed = [c for s, c in _all_changes(report)
                   if c.change_type == "removed" and "no cdp enable" in c.line
                   and "GigabitEthernet1/0/1 - 40" in c.section]
        assert removed, "Removed 'no cdp enable' on user ports not detected"

    def test_trap_snmp_community_change_detected(self, report):
        hits = [c for s, c in _all_changes(report)
                if "snmp-server community" in c.line]
        assert hits, "SNMP community change not detected"
        assert any(c.risk == "critical" for c in hits)

    def test_tacacs_timeout_addition_detected(self, report):
        added = [c for s, c in _all_changes(report)
                 if c.change_type == "added" and c.line.strip() == "timeout 5"
                 and "tacacs" in c.section]
        assert added

    def test_native_vlan_flagged(self, report):
        hits = [c for s, c in _all_changes(report)
                if "switchport trunk native vlan" in c.line]
        assert hits
        assert all(c.risk == "warning" for c in hits)
        assert all("Trunk" in (c.note or "") for c in hits)

    def test_root_guard_flagged_stp(self, report):
        hits = [c for s, c in _all_changes(report)
                if "spanning-tree guard root" in c.line]
        assert hits
        assert all("STP" in (c.note or "") for c in hits)

    def test_banner_is_single_logical_line(self, report):
        # Multiline banner must not explode into pseudo-sections ('^' etc.)
        for section in report.sections:
            assert section.title.strip() != "^"
        banner_changes = [c for s, c in _all_changes(report) if c.line.startswith("banner login")]
        assert len(banner_changes) == 1
        assert banner_changes[0].change_type == "added"

    def test_totals_consistent(self, report):
        assert report.total_added == sum(s.added_count for s in report.sections)
        assert report.total_removed == sum(s.removed_count for s in report.sections)
        assert report.total_modified == sum(s.modified_count for s in report.sections)
        assert report.total_modified >= 4  # username, logging buffered, ntp x1+, snmp community
        assert 0 < report.drift_score <= 100


# ----------------------------
# Round 4: negative controls + unchanged-counter bug + range expansion
# ----------------------------

class TestNegativeControls:
    """Variants generated by the network assistant (2026-07-28 round 4)."""

    def test_variant1_reordered_zero_drift(self, baseline):
        v1 = (FIXTURES / "variant1_reordered.txt").read_text()
        rep = compare_configs(DriftRequest(config_a=baseline, config_b=v1))
        assert rep.drift_score == 0.0
        assert rep.total_added == rep.total_removed == rep.total_modified == 0

    def test_variant2_whitespace_zero_drift(self, baseline):
        v2 = (FIXTURES / "variant2_whitespace.txt").read_text()
        rep = compare_configs(DriftRequest(config_a=baseline, config_b=v2))
        assert rep.drift_score == 0.0
        assert rep.total_added == rep.total_removed == rep.total_modified == 0

    def test_unchanged_counter_deterministic(self, baseline):
        """86-vs-100 inconsistency fix: unchanged must be identical for
        identical, reordered, and whitespace-mangled variants."""
        v1 = (FIXTURES / "variant1_reordered.txt").read_text()
        v2 = (FIXTURES / "variant2_whitespace.txt").read_text()
        ref = compare_configs(DriftRequest(config_a=baseline, config_b=baseline)).total_unchanged
        assert ref > 0
        for variant in (v1, v2):
            rep = compare_configs(DriftRequest(config_a=baseline, config_b=variant))
            assert rep.total_unchanged == ref


class TestUnchangedCounterBug:
    """Round 4 hard defect: Unchanged: 0 / score 100% was mathematically
    impossible when only interface sections changed (unique-line union
    deduplicated identical child lines repeated across per-port sections)."""

    def test_expansion_off_score_not_100(self, baseline):
        v3 = (FIXTURES / "variant3_expanded_interfaces.txt").read_text()
        rep = compare_configs(DriftRequest(
            config_a=baseline, config_b=v3, expand_interface_range=False))
        assert rep.total_unchanged > 50, "globals identical — unchanged must not clamp to 0"
        assert rep.drift_score < 100.0

    def test_score_is_changed_over_changed_plus_unchanged(self, report):
        changed = report.total_added + report.total_removed + report.total_modified
        expected = round(changed / (changed + report.total_unchanged) * 100, 1)
        assert report.drift_score == expected


class TestInterfaceRangeExpansion:
    """Golden templates use 'interface range'; IOS-XE running-config is
    always per-port. Unmatched ranges are expanded before the diff."""

    def test_variant3_per_port_zero_drift(self, baseline):
        v3 = (FIXTURES / "variant3_expanded_interfaces.txt").read_text()
        rep = compare_configs(DriftRequest(config_a=baseline, config_b=v3))
        assert rep.drift_score == 0.0
        assert rep.total_added == rep.total_removed == rep.total_modified == 0

    def test_expand_helper(self):
        out = _expand_interface_range(
            "interface range GigabitEthernet1/0/1 - 3", [" switchport mode access"])
        assert list(out.keys()) == [
            "interface GigabitEthernet1/0/1",
            "interface GigabitEthernet1/0/2",
            "interface GigabitEthernet1/0/3",
        ]
        assert all(lines == [" switchport mode access"] for lines in out.values())

    def test_expand_helper_comma_list(self):
        out = _expand_interface_range(
            "interface range GigabitEthernet1/0/1 - 2, TenGigabitEthernet1/1/1", [])
        assert "interface GigabitEthernet1/0/1" in out
        assert "interface GigabitEthernet1/0/2" in out
        assert "interface TenGigabitEthernet1/1/1" in out

    def test_identical_ranges_stay_compact(self, report):
        # baseline vs hardened: same range headers on both sides -> NOT expanded
        titles = [s.title for s in report.sections]
        assert any("interface range GigabitEthernet1/0/1 - 40" in t for t in titles)
        assert not any(t == "interface GigabitEthernet1/0/1" for t in titles)


class TestNewSectionTriage:
    """Round 4 cosmetic fix: child lines of a brand-new section are initial
    config — warnings downgraded to info, genuine CRITICALs stay."""

    def test_new_interface_children_are_info_not_warning(self):
        a = "hostname X\nntp master\n"
        b = ("hostname X\nntp master\n"
             "interface GigabitEthernet1/0/99\n"
             " description NEW\n switchport mode access\n spanning-tree portfast\n")
        rep = compare_configs(DriftRequest(config_a=a, config_b=b, expand_interface_range=False))
        children = [c for s in rep.sections for c in s.changes
                    if c.section.startswith("interface") and c.line.strip() != c.section]
        assert children
        assert all(c.risk in (None, "info") for c in children), (
            [(c.line, c.risk) for c in children])

    def test_new_section_critical_lines_stay_critical(self):
        a = "hostname X\n"
        b = "hostname X\ntacacs server NEW-ISE\n address ipv4 10.9.9.9\n key SECRET99\n"
        rep = compare_configs(DriftRequest(config_a=a, config_b=b))
        crit = [c for s in rep.sections for c in s.changes if c.risk == "critical"]
        assert crit, "CRITICAL patterns in new sections must not be silenced"

    def test_fixture_warning_count(self, report):
        # Round 3 review counted 13 WARNINGs by hand; round 4 downgrades the
        # 'transport input none' inside brand-new 'line aux 0' to info
        # (initial config in a new section) -> 12 real WARNINGs remain.
        warnings = [c for s, c in _all_changes(report) if c.risk == "warning"]
        assert len(warnings) == 12

    def test_aux_transport_in_new_section_is_info(self, report):
        aux = [c for s, c in _all_changes(report)
               if "line aux" in c.section and "transport" in c.line]
        assert aux
        assert all(c.risk == "info" for c in aux)
