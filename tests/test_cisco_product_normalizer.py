"""
Tests for services.platform_taxonomy.normalize_cisco_product_names (CVE-003 Phase 2).

Covers:
  - Single family detection per input name
  - Multiple families in one advisory
  - Ordering: IOS XR / IOS XE variants must match before bare IOS
  - Firewall family precedence (FTD before ASA on shared prefixes)
  - UNKNOWN fallback on empty / unmatchable input
  - Real-world samples lifted from cache/cisco/iosxe.json
"""

import pytest

from services.platform_taxonomy import (
    ProductFamily,
    normalize_cisco_product_names,
)


# ---------------------------------------------------------------------------
# Single-name dispatching
# ---------------------------------------------------------------------------

class TestSingleNameDispatch:
    def test_ios_xe_software(self):
        assert normalize_cisco_product_names(
            ["Cisco IOS XE Software 17.9.4"]
        ) == {ProductFamily.IOS_XE}

    def test_ios_classic(self):
        assert normalize_cisco_product_names(
            ["Cisco IOS 12.2(55)SE"]
        ) == {ProductFamily.IOS}

    def test_ios_xr(self):
        assert normalize_cisco_product_names(
            ["Cisco IOS XR Software"]
        ) == {ProductFamily.IOS_XR}

    def test_nx_os(self):
        assert normalize_cisco_product_names(
            ["Cisco NX-OS Software"]
        ) == {ProductFamily.NX_OS}

    def test_asa_secure_firewall_name(self):
        """Newer Cisco branding: 'Cisco Secure Firewall Adaptive Security Appliance'."""
        assert normalize_cisco_product_names(
            ["Cisco Secure Firewall Adaptive Security Appliance"]
        ) == {ProductFamily.ASA}

    def test_ftd_secure_firewall_name(self):
        assert normalize_cisco_product_names(
            ["Cisco Secure Firewall Threat Defense (FTD)"]
        ) == {ProductFamily.FTD}

    def test_ios_xe_sdwan(self):
        assert normalize_cisco_product_names(
            ["Cisco IOS XE Catalyst SD-WAN"]
        ) == {ProductFamily.IOS_XE_SDWAN}

    def test_wireless_lan_controller(self):
        assert normalize_cisco_product_names(
            ["Cisco Wireless LAN Controller (WLC)"]
        ) == {ProductFamily.IOS_XE_WLC}

    def test_rv_series_model(self):
        assert normalize_cisco_product_names(["Cisco RV340"]) == {ProductFamily.RV_SERIES}


# ---------------------------------------------------------------------------
# Ordering / precedence edge cases
# ---------------------------------------------------------------------------

class TestOrderingPrecedence:
    def test_ios_xe_not_confused_with_ios_classic(self):
        """'Cisco IOS XE Software' should match IOS_XE only, not IOS."""
        result = normalize_cisco_product_names(["Cisco IOS XE Software 17.9.4"])
        assert result == {ProductFamily.IOS_XE}
        assert ProductFamily.IOS not in result

    def test_ios_xr_not_confused_with_ios_classic(self):
        result = normalize_cisco_product_names(["Cisco IOS XR Software"])
        assert result == {ProductFamily.IOS_XR}
        assert ProductFamily.IOS not in result

    def test_ios_classic_isolated_from_xe_xr(self):
        result = normalize_cisco_product_names(["Cisco IOS 15.7(3)M5"])
        assert result == {ProductFamily.IOS}
        assert ProductFamily.IOS_XE not in result
        assert ProductFamily.IOS_XR not in result

    def test_ftd_before_asa_on_shared_prefix(self):
        """'Cisco Secure Firewall Threat Defense' must map to FTD, not ASA."""
        result = normalize_cisco_product_names(
            ["Cisco Secure Firewall Threat Defense"]
        )
        assert result == {ProductFamily.FTD}

    def test_sdwan_more_specific_than_ios_xe(self):
        """SD-WAN product name must NOT double-count as bare IOS_XE too."""
        result = normalize_cisco_product_names(["Cisco IOS XE Catalyst SD-WAN"])
        assert result == {ProductFamily.IOS_XE_SDWAN}
        assert ProductFamily.IOS_XE not in result


# ---------------------------------------------------------------------------
# Multi-family advisories
# ---------------------------------------------------------------------------

class TestMultiFamily:
    def test_mixed_advisory_returns_both(self):
        """Real advisory cisco-sa-http-code-exec-WmfP3h3O covers IOS XR + IOS classic."""
        names = [
            "Cisco IOS XR Software ",
            "Cisco IOS 12.2(15)B",
            "Cisco IOS 12.2(16)B1",
            "Cisco IOS 12.2(16)B3",
        ]
        result = normalize_cisco_product_names(names)
        assert result == {ProductFamily.IOS_XR, ProductFamily.IOS}

    def test_three_way_advisory(self):
        names = [
            "Cisco IOS XE Software 17.9.4",
            "Cisco IOS 15.7(3)M5",
            "Cisco NX-OS Software",
        ]
        assert normalize_cisco_product_names(names) == {
            ProductFamily.IOS_XE,
            ProductFamily.IOS,
            ProductFamily.NX_OS,
        }

    def test_large_list_collapses_to_small_set(self):
        """The core invariant: storage cap. 1000 variants of 'Cisco IOS XE
        Software X.Y.Z' must collapse to {IOS_XE} — a single enum value."""
        names = [f"Cisco IOS XE Software 17.9.{i}" for i in range(1000)]
        assert normalize_cisco_product_names(names) == {ProductFamily.IOS_XE}


# ---------------------------------------------------------------------------
# Unknown / fallback behavior
# ---------------------------------------------------------------------------

class TestUnknownFallback:
    def test_empty_list(self):
        assert normalize_cisco_product_names([]) == {ProductFamily.UNKNOWN}

    def test_none(self):
        assert normalize_cisco_product_names(None) == {ProductFamily.UNKNOWN}

    def test_unrecognized_product(self):
        """A product name we don't have a pattern for → UNKNOWN."""
        assert normalize_cisco_product_names(
            ["Some Unknown Cisco Gadget 2026"]
        ) == {ProductFamily.UNKNOWN}

    def test_non_string_entries_ignored(self):
        """Defensive: None / numeric entries in list silently skipped."""
        names = ["Cisco IOS XE Software 17.9.4", None, 42, "Cisco NX-OS Software"]
        assert normalize_cisco_product_names(names) == {
            ProductFamily.IOS_XE,
            ProductFamily.NX_OS,
        }

    def test_empty_strings_ignored(self):
        assert normalize_cisco_product_names(
            ["", "   ", "Cisco IOS XE Software"]
        ) == {ProductFamily.IOS_XE}

    def test_mixed_known_unknown_returns_known(self):
        """If at least ONE name matches, don't include UNKNOWN."""
        result = normalize_cisco_product_names(
            ["Cisco IOS XE Software 17.9.4", "Some Unknown Gadget"]
        )
        assert result == {ProductFamily.IOS_XE}
        assert ProductFamily.UNKNOWN not in result


# ---------------------------------------------------------------------------
# Real-world samples from cache/cisco/iosxe.json (smoke test)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "advisory_id,names,expected",
    [
        (
            "cisco-sa-secboot-UqFD8AvC",
            [
                "Cisco IOS XE Software 17.3.1",
                "Cisco IOS XE Software 17.3.2",
                "Cisco IOS XE Software 17.3.3",
            ],
            {ProductFamily.IOS_XE},
        ),
        (
            "cisco-sa-snmp-x4LPhte",
            [
                "Cisco IOS 12.2(55)SE",
                "Cisco IOS 12.2(55)SE3",
                "Cisco IOS 12.2(58)SE",
            ],
            {ProductFamily.IOS},
        ),
        (
            "cisco-sa-http-code-exec-sample",
            [
                "Cisco IOS XR Software ",
                "Cisco IOS 12.2(15)B",
                "Cisco IOS 12.2(16)B1",
            ],
            {ProductFamily.IOS_XR, ProductFamily.IOS},
        ),
        (
            "cisco-sa-asa-ftd-mix",
            [
                "Cisco Secure Firewall Adaptive Security Appliance",
                "Cisco Secure Firewall Threat Defense (FTD)",
            ],
            {ProductFamily.ASA, ProductFamily.FTD},
        ),
        (
            "cisco-sa-nexus-example",
            [
                "Cisco NX-OS Software",
                "Cisco Nexus 9000 Series",
            ],
            {ProductFamily.NX_OS},
        ),
    ],
)
def test_real_world_samples(advisory_id, names, expected):
    assert normalize_cisco_product_names(names) == expected, (
        f"advisory {advisory_id}: expected {expected}, got {normalize_cisco_product_names(names)}"
    )
