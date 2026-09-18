"""
Tests for Cisco ISE version parsing (ISE-01, 2026-09-18).

Covers:
  - "3.4 Patch 7" / "3.5P4" / "Cisco ISE 3.3 Patch 12" parsing
  - installed-image form "3.4.0.608"
  - patch level ordering within a train, and train ordering
  - the ambiguity rule: bare "3.4.0" is IOS XE, NOT ISE
  - cross-family comparison returns None
"""

import pytest

from services.cisco_version import (
    CiscoIosXeVersion,
    CiscoIseVersion,
    cisco_compare,
    parse_cisco_version,
)


class TestIseParse:
    def test_train_with_patch(self):
        assert CiscoIseVersion.parse("3.4 Patch 7") == CiscoIseVersion(3, 4, 0, 0, 7)

    def test_train_without_patch(self):
        assert CiscoIseVersion.parse("3.1") == CiscoIseVersion(3, 1, 0, 0, 0)

    def test_compact_patch_form(self):
        assert CiscoIseVersion.parse("3.5P4") == CiscoIseVersion(3, 5, 0, 0, 4)

    def test_installed_image_form(self):
        assert CiscoIseVersion.parse("3.4.0.608") == CiscoIseVersion(3, 4, 0, 608, 0)

    def test_patch_case_insensitive_and_spacing(self):
        assert CiscoIseVersion.parse("3.3 patch 12") == CiscoIseVersion(3, 3, 0, 0, 12)
        assert CiscoIseVersion.parse("3.3  PATCH  12") == CiscoIseVersion(3, 3, 0, 0, 12)

    def test_garbage_returns_none(self):
        for bad in ("", "   ", "Patch 7", "3", "abc", "3.4 Patch"):
            assert CiscoIseVersion.parse(bad) is None


class TestIsePrefixes:
    @pytest.mark.parametrize("s", [
        "Cisco ISE 3.4 Patch 7",
        "ISE 3.4 Patch 7",
        "Cisco ISE-PIC 3.4 Patch 7",
        "ISE-PIC 3.4 Patch 7",
        "Cisco Identity Services Engine 3.4 Patch 7",
        "Identity Services Engine 3.4 Patch 7",
    ])
    def test_prefix_stripped(self, s):
        assert parse_cisco_version(s) == CiscoIseVersion(3, 4, 0, 0, 7)

    def test_prefix_makes_bare_version_ise(self):
        """Without the prefix "3.4.0" is IOS XE; with it, ISE."""
        assert parse_cisco_version("3.4.0") == CiscoIosXeVersion(3, 4, 0, 0, 0)
        assert parse_cisco_version("ISE 3.4.0") == CiscoIseVersion(3, 4, 0, 0, 0)


class TestIseAmbiguity:
    """The comparator must refuse to guess between ISE and IOS XE.

    A bare dotted triple is a legal IOS XE version and a plausible ISE one.
    Silently picking ISE would cross-match two unrelated product families,
    which is worse than returning a family the caller can override.
    """

    def test_bare_triple_is_ios_xe(self):
        assert isinstance(parse_cisco_version("3.4.0"), CiscoIosXeVersion)

    def test_patch_token_is_enough_without_prefix(self):
        assert parse_cisco_version("3.4 Patch 7") == CiscoIseVersion(3, 4, 0, 0, 7)

    def test_ios_xe_untouched_by_ise_support(self):
        assert parse_cisco_version("17.9.4a") == CiscoIosXeVersion(17, 9, 4, 1, 0)


class TestIseOrdering:
    def test_patch_level_orders_within_train(self):
        assert cisco_compare("ISE 3.4 Patch 7", "ISE 3.4 Patch 6") == 1
        assert cisco_compare("ISE 3.4 Patch 6", "ISE 3.4 Patch 7") == -1
        assert cisco_compare("ISE 3.4 Patch 7", "ISE 3.4 Patch 7") == 0

    def test_unpatched_train_is_lowest(self):
        assert cisco_compare("ISE 3.4", "ISE 3.4 Patch 1") == -1

    def test_train_beats_patch_level(self):
        """3.5 Patch 4 is newer than 3.4 Patch 7 despite the lower patch number."""
        assert cisco_compare("ISE 3.5 Patch 4", "ISE 3.4 Patch 7") == 1

    def test_double_digit_patch_orders_numerically(self):
        """String ordering would put "Patch 9" above "Patch 12"."""
        assert cisco_compare("ISE 3.3 Patch 12", "ISE 3.3 Patch 9") == 1

    def test_cross_family_is_none(self):
        assert cisco_compare("ISE 3.4 Patch 7", "17.9.4") is None
        assert cisco_compare("ISE 3.4 Patch 7", "15.7(3)M5") is None


class TestIseFixedReleasesFromAdvisory:
    """Real fixed releases from cisco-sa-ISE-ABP-VNSW7Tn5 (2026-09-16).

    A device on the listed patch level or above is fixed; below it is not.
    """

    FIXES = {"3.1": "3.1 Patch 12", "3.2": "3.2 Patch 11",
             "3.3": "3.3 Patch 12", "3.4": "3.4 Patch 7", "3.5": "3.5 Patch 4"}

    @pytest.mark.parametrize("train,fix", sorted(FIXES.items()))
    def test_one_patch_below_fix_is_vulnerable(self, train, fix):
        level = int(fix.rsplit(" ", 1)[1])
        running = "%s Patch %d" % (train, level - 1)
        assert cisco_compare("ISE " + running, "ISE " + fix) == -1

    @pytest.mark.parametrize("train,fix", sorted(FIXES.items()))
    def test_at_fix_is_not_below(self, train, fix):
        assert cisco_compare("ISE " + fix, "ISE " + fix) == 0

    @pytest.mark.parametrize("train,fix", sorted(FIXES.items()))
    def test_above_fix_is_fixed(self, train, fix):
        level = int(fix.rsplit(" ", 1)[1])
        running = "%s Patch %d" % (train, level + 1)
        assert cisco_compare("ISE " + running, "ISE " + fix) == 1
