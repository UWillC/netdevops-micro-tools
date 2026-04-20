"""
CVE-009 EoL registry tests (v0.6.18).

Anchors the defect-report Run 1 case (Cisco IOS 15.7(3)M5 on 2900 ISR)
plus a sample of common EoL platforms operators may query.
"""
from services.eol_registry import detect_eol


def test_defect_report_run1_anchor_isr2900_15_7_3_m5():
    """The exact case the defect report flagged: ISR 2900 + 15.7(3)M5
    is end-of-life on both axes. Banner MUST fire."""
    result = detect_eol("Cisco 2900 Series ISR", "15.7(3)M5")
    assert result is not None
    assert result["is_eol"] is True
    assert result["hardware"] is not None
    assert "2900" in result["hardware"]["family"]
    assert result["ios_train"] is not None
    assert "15.7(3)M" in result["ios_train"]["train"]
    assert "no software updates" in result["banner_text"].lower()
    assert "hardware replacement" in result["banner_text"].lower()
    assert "ISR 4000" in result["banner_text"] or "Catalyst 8200" in result["banner_text"]


def test_isr2900_substring_match_variants():
    """Operators paste platform strings in many forms."""
    for variant in [
        "Cisco 2900 Series ISR",
        "ISR2900",
        "isr 2900",
        "Cisco 2911 Integrated Services Router",
        "2951 router",
    ]:
        r = detect_eol(variant, "15.7(3)M5")
        assert r is not None, f"failed for {variant!r}"
        assert "2900" in r["hardware"]["family"]


def test_catalyst_6500_eol():
    """Cat 6500 EoSWM 2018, EoVSS 2022."""
    r = detect_eol("Catalyst 6500", "15.5(1)SY")
    assert r is not None
    assert r["hardware"]["family"].startswith("Cisco Catalyst 6500")
    assert "Catalyst 9600" in r["hardware"]["replacement_suggestion"]


def test_asa_5510_eol_long_past():
    """ASA 5510 EoVSS 2019."""
    r = detect_eol("ASA 5510", "9.1.7")
    assert r is not None
    assert "5510" in r["hardware"]["family"] or "5500 Series" in r["hardware"]["family"]


def test_rv_series_eol():
    """Defect report mentioned RV Series specifically — many CVEs unpatched."""
    r = detect_eol("RV082", "")
    assert r is not None
    assert "RV" in r["hardware"]["family"]
    assert "no patch" in r["hardware"]["replacement_suggestion"].lower() or \
           "many" in r["hardware"]["replacement_suggestion"].lower()


def test_current_platform_no_banner():
    """Catalyst 9300 + IOS XE 17.9.4 = current. Banner MUST NOT fire."""
    r = detect_eol("Catalyst 9300", "17.9.4")
    assert r is None


def test_current_iosxe_no_banner():
    """IOS XE 17.x is the current train. No EoL match."""
    r = detect_eol("Cisco ISR 4451", "17.12.3")
    assert r is None


def test_ios_classic_12_x_legacy():
    """IOS classic 12.x is long EoL — banner fires even on a current-sounding
    hardware string (just in case operator typed a fake/legacy combo)."""
    r = detect_eol("Cisco 7200 Series", "12.4(24)T8")
    # No hardware match for 7200 in our table, but the IOS train alone fires.
    assert r is not None
    assert r["ios_train"] is not None
    assert "12.x" in r["ios_train"]["train"]


def test_unknown_platform_returns_none():
    """Bogus input → None, no false positive banners."""
    assert detect_eol("MadeUpRouter 9999", "999.999") is None
    assert detect_eol("", "") is None
    assert detect_eol(None, None) is None


def test_banner_text_includes_dates():
    """Operators need the actual EoVSS date for compliance reporting."""
    r = detect_eol("Cisco 2900 Series ISR", "15.7(3)M5")
    assert "2022-12-31" in r["banner_text"]


def test_banner_includes_replacement_when_known():
    r = detect_eol("ISR 1900", "")
    assert r is not None
    assert "Suggested replacement" in r["banner_text"]
    assert ("ISR 1000" in r["banner_text"] or "Catalyst 8200" in r["banner_text"])
