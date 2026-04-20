"""
End-of-Life (EoX) registry for Cisco platforms — CVE-009.

Lightweight hardcoded lookup table. Lives independently of the live Cisco
EoX API (which requires PSIRT credentials and a refresh job). The data here
covers the most commonly-asked-about platforms in branch / SMB networks
where EoL is a frequent footgun.

When the target platform falls past `end_of_vuln_security_support`, the
CVE Analyzer emits a top-banner: "no software updates are available;
remediation is hardware replacement, not patch."

Sources:
- Cisco EoL Bulletins (https://www.cisco.com/c/en/us/products/end-of-life-policy.html)
- Per-product EoL notices linked from product pages.

Format:
- HARDWARE_EOX: matched by case-insensitive substring on the platform string.
- IOS_TRAIN_EOX: matched by version prefix (IOS classic). IOS XE 17.x is
  current — no entries needed.

Add an entry by:
1. Find the EoL bulletin URL.
2. Add a row to HARDWARE_EOX or IOS_TRAIN_EOX.
3. Run `pytest tests/test_eol_registry.py` to confirm matching works.
"""
from __future__ import annotations

from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Hardware EoX
# ---------------------------------------------------------------------------
# `match` is a list of substrings (lowercased compare) that identify the
# hardware family on the user-supplied platform string. First match wins.

HARDWARE_EOX: List[Dict] = [
    {
        "match": ["isr 2900", "2900 series isr", "2901", "2911", "2921", "2951", "isr2900"],
        "family": "Cisco 2900 Series ISR (Generation 2)",
        "end_of_sale": "2017-12-09",
        "end_of_software_maintenance": "2018-12-31",
        "end_of_vuln_security_support": "2022-12-31",
        "last_day_of_support": "2022-12-31",
        "replacement_suggestion": "ISR 4000 series (4321/4331/4351/4451) or Catalyst 8200 series",
        "bulletin_url": "https://www.cisco.com/c/en/us/products/collateral/routers/2900-series-integrated-services-routers-isr/eos-eol-notice-c51-739184.html",
    },
    {
        "match": ["isr 1900", "1900 series isr", "1905", "1921", "1941", "isr1900"],
        "family": "Cisco 1900 Series ISR (Generation 2)",
        "end_of_sale": "2017-12-09",
        "end_of_software_maintenance": "2018-12-31",
        "end_of_vuln_security_support": "2022-12-31",
        "last_day_of_support": "2022-12-31",
        "replacement_suggestion": "ISR 1000 series or Catalyst 8200 series",
        "bulletin_url": "https://www.cisco.com/c/en/us/products/collateral/routers/1900-series-integrated-services-routers-isr/eos-eol-notice-c51-739186.html",
    },
    {
        "match": ["isr 3900", "3900 series isr", "3925", "3945", "isr3900"],
        "family": "Cisco 3900 Series ISR (Generation 2)",
        "end_of_sale": "2017-12-09",
        "end_of_software_maintenance": "2018-12-31",
        "end_of_vuln_security_support": "2022-12-31",
        "last_day_of_support": "2022-12-31",
        "replacement_suggestion": "ISR 4000 series (4431/4451) or Catalyst 8300 series",
        "bulletin_url": "https://www.cisco.com/c/en/us/products/collateral/routers/3900-series-integrated-services-routers-isr/eos-eol-notice-c51-739185.html",
    },
    {
        "match": ["catalyst 6500", "cat6500", "c6500", "6500 series"],
        "family": "Cisco Catalyst 6500 Series Switches",
        "end_of_sale": "2017-04-30",
        "end_of_software_maintenance": "2018-04-30",
        "end_of_vuln_security_support": "2022-04-30",
        "last_day_of_support": "2025-04-30",
        "replacement_suggestion": "Catalyst 9600 series",
        "bulletin_url": "https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-6500-series-switches/eos-eol-notice-c51-738605.html",
    },
    {
        "match": ["catalyst 4500", "cat4500", "c4500", "4500 series"],
        "family": "Cisco Catalyst 4500-E Series Switches",
        "end_of_sale": "2019-04-30",
        "end_of_software_maintenance": "2020-04-30",
        "end_of_vuln_security_support": "2024-04-30",
        "last_day_of_support": "2024-04-30",
        "replacement_suggestion": "Catalyst 9400 series",
        "bulletin_url": "https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-4500-series-switches/eos-eol-notice-c51-738603.html",
    },
    {
        "match": ["catalyst 3650", "c3650", "ws-c3650"],
        "family": "Cisco Catalyst 3650 Series Switches",
        "end_of_sale": "2021-10-30",
        "end_of_software_maintenance": "2022-10-31",
        "end_of_vuln_security_support": "2026-10-31",
        "last_day_of_support": "2026-10-31",
        "replacement_suggestion": "Catalyst 9300 series",
        "bulletin_url": "https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-3650-series-switches/eos-eol-notice-c51-744236.html",
    },
    {
        "match": ["catalyst 3850", "c3850", "ws-c3850"],
        "family": "Cisco Catalyst 3850 Series Switches",
        "end_of_sale": "2021-10-30",
        "end_of_software_maintenance": "2022-10-31",
        "end_of_vuln_security_support": "2026-10-31",
        "last_day_of_support": "2026-10-31",
        "replacement_suggestion": "Catalyst 9300 series",
        "bulletin_url": "https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-3850-series-switches/eos-eol-notice-c51-744237.html",
    },
    {
        "match": ["asa 5505", "5505", "asa5505"],
        "family": "Cisco ASA 5505 Adaptive Security Appliance",
        "end_of_sale": "2017-08-25",
        "end_of_software_maintenance": "2018-08-31",
        "end_of_vuln_security_support": "2022-08-31",
        "last_day_of_support": "2022-08-31",
        "replacement_suggestion": "Firepower 1010 (FTD)",
        "bulletin_url": "https://www.cisco.com/c/en/us/products/collateral/security/asa-5505-adaptive-security-appliance/eos-eol-notice-c51-737583.html",
    },
    {
        "match": ["asa 5510", "asa 5520", "asa 5540", "asa 5550", "5510", "5520", "5540"],
        "family": "Cisco ASA 5500 Series (5510/5520/5540/5550)",
        "end_of_sale": "2014-09-15",
        "end_of_software_maintenance": "2015-09-30",
        "end_of_vuln_security_support": "2019-09-30",
        "last_day_of_support": "2019-09-30",
        "replacement_suggestion": "Firepower 1100 series or 2100 series",
        "bulletin_url": "https://www.cisco.com/c/en/us/products/collateral/security/asa-5500-series-next-generation-firewalls/eos-eol-notice-c51-731639.html",
    },
    {
        "match": ["rv042", "rv082", "rv016", "rv110w", "rv130", "rv215w", "rv series", "rv 042", "rv 082"],
        "family": "Cisco RV Series Small Business Routers (legacy)",
        "end_of_sale": "2018-12-31",
        "end_of_software_maintenance": "2019-12-31",
        "end_of_vuln_security_support": "2022-12-01",
        "last_day_of_support": "2025-12-01",
        "replacement_suggestion": "Cisco Business 250/350 routers (note: many RV series CVEs received NO patch from Cisco)",
        "bulletin_url": "https://www.cisco.com/c/en/us/support/routers/small-business-rv-series-routers/series.html",
    },
]


# ---------------------------------------------------------------------------
# IOS train EoX
# ---------------------------------------------------------------------------
# IOS classic train end-of-vuln-support dates. Matched by version prefix.
# Cisco trains the IOS classic releases by major.minor.maintenance(rev)Train.
# For example "15.7(3)M5" — major=15.7, train=M, maintenance=3, rev=5.

IOS_TRAIN_EOX: List[Dict] = [
    {
        "match": ["15.7(3)m", "15.7(3)m5", "15.7(3)m6", "15.7(3)m7", "15.7(3)m8", "15.7(3)m9"],
        "train": "IOS Classic 15.7(3)M",
        "end_of_software_maintenance": "2021-03-31",
        "end_of_vuln_security_support": "2022-12-31",
        "last_day_of_support": "2022-12-31",
        "successor": "IOS XE 17.x (requires hardware capable of IOS XE — most ISR G2 platforms are not)",
    },
    {
        "match": ["15.6(3)m", "15.5(3)m", "15.4(3)m", "15.3(3)m", "15.2(4)m", "15.1(4)m"],
        "train": "IOS Classic 15.x M-train (legacy)",
        "end_of_software_maintenance": "2019-12-31",
        "end_of_vuln_security_support": "2022-12-31",
        "last_day_of_support": "2022-12-31",
        "successor": "IOS XE 17.x (requires hardware capable of IOS XE)",
    },
    {
        "match": ["12.4", "12.3", "12.2", "12.1", "12.0"],
        "train": "IOS Classic 12.x (legacy)",
        "end_of_software_maintenance": "2016-09-30",
        "end_of_vuln_security_support": "2016-09-30",
        "last_day_of_support": "2016-09-30",
        "successor": "IOS XE 17.x or replacement hardware",
    },
]


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def _normalize(s: str) -> str:
    return (s or "").strip().lower()


def _hardware_match(platform: str) -> Optional[Dict]:
    p = _normalize(platform)
    if not p:
        return None
    for entry in HARDWARE_EOX:
        for needle in entry["match"]:
            if needle in p:
                return entry
    return None


def _ios_train_match(version: str) -> Optional[Dict]:
    v = _normalize(version)
    if not v:
        return None
    for entry in IOS_TRAIN_EOX:
        for needle in entry["match"]:
            if v.startswith(needle):
                return entry
    return None


def detect_eol(platform: str, version: str) -> Optional[Dict]:
    """
    Return EoL warning dict if the (platform, version) pair is past
    end-of-vulnerability-security-support, else None.

    The dict carries enough context for the UI to render a top-banner
    and for the recommendation engine to override its "upgrade to X"
    output with "replace the hardware".
    """
    hw = _hardware_match(platform)
    train = _ios_train_match(version)

    if not hw and not train:
        return None

    parts = []
    if hw:
        parts.append(
            f"{hw['family']} reached end-of-vulnerability-security-support on "
            f"{hw['end_of_vuln_security_support']}."
        )
    if train:
        parts.append(
            f"{train['train']} reached end-of-vulnerability-security-support on "
            f"{train['end_of_vuln_security_support']}."
        )

    parts.append(
        "No software updates are available for new CVEs on this platform. "
        "Remediation path is hardware replacement, not patching. "
        "The CVE list below is informational only."
    )

    if hw and hw.get("replacement_suggestion"):
        parts.append(f"Suggested replacement: {hw['replacement_suggestion']}.")

    return {
        "is_eol": True,
        "hardware": hw,
        "ios_train": train,
        "banner_text": " ".join(parts),
    }
