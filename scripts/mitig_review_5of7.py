#!/usr/bin/env python3
"""MITIG-REVIEW 5/7 (2026-09-28): the last 6 files, rewritten from Cisco's Workarounds text.
Closes the 150/150 review started with the C1 audit on 2026-09-25."""
import json, os
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MIT = os.path.join(REPO, "cve_mitigations")
DATE = "2026-09-28"
METHOD = "manual-5of7"


def adv(d):
    return d["cisco_psirt"].rstrip("/").split("/")[-1]


def upgrade_step(order, d):
    return {"order": order, "description": "Upgrade to a fixed release (Cisco's remediation)",
            "commands": ["show version", "! Upgrade per your platform's upgrade guide"],
            "platform_notes": f"The fix. Use the Cisco Software Checker or the Fixed Software section of {adv(d)}."}


def fix_line(d, until):
    return f"Upgrade to a fixed release (Cisco Software Checker, {adv(d)}). Until then: {until}"


def http_steps(d):
    return [{"order": 1, "description": "Check whether the HTTP Server feature is enabled",
             "commands": ["show running-config | include ip http", "show ip http server status"],
             "platform_notes": "Cisco: the attack vector is the web UI (HTTP Server feature)."},
            {"order": 2, "description": "Disable the HTTP Server feature (Cisco mitigation, not a workaround)",
             "commands": ["configure terminal", "no ip http server", "no ip http secure-server", "end", "write memory"],
             "platform_notes": "Cisco: if both the HTTP server and HTTPS server are in use, both commands are required. Disables the web UI; manage the device over SSH/CLI. Restricting the web UI with an ACL is not a mitigation Cisco lists for this CVE."},
            upgrade_step(3, d)]


def build(cve, d):
    if cve in ("CVE-2022-20851", "CVE-2023-20066"):
        return http_steps(d), None, fix_line(d, "disable the HTTP Server feature (Cisco mitigation, no workaround).")
    if cve == "CVE-2023-20065":
        steps = [{"order": 1, "description": "Check whether IOx application hosting is in use",
                  "commands": ["show iox-service", "show app-hosting list"],
                  "platform_notes": "Cisco: customers who do not want to use the IOx application hosting environment can disable IOx permanently."},
                 {"order": 2, "description": "Disable IOx permanently if not needed (Cisco mitigation, not a workaround)",
                  "commands": ["configure terminal", "no iox", "end", "write memory"],
                  "platform_notes": "Verbatim: 'no iox'. Removes application hosting entirely."},
                 upgrade_step(3, d)]
        return steps, None, fix_line(d, "'no iox' where application hosting is not needed (Cisco mitigation, no workaround).")
    if cve == "CVE-2023-20067":
        steps = [{"order": 1, "description": "Check which Wireless Policy Profiles have HTTP client profiling (HTTP TLV caching) enabled",
                  "commands": ["show wireless profile policy summary", "show wireless profile policy detailed <POLICY_PROFILE> | include HTTP|TLV"],
                  "platform_notes": "Cisco: there are no workarounds; the mitigation is to disable the HTTP Client Profiling feature in all active Wireless Policy Profiles."},
                 {"order": 2, "description": "Disable HTTP Client Profiling: uncheck HTTP TLV Caching in every active Wireless Policy Profile (Cisco mitigation)",
                  "commands": ["! WLC web UI: Configuration > Tags & Profiles > Policy > <profile> > Advanced > uncheck 'HTTP TLV Caching' (repeat for all active profiles)",
                               "configure terminal", "wireless profile policy <POLICY_PROFILE>", " shutdown", " no http-tlv-caching", " no shutdown", "end", "write memory"],
                  "platform_notes": "Cisco gives the GUI path (Configure Profiling on 9800 WLC, doc 215661); the CLI lines are the standard Catalyst 9800 equivalent and are marked as such. Changing a policy profile requires shutting it down briefly."},
                 upgrade_step(3, d)]
        return steps, None, fix_line(d, "disable HTTP client profiling (uncheck HTTP TLV Caching) in all active Wireless Policy Profiles (Cisco mitigation, no workaround).")
    if cve == "CVE-2023-20227":
        steps = [{"order": 1, "description": "Identify interfaces where L2TP (UDP 1701) is not expected",
                  "commands": ["show running-config | include l2tp|vpdn", "show ip interface brief"],
                  "platform_notes": "Cisco: there are no workarounds; to reduce the attack surface, block UDP 1701 with an iACL on interfaces where L2TP packets are not expected."},
                 {"order": 2, "description": "Block UDP 1701 to infrastructure addresses with an iACL (Cisco mitigation)",
                  "commands": ["configure terminal", "ip access-list extended CVE-2023-20227", " 10 deny udp any <INFRASTRUCTURE_ADDRESSES> <WILDCARD> eq 1701", " 20 permit ip any any", "exit",
                               "interface <IF>", " ip access-group CVE-2023-20227 in", "end", "write memory"],
                  "platform_notes": "iACL example verbatim from the advisory (include it in your deployed iACL; Cisco doc 43920 'Protecting Your Core'). The interface application line is ours; apply only where L2TP is not expected."},
                 upgrade_step(3, d)]
        acl = {"description": "Cisco iACL: block UDP 1701 (L2TP) to infrastructure addresses where not expected", "acl_name": "CVE-2023-20227",
               "commands": ["ip access-list extended CVE-2023-20227", " 10 deny udp any <INFRASTRUCTURE_ADDRESSES> <WILDCARD> eq 1701", " 20 permit ip any any"],
               "apply_to": "ip access-group CVE-2023-20227 in (interfaces where L2TP packets are not expected)"}
        return steps, acl, fix_line(d, "iACL blocking UDP 1701 to infrastructure addresses on interfaces where L2TP is not expected (Cisco mitigation, no workaround).")
    if cve == "CVE-2023-20231":
        steps = [{"order": 1, "description": "Check whether a Lobby Ambassador account exists",
                  "commands": ["show running-config | include lobby"],
                  "platform_notes": "Cisco: the attack vector exists only with a Lobby Ambassador account configured."},
                 {"order": 2, "description": "Disable the Lobby Ambassador account (Cisco mitigation, not a workaround)",
                  "commands": ["configure terminal", "! Remove or disable the Lobby Ambassador user account (exact syntax depends on your release; the advisory gives no CLI)", "end", "write memory"],
                  "platform_notes": "Cisco: there are no workarounds; disabling the Lobby Ambassador account eliminates the attack vector. Disabling the HTTP server is NOT the mitigation Cisco names for this CVE."},
                 upgrade_step(3, d)]
        return steps, None, fix_line(d, "disable the Lobby Ambassador account (Cisco mitigation, no workaround).")
    raise SystemExit(f"no rule for {cve}")


FILES = ["CVE-2022-20851", "CVE-2023-20065", "CVE-2023-20066", "CVE-2023-20067", "CVE-2023-20227", "CVE-2023-20231"]

if __name__ == "__main__":
    for cve in FILES:
        p = os.path.join(MIT, cve + ".json")
        d = json.load(open(p, encoding="utf-8"))
        assert not d.get("steps_reviewed"), cve
        d["workaround_steps"], d["acl_mitigation"], d["recommended_fix"] = build(cve, d)
        d["steps_reviewed"], d["review_method"], d["last_updated"] = DATE, METHOD, DATE
        with open(p, "w", encoding="utf-8") as f:
            json.dump(d, f, indent=2, ensure_ascii=False)
            f.write("\n")
        print("OK", cve)
