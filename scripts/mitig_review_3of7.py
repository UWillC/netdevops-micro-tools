#!/usr/bin/env python3
"""MITIG-REVIEW 3/7 (2026-09-28): rewrite workaround_steps of 20 files from Cisco's own
Workarounds text (cisco_workaround.text). Nothing here is invented: every step quotes or
paraphrases the advisory text stored in the file; where Cisco gives no CLI, the step says so."""
import json, os, sys
REPO = "/Users/uwillc/SaaS/cisco-microtool-generator"
MIT = os.path.join(REPO, "cve_mitigations")
DATE = "2026-09-28"
METHOD = "manual-3of7"

def adv(d):
    return d["cisco_psirt"].rstrip("/").split("/")[-1]

def upgrade_step(order, d, extra=""):
    return {"order": order,
            "description": "Upgrade to a fixed release (Cisco's remediation)",
            "commands": ["show version", "! Upgrade per your platform's upgrade guide"],
            "platform_notes": f"The fix. Use the Cisco Software Checker or the Fixed Software section of {adv(d)}.{extra}"}

def http_check(order):
    return {"order": order, "description": "Check whether the HTTP Server feature is enabled",
            "commands": ["show running-config | include ip http", "show ip http server status"],
            "platform_notes": "Cisco: the attack vector is the web UI (HTTP Server feature). If neither 'ip http server' nor 'ip http secure-server' is present, the vector is closed."}

def http_disable(order, both="If both the HTTP server and HTTPS server are in use, both commands are required (Cisco)."):
    return {"order": order, "description": "Disable the HTTP Server feature (Cisco mitigation, not a workaround)",
            "commands": ["configure terminal", "no ip http server", "no ip http secure-server", "end", "write memory"],
            "platform_notes": f"Cisco: disabling the HTTP Server feature eliminates the attack vector and may be a suitable mitigation until affected devices can be upgraded. {both} Disables the web UI; manage the device over SSH/CLI."}

WEBUI_ACL = {"description": "Allow only trusted networks to reach the HTTP server (Cisco mitigation)",
             "acl_name": "restrict_ipv4_webui",
             "commands": ["ip access-list standard restrict_ipv4_webui", " permit <TRUSTED_NET> <WILDCARD>"],
             "apply_to": "ip http access-class ipv4 restrict_ipv4_webui (older releases: ip http access-class <ACL>)"}

SNMP_BASE = ["snmp-server view SNMP_DOS iso included",
             "snmp-server view SNMP_DOS snmpUsmMIB excluded",
             "snmp-server view SNMP_DOS snmpVacmMIB excluded",
             "snmp-server view SNMP_DOS snmpCommunityMIB excluded"]
SNMP_OIDS = """ipAddressPrefixEntry.5 ipDefaultRouterEntry.4 tcp.19.1.7 tcp.20.1.4 udp.7.1.8 inetCidrRouteEntry.7
ospfv3AreaAggregateEntry.6 lispMappingDatabaseLocatorRlocPriority mplsVpnInterfaceConfEntry.2 mplsVpnVrfRouteTargetEntry.4
mplsVpnVrfBgpNbrAddrEntry.2 nhrpCachePrefixLength nhrpServerCacheAuthoritative nlmLogEntry.2 nlmLogVariableEntry.2 mplsXCLspId
mplsLabelStackLabel cpaeMIBObject.5.1.3 cContextMappingBridgeDomainIdentifier cilmCurrentImageLevel cilmImageLicenseImageLevel
cewProxyClass cewEventTime cpwVcPeerMappingVcIndex ciiSummAddrEntry mplsLdpLspFecStorageType mplsL3VpnIfConfEntry.2
mplsL3VpnVrfRTEntry.4 mplsL3VpnVrfRteEntry.7 ciscoFlashChipEntry cbgpPeer2CapValue cbgpPeer2AddrFamilyName
cbgpPeer2AcceptedPrefixes callHomeDestEmailAddressEntry.2 callHomeSwInventoryEntry.3 cEigrpActive cipUrpfVrfIfDrops cefPathType
cefAdjSource cefFESelectionSpecial cvVrfListVrfIndex ctspIpSgtMappingEntry.5 ciiRedistributeAddrEntry.4 ciiIPRAEntry.5
ciiLSPTLVEntry.2 ccmSeverityAlertGroupEntry.1 ccmPeriodicAlertGroupEntry.1 ccmPatternAlertGroupEntry.2 callHomeUserDefCmdEntry.2
ccmEventAlertGroupEntry.1 cipsStaticCryptomapType ciscoFlashFileEntry.2""".split()
assert len(SNMP_OIDS) == 52, len(SNMP_OIDS)

def snmp_steps(d):
    return [
        {"order": 1, "description": "Inventory SNMP configuration (communities, v3 users/groups, views)",
         "commands": ["show snmp", "show snmp user", "show snmp group", "show running-config | include snmp-server"],
         "platform_notes": "Cisco: there are no workarounds; the mitigation below (SNMP view excluding the vulnerable OIDs) is strongly recommended until fixed software is installed."},
        {"order": 2, "description": "Create the SNMP view SNMP_DOS and exclude the vulnerable OIDs (Cisco mitigation)",
         "commands": ["configure terminal"] + SNMP_BASE + [f"snmp-server view SNMP_DOS {o} excluded" for o in SNMP_OIDS] + ["end"],
         "platform_notes": "Cisco IOS and IOS XE OID list verbatim from the advisory (IOS XR has its own list there). Cisco: not all software supports every OID; an OID that is not valid on your software means you are not vulnerable to that specific CVE. Excluding these OIDs may affect SNMP-based discovery and hardware inventory."},
        {"order": 3, "description": "Apply the SNMP_DOS view to every community string and every SNMPv3 group (Cisco mitigation)",
         "commands": ["configure terminal", "snmp-server community <COMMUNITY> view SNMP_DOS RO",
                      "snmp-server group <V3_GROUP> v3 auth read SNMP_DOS write SNMP_DOS", "end", "write memory"],
         "platform_notes": "Cisco: for SNMP v1/v2c apply the view to all configured community strings; for SNMPv3 apply it to all configured groups/users. Repeat for each community and group."},
        {"order": 4, "description": "Allow SNMP only from trusted network devices (Cisco best practice, not the mitigation itself)",
         "commands": ["configure terminal", "ip access-list standard SNMP-RESTRICT", " permit <NMS_IP>", " deny any log", "exit",
                      "snmp-server community <COMMUNITY> view SNMP_DOS RO SNMP-RESTRICT", "end", "write memory"],
         "platform_notes": "Cisco points to 'Secure Your Simple Network Management Protocol' (doc 20370) as best practice. This limits who can send the crafted SNMP requests but does not remove the vulnerable OIDs; keep step 2-3."},
        upgrade_step(5, d),
    ]

def build(cve, d):
    a = adv(d)
    if cve in ("CVE-2025-20193", "CVE-2025-20194"):
        steps = [http_check(1), http_disable(2),
                 {"order": 3, "description": "Allow only trusted networks to access the HTTP server (Cisco mitigation)",
                  "commands": ["configure terminal", "ip access-list standard restrict_ipv4_webui", " permit <TRUSTED_NET> <WILDCARD>",
                               "exit", "ip http access-class ipv4 restrict_ipv4_webui", "end", "write memory"],
                  "platform_notes": "Cisco example: permit 192.168.10.0 0.0.0.255 on view restrict_ipv4_webui. Syntax 'ip http access-class ipv4 <ACL>' as in the advisory; older releases use 'ip http access-class <ACL>'. See Cisco doc 221107 (filter traffic to the IOS XE web UI)."},
                 upgrade_step(4, d)]
        acl = WEBUI_ACL
        fix = f"Upgrade to a fixed release (Cisco Software Checker, {a}). Until then (Cisco, no workaround): disable the HTTP Server feature, or restrict web UI access to trusted networks with an access class."
    elif cve == "CVE-2025-20189":
        steps = [{"order": 1, "description": "Monitor RSS memory usage of the uea_mgr process (Cisco mitigation)",
                  "commands": ["! Use the memory-usage command from the advisory's Indicators of Compromise section for the uea_mgr process"],
                  "platform_notes": "Cisco: there are no workarounds. Successful exploitation grows the memory of the uea_mgr process on the ASR 903 RSP3; watch it as described in the advisory's Indicators of Compromise section. The advisory's Workarounds section gives no exact command, so none is invented here."},
                 {"order": 2, "description": "Schedule a planned reload of the RSP before memory reaches a critical level (Cisco mitigation)",
                  "commands": ["! Plan the reload in a maintenance window", "reload"],
                  "platform_notes": "Cisco: a planned reload of the RSP avoids the unexpected reload caused by exploitation. This only resets the condition; it does not remove the vulnerability."},
                 upgrade_step(3, d)]
        acl = None
        fix = f"Upgrade to a fixed release (Cisco Software Checker, {a}). Until then (Cisco, no workaround): monitor uea_mgr RSS memory and schedule a planned RSP reload before it reaches a critical level."
    elif cve == "CVE-2025-20188":
        steps = [{"order": 1, "description": "Confirm the AP file upload (HTTPS) port on the WLC",
                  "commands": ["show ap file-transfer https summary"],
                  "platform_notes": "Cisco's example shows configured/operational port 8443. Use the port shown in the iACL below."},
                 {"order": 2, "description": "Impacted features NOT in use: block the AP file upload port with an iACL on all interfaces (Cisco mitigation, complete)",
                  "commands": ["configure terminal", "ip access-list extended CVE-2025-20188", " 10 deny tcp any any eq 8443", " 20 permit ip any any", "end",
                               "! Apply the iACL to all interfaces per Cisco's Infrastructure Protection ACL guidance (doc 43920)"],
                  "platform_notes": "Cisco: if the impacted features are not used, apply iACLs to all interfaces and block the interface completely; this will completely mitigate the vulnerability."},
                 {"order": 3, "description": "Impacted features IN use: limit the AP file upload interface to expected sources (Cisco mitigation, reduces attack surface)",
                  "commands": ["configure terminal", "ip access-list extended CVE-2025-20188", " 10 deny tcp any <INFRASTRUCTURE_ADDRESSES> <WILDCARD> eq 8443", " 20 permit ip any any", "end",
                               "! Include this in your deployed iACL (Cisco doc 43920)"],
                  "platform_notes": "Cisco: allow traffic from expected sources only; example iACL from the advisory. Use step 2 or step 3 depending on whether the features are used."},
                 {"order": 4, "description": "Workaround: manually trigger the AP client debug bundle once (Cisco workaround, non-persistent)",
                  "commands": ["show wireless client summary", "debug wireless bundle client mac <CLIENT_MAC>",
                               "show ap tag summary | inc <AP_NAME>|AP Name",
                               "debug wireless bundle client start ap-archive site-tag <SITE_TAG> level debug monitor-time 60",
                               "debug wireless bundle client stop-all collect all", "dir bootflash:completeCDB/*"],
                  "platform_notes": "Cisco: triggering the bundle once protects all affected features that use the AP file upload interface, but it does NOT persist through reload and must be repeated after every reload. Pick any client on any AP joined to this WLC; monitor-time 60 keeps the run to 60 seconds; a wireless_bundle_*.tar in bootflash:completeCDB/ confirms success."},
                 upgrade_step(5, d)]
        acl = {"description": "Cisco iACL for the AP file upload port (block completely if the feature is unused, else restrict to infrastructure addresses)",
               "acl_name": "CVE-2025-20188",
               "commands": ["ip access-list extended CVE-2025-20188", " 10 deny tcp any any eq 8443", " 20 permit ip any any"],
               "apply_to": "All interfaces as an infrastructure ACL (Cisco doc 43920); replace 'any any' with '<INFRASTRUCTURE_ADDRESSES> <WILDCARD>' when the feature is in use"}
        fix = "Upgrade to a release Cisco does not list as affected (affected: 17.11.1, 17.12.1 to 17.12.3, 17.13.1, 17.14.1); confirm the target in Cisco Software Checker. Until then (Cisco): iACL on the AP file upload port (deny tcp 8443, or restrict to infrastructure addresses), or trigger the AP client debug bundle once after every reload."
    elif cve == "CVE-2025-20186":
        steps = [{"order": 1, "description": "Check whether a lobby ambassador account exists",
                  "commands": ["show running-config | include lobby"],
                  "platform_notes": "Cisco: the vulnerability requires the lobby ambassador account; the attack vector exists only if that account is configured."},
                 {"order": 2, "description": "Disable the lobby ambassador account (Cisco mitigation, not a workaround)",
                  "commands": ["configure terminal", "! Remove or disable the lobby ambassador user account (exact syntax depends on your release; the advisory gives no CLI)", "end", "write memory"],
                  "platform_notes": "Cisco: there are no workarounds; administrators may disable the lobby ambassador account to eliminate the attack vector. Disabling the HTTP server is NOT the mitigation Cisco names for this CVE."},
                 upgrade_step(3, d)]
        acl = None
        fix = f"Upgrade to a fixed release (Cisco Software Checker, {a}). Until then (Cisco, no workaround): disable the lobby ambassador account."
    elif cve in ("CVE-2025-20169", "CVE-2025-20170", "CVE-2025-20171", "CVE-2025-20172",
                 "CVE-2025-20173", "CVE-2025-20174", "CVE-2025-20175", "CVE-2025-20176"):
        steps = snmp_steps(d)
        acl = {"description": "Cisco best practice: SNMP only from trusted network devices (complements the SNMP_DOS view, does not replace it)",
               "acl_name": "SNMP-RESTRICT",
               "commands": ["ip access-list standard SNMP-RESTRICT", " permit <NMS_IP>", " deny any log"],
               "apply_to": "snmp-server community <COMMUNITY> view SNMP_DOS RO SNMP-RESTRICT"}
        fix = f"Upgrade to a fixed release (Cisco Software Checker, {a}). Until then (Cisco mitigation, no workaround): SNMP view SNMP_DOS that excludes the vulnerable OIDs, applied to every community string and SNMPv3 group; allow SNMP only from trusted hosts."
    elif cve == "CVE-2025-20162":
        steps = [{"order": 1, "description": "Check DHCP snooping state and the VLANs it covers",
                  "commands": ["show ip dhcp snooping"],
                  "platform_notes": "Cisco workaround requires DHCP snooping on ALL VLANs, not only user VLANs."},
                 {"order": 2, "description": "Enable DHCP snooping on all VLANs (Cisco workaround)",
                  "commands": ["configure terminal", "ip dhcp snooping vlan <ALL_VLANS, e.g. 1-4094>", "end", "write memory"],
                  "platform_notes": "Cisco: 'ip dhcp snooping vlan ?' accepts a number or range (example from the advisory: 1,3-5,7,9-11). The advisory shows only the per-VLAN command; DHCP snooping must also be globally enabled ('ip dhcp snooping') to take effect - verify with 'show ip dhcp snooping'."},
                 upgrade_step(3, d)]
        acl = None
        fix = f"Upgrade to a fixed release (Cisco Software Checker, {a}). Until then (Cisco workaround): enable DHCP snooping on all VLANs."
    elif cve == "CVE-2025-20151":
        steps = [{"order": 1, "description": "Check the length of the SNMPv3 user lines written to the startup configuration",
                  "commands": ["show startup-config | include snmp-server user", "show running-config | include snmp-server user|snmp-server group"],
                  "platform_notes": "Cisco: the SNMPv3 configuration written to startup-config must be 255 characters or less; longer lines (user + group + ACL names) trigger the vulnerability."},
                 {"order": 2, "description": "Workaround A: attach the IPv4/IPv6 ACL to the SNMPv3 group instead of the username (Cisco workaround)",
                  "commands": ["configure terminal", "snmp-server group <V3_GROUP> v3 <auth|priv> access <IPV4_ACL> ipv6 <IPV6_ACL>",
                               "! Re-create the SNMPv3 user without the 'access' ACL options", "end", "write memory"],
                  "platform_notes": "Cisco: move the IPv4 ACL name, the IPv6 ACL name, or both to the SNMPv3 group name instead of the username. Placeholders; keep only the address families you use."},
                 {"order": 3, "description": "Workaround B: shorten the combination of user, group and ACL names (Cisco workaround)",
                  "commands": ["! Rename the SNMPv3 user, group and/or ACLs so the written line stays at 255 characters or less", "show startup-config | include snmp-server user"],
                  "platform_notes": "Cisco: either method is sufficient; re-check the startup configuration after 'write memory'."},
                 upgrade_step(4, d)]
        acl = None
        fix = f"Upgrade to a fixed release (Cisco Software Checker, {a}). Until then (Cisco workaround): keep every SNMPv3 line written to startup-config at 255 characters or less by moving ACL names to the group or shortening names."
    elif cve == "CVE-2025-20140":
        steps = [{"order": 1, "description": "Check whether wireless IPv6 clients are enabled",
                  "commands": ["show running-config | include wireless ipv6 client"],
                  "platform_notes": "Cisco: the mitigation applies only if the IPv6 wireless client feature is not in use."},
                 {"order": 2, "description": "Disable wireless IPv6 clients if the feature is not in use (Cisco mitigation, not a workaround)",
                  "commands": ["configure terminal", "no wireless ipv6 client", "end", "write memory"],
                  "platform_notes": "Cisco: there are no workarounds; 'no wireless ipv6 client' removes the attack vector when IPv6 wireless clients are not needed. IPv6 wireless clients lose connectivity."},
                 upgrade_step(3, d)]
        acl = None
        fix = f"Upgrade to a fixed release (Cisco Software Checker, {a}). Until then (Cisco, no workaround): 'no wireless ipv6 client' if the feature is not in use."
    elif cve == "CVE-2024-20510":
        steps = [{"order": 1, "description": "Identify the address family of the CWA redirection ACL on the wireless controller",
                  "commands": ["show ip access-lists", "show ipv6 access-list", "show running-config | include access-list|redirect"],
                  "platform_notes": "Cisco: the workaround adds a deny-all ACL of the OTHER address family (IPv6 ACL if the redirection ACL is IPv4, IPv4 ACL if it is IPv6) during the CWA authentication phase."},
                 {"order": 2, "description": "On the wireless controller, create an extended ACL of the other family that denies all traffic (Cisco workaround)",
                  "commands": ["! WLC web UI: Configuration > Security > ACL > add a new IPv6 (or IPv4) extended ACL that denies all traffic",
                               "! CLI equivalent (not in the advisory text): ipv6 access-list <DENY_ALL_V6> / sequence 10 deny ipv6 any any  |  ip access-list extended <DENY_ALL_V4> / 10 deny ip any any"],
                  "platform_notes": "Cisco gives the web UI path; the CLI lines are the standard IOS XE equivalent and are marked as such."},
                 {"order": 3, "description": "In ISE, attach the new ACL to the CWA authorization profile (Cisco workaround)",
                  "commands": ["! ISE web UI: Policy > Policy Elements > Results > Authorization > Authorization Profiles > <CWA profile>",
                               "! Common Tasks: check 'Airespace IPv6 ACL Name' (or 'Airespace ACL Name') and enter the ACL created in step 2"],
                  "platform_notes": "Cisco: the deny-all ACL of the other family must be applied during the CWA authentication phase; use 'Airespace IPv6 ACL Name' when adding an IPv6 ACL and 'Airespace ACL Name' when adding an IPv4 ACL."},
                 upgrade_step(4, d)]
        acl = None
        fix = f"Upgrade to a fixed release (Cisco Software Checker, {a}). Until then (Cisco workaround): add a deny-all ACL of the other address family (IPv4 or IPv6) on the WLC and apply it in the ISE CWA authorization profile."
    elif cve == "CVE-2024-20455":
        steps = [{"order": 1, "description": "Check whether the UTD (Unified Threat Defense) feature is installed and running",
                  "commands": ["show utd engine standard status", "show running-config | include utd"],
                  "platform_notes": "Cisco: the mitigation applies only where the UTD feature is not needed."},
                 {"order": 2, "description": "Remove or disable the UTD feature if it is not needed (Cisco mitigation, not a workaround)",
                  "commands": ["! Follow Cisco's guide 'Install and Uninstall UTD Engine in SD-WAN with CLI' (doc 218339) to uninstall/disable UTD"],
                  "platform_notes": "Cisco: there are no workarounds; removing or disabling UTD closes the attack vector. The advisory refers to the guide instead of listing commands, so none are invented here."},
                 upgrade_step(3, d)]
        acl = None
        fix = f"Upgrade to a fixed release (Cisco Software Checker, {a}). Until then (Cisco, no workaround): remove or disable the UTD feature where it is not needed (Cisco doc 218339)."
    elif cve == "CVE-2024-20437":
        steps = [{"order": 1, "description": "Check for 'service internal' and the HTTP Server feature",
                  "commands": ["show running-config | include service internal|ip http"],
                  "platform_notes": "Cisco: the CSRF requires 'service internal' to be enabled; either mitigation below removes the vector."},
                 {"order": 2, "description": "Mitigation A: disable service internal (Cisco mitigation)",
                  "commands": ["configure terminal", "no service internal", "end", "write memory"],
                  "platform_notes": "Cisco: if this mitigation is chosen, there is no need to disable the HTTP Server."},
                 http_disable(3, "Cisco: mitigation B, needed only if 'service internal' stays enabled; if both HTTP and HTTPS servers are in use, both commands are required."),
                 upgrade_step(4, d)]
        acl = None
        fix = f"Upgrade to a fixed release (Cisco Software Checker, {a}). Until then (Cisco, no workaround): 'no service internal', or disable the HTTP Server feature. Restricting the web UI with an ACL is not a mitigation Cisco lists for this CVE."
    elif cve == "CVE-2024-20436":
        steps = [http_check(1),
                 http_disable(2, "Cisco lists 'no ip http server' or 'no ip http secure-server'; disable both if both are in use."),
                 upgrade_step(3, d)]
        acl = None
        fix = f"Upgrade to a fixed release (Cisco Software Checker, {a}). Until then (Cisco mitigation, no workaround): disable the HTTP Server feature. Restricting the web UI with an ACL is not a mitigation Cisco lists for this CVE."
    else:
        raise SystemExit(f"no rule for {cve}")
    return steps, acl, fix

FILES = ["CVE-2025-20194", "CVE-2025-20193", "CVE-2025-20189", "CVE-2025-20188", "CVE-2025-20186",
         "CVE-2025-20176", "CVE-2025-20175", "CVE-2025-20174", "CVE-2025-20173", "CVE-2025-20172",
         "CVE-2025-20171", "CVE-2025-20170", "CVE-2025-20169", "CVE-2025-20162", "CVE-2025-20151",
         "CVE-2025-20140", "CVE-2024-20510", "CVE-2024-20455", "CVE-2024-20437", "CVE-2024-20436"]

for cve in FILES:
    p = os.path.join(MIT, cve + ".json")
    d = json.load(open(p, encoding="utf-8"))
    assert not d.get("steps_reviewed"), cve
    steps, acl, fix = build(cve, d)
    d["workaround_steps"] = steps
    d["acl_mitigation"] = acl
    d["recommended_fix"] = fix
    d["steps_reviewed"] = DATE
    d["review_method"] = METHOD
    d["last_updated"] = DATE
    with open(p, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print("OK", cve, len(steps), "steps")
