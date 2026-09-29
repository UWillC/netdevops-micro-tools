#!/usr/bin/env python3
"""MITIG-REVIEW 4/7 (2026-09-28): rewrite workaround_steps of 20 files from Cisco's own
Workarounds text (cisco_workaround.text). Where Cisco names a feature but gives no CLI, the
step says so and any command shown is marked as the standard IOS XE equivalent, not the advisory."""
import json, os
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MIT = os.path.join(REPO, "cve_mitigations")
DATE = "2026-09-28"
METHOD = "manual-4of7"


def adv(d):
    return d["cisco_psirt"].rstrip("/").split("/")[-1]


def upgrade_step(order, d, extra=""):
    return {"order": order,
            "description": "Upgrade to a fixed release (Cisco's remediation)",
            "commands": ["show version", "! Upgrade per your platform's upgrade guide"],
            "platform_notes": f"The fix. Use the Cisco Software Checker or the Fixed Software section of {adv(d)}.{extra}"}


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


SNMP_2017_VIEW = ["snmp-server view NO_BAD_SNMP iso included",
                  "snmp-server view NO_BAD_SNMP internet included",
                  "snmp-server view NO_BAD_SNMP snmpUsmMIB excluded",
                  "snmp-server view NO_BAD_SNMP snmpVacmMIB excluded",
                  "snmp-server view NO_BAD_SNMP snmpCommunityMIB excluded",
                  "snmp-server view NO_BAD_SNMP ciscoMgmt.252 excluded",
                  "snmp-server view NO_BAD_SNMP transmission.94 excluded",
                  "snmp-server view NO_BAD_SNMP mib-2.34.9 excluded",
                  "snmp-server view NO_BAD_SNMP ciscoMgmt.35 excluded",
                  "snmp-server view NO_BAD_SNMP ciscoMgmt.95 excluded",
                  "snmp-server view NO_BAD_SNMP ciscoMgmt.130 excluded",
                  "snmp-server view NO_BAD_SNMP ciscoAuthFrameworkMIB excluded",
                  "snmp-server view NO_BAD_SNMP ciscoMgmt.219 excluded",
                  "snmp-server view NO_BAD_SNMP ciscoMgmt.254 excluded",
                  "snmp-server view NO_BAD_SNMP ciscoMabMIB excluded",
                  "snmp-server view NO_BAD_SNMP ciscoExperiment.997 excluded"]

L2_2021_NOTE = ("Advisory cisco-sa-VU855201-J3z8CKTX (Layer 2 network security controls, Sept 2022) lists workarounds "
                "only for CVE-2021-27853 and CVE-2021-27861; ")


def build(cve, d):
    a = adv(d)
    if cve == "CVE-2017-6741":
        steps = [{"order": 1, "description": "Check whether SNMP is enabled (any version) and who uses it",
                  "commands": ["show snmp", "show snmp community", "show snmp user", "show snmp host"],
                  "platform_notes": "Cisco: allow only trusted users to have SNMP access and monitor with 'show snmp host'. All SNMP versions are affected; exploitation needs valid SNMP credentials."},
                 {"order": 2, "description": "Exclude the affected MIBs with the SNMP view NO_BAD_SNMP (Cisco workaround)",
                  "commands": ["configure terminal"] + SNMP_2017_VIEW + ["end"],
                  "platform_notes": "Verbatim from cisco-sa-20170629-snmp: standard view/security exclusions plus the 10 advisory MIBs (ADSL-LINE, TN3270E-RT, CISCO-BSTUN, ALPS, CISCO-ADSL-DMT-LINE, CISCO-AUTH-FRAMEWORK, CISCO-VOICE-DNIS, CISCO-SLB-EXT, CISCO-MAC-AUTH-BYPASS, CISCO-VOICE-NUMBER-EXPANSION). The advisory covers 9 CVEs with one view; excluding all 10 MIBs covers this CVE."},
                 {"order": 3, "description": "Apply the view to every community string and every SNMPv3 group (Cisco workaround)",
                  "commands": ["configure terminal", "snmp-server community <COMMUNITY> view NO_BAD_SNMP RO",
                               "snmp-server group <V3_GROUP> v3 auth read NO_BAD_SNMP write NO_BAD_SNMP", "end", "write memory"],
                  "platform_notes": "Cisco's example: 'snmp-server community mycomm view NO_BAD_SNMP RO' and 'snmp-server group v3group auth read NO_BAD_SNMP write NO_BAD_SNMP'."},
                 {"order": 4, "description": "Allow SNMP only from trusted hosts (Cisco advice; the ACL is our example)",
                  "commands": ["configure terminal", "ip access-list standard SNMP-RESTRICT", " permit <NMS_IP>", " deny any log", "exit",
                               "snmp-server community <COMMUNITY> view NO_BAD_SNMP RO SNMP-RESTRICT", "end", "write memory"],
                  "platform_notes": "Cisco advises trusted users only; the ACL form is ours."},
                 upgrade_step(5, d)]
        acl = {"description": "Restrict SNMP to trusted hosts (Cisco advice; our ACL example)", "acl_name": "SNMP-RESTRICT",
               "commands": ["ip access-list standard SNMP-RESTRICT", " permit <NMS_IP>", " deny any log"],
               "apply_to": "snmp-server community <COMMUNITY> view NO_BAD_SNMP RO SNMP-RESTRICT"}
        fix = fix_line(d, "SNMP view NO_BAD_SNMP excluding the 10 affected MIBs on every community and v3 group (Cisco workaround) + SNMP only from trusted hosts.")
    elif cve == "CVE-2021-27853":
        steps = [{"order": 1, "description": "Identify access ports with First Hop Security (FHS) features and their VLANs",
                  "commands": ["show running-config | include ipv6 nd raguard|ipv6 snooping|ip dhcp snooping|ip arp inspection",
                               "show running-config | include switchport access vlan", "show ip interface brief | include Vlan"],
                  "platform_notes": "Cisco: the workaround drops frames whose ethertype cannot be detected (stacked VLAN-0/dot1p headers) before FHS sees them."},
                 {"order": 2, "description": "IOS switches: Layer 2 ACL on FHS access ports permitting only IPv6, IPv4 and ARP ethertypes (Cisco workaround)",
                  "commands": ["configure terminal", "mac access-list extended CSCwa14271", " permit any any 0x86DD 0x0", " permit any any 0x800 0x0",
                               " permit any any 0x806 0x0", " deny any any", "exit", "interface <ACCESS_PORT>", " mac access-group CSCwa14271 in", "end", "write memory"],
                  "platform_notes": "Verbatim from the advisory (example on GigabitEthernet1/0/1 with 'switchport voice vlan dot1p' and 'ipv6 nd raguard attach-policy HOSTS'). Where tags are not expected, dropping tagged traffic is also acceptable per Cisco."},
                 {"order": 3, "description": "IOS XE switches: give every access-port VLAN an SVI; for Dynamic ARP Inspection add static ARP entries for gateways and critical hosts (Cisco workaround)",
                  "commands": ["configure terminal", "interface Vlan<ACCESS_VLAN>", " ! an active SVI on the access VLAN", "exit",
                               "arp <GATEWAY_IP> <GATEWAY_MAC> arpa", "end", "write memory"],
                  "platform_notes": "Cisco: on IOS XE switches (17.6.1 and later, before the first fixed release) FHS impact is not seen when the access-port VLAN has an active SVI. DAI is affected on all releases; static ARP entries for default gateways and critical servers/hosts protect the critical assets."},
                 {"order": 4, "description": "IOS XE routers: examine only the first tag on priority-tagged service instances (Cisco workaround)",
                  "commands": ["configure terminal", "interface <IF>", " service instance <ID> ethernet", "  encapsulation priority-tagged exact",
                               "  ! or: encapsulation priority-tagged etype ipv4 , ipv6", "end", "write memory"],
                  "platform_notes": "Cisco: add 'exact' after 'encapsulation priority-tagged' or filter on the ethertype field. Where no service instance uses priority-tagged, configure one that is not assigned to a bridge domain with 'encapsulation priority-tagged' so dot1p-fronted packets are not forwarded."},
                 upgrade_step(5, d, " NX-OS and Small Business switches have their own MAC-ACL examples in the advisory.")]
        acl = {"description": "Cisco Layer 2 ACL for FHS access ports (IOS switches): permit IPv6/IPv4/ARP ethertypes, deny the rest",
               "acl_name": "CSCwa14271",
               "commands": ["mac access-list extended CSCwa14271", " permit any any 0x86DD 0x0", " permit any any 0x800 0x0", " permit any any 0x806 0x0", " deny any any"],
               "apply_to": "mac access-group CSCwa14271 in (on access ports where FHS is configured)"}
        fix = fix_line(d, "Cisco workarounds per platform: L2 MAC ACL on FHS access ports (IOS switches), SVI on every access VLAN + static ARP for critical hosts (IOS XE switches), 'encapsulation priority-tagged exact' / etype filter (IOS XE routers).")
    elif cve == "CVE-2021-27861":
        steps = [{"order": 1, "description": "IOS / IOS XE: no mitigation or workaround (Cisco)",
                  "commands": ["show version"],
                  "platform_notes": L2_2021_NOTE + "for CVE-2021-27861 Cisco states 'No mitigations or workarounds' for Cisco IOS Software switches and IOS XR; only NX-OS has a Layer 2 ACL (mac access-list drop_non: permit 0x86dd / ip / 0x806 / 0100.0ccc.cccc, deny the rest, applied with 'mac port access-group drop_non' on FHS access ports). Only an upgrade closes this on IOS XE."},
                 upgrade_step(2, d)]
        acl = None
        fix = fix_line(d, "nothing on IOS/IOS XE (Cisco: no mitigations or workarounds for this CVE on IOS switches); NX-OS has the drop_non MAC ACL in the advisory.")
    elif cve in ("CVE-2021-27854", "CVE-2021-27862"):
        steps = [{"order": 1, "description": "No Cisco workaround for this CVE",
                  "commands": ["show version"],
                  "platform_notes": L2_2021_NOTE + f"{cve} has no workaround or mitigation in the advisory ('workarounds that address some of these vulnerabilities'). Not a Cisco workaround. Only an upgrade to a fixed release closes this vulnerability."},
                 upgrade_step(2, d)]
        acl = None
        fix = fix_line(d, "nothing (Cisco lists no workaround for this CVE; the advisory's L2 ACL workarounds apply to CVE-2021-27853 and CVE-2021-27861).")
    elif cve == "CVE-2023-20186":
        steps = [{"order": 1, "description": "Check whether the SCP server is enabled and how commands are authorized",
                  "commands": ["show running-config | include ip scp server|aaa authorization commands"],
                  "platform_notes": "Cisco: the bypass affects AAA command authorization for SCP server commands."},
                 {"order": 2, "description": "Workaround: enable privilege level 0 command authorization and filter 'scp -f' / 'scp -t' on the AAA server (Cisco workaround)",
                  "commands": ["configure terminal", "aaa authorization commands 0 <LIST_NAME> group <TACACS_GROUP>", "end", "write memory",
                               "! On the AAA server: command policy denying 'scp -f' and 'scp -t' (or allowing them only for intended users)"],
                  "platform_notes": "Cisco: 'aaa authorization commands 0' forces the AAA server to check SCP server commands; add filters for the commands 'scp -f' and 'scp -t' to allow or deny file uploads/downloads through SCP. Method-list placeholders are ours."},
                 {"order": 3, "description": "Mitigation: disable the SCP server (Cisco mitigation)",
                  "commands": ["configure terminal", "no ip scp server enable", "end", "write memory"],
                  "platform_notes": "Cisco: administrators can still use the SCP client on the device to copy images or configurations to or from the router."},
                 upgrade_step(4, d)]
        acl = None
        fix = fix_line(d, "'aaa authorization commands 0' with scp -f / scp -t filters on the AAA server (Cisco workaround), or 'no ip scp server enable' (Cisco mitigation).")
    elif cve == "CVE-2023-20187":
        steps = [{"order": 1, "description": "Check whether multicast Leaf Recycle Elimination (mLRE) is enabled",
                  "commands": ["show platform hardware qfp active feature multicast lre"],
                  "platform_notes": "Cisco's example output after the workaround: 'Platform v4mcast LRE config: Off' / 'Platform v6mcast LRE config: Off'."},
                 {"order": 2, "description": "Disable mLRE (Cisco workaround)",
                  "commands": ["configure terminal", "platform multicast lre off", "end", "show platform hardware qfp active feature multicast lre", "write memory"],
                  "platform_notes": "Cisco: with mLRE disabled, packets are processed separately for the interfaces that replicate multicast traffic (performance impact; see Cisco doc 215632 'mLRE Feature on the IOS-XE Router')."},
                 upgrade_step(3, d)]
        acl = None
        fix = fix_line(d, "'platform multicast lre off' (Cisco workaround; multicast replication then runs per interface).")
    elif cve == "CVE-2024-20307":
        steps = [{"order": 1, "description": "Check IKEv1 fragmentation and the 'buffers huge' setting",
                  "commands": ["show running-config | include crypto isakmp fragmentation|buffers huge"],
                  "platform_notes": "Cisco (CVE-2024-20307): either revert 'buffers huge' to its default or disable IKEv1 fragmentation."},
                 {"order": 2, "description": "Workaround A: revert the buffers huge configuration to its default (Cisco workaround)",
                  "commands": ["configure terminal", "default buffers huge size", "end", "write memory"],
                  "platform_notes": "Verbatim from the advisory."},
                 {"order": 3, "description": "Workaround B: disable IKEv1 fragmentation (Cisco workaround)",
                  "commands": ["configure terminal", "no crypto isakmp fragmentation", "end", "write memory"],
                  "platform_notes": "Cisco: IKEv1 fragmentation splits large IKE packets (e.g. certificate payloads) to avoid UDP fragmentation; some third-party firewalls drop UDP fragments, so disabling it can break large-certificate IKEv1 exchanges through such devices."},
                 upgrade_step(4, d)]
        acl = None
        fix = fix_line(d, "'default buffers huge size' or 'no crypto isakmp fragmentation' (Cisco workarounds).")
    elif cve == "CVE-2024-20308":
        steps = [{"order": 1, "description": "Check whether IKEv1 fragmentation is enabled",
                  "commands": ["show running-config | include crypto isakmp fragmentation"],
                  "platform_notes": "Cisco (CVE-2024-20308): the workaround is to disable IKEv1 fragmentation."},
                 {"order": 2, "description": "Disable IKEv1 fragmentation (Cisco workaround)",
                  "commands": ["configure terminal", "no crypto isakmp fragmentation", "end", "write memory"],
                  "platform_notes": "Cisco: IKEv1 fragmentation avoids UDP-layer fragmentation of large IKE packets (certificate payloads); third-party firewalls doing stateful inspection may drop UDP fragments, so evaluate before disabling."},
                 upgrade_step(3, d)]
        acl = None
        fix = fix_line(d, "'no crypto isakmp fragmentation' (Cisco workaround).")
    elif cve == "CVE-2024-20309":
        steps = [{"order": 1, "description": "Check the AUX port configuration",
                  "commands": ["show running-config | section line aux 0"],
                  "platform_notes": "Cisco: if the AUX port is not being used, it should be disabled."},
                 {"order": 2, "description": "Disable the AUX port if unused (Cisco workaround)",
                  "commands": ["configure terminal", "line aux 0", " transport input none", " transport output none", " no exec", "end", "write memory"],
                  "platform_notes": "Verbatim from the advisory's example ('line aux 0 / transport input none / transport output none / no exec')."},
                 upgrade_step(3, d)]
        acl = None
        fix = fix_line(d, "disable the unused AUX port: transport input/output none + no exec (Cisco workaround).")
    elif cve == "CVE-2024-20316":
        steps = [{"order": 1, "description": "Check whether ACLs are managed through NETCONF/RESTCONF (DMI)",
                  "commands": ["show running-config | include netconf-yang|restconf", "show netconf-yang sessions"],
                  "platform_notes": "Cisco: the ACL bypass occurs when ACLs are managed through the Data Model Interface (NETCONF or RESTCONF)."},
                 {"order": 2, "description": "Manage ACLs directly on the device CLI instead of NETCONF/RESTCONF (Cisco workaround)",
                  "commands": ["! Configure and change ACLs on the CLI (configure terminal / ip access-list ...) rather than via NETCONF or RESTCONF until upgraded"],
                  "platform_notes": "Verbatim intent from the advisory; no further CLI is given by Cisco."},
                 upgrade_step(3, d)]
        acl = None
        fix = fix_line(d, "manage ACLs on the CLI, not through NETCONF/RESTCONF (Cisco workaround).")
    elif cve == "CVE-2024-20373":
        steps = [{"order": 1, "description": "Find extended named ACLs applied to SNMP configuration",
                  "commands": ["show running-config | include snmp-server community|snmp-server group|snmp-server user", "show ip access-lists"],
                  "platform_notes": "Cisco: extended IPv4 ACLs are not supported against SNMP; only standard numbered and named IPv4 ACLs are. An extended named ACL on SNMP is the vulnerable configuration."},
                 {"order": 2, "description": "Replace every extended named ACL on SNMP with a standard named ACL (Cisco workaround; apply BEFORE upgrading)",
                  "commands": ["configure terminal", "ip access-list standard SNMP-RESTRICT", " permit <NMS_IP>", " deny any log", "exit",
                               "snmp-server community <COMMUNITY> RO SNMP-RESTRICT", "snmp-server group <V3_GROUP> v3 priv access SNMP-RESTRICT", "end", "write memory"],
                  "platform_notes": "Cisco: fixed releases prevent applying extended named ACLs to SNMP, so change them to standard named ACLs before the upgrade. ACL name and entries are placeholders."},
                 upgrade_step(3, d, " Apply the workaround first: fixed releases reject extended named ACLs on SNMP.")]
        acl = {"description": "Standard named IPv4 ACL for SNMP (the only supported form per Cisco)", "acl_name": "SNMP-RESTRICT",
               "commands": ["ip access-list standard SNMP-RESTRICT", " permit <NMS_IP>", " deny any log"],
               "apply_to": "snmp-server community <COMMUNITY> RO SNMP-RESTRICT / snmp-server group <V3_GROUP> v3 priv access SNMP-RESTRICT"}
        fix = fix_line(d, "change all extended named ACLs applied to SNMP to standard named ACLs, before upgrading (Cisco workaround).")
    elif cve == "CVE-2024-20414":
        steps = http_steps(d)
        acl = None
        fix = fix_line(d, "disable the HTTP Server feature (Cisco mitigation, no workaround).")
    elif cve == "CVE-2024-20324":
        steps = [{"order": 1, "description": "Check whether WLAN PSKs are stored without password encryption",
                  "commands": ["show running-config | include security wpa psk|password encryption|key config-key"],
                  "platform_notes": "Cisco: there are no workarounds; if a PSK is used and password encryption is not enabled, the WLAN PSK can be exposed to unauthorized users."},
                 {"order": 2, "description": "Enable password encryption so the WLAN PSK is not exposed (Cisco mitigation)",
                  "commands": ["configure terminal", "key config-key password-encrypt <MASTER_KEY>", "password encryption aes", "end", "write memory"],
                  "platform_notes": "Cisco names the feature (password encryption) but gives no CLI; the two commands are the standard IOS XE type-6 password encryption and are marked as such. Cisco: other configuration details may still be accessible to unauthorized users."},
                 upgrade_step(3, d)]
        acl = None
        fix = fix_line(d, "enable password encryption for the WLAN PSK (Cisco mitigation; other configuration details remain readable).")
    elif cve == "CVE-2024-20313":
        steps = [{"order": 1, "description": "Check whether OSPF authentication is configured",
                  "commands": ["show ip ospf interface | include authentication|Message digest", "show running-config | section router ospf"],
                  "platform_notes": "Cisco: there are no workarounds; as a best practice configure OSPF authentication so attackers would need to pass authentication to trigger the vulnerability."},
                 {"order": 2, "description": "Configure OSPF authentication (Cisco mitigation)",
                  "commands": ["configure terminal", "interface <OSPF_IF>", " ip ospf authentication message-digest", " ip ospf message-digest-key 1 md5 <KEY>", "end", "write memory"],
                  "platform_notes": "Cisco refers to the IP Routing: OSPF Configuration Guide; the commands are the standard IOS XE MD5 interface authentication example, not text from the advisory. Apply consistently on all OSPF neighbours or adjacencies drop."},
                 upgrade_step(3, d)]
        acl = None
        fix = fix_line(d, "OSPF authentication on all OSPF-enabled interfaces (Cisco mitigation/best practice).")
    elif cve == "CVE-2024-20312":
        steps = [{"order": 1, "description": "Check whether IS-IS area authentication is configured",
                  "commands": ["show running-config | section router isis", "show isis protocol"],
                  "platform_notes": "Cisco: there are no workarounds; as a best practice configure IS-IS area authentication so attackers would first have to pass authentication."},
                 {"order": 2, "description": "Configure IS-IS area authentication (Cisco mitigation)",
                  "commands": ["configure terminal", "key chain <ISIS_KC>", " key 1", "  key-string <KEY>", "exit", "router isis <TAG>",
                               " authentication mode md5 level-1", " authentication key-chain <ISIS_KC> level-1", "end", "write memory"],
                  "platform_notes": "Cisco refers to 'Configuring IS-IS Authentication' (doc 13792); the commands are the standard IOS XE key-chain/MD5 example for level-1 area authentication, not text from the advisory. Use level-2 or both as your topology requires; apply on all routers in the area."},
                 upgrade_step(3, d)]
        acl = None
        fix = fix_line(d, "IS-IS area authentication (Cisco mitigation/best practice).")
    elif cve == "CVE-2024-20278":
        steps = [{"order": 1, "description": "Check whether NETCONF is enabled and whether it has a service-level ACL",
                  "commands": ["show running-config | include netconf-yang", "show netconf-yang sessions"],
                  "platform_notes": "Cisco: there are no workarounds; as a best practice use NETCONF service-level ACLs to restrict NETCONF traffic to trusted devices."},
                 {"order": 2, "description": "Restrict NETCONF to trusted devices with a service-level ACL (Cisco mitigation)",
                  "commands": ["configure terminal", "ip access-list standard NETCONF-TRUSTED", " permit <MGMT_HOST>", " deny any log", "exit",
                               "netconf-yang ssh ipv4 access-list name NETCONF-TRUSTED", "end", "write memory"],
                  "platform_notes": "Cisco refers to the Programmability Configuration Guide (service-level ACLs for NETCONF/RESTCONF); the command form is from that guide, not the advisory. Placeholders are ours."},
                 upgrade_step(3, d)]
        acl = {"description": "NETCONF service-level ACL: trusted management hosts only (Cisco best practice)", "acl_name": "NETCONF-TRUSTED",
               "commands": ["ip access-list standard NETCONF-TRUSTED", " permit <MGMT_HOST>", " deny any log"],
               "apply_to": "netconf-yang ssh ipv4 access-list name NETCONF-TRUSTED"}
        fix = fix_line(d, "NETCONF service-level ACL restricting NETCONF to trusted devices (Cisco best practice; no workaround).")
    elif cve == "CVE-2024-3596":
        steps = [{"order": 1, "description": "Inventory RADIUS servers and their transport (UDP vs DTLS/TLS)",
                  "commands": ["show aaa servers", "show running-config | section radius", "show radius server-group all"],
                  "platform_notes": "Cisco: there are no workarounds. RADIUS clients and servers configured to use DTLS or TLS over TCP are not exploitable as long as the traffic is not sent in plaintext; plaintext RADIUS over UDP is."},
                 {"order": 2, "description": "Move RADIUS to DTLS or TLS (RadSec) where the server supports it (Cisco mitigation)",
                  "commands": ["configure terminal", "radius server <NAME>", " address ipv4 <RADIUS_SERVER> auth-port 2083 acct-port 2083",
                               " tls trustpoint client <CLIENT_TP>", " tls trustpoint server <SERVER_TP>", "end", "write memory"],
                  "platform_notes": "Cisco names the mitigation (DTLS/TLS), not the CLI; the commands are the standard IOS XE RADIUS-over-TLS form and need PKI trustpoints on both sides - verify the syntax for your release in the Security Configuration Guide. Both the network device and the RADIUS server must support it."},
                 upgrade_step(3, d, " BlastRADIUS is a protocol issue: the RADIUS server side needs its vendor's fix as well.")]
        acl = None
        fix = fix_line(d, "RADIUS over DTLS/TLS (Cisco: not exploitable when traffic is not plaintext); no workaround for plaintext UDP RADIUS.")
    elif cve == "CVE-2023-20235":
        steps = [{"order": 1, "description": "Check whether the application development workflow is enabled in production",
                  "commands": ["show iox-service", "show app-hosting list"],
                  "platform_notes": "Cisco: the application development workflow is meant only for development systems, never production."},
                 {"order": 2, "description": "Disable the application development workflow feature in production (Cisco mitigation)",
                  "commands": ["! Disable the IOx application development workflow on production devices (Cisco gives no CLI in the advisory; see the IOx application hosting guide for your platform)"],
                  "platform_notes": "Cisco: there are no workarounds; the mitigation is to not run the development workflow in production."},
                 upgrade_step(3, d)]
        acl = None
        fix = fix_line(d, "disable the application development workflow on production devices (Cisco mitigation, no workaround).")
    elif cve == "CVE-2023-20076":
        steps = [{"order": 1, "description": "Check whether IOx application hosting is in use",
                  "commands": ["show iox-service", "show app-hosting list"],
                  "platform_notes": "Cisco: customers who do not want to use the IOx application hosting environment can disable IOx permanently."},
                 {"order": 2, "description": "Disable IOx permanently if not needed (Cisco mitigation, not a workaround)",
                  "commands": ["configure terminal", "no iox", "end", "write memory"],
                  "platform_notes": "Verbatim: 'no iox'. Removes application hosting entirely; the earlier account/logging/ACL hardening steps were ours, not Cisco's, and are dropped."},
                 upgrade_step(3, d)]
        acl = None
        fix = fix_line(d, "'no iox' where application hosting is not needed (Cisco mitigation, no workaround).")
    else:
        raise SystemExit(f"no rule for {cve}")
    return steps, acl, fix


FILES = ["CVE-2017-6741", "CVE-2021-27853", "CVE-2021-27854", "CVE-2021-27861", "CVE-2021-27862",
         "CVE-2023-20186", "CVE-2023-20187", "CVE-2024-20307", "CVE-2024-20308", "CVE-2024-20309",
         "CVE-2024-20316", "CVE-2024-20373", "CVE-2024-20414", "CVE-2024-20324", "CVE-2024-20313",
         "CVE-2024-20312", "CVE-2024-20278", "CVE-2024-3596", "CVE-2023-20235", "CVE-2023-20076"]

if __name__ == "__main__":
    for cve in FILES:
        p = os.path.join(MIT, cve + ".json")
        d = json.load(open(p, encoding="utf-8"))
        assert not d.get("steps_reviewed"), cve
        steps, acl, fix = build(cve, d)
        d["workaround_steps"], d["acl_mitigation"], d["recommended_fix"] = steps, acl, fix
        d["steps_reviewed"], d["review_method"], d["last_updated"] = DATE, METHOD, DATE
        with open(p, "w", encoding="utf-8") as f:
            json.dump(d, f, indent=2, ensure_ascii=False)
            f.write("\n")
        print("OK", cve, len(steps), "steps")
