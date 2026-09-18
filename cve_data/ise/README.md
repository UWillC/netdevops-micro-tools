# cve_data/ise — Cisco Identity Services Engine

Seeded 2026-09-18 (ISE-01). Regenerate with `python3 scripts/seed_ise_cve_data.py`;
CI drift guard: `python3 scripts/seed_ise_cve_data.py --check`.

## What is in here

The Cisco ISE advisory bundle published **2026-09-16** — 8 of the ~40 CVEs from
that day, chosen because each one has a CVSS base score from NVD (source
`psirt@cisco.com`) *and* a fixed-release table read from the advisory CVRF XML.
Records without both were left out rather than filled with guesses.

| CVE | CVSS | Why it is here |
|---|---|---|
| CVE-2026-76460 | 10.0 | Auth bypass, **in CISA KEV**, PSIRT confirms active exploitation |
| CVE-2026-20192 / 20130 | 10.0 | Hardening release, Access Control / Improper Neutralization |
| CVE-2026-20234 | 9.9 | Hardening release, Insufficiently Protected Credentials |
| CVE-2026-20237 / 20194 | 9.1 | Hardening release, Input Validation / Incorrect Resource Transfer |
| CVE-2026-20287 | 6.5 | Hardening release, Improper Privilege Management — CVSS/SIR divergence |
| CVE-2026-20352 | 8.6 | RADIUS DoS — the one record where 3.1 and earlier are *not* vulnerable |

## Two deliberate deviations from the ios_xe convention

**1. `first_fixed_version.fixes` is keyed by ISE train, not by product family.**

The docstring on `CVEFirstFixed` says the map is keyed by `ProductFamily` enum
value (`"ios-xe"`, `"asa"`, …). That shape assumes one fix version per product
family. ISE breaks the assumption: every fix belongs to family `ise`, but Cisco
ships a *different* patch level per train:

```json
"fixes": {"ise-3.1": "3.1 Patch 12", "ise-3.4": "3.4 Patch 7"}
```

Keys are therefore `ise-<train>`. This is faithful to the advisory and keeps
`data_confidence()` at `verified`, but it is a widened contract, not the
documented one. Resolving it properly belongs to **CVE-007** (see
`projects/netdevops/backlog.md` in the CEO repo), which revisits the record
shape for Cisco's bundled-CVE model. Anything consuming `fixes` should treat
the key as an opaque path label, which is what the matcher already does.

**2. `severity` follows CVSS, `cisco_sir` follows the advisory.**

CVE-2026-20287 is CVSS 6.5 (medium) inside an advisory whose Cisco SIR is
Critical, because the SIR describes the hardening release as a whole. The record
keeps both and is tagged `sir-cvss-divergence` so the disagreement is visible
rather than silently resolved in one direction.

## Bundled CVEs are classes of bugs, not single bugs

Six of these records come from *Cisco Identity Services Engine Hardening
Release: September 2026*. Under Cisco's risk-based disclosure model
(twice-monthly, 1st and 3rd Wednesday, seven-day advance notice) a hardening
release does **not** assign one CVE per defect — one CVE covers many fixes in a
single CWE category. Their advisory titles say so: "Access Control
Vulnerabilities", "Input Validation Vulnerabilities".

Consequence for anyone reading this directory: `CVE-2026-20192` is not an
exploit path you can reason about individually. It is a category with a shared
fixed release. The `bundled-cve` tag marks these.

## Version strings

ISE versions parse through `services.cisco_version.CiscoIseVersion`
("3.4 Patch 7", "3.5P4", "Cisco ISE 3.3 Patch 12", "3.4.0.608"). A bare
`"3.4.0"` deliberately parses as **IOS XE**, not ISE — the comparator refuses to
guess between families. Prefix it (`"ISE 3.4.0"`) when the family is known.

## End-of-life caveat

ISE 3.0 has reached End of Software Maintenance: there is no fixed release on
that train, only migration. Releases 3.1 and 3.2 are in Software Maintenance and
receive Critical SIR fixes only. ISE-PIC is end-of-sale with 3.4 as its last
supported release. A "no patch exists for your train" answer is a real outcome
here, not a data gap.

## Provenance

All fields read from primary on 2026-09-18: CISA KEV JSON (`catalogVersion
2026.09.16`), Cisco CVRF XML per advisory, NVD API 2.0. Full read-out with
verbatim quotes: `projects/netdevops/ise/zagrozenia-2026-09-18.md` (CEO repo).
