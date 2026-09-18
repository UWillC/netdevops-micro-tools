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

## Conventions specific to this directory

**1. `first_fixed_version.fixes` is keyed by fix path: `ise-<train>`.**

One fix per product family cannot express ISE: every fix belongs to family
`ise`, but Cisco ships a different patch level per train.

```json
"fixes": {"ise-3.1": "3.1 Patch 12", "ise-3.4": "3.4 Patch 7"}
```

This started as an undocumented widening of the `CVEFirstFixed` contract
(v0.6.31). As of v0.6.34 it is the documented contract — a key is a
`ProductFamily` value, optionally followed by `-<train>` — and consumers should
call `CVEFirstFixed.fix_for("ise", "3.4")` / `.trains("ise")` instead of
indexing the dict.

**2. `severity` follows CVSS, `cisco_sir` follows the advisory.**

CVE-2026-20287 is CVSS 6.5 (medium) inside an advisory whose Cisco SIR is
Critical, because the SIR describes the hardening release as a whole. The record
keeps both and is tagged `sir-cvss-divergence` so the disagreement is visible
rather than silently resolved in one direction.

**3. CWE and CVSS vector come from NVD, never from the advisory title.**

v0.6.31 shipped two CWE values inferred from titles: CVE-2026-20130 as CWE-707
(NVD: CWE-74) and CVE-2026-20352 with none (NVD: CWE-119). Both were corrected
in v0.6.34 and `tests/test_hardening_release.py::TestDatasetAgainstNvd` now pins
every CWE, score and vector in this directory to the NVD values.

**4. `bundle` is empty on purpose.**

`CVEEntry.bundle` (CVE-010) marks Cisco's *semi-annual IOS / IOS XE bundled
publication* (March and September). The ISE advisories of 2026-09-16 are a
scheduled twice-monthly disclosure, which is a different thing. v0.6.31 set
`bundle: "2026-09"` on these records and the analyzer then reported "In Cisco
bundle: 8 CVE(s)" — corrected in v0.6.38. The shared publication date is kept
as the tag `cisco-drop-2026-09-16`.

## Bundled CVEs are classes of bugs, not single bugs

Six of these records come from *Cisco Identity Services Engine Hardening
Release: September 2026*. Under Cisco's risk-based disclosure model
(twice-monthly, 1st and 3rd Wednesday, seven-day advance notice) a hardening
release does **not** assign one CVE per defect — one CVE covers many fixes in a
single CWE category. Their advisory titles say so: "Access Control
Vulnerabilities", "Input Validation Vulnerabilities".

Consequence for anyone reading this directory: `CVE-2026-20192` is not an
exploit path you can reason about individually. It is a category with a shared
fixed release. These records carry a typed `bundled` block (`advisory_id`,
`cwe_categories`, `sibling_cves`, `one_cve_per_cwe`) plus the `bundled-cve` tag;
detection lives in `services/hardening_release.py`.

## Version strings

ISE versions parse through `services.cisco_version.CiscoIseVersion`
("3.4 Patch 7", "3.5P4", "Cisco ISE 3.3 Patch 12", "3.4.0.608"). A bare
`"3.4.0"` deliberately parses as **IOS XE**, not ISE — the comparator refuses to
guess between families. Prefix it (`"ISE 3.4.0"`) when the family is known.

## Software lifecycle

ISE 3.0 has reached End of Software Maintenance: no fixed release on that train,
only migration. Releases 3.1 and 3.2 are in Software Maintenance and receive
Critical SIR fixes only. ISE-PIC is end-of-sale with 3.4 as its last supported
release. "No patch exists for your train" is a real outcome here, not a data gap.

These statements are **not** stored in the records. v0.6.31 pasted them into
seven of the eight descriptions, so a report for a 3.4 deployment repeated them
seven times. Since v0.6.41 they come from
`services.cve_engine.ise_lifecycle_note()`: one statement per report, only when
it applies to the caller's train, with its source and without dates — the
advisory gives none.

**Lower bound.** The hardening advisory's table reads "3.0 and earlier — Migrate
to fixed release", so those six records are unbounded below (`affected.min`
`0.0`). v0.6.31 used `3.0`, which reported ISE 2.x as not affected. The
authentication-bypass advisory lists 3.1–3.5 and footnotes 3.0 only, so its
bound stays at `3.0`; nothing there speaks about 2.x and the record does not
claim it.

## Provenance

All fields read from primary on 2026-09-18: CISA KEV JSON (`catalogVersion
2026.09.16`), Cisco CVRF XML per advisory, NVD API 2.0. Full read-out with
verbatim quotes: `projects/netdevops/ise/zagrozenia-2026-09-18.md` (CEO repo).
