# cve_data/nx_os

NX-OS-01 (2026-09-18). One record per CVE from Cisco PSIRT advisories that
**enumerate standalone NX-OS releases** (`productNames`: "Cisco NX-OS Software
10.2(6)"). That list is the only thing a match is ever based on.

- Seeded from PSIRT on 2026-09-18: 246 NX-OS advisories, 222 with a release list,
  288 CVEs. The 24 without a list are left out: a match must be checkable.
- Per-CVE title / CVSS / vector come from the advisory's CVRF document. Where CVRF
  has no per-CVE score the advisory maximum is used and the record is tagged
  `cvss-advisory-level`.
- `fixed_in` is always null. Cisco does not publish first fixed NX-OS releases
  through its API (advisories defer to Software Checker); the report says so
  rather than naming a release nobody read.
- ACI-mode images ("Cisco NX-OS System Software in ACI Mode 14.2(1i)") are kept
  under their own list key `nx-os-aci` and are never used for an NX-OS query.
- Production imports new CVEs and refreshes lists on every PSIRT sync
  (`services.cisco_sync.auto_sync_nxos`); the repo copy is refreshed weekly by
  `.github/workflows/refresh-known-affected.yml`.
- No mitigation templates are generated: the templates in this project are IOS
  configuration snippets.
