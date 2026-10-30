# Cheat sheet tools

The page: `cheatsheet/Cisco_CLI_Cheat_Sheet.html` (one self-contained file, served by `api/cheatsheet.py`).
Runner: `run.mjs`, Node 18+ and Chrome / Chromium / Edge (set `CHROME=<path>` if not found). No npm packages.
It injects a script into a temporary copy of the page, runs it in headless Chrome with all network
off, and decodes the base64 result from `<pre id="out">`. Only `splice` and `merge-verif --apply`
modify the page. Run from the repo root.

| Command | Purpose | Expected result (baseline 2026-10-29) |
|---|---|---|
| `node tools/cheatsheet/run.mjs check` | `uxtest.js` + `audit.js` in one go (also run by `tests/test_cheatsheet.py`, required in CI) | `uxtest: 58 PASS`, `audit: 5 findings` (the known false positives listed in `run.mjs`), exit 0 |
| `node tools/cheatsheet/run.mjs run tools/cheatsheet/uxtest.js` | Functional tests, full output | 58 x PASS |
| `node tools/cheatsheet/run.mjs run tools/cheatsheet/audit.js` | Data quality audit, full output | the 5 known false positives plus informational lines (commands in 3+ sections, placeholder list) |
| `node tools/cheatsheet/run.mjs run my-transform.js --out newdata.js` | Bulk data edit (copy `transform-template.js` outside the repo) | page title "OK sections ..." |
| `node tools/cheatsheet/run.mjs splice newdata.js` | Write a new DATA block into the page (an optional `/*RENAMED*/` part replaces the rename table) | "Spliced DATA into ..." (snapshot the page first, outside the repo) |
| `node tools/cheatsheet/run.mjs merge-verif export.json [--apply --snapshot-dir <dir>]` | Merge users' field checks (Favorites › Export, key `verified`) into the 6th row field | report: REVIEW-FAILS / REVIEW-DIFFERS (fix by hand), BADGE, MASK?, ORPHAN |

The comments inside `transform-template.js` and `merge-verif.js` still name the original Windows
runner (`Run-CheatSheetScript.ps1`, `Splice-Data.ps1`, `Merge-Verification.ps1`); the commands above
replace them one to one.

Content rules:
- Generic content only: no hostnames, real IPs, sites, domains, organisation / team / people names.
- An export JSON from a user is untrusted input: corrections are only listed, never applied automatically.
- Keep the ⚠ warnings and UNVERIFIED badges. A renamed or new section title must be in `CATEGORIES`;
  renames go into `RENAMED` unless the old name is wording that was removed on purpose.
- Read and write the page as UTF-8. Snapshots never go into the repo.
- After an edit: `node tools/cheatsheet/run.mjs check`, then `pytest tests/test_cheatsheet.py`
  (the CSP hash is computed from the file at startup, nothing to update by hand).
