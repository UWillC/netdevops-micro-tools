# Golden-output regression tests

Every `.cfg` here is a canonical "known-answer" fixture. The pytest harness
in `tests/test_cis_goldens.py` runs each config through the CIS Audit engine
at both Level 1 and Level 2, and diffs the result against the checked-in
`.expected.json`.

Any drift fails the test → blocks the PR. This is the guardrail that would
have prevented every bug in the 2026-04-19 defect report.

## Current fixtures (CIS)

| Config | Purpose |
|--------|---------|
| `branch-router-01.cfg` | Defect-report §2 test config (verbatim). Level 1 score 17.3%, 7 CRITICAL FAILs. Anchor for CIS-001 … CIS-010. |
| `indented-paste.cfg` | Same content as branch-router-01 but with 2-space chat-paste indent. Anchor for the v0.6.13/v0.6.14 normalize-config fix. Expected output MUST match branch-router-01. |
| `hardened-baseline.cfg` | Fully-hardened Cisco IOS-XE config. Level 1 score 100%, Grade A, all 23 rules PASS. Anchors severity weighting and regression against false-FAIL drift. |
| `l3-only-router.cfg` | Pure L3 router (no switchport tokens). Anchors CIS-009 — all 6.1.x L2 rules must return N/A, not WARN. |

## Add a new case

1. Drop `my-device.cfg` into `tests/goldens/cis/`.
2. Generate the expected output:
   ```
   PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python \
   UPDATE_GOLDENS=1 python3 -m pytest tests/test_cis_goldens.py
   ```
3. **Eyeball the generated JSON.** It is your statement of truth for what
   this config SHOULD produce. Wrong expectations bake in wrong behavior.
4. Commit both the `.cfg` and the `.expected.json`.

## Update an existing expectation

When you intentionally change rule behavior:

```
PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python \
UPDATE_GOLDENS=1 python3 -m pytest tests/test_cis_goldens.py
```

Then:
```
git diff tests/goldens/
```

Review every line of the diff. Ask: *is this change intentional, and does it
match what the CHANGELOG entry says?* If yes, commit. If no, you've found a
regression.

Goldens are a **PR-reviewed artefact**, never silently regenerated in CI.

## Running locally

```
cd /path/to/cisco-microtool-generator
PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python python3 -m pytest tests/test_cis_goldens.py -v
```

The `PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python` workaround dodges a
pytest-plugin protobuf version mismatch in the dev environment; it's a no-op
for correctness.

## CI

`.github/workflows/tests.yml` runs the full test suite on every PR and every
push to `main`. A golden drift fails the check and blocks the merge.
