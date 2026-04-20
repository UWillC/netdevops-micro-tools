"""
Golden-output regression tests for the CIS Compliance Audit tool.

Every .cfg in tests/goldens/cis/ is run through cis_audit() at the declared
levels. The output JSON is diffed against the checked-in expected JSON. Any
drift fails the test, blocking the PR.

Add a case:
    1. Drop `my-device.cfg` into tests/goldens/cis/.
    2. Add `my-device.cis-l1.expected.json` (and/or `-l2`) by running:
           UPDATE_GOLDENS=1 python3 -m pytest tests/test_cis_goldens.py
    3. Review the generated JSON; commit both files.

Update an existing expectation (after a deliberate rule change):
    UPDATE_GOLDENS=1 python3 -m pytest tests/test_cis_goldens.py
    # Then: git diff tests/goldens/  -> eyeball the diff -> commit.

The regeneration path is intentional: goldens are a PR-reviewed artefact,
not a silent auto-update.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterator, Tuple

import pytest

from api.routers.cis_audit import cis_audit, AuditRequest

GOLDENS_DIR = Path(__file__).parent / "goldens" / "cis"
UPDATE = os.environ.get("UPDATE_GOLDENS") == "1"
LEVELS = ("1", "2")


def _case_ids() -> Iterator[Tuple[str, str]]:
    """Yield (cfg_stem, level) for every cfg in the goldens dir, both levels."""
    for cfg in sorted(GOLDENS_DIR.glob("*.cfg")):
        for level in LEVELS:
            yield cfg.stem, level


def _expected_path(stem: str, level: str) -> Path:
    return GOLDENS_DIR / f"{stem}.cis-l{level}.expected.json"


def _to_serializable(resp) -> dict:
    """Convert AuditResponse -> JSON-friendly dict, dropping fields that could
    reasonably drift between runs (none currently, but leave the hook)."""
    d = resp.model_dump() if hasattr(resp, "model_dump") else resp.dict()
    return d


@pytest.mark.parametrize("stem,level", list(_case_ids()), ids=lambda v: str(v))
def test_cis_golden(stem: str, level: str):
    cfg_path = GOLDENS_DIR / f"{stem}.cfg"
    cfg_text = cfg_path.read_text()
    resp = cis_audit(AuditRequest(config_text=cfg_text, level=level))
    actual = _to_serializable(resp)

    expected_path = _expected_path(stem, level)

    if UPDATE:
        expected_path.write_text(json.dumps(actual, indent=2, sort_keys=True) + "\n")
        pytest.skip(f"updated {expected_path.name}")

    if not expected_path.exists():
        pytest.fail(
            f"Missing expected golden: {expected_path.name}. "
            f"Run `UPDATE_GOLDENS=1 python3 -m pytest tests/test_cis_goldens.py` "
            f"to generate."
        )

    expected = json.loads(expected_path.read_text())

    if actual != expected:
        diff = _diff_summary(expected, actual)
        pytest.fail(
            f"Golden drift for {cfg_path.name} (level {level}):\n{diff}\n\n"
            f"If this change is intentional, regenerate with "
            f"UPDATE_GOLDENS=1 and review the diff in the PR."
        )


def _diff_summary(expected: dict, actual: dict) -> str:
    """Compact diff for test failure output. Lists top-level scalar drifts
    and a per-rule result change summary."""
    lines = []
    # Scalars
    for k in ("score", "grade", "passed", "failed", "warnings", "not_applicable",
              "critical_fails", "score_capped", "parser_coverage"):
        e, a = expected.get(k), actual.get(k)
        if e != a:
            lines.append(f"  {k}: {e!r} -> {a!r}")
    # Per-rule
    def _rule_map(d):
        out = {}
        for cat in d.get("categories", []):
            for r in cat.get("rules", []):
                out[r["rule_id"]] = r
        return out

    em, am = _rule_map(expected), _rule_map(actual)
    all_ids = sorted(set(em) | set(am))
    for rid in all_ids:
        er = em.get(rid)
        ar = am.get(rid)
        if er is None:
            lines.append(f"  +rule {rid}: {ar.get('title')} = {ar.get('result')}")
            continue
        if ar is None:
            lines.append(f"  -rule {rid}: {er.get('title')}")
            continue
        if er.get("result") != ar.get("result"):
            lines.append(
                f"  rule {rid} {er.get('title')}: "
                f"{er.get('result')} -> {ar.get('result')}"
            )
        elif er.get("evidence") != ar.get("evidence"):
            lines.append(
                f"  rule {rid} evidence changed: "
                f"{er.get('evidence')[:60]!r} -> {ar.get('evidence')[:60]!r}"
            )
    return "\n".join(lines) if lines else "  (structural change outside scalars/rules)"
