"""
Loader for curated CVE preconditions JSON files (XCUT-001 Phase 3).

Reads `cve_preconditions/CVE-*.json` into a CVE-keyed dict that the Phase 4
correlation engine consumes. Validates each file against CVEPreconditions
schema on load — malformed files produce warnings, not exceptions (we want
a single broken curator file to not break the whole engine).

Condition strings in `required` and `sufficient_for_unauthenticated` are
ALSO validated against ExploitabilityCondition enum — unknown identifiers
are flagged but the file still loads (Phase 2 may add new conditions before
a given CVE file is updated).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, Optional

from models.cve_preconditions_model import CVEPreconditions
from services.exploitability_conditions import ExploitabilityCondition

logger = logging.getLogger(__name__)

# Module-level default: repo-root / cve_preconditions.
# Tests pass an explicit directory to avoid pollution.
_DEFAULT_DIR = Path(__file__).parent.parent / "cve_preconditions"


_VALID_CONDITION_VALUES = frozenset(c.value for c in ExploitabilityCondition)


def _validate_conditions(record: CVEPreconditions) -> None:
    """Warn (don't raise) on condition identifiers not in the enum."""
    all_conditions = (
        list(record.preconditions.required)
        + list(record.preconditions.sufficient_for_unauthenticated)
    )
    for cond in all_conditions:
        if cond not in _VALID_CONDITION_VALUES:
            logger.warning(
                "cve_preconditions: %s references unknown condition '%s' "
                "(not in ExploitabilityCondition enum)",
                record.cve_id, cond,
            )


def load_cve_preconditions(
    directory: Optional[Path] = None,
) -> Dict[str, CVEPreconditions]:
    """Read every CVE-*.json file in the directory into a dict by cve_id.

    Malformed files (bad JSON, schema mismatch) are logged and skipped.
    Returns empty dict if the directory doesn't exist.
    """
    path = Path(directory) if directory else _DEFAULT_DIR
    if not path.exists() or not path.is_dir():
        return {}

    out: Dict[str, CVEPreconditions] = {}
    for json_file in sorted(path.glob("CVE-*.json")):
        try:
            with json_file.open() as f:
                data = json.load(f)
            record = CVEPreconditions(**data)
        except (json.JSONDecodeError, ValueError, TypeError) as e:
            logger.warning("cve_preconditions: skipping malformed file %s: %s", json_file.name, e)
            continue

        if record.cve_id in out:
            logger.warning(
                "cve_preconditions: duplicate cve_id %s (file %s overrides prior record)",
                record.cve_id, json_file.name,
            )

        _validate_conditions(record)
        out[record.cve_id] = record

    return out


def get_preconditions_for(
    cve_id: str,
    loaded: Optional[Dict[str, CVEPreconditions]] = None,
) -> Optional[CVEPreconditions]:
    """Convenience lookup. Pass pre-loaded dict for hot-path use, or omit
    to reload on every call (useful in tests; slow in production).
    """
    if loaded is None:
        loaded = load_cve_preconditions()
    return loaded.get(cve_id)
