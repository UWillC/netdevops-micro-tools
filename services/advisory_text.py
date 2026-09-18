"""
Plain text from Cisco advisory HTML (HTML-01, 2026-09-18).

Three importers each stripped tags with their own regex and none decoded
entities, so stored descriptions read "Protocol&nbsp;(SNMP)" and
"Cisco&nbsp;IOS XE". One function, used by all of them and by the migration
that cleaned the 49 affected fields already on disk.
"""

from __future__ import annotations

import html
import re

_TAG_RE = re.compile(r"<[^>]+>")
_SPACES_RE = re.compile(r"[ \t ]{2,}")


def clean_advisory_text(text) -> str:
    """Strip tags, decode entities, fold non-breaking and repeated spaces."""
    if not isinstance(text, str):
        return ""
    out = _TAG_RE.sub("", text)
    out = html.unescape(out).replace(" ", " ")
    return _SPACES_RE.sub(" ", out).strip()
