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


_BOILERPLATE_RES = [
    re.compile(r"\s*Cisco (has released|plans to release|will release)[^.]*\.(\s*There (are|is) (no )?workarounds?[^.]*\.)?", re.I),
    re.compile(r"\s*There (are|is) (no )?workarounds? that address(es)? (this|these) vulnerabilit(y|ies)\.", re.I),
    # the URL may run straight into the next paragraph when tags are stripped
    re.compile(r"\s*This advisory is available at the following link:\s*\S*?(?=This advisory|\s|$)", re.I),
    re.compile(r"\s*This advisory is part of the .*?Bundled Publication\.?(\s*For a complete list of the advisories.*)?$", re.I | re.S),
    re.compile(r"\s*For more information about these vulnerabilities, see the Details section of this advisory\.", re.I),
]


def summarize_advisory_text(text: str, limit: int = 700) -> str:
    """Advisory summary without Cisco's closing boilerplate, cut at a sentence end.

    The vulnerability is in the first sentences. What follows in every summary
    ("Cisco has released software updates...", "This advisory is available at the
    following link:...", the bundled-publication paragraph) tells an analyst
    nothing and, at a hard 1500-character cut, left reports ending mid-word.
    """
    out = clean_advisory_text(text or "")
    # Text already cut mid-word by an older importer ("...improper valida..."):
    # drop the dangling fragment back to the last whole sentence.
    if out.rstrip().endswith("...") and ". " in out:
        out = out[:out.rfind(". ") + 1]
    for rx in _BOILERPLATE_RES:
        out = rx.sub("", out)
    out = re.sub(r"[ \t]*\n\s*\n\s*", "\n", out).strip()
    out = re.sub(r"[ \t]{2,}", " ", out)
    if len(out) <= limit:
        return out
    cut = out[:limit]
    end = max(cut.rfind(". "), cut.rfind(".\n"))
    return (cut[:end + 1] if end > limit * 0.4 else cut.rsplit(" ", 1)[0] + " ...").strip()
