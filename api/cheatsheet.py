"""Cisco CLI Cheat Sheet (reference page, not a counted module).

One self-contained HTML file in ``cheatsheet/`` (data, CSS and JS inline; works offline from
disk). It is served byte for byte, never rewritten:

* ``/cli-cheat-sheet``                 the page, inline
* ``/cli-cheat-sheet/download``        the same bytes as an attachment ("Download offline copy")
* ``/cli-cheat-sheet/sha256``          ``sha256sum`` line for the file (shown next to the link)

The file lives outside ``web/`` on purpose: ``web/`` is also mounted as ``/static`` without
these headers, so a copy there would be a second, unhardened address of the same page.

Strict CSP on these routes only (site-wide headers are slot WEBSEC-01(a)). The hash of the one
inline script is computed from the file at startup, so editing the data never needs a manual
header update. ``connect-src 'none'``: the page shares its origin with the SPA (localStorage
holds the beta token); even an XSS in the data could not send anything anywhere.
``style-src 'unsafe-inline'`` is required by the ``style="--hue:..."`` attributes the page
generates; scripts stay hash-only.
"""

import base64
import hashlib
import os
import re

from fastapi import APIRouter
from fastapi.responses import PlainTextResponse, Response

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILENAME = "Cisco_CLI_Cheat_Sheet.html"
PATH = os.path.join(BASE_DIR, "cheatsheet", FILENAME)

PAGE_PATH = "/cli-cheat-sheet"
DOWNLOAD_PATH = "/cli-cheat-sheet/download"
SHA256_PATH = "/cli-cheat-sheet/sha256"

# no-transform: a proxy / CDN must not rewrite the bytes (a changed inline script no longer
# matches the CSP hash, and the download would no longer match its SHA-256).
CACHE_CONTROL = "no-cache, no-transform"

# What the browser hashes: the text between <script> and the first </script> (same rule as the
# HTML parser, so "<script>" inside the data, which is inside the block, does not count).
_SCRIPT_RE = re.compile(r"<script(\s[^>]*)?>(.*?)</script\s*>", re.S | re.I)

router = APIRouter()


def _script_hashes(html: str) -> list:
    hashes = []
    for attrs, body in _SCRIPT_RE.findall(html):
        if attrs and re.search(r"\bsrc\s*=", attrs, re.I):
            raise ValueError("cheat sheet must not load external scripts")
        digest = hashlib.sha256(body.encode("utf-8")).digest()
        hashes.append("'sha256-" + base64.b64encode(digest).decode("ascii") + "'")
    if not hashes:
        raise ValueError("no inline script found in the cheat sheet")
    return hashes


def build_csp(html: str) -> str:
    return "; ".join([
        "default-src 'none'",
        "script-src " + " ".join(_script_hashes(html)),
        "style-src 'unsafe-inline'",
        "img-src 'self' data:",
        "connect-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'",
        "object-src 'none'",
    ])


def _load():
    with open(PATH, "rb") as fh:
        data = fh.read()
    return data, hashlib.sha256(data).hexdigest(), build_csp(data.decode("utf-8"))


# Read once at startup (the container image is immutable). A missing or broken file must not
# take the other 22 modules down, so the routes answer 503 instead.
try:
    CONTENT, SHA256, CSP = _load()
except Exception as exc:  # pragma: no cover - exercised only on a broken deploy
    print(f"[WARN] CLI cheat sheet not served: {exc}")
    CONTENT, SHA256, CSP = None, None, None


def _headers(extra=None) -> dict:
    h = {
        "Content-Security-Policy": CSP,
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Cache-Control": CACHE_CONTROL,
    }
    h.update(extra or {})
    return h


def _unavailable() -> PlainTextResponse:
    return PlainTextResponse("CLI cheat sheet is temporarily unavailable.", status_code=503)


@router.api_route(PAGE_PATH, methods=["GET", "HEAD"], include_in_schema=False)
def cheat_sheet_page():
    if CONTENT is None:
        return _unavailable()
    return Response(content=CONTENT, media_type="text/html; charset=utf-8", headers=_headers())


@router.api_route(DOWNLOAD_PATH, methods=["GET", "HEAD"], include_in_schema=False)
def cheat_sheet_download():
    if CONTENT is None:
        return _unavailable()
    return Response(
        content=CONTENT,
        media_type="text/html; charset=utf-8",
        headers=_headers({"Content-Disposition": f'attachment; filename="{FILENAME}"'}),
    )


@router.api_route(SHA256_PATH, methods=["GET", "HEAD"], include_in_schema=False)
def cheat_sheet_sha256():
    if CONTENT is None:
        return _unavailable()
    return PlainTextResponse(
        f"{SHA256}  {FILENAME}\n",
        headers={"X-Content-Type-Options": "nosniff", "Cache-Control": CACHE_CONTROL},
    )
