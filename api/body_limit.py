"""
Request body limit for the whole application (WEBSEC-01d, @ciso N4).

One process serves every tool, and without a limit any POST could make it read
and parse a body of any size. A declared Content-Length over the limit gets 413
before the body is read. A chunked request declares no length, so the bytes are
also counted as they arrive.

Limits, measured 2026-11-02 on generated access-switch pastes, JSON bytes:
    48-port switch per stack member: running-config ~38 KB, `show interfaces` ~75 KB
    8 member stack: Hardening / Parser / Explainer 307 KB, Port Auditor 600 KB,
                    Config Drift 614 KB (it takes two configs)
so the 256 KB proposed by N4 fits the short forms and ACL What-If (100 000
characters, ~101 KB of JSON) but would refuse a real paste on the tools below.
PASTE_MAX stays under 1 MB and leaves room for routing and ACL sections.
"""

from fastapi import HTTPException
from starlette.responses import JSONResponse

DEFAULT_MAX = 256 * 1024
PASTE_MAX = 960 * 1024

# Endpoints that take a whole running-config or a device-wide `show` output.
PASTE_PATHS = frozenset({
    "/tools/config-drift/compare",
    "/tools/hardening-audit/check",
    "/tools/cis-audit/check",  # legacy alias of hardening-audit
    "/tools/config/parse",
    "/tools/config/parse/summary",
    "/tools/config-explainer/explain",
    "/tools/port-auditor/analyze",
})


def _limit_for(path: str) -> int:
    return PASTE_MAX if path in PASTE_PATHS else DEFAULT_MAX


def _message(limit: int) -> str:
    return "Request too large: at most %d KB for this tool." % (limit // 1024)


class BodyLimitMiddleware:
    """Plain ASGI, so it can wrap ``receive`` without buffering the body."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        limit = _limit_for(scope["path"])
        declared = dict(scope["headers"]).get(b"content-length", b"")
        if declared.isdigit() and int(declared) > limit:
            response = JSONResponse({"detail": _message(limit)}, status_code=413)
            await response(scope, receive, send)
            return

        seen = 0

        async def counted_receive():
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > limit:
                    # FastAPI re-raises HTTPException from its body read; any
                    # other exception there would turn into a 400.
                    raise HTTPException(status_code=413, detail=_message(limit))
            return message

        await self.app(scope, counted_receive, send)
