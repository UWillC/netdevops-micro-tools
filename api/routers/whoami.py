"""
Whoami Router (ifconfig.me-style client info)

Returns the caller's public IP and connection metadata.
curl-first: plain text IP for CLI clients, full JSON for browsers/APIs.
Behind Render's proxy the client IP is the first entry of X-Forwarded-For.
"""

from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse, JSONResponse


router = APIRouter()

# Headers reflected back to the caller. Anything else (cookies, auth,
# proxy internals) is deliberately never echoed.
REFLECTED_HEADERS = [
    "user-agent",
    "accept",
    "accept-language",
    "accept-encoding",
    "referer",
    "x-forwarded-for",
    "x-forwarded-proto",
]


def client_ip(request: Request) -> str:
    """First X-Forwarded-For entry (real client behind proxy), else socket peer."""
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        first = xff.split(",")[0].strip()
        if first:
            return first
    if request.client:
        return request.client.host
    return "unknown"


def wants_plain(request: Request) -> bool:
    """CLI clients (curl/wget/httpie/fetch) get bare IP; browsers get JSON."""
    accept = request.headers.get("accept", "")
    if "application/json" in accept:
        return False
    if "text/html" in accept:
        return False
    ua = request.headers.get("user-agent", "").lower()
    cli_agents = ("curl", "wget", "httpie", "fetch", "powershell", "python-requests")
    return any(agent in ua for agent in cli_agents) or accept in ("", "*/*")


def build_info(request: Request) -> dict:
    info = {
        "ip": client_ip(request),
        "method": request.method,
        "host": request.headers.get("host", ""),
        "proto": request.headers.get("x-forwarded-proto", request.url.scheme),
    }
    for header in REFLECTED_HEADERS:
        value = request.headers.get(header)
        if value:
            info[header.replace("-", "_")] = value
    return info


@router.get("/whoami", summary="Your public IP (plain for CLI, JSON for browsers)")
def whoami(request: Request):
    """`curl <host>/tools/whoami` -> bare IP. Browser/JSON clients -> full info."""
    if wants_plain(request):
        return PlainTextResponse(client_ip(request) + "\n")
    return JSONResponse(build_info(request))


@router.get("/whoami/ip", response_class=PlainTextResponse, summary="Bare public IP")
def whoami_ip(request: Request):
    """Always plain text, always just the IP. Script-safe."""
    return PlainTextResponse(client_ip(request) + "\n")


@router.get("/whoami/json", summary="Full client info as JSON")
def whoami_json(request: Request):
    """Always JSON: IP + reflected client headers (safe subset only)."""
    return JSONResponse(build_info(request))
