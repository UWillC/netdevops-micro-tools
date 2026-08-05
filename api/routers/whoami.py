"""
Whoami Router (ifconfig.me-style client info)

Returns the caller's public IP and connection metadata.
curl-first: plain text IP for CLI clients, full JSON for browsers/APIs.
Behind Render's proxy the client IP is the first entry of X-Forwarded-For.
Note: Render's edge 301-redirects http:// to https:// — documented usage
always shows explicit https:// URLs.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout

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
    "via",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-port",
]

_dns_pool = ThreadPoolExecutor(max_workers=2)
REVERSE_DNS_TIMEOUT_S = 0.8


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


def reverse_dns(ip: str) -> str:
    """PTR lookup with a hard timeout; 'unavailable' on miss (ifconfig.me parity)."""
    def _lookup():
        return socket.gethostbyaddr(ip)[0]

    try:
        return _dns_pool.submit(_lookup).result(timeout=REVERSE_DNS_TIMEOUT_S)
    except (FuturesTimeout, OSError, UnicodeError):
        return "unavailable"


def client_port(request: Request) -> str:
    forwarded_port = request.headers.get("x-forwarded-port", "")
    if forwarded_port:
        return forwarded_port
    if request.client and request.client.port:
        return str(request.client.port)
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


def build_info(request: Request, with_remote_host: bool = False) -> dict:
    ip = client_ip(request)
    info = {
        "ip": ip,
        "method": request.method,
        "host": request.headers.get("host", ""),
        "proto": request.headers.get("x-forwarded-proto", request.url.scheme),
        "port": client_port(request),
        "mime": request.headers.get("accept", ""),
    }
    if with_remote_host:
        info["remote_host"] = reverse_dns(ip)
    for header in REFLECTED_HEADERS:
        value = request.headers.get(header)
        if value:
            info[header.replace("-", "_")] = value
    return info


# Per-field plain-text endpoints (ifconfig.me parity: /ua, /lang, ...).
# Maps URL segment -> key resolution over build_info.
FIELD_MAP = {
    "ua": "user_agent",
    "lang": "accept_language",
    "encoding": "accept_encoding",
    "mime": "mime",
    "method": "method",
    "host": "host",
    "proto": "proto",
    "port": "port",
    "forwarded": "x_forwarded_for",
    "referer": "referer",
    "via": "via",
}


def format_all(info: dict) -> str:
    lines = []
    for key, value in info.items():
        lines.append("%s: %s" % (key, value))
    return "\n".join(lines) + "\n"


@router.get("/whoami", summary="Your public IP (plain for CLI, JSON for browsers)")
def whoami(request: Request):
    """`curl https://<host>/tools/whoami` -> bare IP. Browser/JSON clients -> full info."""
    if wants_plain(request):
        return PlainTextResponse(client_ip(request) + "\n")
    return JSONResponse(build_info(request, with_remote_host=True))


@router.get("/whoami/ip", response_class=PlainTextResponse, summary="Bare public IP")
def whoami_ip(request: Request):
    """Always plain text, always just the IP. Script-safe."""
    return PlainTextResponse(client_ip(request) + "\n")


@router.get("/whoami/json", summary="Full client info as JSON")
def whoami_json(request: Request):
    """Always JSON: IP + reverse DNS + reflected client headers (safe subset only)."""
    return JSONResponse(build_info(request, with_remote_host=True))


@router.get("/whoami/all", response_class=PlainTextResponse, summary="All fields, plain text")
def whoami_all(request: Request):
    """key: value listing (ifconfig.me /all parity), script-friendly."""
    return PlainTextResponse(format_all(build_info(request, with_remote_host=True)))


@router.get("/whoami/remote_host", response_class=PlainTextResponse, summary="Reverse DNS of your IP")
def whoami_remote_host(request: Request):
    return PlainTextResponse(reverse_dns(client_ip(request)) + "\n")


@router.get("/whoami/{field}", response_class=PlainTextResponse, summary="Single field, plain text")
def whoami_field(field: str, request: Request):
    """Per-field endpoints: ua, lang, encoding, mime, method, host, proto, port, forwarded, referer, via."""
    key = FIELD_MAP.get(field)
    if key is None:
        valid = ", ".join(sorted(FIELD_MAP.keys()))
        return PlainTextResponse("unknown field '%s' (valid: %s)\n" % (field, valid), status_code=404)
    info = build_info(request)
    return PlainTextResponse(str(info.get(key, "")) + "\n")
