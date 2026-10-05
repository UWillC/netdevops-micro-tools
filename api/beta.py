"""
Public beta, variant A: who is an active tester (BETA-A, 2026-10-05).

The email gate is a browser-only check, so the server never knew who ran a
tool. Variant A (decision 2026-10-04, @ciso review 2026-10-04, conditions W1-W6):

- /api/subscribe returns a signed token  v1.<subscriber_id>.<b64url(hmac)>
  for the MailerLite subscriber id (never the email). Secret BETA_TOKEN_SECRET
  (>= 32 bytes, env only). No secret = no token; the app works as before.
- The frontend sends it as X-Beta-Token, only same-origin and only on tool
  paths (web/app-gate.js).
- BetaActivityMiddleware: a 2xx answer on a tool path with a valid token marks
  the subscriber active for that day. It never reads or logs the request body;
  the path decides, nothing else.
- At most once per subscriber per day (in-memory dedup) a background task
  writes two MailerLite DATE fields with PUT /subscribers/{id}:
  beta_first_use (only while empty) and beta_last_use. Fields only: never
  status, groups or resubscribe, so an unsubscribed person is never revived.
  Minimisation (@ciso 1.2): dates, no list of tools.
- Errors from MailerLite are swallowed; logs carry no email, no subscriber id,
  no token, no body.

A token is not tester status: status needs a confirmed mailbox (claim link at
the end of the beta, @ciso W6). The token only records "someone holding this
subscriber's token ran a tool on this day".
"""

import asyncio
import base64
import datetime
import hashlib
import hmac
import logging
import os
import re
import threading
from typing import Callable, Optional, Set

import httpx
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

# httpx logs every request URL at INFO; ours carry a subscriber id or an email.
logging.getLogger("httpx").setLevel(logging.WARNING)

TOKEN_VERSION = "v1"
TOKEN_HEADER = "x-beta-token"
MIN_SECRET_BYTES = 32

MAILERLITE_API_URL = "https://connect.mailerlite.com/api"
FIELD_FIRST_USE = "beta_first_use"
FIELD_LAST_USE = "beta_last_use"

# Tools live at the root, not under /api (api/main.py router prefixes).
TOOL_PREFIXES = (
    "/generate/",   # SNMPv3, NTP, AAA, Golden Config, iPerf3
    "/analyze/",    # CVE Analyzer
    "/tools/",      # Subnet, MTU, Config Parser/Explainer/Drift, IP Path Tracer,
                    # Port Auditor, Hardening Audit, Timezone, Whoami
    "/mitigate/",   # CVE Mitigation
    "/export/",     # Security report export
    "/profiles/",   # Device Profiles, vulnerability widget, Security Score
    "/api/kev/",    # KEV Watch
)
# Requests the page fires by itself on load. Counting them would make every
# visit "activity" without anyone running a tool.
PASSIVE_PATHS = frozenset({
    "/analyze/advisories",     # Threat Feed initial load (app-feeds.js)
    "/analyze/critical-feed",  # deprecated alias of the same feed
    "/profiles/list",          # profile dropdown fill on load (app-profiles.js)
})
COUNTED_METHODS = frozenset({"GET", "POST"})

_SUBSCRIBER_ID_RE = re.compile(r"^[0-9]{1,32}$")

# Rotation: a token signed with the previous secret stays valid while
# BETA_TOKEN_SECRET_PREVIOUS is set (new tokens always use the current one).
_warned = set()
_warn_lock = threading.Lock()


def _warn_once(key: str, message: str) -> None:
    with _warn_lock:
        if key in _warned:
            return
        _warned.add(key)
    print(f"[WARN] {message}")


def _load_secret(name: str) -> Optional[bytes]:
    raw = os.getenv(name, "")
    if not raw:
        return None
    value = raw.encode("utf-8")
    if len(value) < MIN_SECRET_BYTES:
        _warn_once(name + ":short",
                   f"{name} is shorter than {MIN_SECRET_BYTES} bytes: ignored")
        return None
    return value


def current_secret() -> Optional[bytes]:
    secret = _load_secret("BETA_TOKEN_SECRET")
    if secret is None:
        _warn_once("BETA_TOKEN_SECRET:missing",
                   "BETA_TOKEN_SECRET not set (or too short): beta tokens are not issued "
                   "and tool use is not recorded")
    return secret


def _verification_secrets():
    secrets = []
    cur = current_secret()
    if cur:
        secrets.append(cur)
    prev = _load_secret("BETA_TOKEN_SECRET_PREVIOUS")
    if prev:
        secrets.append(prev)
    return secrets


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _sign(secret: bytes, subscriber_id: str) -> str:
    msg = f"{TOKEN_VERSION}.{subscriber_id}".encode("ascii")
    return _b64url(hmac.new(secret, msg, hashlib.sha256).digest())


def issue_token(subscriber_id) -> Optional[str]:
    """Signed token for a MailerLite subscriber id, or None (no secret / bad id)."""
    sid = str(subscriber_id or "")
    if not _SUBSCRIBER_ID_RE.match(sid):
        return None
    secret = current_secret()
    if secret is None:
        return None
    return f"{TOKEN_VERSION}.{sid}.{_sign(secret, sid)}"


def verify_token(token: Optional[str]) -> Optional[str]:
    """Subscriber id if the token is well-formed, current version and correctly signed."""
    if not token or len(token) > 200:
        return None
    parts = token.split(".")
    if len(parts) != 3:
        return None
    version, sid, sig = parts
    if version != TOKEN_VERSION or not _SUBSCRIBER_ID_RE.match(sid):
        return None
    for secret in _verification_secrets():
        if hmac.compare_digest(_sign(secret, sid), sig):
            return sid
    return None


def decoy_subscriber_id(email: str) -> Optional[str]:
    """Stable, numeric, non-existent-looking id for an address that is not a
    subscriber, so the read-only backfill answers the same shape either way
    (no enumeration). A decoy token later meets a 404 in MailerLite and is
    dropped; nothing is created."""
    secret = current_secret()
    if secret is None:
        return None
    digest = hmac.new(secret, b"decoy:" + email.strip().lower().encode("utf-8"),
                      hashlib.sha256).digest()
    return str(int.from_bytes(digest[:8], "big") % 10**18).rjust(18, "1")


# ---------------------------------------------------------------- activity

def is_tool_path(method: str, path: str) -> bool:
    if method not in COUNTED_METHODS:
        return False
    if path in PASSIVE_PATHS:
        return False
    return path.startswith(TOOL_PREFIXES)


def _today() -> datetime.date:
    return datetime.datetime.now(datetime.timezone.utc).date()


class DailyDedup:
    """One write per subscriber per UTC day; memory holds today only."""

    def __init__(self):
        self._day = None
        self._seen: Set[str] = set()
        self._lock = threading.Lock()

    def first_today(self, subscriber_id: str, day: datetime.date) -> bool:
        with self._lock:
            if day != self._day:
                self._day = day
                self._seen = set()
            if subscriber_id in self._seen:
                return False
            self._seen.add(subscriber_id)
            return True

    def reset(self):
        with self._lock:
            self._day = None
            self._seen = set()


dedup = DailyDedup()


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=10.0)


def _api_key() -> str:
    return os.getenv("MAILERLITE_API_KEY", "")


async def record_activity(subscriber_id: str, day: datetime.date) -> None:
    """GET the subscriber (read), then PUT only the two date fields.

    Never raises. Never logs the id, email or anything from MailerLite."""
    key = _api_key()
    if not key:
        return
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json",
               "Accept": "application/json"}
    url = f"{MAILERLITE_API_URL}/subscribers/{subscriber_id}"
    stamp = day.isoformat()
    try:
        async with _client() as client:
            got = await client.get(url, headers=headers)
            if got.status_code == 404:
                return  # forgotten, deleted or a decoy: nothing to write
            if got.status_code != 200:
                print(f"[WARN] beta activity: lookup failed status={got.status_code}")
                return
            fields = ((got.json() or {}).get("data") or {}).get("fields") or {}
            update = {FIELD_LAST_USE: stamp}
            if not fields.get(FIELD_FIRST_USE):
                update[FIELD_FIRST_USE] = stamp
            put = await client.put(url, json={"fields": update}, headers=headers)
            if put.status_code not in (200, 201):
                print(f"[WARN] beta activity: field update failed status={put.status_code}")
    except Exception as exc:  # network, JSON, anything: never break a tool call
        print(f"[WARN] beta activity: write error {type(exc).__name__}")


_tasks: Set[asyncio.Task] = set()


def _spawn(coro) -> None:
    """Fire-and-forget on the running loop; keep a reference until done."""
    try:
        task = asyncio.get_running_loop().create_task(coro)
    except RuntimeError:
        coro.close()
        return
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)


def note_activity(subscriber_id: str, day: Optional[datetime.date] = None) -> bool:
    """Schedule the MailerLite write once per subscriber per day. True if scheduled."""
    day = day or _today()
    if not dedup.first_today(subscriber_id, day):
        return False
    _spawn(record_activity(subscriber_id, day))
    return True


class BetaActivityMiddleware(BaseHTTPMiddleware):
    """Counts 2xx tool responses carrying a valid X-Beta-Token.

    Reads only method, path, one header and the status code. Never the body."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        try:
            token = request.headers.get(TOKEN_HEADER)
            if (token and 200 <= response.status_code < 300
                    and is_tool_path(request.method, request.url.path)):
                sid = verify_token(token)
                if sid:
                    note_activity(sid)
        except Exception as exc:
            print(f"[WARN] beta activity: middleware error {type(exc).__name__}")
        return response


def reset_for_tests() -> None:
    dedup.reset()
    with _warn_lock:
        _warned.clear()
