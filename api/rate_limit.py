"""
Per-IP rate limit for every POST endpoint (generators, analyzers, subscribe).

Fix 2026-09-30 (@ciso H8 S2 recon: the app is reachable without any limit;
Cloudflare in front does not throttle). One middleware instead of decorating
28 routes; GET (pages, assets, whoami, KEV Watch reads) is never limited.

Client IP: Render sits behind Cloudflare on BOTH hostnames (onrender.com and
the custom domain). Measured 2026-09-30 with a forged header:
    X-Forwarded-For: "<client-sent>, <real client>, <cloudflare edge>"
so the first entry is attacker-controlled and the second-to-last is the
address Cloudflare saw. We key on that one; with a single entry we use it,
with no header we fall back to the socket peer.

Mechanism: in-process sliding windows (dict of deques, one lock), same as the
The Backroom magic-link limiter. Counters reset on deploy and are not shared
between instances - acceptable while Render runs one instance.
Fail-open on a limiter bug: a broken counter must not take the tools down
(unlike login e-mail, a missed limit here costs CPU, not a victim's inbox).
"""

import hashlib
import threading
import time
from collections import deque
from typing import Callable, Dict, Optional, Tuple

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

# Tests switch this off suite-wide (tests/conftest.py); limiter tests turn it on.
ENABLED = True

# (max requests, window seconds) per client IP, any POST endpoint
DEFAULT_LIMITS = (
    (60, 60),          # 60 / min: well above a human clicking through tools
    (600, 60 * 60),    # 600 / h: caps sustained scripted load
)
# Extra, stricter limits per path (on top of DEFAULT_LIMITS)
PATH_LIMITS = {
    "/api/subscribe": ((5, 15 * 60),),  # each call hits MailerLite
}
MAX_KEYS_BEFORE_SWEEP = 10_000

LIMIT_MESSAGE = "Too many requests. Try again later."


def _short_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def client_ip(request: Request) -> str:
    """Address Cloudflare saw (second-to-last X-Forwarded-For entry)."""
    parts = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
    if len(parts) >= 2:
        return parts[-2]
    if parts:
        return parts[0]
    if request.client:
        return request.client.host
    return "unknown"


class SlidingWindowLimiter:
    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._hits: Dict[str, deque] = {}
        self._lock = threading.Lock()

    def _sweep(self, now: float) -> None:
        horizon = now - max(w for _, w in DEFAULT_LIMITS)
        for key in list(self._hits):
            q = self._hits[key]
            while q and q[0] <= horizon:
                q.popleft()
            if not q:
                del self._hits[key]

    @staticmethod
    def _over(q: Optional[deque], limits, now: float) -> Optional[Tuple[int, int]]:
        if not q:
            return None
        for max_count, window in limits:
            cutoff = now - window
            if sum(1 for t in q if t > cutoff) >= max_count:
                return max_count, window
        return None

    def check_and_record(self, keys_limits) -> Optional[Tuple[int, int]]:
        """None = allowed (and recorded); else the (max, window) that fired."""
        now = self._clock()
        with self._lock:
            if len(self._hits) > MAX_KEYS_BEFORE_SWEEP:
                self._sweep(now)
            for key, limits in keys_limits:
                q = self._hits.get(key)
                if q:
                    horizon = now - max(w for _, w in limits)
                    while q and q[0] <= horizon:
                        q.popleft()
                hit = self._over(q, limits, now)
                if hit:
                    return hit
            for key, _ in keys_limits:
                self._hits.setdefault(key, deque()).append(now)
        return None


limiter = SlidingWindowLimiter()


def _label(window: int) -> str:
    return f"{window // 3600}h" if window % 3600 == 0 else f"{window // 60}m"


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if not ENABLED or request.method != "POST":
            return await call_next(request)
        path = request.url.path
        try:
            ip = client_ip(request)
            keys = [("ip:" + ip, DEFAULT_LIMITS)]
            if path in PATH_LIMITS:
                keys.append(("ip:" + ip + "|" + path, PATH_LIMITS[path]))
            hit = limiter.check_and_record(keys)
        except Exception as e:
            print(f"rate limiter error, allowing: {type(e).__name__}")
            return await call_next(request)
        if hit:
            print(f"INFO rate limit hit: path={path} limit={hit[0]}/{_label(hit[1])} "
                  f"ip={_short_hash(ip)}")
            return JSONResponse(
                {"detail": LIMIT_MESSAGE},
                status_code=429,
                headers={"Retry-After": str(hit[1])},
            )
        return await call_next(request)
