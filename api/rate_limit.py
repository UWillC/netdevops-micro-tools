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

Retention (2026-10-18, privacy policy "kept in memory for up to about an
hour"): every SWEEP_INTERVAL seconds a background thread (started at app
startup) drops request times older than the longest window (1 h) and deletes
addresses left with none. The same sweep also runs inline on a POST when it is
due, so retention holds even if the thread is not running. Worst case an
address stays in memory for 1 h + SWEEP_INTERVAL after its last request.
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
    "/api/beta/token": ((5, 15 * 60),),  # read-only backfill lookup (BETA-A)
    # ACL-01.3 (@ciso W1, 2026-10-28): ~0.4 s CPU locally (~1 s on Render) and
    # up to ~30x response amplification per call; the hourly cap bounds transfer.
    "/tools/acl/analyze": ((10, 60), (120, 3600)),
}
MAX_KEYS_BEFORE_SWEEP = 10_000
SWEEP_INTERVAL = 5 * 60  # seconds between retention sweeps of inactive addresses
# Longest window over all limits: nothing older is ever needed for a decision.
RETENTION_SECONDS = max(
    w for limits in (DEFAULT_LIMITS, *PATH_LIMITS.values()) for _, w in limits
)

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
        self._last_sweep = clock()

    def _sweep(self, now: float) -> None:
        horizon = now - RETENTION_SECONDS
        for key in list(self._hits):
            q = self._hits[key]
            while q and q[0] <= horizon:
                q.popleft()
            if not q:
                del self._hits[key]
        self._last_sweep = now

    def sweep_if_due(self) -> bool:
        """Retention sweep when SWEEP_INTERVAL has passed; True if it ran."""
        now = self._clock()
        with self._lock:
            if now - self._last_sweep < SWEEP_INTERVAL:
                return False
            self._sweep(now)
            return True

    def key_count(self) -> int:
        with self._lock:
            return len(self._hits)

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
            if (len(self._hits) > MAX_KEYS_BEFORE_SWEEP
                    or now - self._last_sweep >= SWEEP_INTERVAL):
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

_sweeper_started = False
_sweeper_lock = threading.Lock()


def _sweeper_loop(sleep: Callable[[float], None] = time.sleep) -> None:
    while True:
        sleep(SWEEP_INTERVAL)
        try:
            limiter.sweep_if_due()  # module global: tests may swap the limiter
        except Exception as e:  # never let the retention thread die silently
            print(f"rate limiter sweep error: {type(e).__name__}")


def start_sweeper() -> bool:
    """Start the background retention thread once per process; True if started now."""
    global _sweeper_started
    with _sweeper_lock:
        if _sweeper_started:
            return False
        threading.Thread(target=_sweeper_loop, name="rate-limit-sweeper", daemon=True).start()
        _sweeper_started = True
        return True


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
