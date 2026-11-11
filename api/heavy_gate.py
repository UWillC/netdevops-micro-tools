"""
One heavy request at a time, whoever sends it (WEBSEC-01, @ciso W19).

The per-IP limits do not bound parallel work, and memory adds up per request:
Config Drift at the body limit peaks near 390 MB, three at once near 930 MB on
one uvicorn process. The tools in PASTE_PATHS therefore share one slot; a request
that finds it taken gets 503 with Retry-After at once, without being parsed.

The body is read before the slot is taken, so a slow upload cannot hold it. The
slot is freed when the response starts: the work is done by then, and a slow
reader must not hold it either.
"""

import threading

from fastapi import HTTPException
from starlette.responses import JSONResponse

from api.body_limit import PASTE_PATHS

RETRY_AFTER_SECONDS = 5
BUSY_MESSAGE = "Another large paste is being processed. Please try again in a few seconds."
CLIENT_LEFT_MESSAGE = "The request body was not received in full."

_slot = threading.Lock()


class HeavyGateMiddleware:
    """Plain ASGI, inside BodyLimitMiddleware: reading the body here is what counts it."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] != "POST" or scope["path"] not in PASTE_PATHS:
            await self.app(scope, receive, send)
            return

        chunks = []
        while True:
            try:
                message = await receive()
            except HTTPException as exc:  # the body limit, raised while counting
                response = JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
                await response(scope, receive, send)
                return
            if message["type"] != "http.request":
                # The client left before sending the whole body. Answer anyway (W30):
                # a bare return made the outer middleware log "No response returned"
                # with a full traceback. Nobody reads this 400; the slot is never taken.
                response = JSONResponse({"detail": CLIENT_LEFT_MESSAGE}, status_code=400)
                await response(scope, receive, send)
                return
            chunks.append(message.get("body", b""))
            if not message.get("more_body", False):
                break

        # Join before acquire (W31): a MemoryError here must not leave the slot taken.
        body = b"".join(chunks)
        del chunks

        if not _slot.acquire(blocking=False):
            response = JSONResponse(
                {"detail": BUSY_MESSAGE},
                status_code=503,
                headers={"Retry-After": str(RETRY_AFTER_SECONDS)},
            )
            await response(scope, receive, send)
            return

        held = True

        def release():
            nonlocal held
            if held:
                held = False
                _slot.release()

        replayed = False

        async def replay():
            nonlocal replayed, body
            if replayed:
                return await receive()
            replayed = True
            message = {"type": "http.request", "body": body, "more_body": False}
            body = b""
            return message

        async def send_and_release(message):
            if message["type"] == "http.response.start":
                release()
            await send(message)

        try:
            await self.app(scope, replay, send_and_release)
        finally:
            release()
