import json
import socket
import urllib.error
import urllib.request
from typing import Any


class HttpClientError(Exception):
    """Base exception for HTTP client errors."""
    pass


class HttpTimeoutError(HttpClientError):
    """Request timed out."""
    pass


class HttpConnectionError(HttpClientError):
    """Could not connect to server."""
    pass


class HttpResponseError(HttpClientError):
    """Server returned an error response."""
    pass


def http_get_json(url: str, timeout_seconds: int = 10) -> Any:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "netdevops-micro-tools/0.3.4 (+https://github.com/UWillC/netdevops-micro-tools)"
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw)
    except socket.timeout:
        raise HttpTimeoutError(f"Request timed out after {timeout_seconds}s: {url}")
    except urllib.error.URLError as e:
        if isinstance(e.reason, socket.timeout):
            raise HttpTimeoutError(f"Request timed out after {timeout_seconds}s: {url}")
        raise HttpConnectionError(f"Connection failed: {e.reason}")
    except urllib.error.HTTPError as e:
        raise HttpResponseError(f"HTTP {e.code}: {e.reason}")
    except json.JSONDecodeError as e:
        raise HttpResponseError(f"Invalid JSON response: {e}")
