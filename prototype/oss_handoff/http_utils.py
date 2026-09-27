from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http.cookiejar import CookieJar
from typing import Any


class HttpFailure(RuntimeError):
    def __init__(self, status: int | None, url: str, body: str):
        super().__init__(f"HTTP failure status={status} url={url}: {body[:300]}")
        self.status = status
        self.url = url
        self.body = body


@dataclass(frozen=True)
class Response:
    status: int
    url: str
    headers: dict[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body.decode())

    def text(self) -> str:
        return self.body.decode(errors="replace")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def opener(*, redirects: bool = True) -> urllib.request.OpenerDirector:
    handlers: list[Any] = [urllib.request.HTTPCookieProcessor(CookieJar())]
    if not redirects:
        handlers.append(NoRedirect())
    return urllib.request.build_opener(*handlers)


def request(
    url: str,
    *,
    method: str = "GET",
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 10,
    client: urllib.request.OpenerDirector | None = None,
    allow_error: bool = False,
) -> Response:
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    active = client or urllib.request.build_opener()
    try:
        with active.open(req, timeout=timeout) as raw:
            return Response(raw.status, raw.geturl(), dict(raw.headers.items()), raw.read())
    except urllib.error.HTTPError as exc:
        body = exc.read()
        response = Response(exc.code, exc.geturl(), dict(exc.headers.items()), body)
        if allow_error or 300 <= exc.code < 400:
            return response
        raise HttpFailure(exc.code, exc.geturl(), body.decode(errors="replace")) from exc
    except urllib.error.URLError as exc:
        raise HttpFailure(None, url, str(exc.reason)) from exc


def request_json(
    url: str,
    *,
    method: str = "GET",
    payload: Any | None = None,
    form: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 10,
    allow_error: bool = False,
) -> tuple[Response, Any]:
    actual_headers = dict(headers or {})
    data = None
    if payload is not None:
        data = json.dumps(payload).encode()
        actual_headers.setdefault("Content-Type", "application/json")
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        actual_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    response = request(
        url,
        method=method,
        data=data,
        headers=actual_headers,
        timeout=timeout,
        allow_error=allow_error,
    )
    try:
        decoded = response.json() if response.body else None
    except json.JSONDecodeError:
        decoded = None
    return response, decoded


def wait_json(url: str, *, timeout_seconds: int = 120) -> Any:
    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            response, value = request_json(url, timeout=3, allow_error=True)
            if 200 <= response.status < 300 and value is not None:
                return value
        except Exception as exc:  # startup polling intentionally keeps the last error
            last_error = exc
        time.sleep(1)
    raise RuntimeError(f"timed out waiting for {url}: {last_error}")
