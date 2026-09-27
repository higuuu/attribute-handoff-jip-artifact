from __future__ import annotations

import argparse
import hmac
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from prototype.oss_handoff.crypto_utils import decode_jwt
from prototype.oss_handoff.http_utils import request_json

from .common import CONFIG_PATH, EVENTS_PATH, TOKEN_PATH, canonical_json, load_json
from .pep import evaluate_handoff


MAX_REQUEST_BYTES = 64 * 1024
USERNAME = "region-a-user"
PASSWORD = "local-user-only"


def policy_check(config: dict[str, Any], route: str) -> tuple[bool, float]:
    started = time.perf_counter()
    response, value = request_json(
        f"{config['policy_url']}/stores/{config['store_id']}/check",
        method="POST",
        payload={
            "tuple_key": {"user": config["policy_user"], "relation": "allowed", "object": f"route:{route}"},
            "authorization_model_id": config["policy_model_id"],
        },
        timeout=5,
        allow_error=True,
    )
    latency_ms = (time.perf_counter() - started) * 1000
    if response.status != 200 or not isinstance(value, dict):
        raise RuntimeError("OpenFGA check failed")
    return bool(value.get("allowed")), latency_ms


def issue_evidence(config: dict[str, Any], route: str) -> tuple[str, dict[str, Any], float]:
    client = config["issuer_clients"][route]
    started = time.perf_counter()
    response, value = request_json(
        f"{config['region_a_url']}/realms/region-a/protocol/openid-connect/token",
        method="POST",
        form={
            "grant_type": "password",
            "client_id": client["client_id"],
            "client_secret": client["client_secret"],
            "username": USERNAME,
            "password": PASSWORD,
            "scope": "openid",
        },
        timeout=10,
        allow_error=True,
    )
    latency_ms = (time.perf_counter() - started) * 1000
    if response.status != 200 or not isinstance(value, dict) or not isinstance(value.get("access_token"), str):
        raise RuntimeError("Keycloak token issuance failed")
    evidence = value["access_token"]
    _, claims = decode_jwt(evidence)
    return evidence, claims, latency_ms


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], handler, *, config_path: Path, token_path: Path, events_path: Path):  # noqa: ANN001
        super().__init__(address, handler)
        self.config_path = config_path
        self.token_path = token_path
        self.events_path = events_path


class Handler(BaseHTTPRequestHandler):
    server: Server

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send(self, status: int, value: dict[str, Any]) -> None:
        body = canonical_json(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        expected = self.server.token_path.read_text().strip()
        supplied = self.headers.get("Authorization", "")
        return supplied.startswith("Bearer ") and hmac.compare_digest(supplied[7:], expected)

    def _append_event(self, event: dict[str, Any]) -> None:
        self.server.events_path.parent.mkdir(parents=True, exist_ok=True)
        record = {"recorded_at_unix": int(time.time()), **event}
        descriptor = os.open(
            self.server.events_path,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            0o600,
        )
        with os.fdopen(descriptor, "a") as handle:
            handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            self._send(200, {"status": "ok", "service": "two-host-handoff-pep"})
            return
        if not self._authorized():
            self._send(401, {"error": "UNAUTHORIZED"})
            return
        config = load_json(self.server.config_path)
        if self.path == "/v1/config":
            self._send(
                200,
                {
                    "schema_version": 1,
                    "phase": config["phase"],
                    "enforcement_mode": config["enforcement_mode"],
                    "audience": config["audience"],
                    "purpose": config["purpose"],
                    "issuer": config["issuer"],
                    "policy_model_id": config["policy_model_id"],
                    "allowed_routes": config["allowed_routes"],
                    "source_host_sha256": config["source_host_sha256"],
                    "implementation_commit": config["implementation_commit"],
                },
            )
            return
        if self.path == "/v1/jwks":
            response, value = request_json(
                f"{config['region_a_url']}/realms/region-a/protocol/openid-connect/certs",
                timeout=5,
                allow_error=True,
            )
            if response.status != 200 or not isinstance(value, dict):
                self._send(502, {"error": "JWKS_UNAVAILABLE"})
                return
            self._send(200, value)
            return
        self._send(404, {"error": "NOT_FOUND"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/v1/handoff":
            self._send(404, {"error": "NOT_FOUND"})
            return
        if not self._authorized():
            self._send(401, {"error": "UNAUTHORIZED"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send(400, {"error": "INVALID_CONTENT_LENGTH"})
            return
        if length <= 0 or length > MAX_REQUEST_BYTES:
            self._send(413, {"error": "INVALID_REQUEST_SIZE"})
            return
        raw = self.rfile.read(length)
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send(400, {"error": "INVALID_JSON"})
            return
        if not isinstance(value, dict):
            self._send(400, {"error": "INVALID_JSON_TYPE"})
            return
        config = load_json(self.server.config_path)
        result = evaluate_handoff(
            value,
            config=config,
            request_bytes=len(raw),
            policy_check=policy_check,
            issue_evidence=issue_evidence,
        )
        self._append_event(result.event)
        self._send(result.status, result.body)


def main() -> None:
    parser = argparse.ArgumentParser(description="Tailnet-only source-side handoff PEP")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--config", type=Path, default=CONFIG_PATH)
    parser.add_argument("--token-file", type=Path, default=TOKEN_PATH)
    parser.add_argument("--events", type=Path, default=EVENTS_PATH)
    args = parser.parse_args()
    if args.host not in {"127.0.0.1", "::1", "localhost"}:
        raise SystemExit("refusing non-loopback bind; expose with `tailscale serve`, never Funnel")
    if not args.config.exists() or not args.token_file.exists():
        raise SystemExit("run macmini_control setup before starting the PEP")
    if args.token_file.stat().st_mode & 0o077:
        raise SystemExit(f"token file permissions must be 0600: {args.token_file}")
    token = args.token_file.read_text().strip()
    if len(token) < 32:
        raise SystemExit("token file must contain at least 32 characters")
    server = Server((args.host, args.port), Handler, config_path=args.config, token_path=args.token_file, events_path=args.events)
    print(json.dumps({"listening": f"http://{args.host}:{args.port}", "tailscale_only": True}))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
