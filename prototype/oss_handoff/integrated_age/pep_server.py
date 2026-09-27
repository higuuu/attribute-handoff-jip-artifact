"""Loopback-only source PEP for the prospective integrated age experiment."""

from __future__ import annotations

import argparse
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from prototype.oss_handoff.crypto_utils import public_jwk, verify_jwt
from prototype.oss_handoff.http_utils import request_json
from prototype.oss_handoff.integrated_age.core import KEY_ID, issue_bound_assertion
from prototype.oss_handoff.integrated_age.prepare import RUNTIME_DIR
from prototype.oss_handoff.two_host.common import load_json
from prototype.oss_handoff.two_host.pep import evaluate_handoff
from prototype.oss_handoff.two_host.pep_server import MAX_REQUEST_BYTES, Handler as BaseHandler, Server as BaseServer, policy_check


USERNAME = "synthetic-age-user"
PASSWORD = "synthetic-local-only"


def keycloak_jwks(config: dict[str, Any]) -> dict[str, Any]:
    response, value = request_json(
        f"{config['issuer']}/protocol/openid-connect/certs",
        timeout=5,
        allow_error=True,
    )
    if response.status != 200 or not isinstance(value, dict):
        raise RuntimeError("source JWKS unavailable")
    return value


def request_source_token(config: dict[str, Any], route: str) -> str:
    client = config["issuer_clients"][route]
    response, value = request_json(
        f"{config['issuer']}/protocol/openid-connect/token",
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
    if response.status != 200 or not isinstance(value, dict) or not isinstance(value.get("access_token"), str):
        raise RuntimeError("Keycloak token issuance failed")
    return value["access_token"]


class Server(BaseServer):
    def __init__(self, address: tuple[str, int], handler: type[BaseHandler], *, config_path: Path, token_path: Path, events_path: Path):
        super().__init__(address, handler, config_path=config_path, token_path=token_path, events_path=events_path)
        self.signing_key = ec.generate_private_key(ec.SECP256R1())
        self.subject_salt = os.urandom(32)
        self.public_jwk = {**public_jwk(self.signing_key), "kid": KEY_ID}


class Handler(BaseHandler):
    server: Server

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            self._send(200, {"status": "ok", "service": "integrated-age-pep"})
            return
        if not self._authorized():
            self._send(401, {"error": "UNAUTHORIZED"})
            return
        config = load_json(self.server.config_path)
        if self.path == "/v1/config":
            self._send(200, {key: config[key] for key in (
                "phase", "enforcement_mode", "audience", "purpose", "issuer",
                "policy_model_id", "allowed_routes", "source_host_sha256",
                "implementation_commit", "realm_sha256",
            )})
        elif self.path == "/v1/jwks":
            try:
                self._send(200, keycloak_jwks(config))
            except Exception:
                self._send(502, {"error": "JWKS_UNAVAILABLE"})
        elif self.path == "/v1/live-age-jwk":
            self._send(200, {"keys": [self.server.public_jwk]})
        else:
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
        if not 0 < length <= MAX_REQUEST_BYTES:
            self._send(413, {"error": "INVALID_REQUEST_SIZE"})
            return
        raw = self.rfile.read(length)
        try:
            request = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send(400, {"error": "INVALID_JSON"})
            return
        if not isinstance(request, dict):
            self._send(400, {"error": "INVALID_JSON_TYPE"})
            return
        if request.get("route") not in {"R", "O_live"}:
            self._send(400, {"error": "UNSUPPORTED_ROUTE"})
            return
        config = load_json(self.server.config_path)

        def issue_evidence(value: dict[str, Any], route: str) -> tuple[str, dict[str, Any], float]:
            started = time.perf_counter()
            source_token = request_source_token(value, route)
            jwks = keycloak_jwks(value)
            if route == "R":
                claims = verify_jwt(
                    source_token, jwks, audience=str(value["audience"]), issuer=str(value["issuer"])
                )
                return source_token, claims, (time.perf_counter() - started) * 1000
            if route != "O_live":
                raise ValueError("unsupported route in integrated experiment")
            issued_at = int(time.time())
            assertion, claims = issue_bound_assertion(
                source_token,
                jwks,
                source_issuer=str(value["issuer"]),
                signing_key=self.server.signing_key,
                subject_salt=self.server.subject_salt,
                as_of=datetime.fromtimestamp(issued_at, timezone.utc).date(),
                issued_at=issued_at,
                nonce=str(request["request_id"]),
            )
            return assertion, claims, (time.perf_counter() - started) * 1000

        result = evaluate_handoff(
            request,
            config=config,
            request_bytes=len(raw),
            policy_check=policy_check,
            issue_evidence=issue_evidence,
        )
        self._append_event(result.event)
        self._send(result.status, result.body)


def main() -> None:
    parser = argparse.ArgumentParser(description="Loopback-only integrated age PEP")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18882)
    parser.add_argument("--config", type=Path, default=RUNTIME_DIR / "pep-config.json")
    parser.add_argument("--token-file", type=Path, default=RUNTIME_DIR / "api-token")
    parser.add_argument("--events", type=Path, default=RUNTIME_DIR / "pep-events.jsonl")
    args = parser.parse_args()
    if args.host not in {"127.0.0.1", "::1", "localhost"}:
        raise SystemExit("refusing non-loopback bind")
    if not args.config.exists() or not args.token_file.exists():
        raise SystemExit("first run integrated_age.prepare setup")
    if args.token_file.stat().st_mode & 0o077:
        raise SystemExit("API token file must be mode 0600")
    token = args.token_file.read_text().strip()
    if len(token) < 32:
        raise SystemExit("invalid API token")
    server = Server((args.host, args.port), Handler, config_path=args.config, token_path=args.token_file, events_path=args.events)
    print(json.dumps({"listening": f"http://{args.host}:{args.port}", "key_ephemeral": True}), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
