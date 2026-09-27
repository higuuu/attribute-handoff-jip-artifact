from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import stat
from pathlib import Path
from typing import Any

from prototype.oss_handoff.http_utils import request_json, wait_json

from .common import (
    AUDIENCE,
    CONFIG_PATH,
    PURPOSE,
    TOKEN_PATH,
    USER,
    host_fingerprint,
    load_json,
    repository_commit,
    write_json_atomic,
)


DEFAULT_REGION_A = "http://127.0.0.1:18080"
DEFAULT_POLICY = "http://127.0.0.1:18081"


def ensure_token(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        value = path.read_text().strip()
        if len(value) >= 32 and re.fullmatch(r"[A-Za-z0-9_-]+", value):
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
            return
    path.write_text(secrets.token_urlsafe(32) + "\n")
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def create_policy(policy_url: str, *, allow_raw: bool) -> dict[str, Any]:
    response, store = request_json(
        f"{policy_url}/stores",
        method="POST",
        payload={"name": "jip-two-host-handoff"},
        allow_error=True,
    )
    if response.status not in {200, 201} or not isinstance(store, dict):
        raise RuntimeError(f"OpenFGA store creation failed: {response.status}")
    store_id = str(store["id"])
    response, model = request_json(
        f"{policy_url}/stores/{store_id}/authorization-models",
        method="POST",
        payload={
            "schema_version": "1.1",
            "type_definitions": [
                {"type": "user", "relations": {}, "metadata": {"relations": {}}},
                {
                    "type": "route",
                    "relations": {"allowed": {"this": {}}},
                    "metadata": {
                        "relations": {"allowed": {"directly_related_user_types": [{"type": "user"}]}}
                    },
                },
            ],
        },
        allow_error=True,
    )
    if response.status not in {200, 201} or not isinstance(model, dict):
        raise RuntimeError(f"OpenFGA model creation failed: {response.status}")
    model_id = str(model["authorization_model_id"])
    routes = ["O", "C"] + (["R"] if allow_raw else [])
    response, _ = request_json(
        f"{policy_url}/stores/{store_id}/write",
        method="POST",
        payload={
            "writes": {
                "tuple_keys": [
                    {"user": USER, "relation": "allowed", "object": f"route:{route}"}
                    for route in routes
                ]
            },
            "authorization_model_id": model_id,
        },
        allow_error=True,
    )
    if response.status not in {200, 201, 204}:
        raise RuntimeError(f"OpenFGA tuple write failed: {response.status}")
    return {"store_id": store_id, "policy_model_id": model_id, "allowed_routes": routes}


def setup(args: argparse.Namespace) -> None:
    wait_json(f"{args.region_a}/realms/region-a", timeout_seconds=180)
    wait_json(f"{args.policy}/healthz", timeout_seconds=60)
    policy = create_policy(args.policy, allow_raw=args.allow_raw)
    ensure_token(args.token_file)
    config = {
        "schema_version": 1,
        "phase": args.phase,
        "enforcement_mode": args.mode,
        "region_a_url": args.region_a,
        "issuer": f"{args.region_a}/realms/region-a",
        "policy_url": args.policy,
        "store_id": policy["store_id"],
        "policy_model_id": policy["policy_model_id"],
        "allowed_routes": policy["allowed_routes"],
        "policy_user": USER,
        "audience": AUDIENCE,
        "purpose": PURPOSE,
        "source_host_sha256": host_fingerprint(),
        "implementation_commit": repository_commit(),
        "issuer_clients": {
            "R": {"client_id": "region-b-raw", "client_secret": "local-raw-only"},
            "O*": {"client_id": "region-b-derived", "client_secret": "local-derived-only"},
        },
    }
    write_json_atomic(args.config, config)
    print(json.dumps(public_config(config), indent=2, sort_keys=True))


def public_config(config: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": config["schema_version"],
        "phase": config["phase"],
        "enforcement_mode": config["enforcement_mode"],
        "audience": config["audience"],
        "purpose": config["purpose"],
        "issuer": config["issuer"],
        "policy_model_id": config["policy_model_id"],
        "allowed_routes": config["allowed_routes"],
        "source_host_sha256": config["source_host_sha256"],
        "implementation_commit": config["implementation_commit"],
    }


def set_mode(args: argparse.Namespace) -> None:
    config = load_json(args.config)
    config["enforcement_mode"] = args.mode
    config["phase"] = args.phase
    write_json_atomic(args.config, config)
    print(json.dumps(public_config(config), indent=2, sort_keys=True))


def show(args: argparse.Namespace) -> None:
    print(json.dumps(public_config(load_json(args.config)), indent=2, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare the Mac mini side of the two-host experiment")
    parser.set_defaults(func=None)
    subparsers = parser.add_subparsers(dest="command")

    setup_parser = subparsers.add_parser("setup")
    setup_parser.add_argument("--allow-raw", action="store_true")
    setup_parser.add_argument("--mode", choices=["observe-only", "enforce"], default="observe-only")
    setup_parser.add_argument("--phase", default="baseline-deny-raw")
    setup_parser.add_argument("--region-a", default=DEFAULT_REGION_A)
    setup_parser.add_argument("--policy", default=DEFAULT_POLICY)
    setup_parser.add_argument("--config", type=Path, default=CONFIG_PATH)
    setup_parser.add_argument("--token-file", type=Path, default=TOKEN_PATH)
    setup_parser.set_defaults(func=setup)

    mode_parser = subparsers.add_parser("set-mode")
    mode_parser.add_argument("mode", choices=["observe-only", "enforce"])
    mode_parser.add_argument("--phase", required=True)
    mode_parser.add_argument("--config", type=Path, default=CONFIG_PATH)
    mode_parser.set_defaults(func=set_mode)

    show_parser = subparsers.add_parser("show")
    show_parser.add_argument("--config", type=Path, default=CONFIG_PATH)
    show_parser.set_defaults(func=show)

    args = parser.parse_args()
    if args.func is None:
        parser.error("a command is required")
    args.func(args)


if __name__ == "__main__":
    main()
