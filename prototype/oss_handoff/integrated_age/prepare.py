"""Create an isolated synthetic realm and source-side PEP configuration."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path

from prototype.oss_handoff.two_host.common import AUDIENCE, PURPOSE, RUNTIME, USER, host_fingerprint, repository_commit, write_json_atomic
from prototype.oss_handoff.two_host.macmini_control import create_policy, ensure_token
from prototype.oss_handoff.http_utils import wait_json


ROOT = Path(__file__).resolve().parents[3]
RUNTIME_DIR = RUNTIME.parent / "integrated-age"
SOURCE_REALM = ROOT / "prototype/oss_handoff/live_age/realm.json"


def prepare_realm(source: Path, target: Path) -> str:
    realm = json.loads(source.read_text())
    if realm.get("realm") != "live-age" or len(realm.get("clients", [])) != 1:
        raise ValueError("unexpected live-age fixture")
    raw_client = copy.deepcopy(realm["clients"][0])
    raw_client["clientId"] = "region-b-raw"
    raw_client["secret"] = "synthetic-raw-only"
    for mapper in raw_client["protocolMappers"]:
        if mapper["name"] == "internal-adapter-audience":
            mapper["name"] = "region-b-raw-audience"
            mapper["config"]["included.client.audience"] = AUDIENCE
    realm["clients"].append(raw_client)
    if "age_over_18" in realm["users"][0].get("attributes", {}):
        raise ValueError("fixture must have no stored age predicate")
    write_json_atomic(target, realm)
    return hashlib.sha256(target.read_bytes()).hexdigest()


def setup(args: argparse.Namespace) -> None:
    if not args.realm.exists():
        raise SystemExit("first run prepare-realm, then start the isolated compose stack")
    wait_json(f"{args.source_url}/realms/live-age", timeout_seconds=180)
    wait_json(f"{args.policy_url}/healthz", timeout_seconds=60)
    policy = create_policy(args.policy_url, allow_raw=False)
    ensure_token(args.token_file)
    config = {
        "schema_version": 1,
        "experiment": "integrated-live-age",
        "phase": "baseline",
        "enforcement_mode": "observe-only",
        "region_a_url": args.source_url,
        "issuer": f"{args.source_url}/realms/live-age",
        "policy_url": args.policy_url,
        "store_id": policy["store_id"],
        "policy_model_id": policy["policy_model_id"],
        "allowed_routes": policy["allowed_routes"],
        "policy_user": USER,
        "audience": AUDIENCE,
        "purpose": PURPOSE,
        "source_host_sha256": host_fingerprint(),
        "implementation_commit": repository_commit(),
        "realm_sha256": hashlib.sha256(args.realm.read_bytes()).hexdigest(),
        "issuer_clients": {
            "R": {"client_id": "region-b-raw", "client_secret": "synthetic-raw-only"},
            "O_live": {"client_id": "source-internal-adapter", "client_secret": "synthetic-adapter-only"},
        },
    }
    write_json_atomic(args.config, config)
    print(json.dumps({key: config[key] for key in ("phase", "enforcement_mode", "policy_model_id", "implementation_commit", "realm_sha256")}, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    realm = sub.add_parser("prepare-realm")
    realm.add_argument("--source", type=Path, default=SOURCE_REALM)
    realm.add_argument("--output", type=Path, default=RUNTIME_DIR / "realm.json")
    setup_parser = sub.add_parser("setup")
    setup_parser.add_argument("--source-url", default="http://127.0.0.1:18880")
    setup_parser.add_argument("--policy-url", default="http://127.0.0.1:18881")
    setup_parser.add_argument("--realm", type=Path, default=RUNTIME_DIR / "realm.json")
    setup_parser.add_argument("--config", type=Path, default=RUNTIME_DIR / "pep-config.json")
    setup_parser.add_argument("--token-file", type=Path, default=RUNTIME_DIR / "api-token")
    args = parser.parse_args()
    if args.command == "prepare-realm":
        print(json.dumps({"realm_sha256": prepare_realm(args.source, args.output)}, sort_keys=True))
    else:
        setup(args)


if __name__ == "__main__":
    main()
