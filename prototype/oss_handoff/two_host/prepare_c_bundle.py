from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

from prototype.oss_handoff import run_experiment

from .common import AUDIENCE, RUNTIME, host_fingerprint, repository_commit, write_json_atomic


MINIMUM_CREDENTIAL_LIFETIME_SECONDS = 3600


def main() -> None:
    parser = argparse.ArgumentParser(description="Issue a fresh synthetic C credential for the Air verifier")
    parser.add_argument("--region-a", default="http://127.0.0.1:18080")
    parser.add_argument("--output", type=Path, default=RUNTIME / "air-c-bundle.json")
    args = parser.parse_args()

    run_experiment.REGION_A = args.region_a
    jwks = run_experiment.keycloak_jwks(args.region_a, run_experiment.REALM_A)
    entitlement = run_experiment.ensure_user_credential()
    state = run_experiment.issue_credential(jwks)
    issuer_payload = state["issuer_payload"]
    issued_at = issuer_payload.get("iat")
    expires_at = issuer_payload.get("exp")
    expected_issuer = f"{args.region_a}/realms/{run_experiment.REALM_A}"
    if issuer_payload.get("iss") != expected_issuer:
        raise RuntimeError("issued C credential has an unexpected issuer")
    if not isinstance(issued_at, int) or not isinstance(expires_at, int):
        raise RuntimeError("issued C credential must contain integer iat and exp claims")
    lifetime_seconds = expires_at - issued_at
    if lifetime_seconds < MINIMUM_CREDENTIAL_LIFETIME_SECONDS:
        raise RuntimeError(
            f"issued C credential lifetime is {lifetime_seconds}s; "
            f"at least {MINIMUM_CREDENTIAL_LIFETIME_SECONDS}s is required"
        )
    bundle = {
        "schema_version": 1,
        "synthetic_data_only": True,
        "audience": AUDIENCE,
        "issuer": expected_issuer,
        "credential": state["credential"],
        "holder_private_key": state["holder_private_key"],
        "holder_public_jwk": state["holder_public_jwk"],
        "jwks": jwks,
        "credential_configuration_id": entitlement.get("credentialConfigurationId"),
        "credential_issued_at": issued_at,
        "credential_expires_at": expires_at,
        "credential_lifetime_seconds": lifetime_seconds,
        "source_host_sha256": host_fingerprint(),
        "implementation_commit": repository_commit(),
    }
    write_json_atomic(args.output, bundle)
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    os.chmod(args.output, 0o600)
    print(json.dumps({"output": str(args.output), "sha256": digest, "contains_synthetic_secret": True}))


if __name__ == "__main__":
    main()
