"""Fixed-calendar control using an actual Keycloak source token."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from datetime import date
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

from prototype.oss_handoff.crypto_utils import public_jwk
from prototype.oss_handoff.integrated_age.core import KEY_ID, issue_bound_assertion, verify_bound_assertion
from prototype.oss_handoff.integrated_age.pep_server import keycloak_jwks, request_source_token
from prototype.oss_handoff.integrated_age.prepare import RUNTIME_DIR
from prototype.oss_handoff.two_host.common import load_json, write_json_atomic


CASES = (
    ("before_18th_birthday", date(2026, 9, 26), False),
    ("on_18th_birthday", date(2026, 9, 27), True),
    ("after_18th_birthday", date(2026, 9, 28), True),
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=RUNTIME_DIR / "pep-config.json")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("refusing to overwrite existing result")
    config = load_json(args.config)
    source_token = request_source_token(config, "O_live")
    jwks = keycloak_jwks(config)
    key = ec.generate_private_key(ec.SECP256R1())
    public = {**public_jwk(key), "kid": KEY_ID}
    salt = os.urandom(32)
    now = int(time.time())
    results = []
    for label, as_of, expected in CASES:
        nonce = f"boundary-{label}"
        assertion, _ = issue_bound_assertion(
            source_token, jwks, source_issuer=config["issuer"], signing_key=key,
            subject_salt=salt, as_of=as_of, issued_at=now, nonce=nonce,
        )
        claims = verify_bound_assertion(assertion, public, nonce=nonce, now=now)
        results.append({
            "case": label,
            "expected": expected,
            "observed": claims["age_over_18"],
            "disclosure_fields": [field for field in ("birth_date", "age_over_18") if field in claims],
            "signature_verified": True,
            "pass": claims["age_over_18"] is expected and "birth_date" not in claims,
        })
    result = {
        "experiment": "integrated-live-age-fixed-calendar-control",
        "actual_keycloak_source_token_used": True,
        "same_host_adapter_control_not_remote_pep": True,
        "realm_sha256": config["realm_sha256"],
        "cases": results,
        "all_expectations_passed": all(case["pass"] for case in results),
    }
    write_json_atomic(args.output, result)
    print(json.dumps({"output": str(args.output), "sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(), "all_expectations_passed": result["all_expectations_passed"]}))
    if not result["all_expectations_passed"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
