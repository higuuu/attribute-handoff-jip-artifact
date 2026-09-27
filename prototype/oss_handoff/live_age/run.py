"""Execute the prospective O_live test against loopback Keycloak."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import date
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec

from prototype.oss_handoff.crypto_utils import public_jwk, verify_jwt
from prototype.oss_handoff.live_age.core import (
    ASSERTION_FIELDS,
    SOURCE_AUDIENCE,
    issue_for_verified_source_token,
    over_18,
)
from prototype.oss_handoff.two_host.common import repository_commit, write_json_atomic


ROOT = Path(__file__).resolve().parents[3]
REALM = Path(__file__).with_name("realm.json")


def get_json(url: str, data: bytes | None = None) -> dict[str, Any]:
    request = urllib.request.Request(url, data=data)
    if data is not None:
        request.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(request, timeout=10) as response:
        value = json.load(response)
    if not isinstance(value, dict):
        raise ValueError("expected JSON object")
    return value


def expect_rejection(action: Any) -> bool:
    try:
        action()
    except (ValueError, TypeError, KeyError, InvalidSignature):
        return True
    return False


def run(base_url: str) -> dict[str, Any]:
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise ValueError("only loopback HTTP is permitted for this synthetic test")
    issuer = base_url.rstrip("/") + "/realms/live-age"
    discovery = get_json(issuer + "/.well-known/openid-configuration")
    if discovery.get("issuer") != issuer:
        raise ValueError("unexpected Keycloak issuer")
    jwks = get_json(discovery["jwks_uri"])
    form = urllib.parse.urlencode(
        {
            "grant_type": "password",
            "client_id": SOURCE_AUDIENCE,
            "client_secret": "synthetic-adapter-only",
            "username": "synthetic-age-user",
            "password": "synthetic-local-only",
        }
    ).encode()
    source_token = get_json(discovery["token_endpoint"], form)["access_token"]
    if not isinstance(source_token, str):
        raise ValueError("missing source access token")

    signing_key = ec.generate_private_key(ec.SECP256R1())
    destination_jwk = public_jwk(signing_key)
    destination_jwk["kid"] = "live-age-local"
    subject_salt = os.urandom(32)
    issued_at = int(time.time())
    cases = []
    for label, as_of, expected in (
        ("before_18th_birthday", date(2026, 9, 26), False),
        ("on_18th_birthday", date(2026, 9, 27), True),
        ("after_18th_birthday", date(2026, 9, 28), True),
    ):
        assertion = issue_for_verified_source_token(
            source_token,
            jwks,
            source_issuer=issuer,
            signing_key=signing_key,
            subject_salt=subject_salt,
            as_of=as_of,
            issued_at=issued_at,
        )
        destination = subprocess.run(
            [sys.executable, "-m", "prototype.oss_handoff.live_age.verifier"],
            input=json.dumps({"assertion": assertion, "jwk": destination_jwk, "now": issued_at}),
            text=True,
            capture_output=True,
            check=True,
            cwd=ROOT,
        )
        verdict = json.loads(destination.stdout)
        fields = verdict["assertion_fields"]
        cases.append(
            {
                "case": label,
                "expected": expected,
                "observed": verdict["age_over_18"],
                "signature_valid": verdict["signature_valid"],
                "assertion_fields": fields,
                "assertion_bytes": len(assertion.encode()),
                "pass": verdict["age_over_18"] is expected and
                verdict["signature_valid"] is True and set(fields) == ASSERTION_FIELDS,
            }
        )

    bad_signature = source_token.rsplit(".", 1)
    bad_signature[1] = ("A" if bad_signature[1][0] != "A" else "B") + bad_signature[1][1:]
    controls = {
        "leap_day_before": over_18("2008-02-29", date(2026, 2, 28)) is False,
        "leap_day_after": over_18("2008-02-29", date(2026, 3, 1)) is True,
        "invalid_date_rejected": expect_rejection(lambda: over_18("2008-02-30", date(2026, 9, 27))),
        "missing_date_rejected": expect_rejection(lambda: over_18(None, date(2026, 9, 27))),
        "future_date_rejected": expect_rejection(lambda: over_18("2027-01-01", date(2026, 9, 27))),
        "tampered_source_token_rejected": expect_rejection(
            lambda: issue_for_verified_source_token(
                ".".join(bad_signature), jwks, source_issuer=issuer,
                signing_key=signing_key, subject_salt=subject_salt,
                as_of=date(2026, 9, 27), issued_at=issued_at,
            )
        ),
        "wrong_source_audience_rejected": expect_rejection(
            lambda: verify_jwt(
                source_token, jwks, issuer=issuer,
                audience="wrong-source-audience", now=issued_at,
            )
        ),
    }
    source_files = [Path(__file__).with_name(name) for name in ("core.py", "run.py", "verifier.py")]
    source_files.append(REALM)
    source_fingerprints = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in source_files
    }
    return {
        "study": "supplemental-local-O_live",
        "protocol_commit": "f41612334945e8529e6bd7f8aa7241d85de38891",
        "repository_head_at_run": repository_commit(),
        "source_files_sha256": source_fingerprints,
        "keycloak_version": "26.7.3",
        "realm_sha256": hashlib.sha256(REALM.read_bytes()).hexdigest(),
        "actual_keycloak_endpoint": True,
        "cases": cases,
        "negative_controls": controls,
        "all_expectations_passed": all(case["pass"] for case in cases) and all(controls.values()),
        "limits": ["single-host-loopback", "synthetic-DOB", "not-geographic", "not-all-path"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:18880")
    parser.add_argument("--output", type=Path, default=ROOT / "output/results/live-age-supplement.json")
    args = parser.parse_args()
    result = run(args.base_url)
    write_json_atomic(args.output, result)
    print(f"result: {args.output}")
    print(f"all_expectations_passed: {result['all_expectations_passed']}")
    if not result["all_expectations_passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
