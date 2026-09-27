"""Lightweight destination-side runner; writes no tokens or raw responses."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import secrets
import time
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature

from prototype.oss_handoff.crypto_utils import verify_jwt
from prototype.oss_handoff.integrated_age.core import BOUND_FIELDS, verify_bound_assertion
from prototype.oss_handoff.two_host.air_runner import host_fingerprint, probe_direct_source, probe_matches_pep, request_json
from prototype.oss_handoff.two_host.common import AUDIENCE, PURPOSE, canonical_json, percentile, write_json_atomic


CASES = (
    ("R_CURRENT", "R", False),
    ("O_LIVE_STALE", "O_live", True),
    ("O_LIVE_CURRENT", "O_live", False),
)


def rejected(action: Any) -> bool:
    try:
        action()
    except (ValueError, InvalidSignature):
        return True
    return False


def run_case(
    *,
    base_url: str,
    token: str,
    config: dict[str, Any],
    source_jwks: dict[str, Any],
    adapter_jwk: dict[str, Any],
    case: str,
    route: str,
    stale: bool,
    repetition: int,
) -> tuple[dict[str, Any], str | None]:
    request_id = f"{config['phase']}:{case}:{repetition:03d}:{secrets.token_hex(16)}"
    payload = {
        "request_id": request_id,
        "route": route,
        "audience": AUDIENCE,
        "purpose": PURPOSE,
        "policy_model_id": "intentionally-stale-model-id" if stale else config["policy_model_id"],
    }
    status, body, response_bytes, elapsed_ms, transport_error = request_json(
        f"{base_url}/v1/handoff", token=token, payload=payload
    )
    fields: list[str] = []
    verified = False
    predicate: bool | None = None
    evidence_bytes = 0
    evidence_type = body.get("evidence_type") if body else None
    controls: dict[str, bool] = {}
    if status == 200 and body and isinstance(body.get("evidence"), str):
        evidence = body["evidence"]
        evidence_bytes = len(evidence.encode())
        if route == "R":
            claims = verify_jwt(
                evidence,
                source_jwks,
                audience=AUDIENCE,
                issuer=str(config["issuer"]),
            )
            fields = sorted(field for field in ("birth_date", "age_over_18") if field in claims)
            verified = True
        else:
            claims = verify_bound_assertion(
                evidence, adapter_jwk, nonce=request_id, now=int(time.time())
            )
            fields = sorted(field for field in ("birth_date", "age_over_18") if field in claims)
            predicate = claims["age_over_18"]
            verified = set(claims) == BOUND_FIELDS
            if case == "O_LIVE_CURRENT" and repetition == 1:
                signed, signature = evidence.rsplit(".", 1)
                tampered = signed + "." + ("A" if signature[0] != "A" else "B") + signature[1:]
                controls = {
                    "wrong_nonce_rejected": rejected(lambda: verify_bound_assertion(
                        evidence, adapter_jwk, nonce="wrong-nonce", now=int(time.time())
                    )),
                    "tampered_assertion_rejected": rejected(lambda: verify_bound_assertion(
                        tampered,
                        adapter_jwk, nonce=request_id, now=int(time.time())
                    )),
                }
    record = {
        "case": case,
        "repetition": repetition,
        "request_id": request_id,
        "route": route,
        "status": status,
        "elapsed_ms": round(elapsed_ms, 3),
        "request_bytes": len(canonical_json(payload)),
        "response_bytes": response_bytes,
        "transport_error_class": transport_error,
        "reason": body.get("error") if body else None,
        "warnings": body.get("warnings", []) if body else [],
        "evidence_type": evidence_type,
        "evidence_bytes": evidence_bytes,
        "disclosure_fields": fields,
        "signature_verified": verified,
        "age_over_18": predicate,
        "controls": controls,
    }
    return record, None


def expected(record: dict[str, Any], mode: str) -> bool:
    if record["case"] == "R_CURRENT":
        if mode == "observe-only":
            return (
                record["status"] == 200 and record["signature_verified"]
                and record["disclosure_fields"] == ["birth_date"]
                and record["evidence_type"] == "oidc_access_token"
                and "ROUTE_DENIED_OBSERVED" in record["warnings"]
            )
        return record["status"] == 403 and record["reason"] == "ROUTE_DENIED" and record["evidence_bytes"] == 0
    if record["case"] == "O_LIVE_STALE" and mode == "enforce":
        return record["status"] == 409 and record["reason"] == "STALE_POLICY_MODEL" and record["evidence_bytes"] == 0
    return (
        record["status"] == 200 and record["signature_verified"]
        and record["disclosure_fields"] == ["age_over_18"]
        and record["age_over_18"] is True
        and record["evidence_type"] == "age_predicate_assertion"
        and (record["case"] != "O_LIVE_STALE" or "STALE_POLICY_OBSERVED" in record["warnings"])
    )


def summarize(records: list[dict[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for case in sorted({record["case"] for record in records}):
        selected = [record for record in records if record["case"] == case]
        latencies = [float(record["elapsed_ms"]) for record in selected]
        output[case] = {
            "count": len(selected),
            "status_counts": {str(status): sum(record["status"] == status for record in selected)
                              for status in sorted({record["status"] for record in selected}, key=str)},
            "latency_ms": {
                "p50": round(percentile(latencies, 0.5) or 0, 3),
                "p95": round(percentile(latencies, 0.95) or 0, 3),
            },
            "evidence_bytes_p50": round(percentile([float(record["evidence_bytes"]) for record in selected], 0.5) or 0),
            "disclosure_fields": sorted({field for record in selected for field in record["disclosure_fields"]}),
            "expectations_passed": all(record["expected"] for record in selected),
        }
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description="Minimal destination client for live age handoff")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=10)
    parser.add_argument("--two-physical-hosts", action="store_true")
    parser.add_argument("--direct-source-probe-url")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("refusing to overwrite an existing result")
    if not 1 <= args.repetitions <= 100:
        parser.error("repetitions must be 1..100")
    base_url = args.base_url.rstrip("/")
    if not base_url.startswith("https://") and not base_url.startswith("http://127.0.0.1:"):
        parser.error("remote PEP requires HTTPS")
    if args.two_physical_hosts and (not base_url.startswith("https://") or not args.direct_source_probe_url):
        parser.error("two-host mode requires HTTPS and a direct source probe URL")
    token = args.token_file.read_text().strip()
    status, config, _, _, error = request_json(f"{base_url}/v1/config", token=token)
    if status != 200 or config is None:
        raise SystemExit(f"config unavailable: {status} {error}")
    status, source_jwks, _, _, error = request_json(f"{base_url}/v1/jwks", token=token)
    if status != 200 or source_jwks is None:
        raise SystemExit(f"source JWKS unavailable: {status} {error}")
    status, adapter_jwks, _, _, error = request_json(f"{base_url}/v1/live-age-jwk", token=token)
    if status != 200 or not adapter_jwks or len(adapter_jwks.get("keys", [])) != 1:
        raise SystemExit(f"adapter JWK unavailable: {status} {error}")
    adapter_jwk = adapter_jwks["keys"][0]
    records = []
    for repetition in range(1, args.repetitions + 1):
        for case, route, stale in CASES:
            record, _ = run_case(
                base_url=base_url, token=token, config=config, source_jwks=source_jwks,
                adapter_jwk=adapter_jwk, case=case, route=route, stale=stale,
                repetition=repetition,
            )
            record["expected"] = expected(record, str(config["enforcement_mode"]))
            records.append(record)
    controls = next((record["controls"] for record in records if record["controls"]), {})
    direct_probe = probe_direct_source(args.direct_source_probe_url, 3) if args.direct_source_probe_url else None
    if direct_probe is not None:
        direct_probe["target_matches_pep"] = probe_matches_pep(base_url, args.direct_source_probe_url)
    separate_hosts = host_fingerprint() != config["source_host_sha256"]
    boundary_passed = not args.two_physical_hosts or (
        separate_hosts and direct_probe is not None and not direct_probe["reachable"]
        and direct_probe["target_matches_pep"] is True
    )
    result = {
        "schema_version": 1,
        "experiment": "integrated-live-age-handoff",
        "phase": config["phase"],
        "enforcement_mode": config["enforcement_mode"],
        "model_id_sha256": hashlib.sha256(str(config["policy_model_id"]).encode()).hexdigest(),
        "adapter_jwk_sha256": hashlib.sha256(canonical_json(adapter_jwk)).hexdigest(),
        "implementation_commit": config["implementation_commit"],
        "realm_sha256": config["realm_sha256"],
        "source_host_sha256": config["source_host_sha256"],
        "client_host_sha256": host_fingerprint(),
        "two_physical_hosts_claimed": args.two_physical_hosts and separate_hosts,
        "environment": {"system": platform.system(), "machine": platform.machine(), "python": platform.python_version()},
        "parameters": {"repetitions": args.repetitions, "synthetic_data_only": True},
        "direct_source_probe": direct_probe,
        "controls": controls,
        "records": records,
        "summary": summarize(records),
        "all_expectations_passed": all(record["expected"] for record in records)
            and all(controls.values()) and bool(controls) and boundary_passed,
        "claim_boundary": {
            "same_author": True,
            "geographic_or_legal_separation": False,
            "all_path_enforcement": False,
            "credential_status": False,
            "latency_is_descriptive": True,
        },
    }
    write_json_atomic(args.output, result)
    print(json.dumps({"output": str(args.output), "sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(), "all_expectations_passed": result["all_expectations_passed"]}))
    if not result["all_expectations_passed"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
