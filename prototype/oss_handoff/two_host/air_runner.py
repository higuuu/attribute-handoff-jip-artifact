from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import platform
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import certifi

try:
    from prototype.oss_handoff.crypto_utils import (
        build_key_binding_jwt,
        load_private_key,
        parse_and_verify_sd_jwt,
        verify_jwt,
        verify_key_binding_jwt,
    )
    from prototype.oss_handoff.two_host.common import canonical_json, load_json, percentile
except ImportError:  # Standalone Air client bundle.
    from crypto_utils import (  # type: ignore[no-redef]
        build_key_binding_jwt,
        load_private_key,
        parse_and_verify_sd_jwt,
        verify_jwt,
        verify_key_binding_jwt,
    )

    def canonical_json(value: Any) -> bytes:
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

    def load_json(path: Path) -> dict[str, Any]:
        value = json.loads(path.read_text())
        if not isinstance(value, dict):
            raise ValueError(f"expected JSON object in {path}")
        return value

    def percentile(values: list[float], fraction: float) -> float | None:
        if not values:
            return None
        ordered = sorted(values)
        position = (len(ordered) - 1) * fraction
        lower = int(position)
        upper = min(lower + 1, len(ordered) - 1)
        weight = position - lower
        return ordered[lower] * (1 - weight) + ordered[upper] * weight


def request_json(
    url: str,
    *,
    token: str | None = None,
    payload: dict[str, Any] | None = None,
    timeout: float = 15,
) -> tuple[int | None, dict[str, Any] | None, int, float, str | None]:
    body = canonical_json(payload) if payload is not None else None
    headers = {"Accept": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=body, headers=headers, method="POST" if body is not None else "GET")
    parsed = urllib.parse.urlsplit(url)
    tls_context = ssl.create_default_context(cafile=certifi.where()) if parsed.scheme == "https" else None
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=tls_context) as response:
            raw = response.read()
            status = response.status
    except urllib.error.HTTPError as error:
        raw = error.read()
        status = error.code
    except urllib.error.URLError as error:
        return None, None, 0, (time.perf_counter() - started) * 1000, type(error.reason).__name__
    elapsed = (time.perf_counter() - started) * 1000
    try:
        value = json.loads(raw) if raw else None
    except json.JSONDecodeError:
        value = None
    return status, value if isinstance(value, dict) else None, len(raw), elapsed, None


def inspect_evidence(evidence: str, jwks: dict[str, Any], audience: str, issuer: str) -> dict[str, Any]:
    claims = verify_jwt(evidence, jwks, audience=audience, issuer=issuer)
    disclosure_fields = sorted(field for field in ("birth_date", "age_over_18") if field in claims)
    return {
        "signature_verified": True,
        "issuer_verified": True,
        "evidence_bytes": len(evidence.encode()),
        "disclosure_fields": disclosure_fields,
        "birth_date_present": "birth_date" in claims,
        "predicate_present": "age_over_18" in claims,
    }


def run_online_case(
    *,
    base_url: str,
    token: str,
    config: dict[str, Any],
    jwks: dict[str, Any],
    case_name: str,
    route: str,
    model_id: str,
    repetition: int,
    timeout: float,
) -> dict[str, Any]:
    payload = {
        "request_id": f"{config['phase']}:{case_name}:{repetition:03d}",
        "route": route,
        "audience": config["audience"],
        "purpose": config["purpose"],
        "policy_model_id": model_id,
    }
    request_bytes = len(canonical_json(payload))
    status, value, response_bytes, elapsed_ms, transport_error_class = request_json(
        f"{base_url}/v1/handoff",
        token=token,
        payload=payload,
        timeout=timeout,
    )
    result: dict[str, Any] = {
        "case": case_name,
        "repetition": repetition,
        "route": route,
        "status": status,
        "elapsed_ms": round(elapsed_ms, 3),
        "request_bytes": request_bytes,
        "response_bytes": response_bytes,
        "transport_error_class": transport_error_class,
        "reason": value.get("error") if value else None,
        "warnings": value.get("warnings", []) if value else [],
        "evidence_bytes": 0,
        "disclosure_fields": [],
        "signature_verified": False,
        "issuer_verified": False,
    }
    if status == 200 and value and isinstance(value.get("evidence"), str):
        result.update(
            inspect_evidence(
                value["evidence"],
                jwks,
                str(config["audience"]),
                str(config["issuer"]),
            )
        )
    return result


def run_cached_c(bundle: dict[str, Any], repetition: int) -> dict[str, Any]:
    started = time.perf_counter()
    now = int(time.time())
    parsed = parse_and_verify_sd_jwt(
        str(bundle["credential"]),
        bundle["jwks"],
        issuer=str(bundle["issuer"]),
        now=now,
    )
    private_key = load_private_key(str(bundle["holder_private_key"]))
    nonce = f"air-c-{repetition:03d}-{now}"
    key_binding = build_key_binding_jwt(
        parsed.compact_without_kb,
        private_key,
        audience=str(bundle["audience"]),
        nonce=nonce,
        issued_at=now,
    )
    holder_jwk = parsed.issuer_payload.get("cnf", {}).get("jwk")
    if holder_jwk != bundle["holder_public_jwk"]:
        raise ValueError("C bundle holder binding mismatch")
    verify_key_binding_jwt(
        key_binding,
        holder_jwk,
        compact_without_kb=parsed.compact_without_kb,
        audience=str(bundle["audience"]),
        nonce=nonce,
    )
    claims = {**parsed.issuer_payload, **parsed.disclosures}
    elapsed_ms = (time.perf_counter() - started) * 1000
    return {
        "case": "C_OFFLINE",
        "repetition": repetition,
        "route": "C",
        "status": 200,
        "elapsed_ms": round(elapsed_ms, 3),
        "request_bytes": 0,
        "response_bytes": 0,
        "transport_error_class": None,
        "reason": None,
        "warnings": [],
        "evidence_bytes": len(str(bundle["credential"]).encode()) + len(key_binding.encode()),
        "disclosure_fields": sorted(field for field in ("birth_date", "age_over_18") if field in claims),
        "signature_verified": True,
        "issuer_verified": True,
        "source_requests_required": 0,
    }


def expected(record: dict[str, Any], config: dict[str, Any]) -> bool:
    mode = config["enforcement_mode"]
    allowed = set(config["allowed_routes"])
    case = record["case"]
    if case == "O_CURRENT":
        return (
            record["status"] == 200
            and record["signature_verified"]
            and record["issuer_verified"]
            and record["disclosure_fields"] == ["age_over_18"]
        )
    if case == "R_CURRENT":
        if "R" in allowed:
            return (
                record["status"] == 200
                and record["signature_verified"]
                and record["issuer_verified"]
                and record["disclosure_fields"] == ["birth_date"]
            )
        if mode == "observe-only":
            return (
                record["status"] == 200
                and record["signature_verified"]
                and record["issuer_verified"]
                and "birth_date" in record["disclosure_fields"]
                and "ROUTE_DENIED_OBSERVED" in record["warnings"]
            )
        return record["status"] == 403 and record["reason"] == "ROUTE_DENIED" and record["evidence_bytes"] == 0
    if case == "O_STALE_MODEL":
        if mode == "observe-only":
            return (
                record["status"] == 200
                and record["signature_verified"]
                and record["issuer_verified"]
                and record["disclosure_fields"] == ["age_over_18"]
                and record["evidence_bytes"] > 0
                and "STALE_POLICY_OBSERVED" in record["warnings"]
            )
        return record["status"] == 409 and record["reason"] == "STALE_POLICY_MODEL" and record["evidence_bytes"] == 0
    if case == "C_OFFLINE":
        return (
            record["status"] == 200
            and record["signature_verified"]
            and record["issuer_verified"]
            and record["disclosure_fields"] == ["age_over_18"]
            and record["source_requests_required"] == 0
        )
    return False


def summarize(records: list[dict[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for case in sorted({record["case"] for record in records}):
        selected = [record for record in records if record["case"] == case]
        latencies = [float(record["elapsed_ms"]) for record in selected]
        output[case] = {
            "count": len(selected),
            "status_counts": {
                str(status): sum(1 for record in selected if record["status"] == status)
                for status in sorted({record["status"] for record in selected}, key=lambda item: str(item))
            },
            "latency_ms": {
                "p50": round(percentile(latencies, 0.50) or 0, 3),
                "p95": round(percentile(latencies, 0.95) or 0, 3),
            },
            "request_bytes_p50": round(percentile([float(record["request_bytes"]) for record in selected], 0.50) or 0),
            "response_bytes_p50": round(percentile([float(record["response_bytes"]) for record in selected], 0.50) or 0),
            "evidence_bytes_p50": round(percentile([float(record["evidence_bytes"]) for record in selected], 0.50) or 0),
            "disclosure_fields": sorted({field for record in selected for field in record["disclosure_fields"]}),
            "expectations_passed": all(bool(record["expected"]) for record in selected),
        }
    return output


def probe_direct_source(url: str | None, timeout: float) -> dict[str, Any] | None:
    if not url:
        return None
    status, _, _, elapsed_ms, error = request_json(url, timeout=timeout)
    parsed = urllib.parse.urlsplit(url)
    return {
        "target_host_sha256": hashlib.sha256((parsed.hostname or "").encode()).hexdigest(),
        "target_port": parsed.port,
        "reachable": status is not None,
        "status": status,
        "elapsed_ms": round(elapsed_ms, 3),
        "transport_error_class": error,
    }


def host_fingerprint() -> str:
    value = platform.node().strip()
    if not value:
        raise RuntimeError("host name is unavailable")
    return hashlib.sha256(value.encode()).hexdigest()


def resolved_addresses(url: str) -> set[str]:
    parsed = urllib.parse.urlsplit(url)
    if not parsed.hostname:
        return set()
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    addresses: set[str] = set()
    for item in socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM):
        raw = item[4][0].split("%", 1)[0]
        addresses.add(str(ipaddress.ip_address(raw)))
    return addresses


def probe_matches_pep(base_url: str, probe_url: str) -> bool:
    try:
        return bool(resolved_addresses(base_url) & resolved_addresses(probe_url))
    except (OSError, ValueError):
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Lightweight MacBook Air runner for the JIP two-host experiment")
    parser.add_argument("--base-url")
    parser.add_argument("--token-file", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=10)
    parser.add_argument("--timeout", type=float, default=15)
    parser.add_argument("--direct-source-probe-url")
    parser.add_argument("--c-bundle", type=Path)
    parser.add_argument("--offline-c-only", action="store_true")
    parser.add_argument(
        "--two-physical-hosts",
        action="store_true",
        help="require cross-host fingerprint, direct-probe, and C-bundle checks",
    )
    args = parser.parse_args()

    if args.repetitions < 1 or args.repetitions > 100:
        parser.error("--repetitions must be between 1 and 100")
    if args.output.exists():
        parser.error(f"refusing to overwrite existing result: {args.output}")
    if args.two_physical_hosts and args.direct_source_probe_url is None:
        parser.error("--two-physical-hosts requires --direct-source-probe-url")
    if args.two_physical_hosts and args.c_bundle is None:
        parser.error("--two-physical-hosts requires --c-bundle")

    bundle = load_json(args.c_bundle) if args.c_bundle else None
    bundle_hash = hashlib.sha256(args.c_bundle.read_bytes()).hexdigest() if args.c_bundle else None
    if bundle is not None:
        required_bundle_fields = {
            "issuer",
            "credential_issued_at",
            "credential_expires_at",
            "credential_lifetime_seconds",
            "source_host_sha256",
            "implementation_commit",
        }
        missing = sorted(required_bundle_fields - set(bundle))
        if missing:
            parser.error(f"C bundle is missing required fields: {missing}")
        remaining = int(bundle["credential_expires_at"]) - int(time.time())
        if args.two_physical_hosts and remaining < 600:
            parser.error(f"C credential has only {remaining}s remaining; issue and transfer a fresh bundle")

    records: list[dict[str, Any]] = []
    base_url: str | None = None
    if args.offline_c_only:
        if bundle is None:
            parser.error("--offline-c-only requires --c-bundle")
        config = {
            "phase": "c-source-offline",
            "enforcement_mode": "offline-verifier",
            "allowed_routes": ["C"],
            "policy_model_id": "not-contacted",
            "issuer": bundle["issuer"],
            "source_host_sha256": bundle["source_host_sha256"],
            "implementation_commit": bundle["implementation_commit"],
        }
    else:
        if args.base_url is None or args.token_file is None:
            parser.error("online phases require --base-url and --token-file")
        base_url = args.base_url.rstrip("/")
        if not base_url.startswith("https://") and not base_url.startswith("http://127.0.0.1"):
            parser.error("remote PEP URL must use tailnet HTTPS")
        token = args.token_file.read_text().strip()
        status, config, _, _, error = request_json(f"{base_url}/v1/config", token=token, timeout=args.timeout)
        if status != 200 or config is None:
            raise SystemExit(f"PEP config unavailable: status={status} error={error}")
        required_config_fields = {"issuer", "source_host_sha256", "implementation_commit"}
        missing = sorted(required_config_fields - set(config))
        if missing:
            raise SystemExit(f"PEP config is missing required fields: {missing}")
        status, jwks, _, _, error = request_json(f"{base_url}/v1/jwks", token=token, timeout=args.timeout)
        if status != 200 or jwks is None:
            raise SystemExit(f"PEP JWKS unavailable: status={status} error={error}")
        for repetition in range(1, args.repetitions + 1):
            records.append(
                run_online_case(
                    base_url=base_url,
                    token=token,
                    config=config,
                    jwks=jwks,
                    case_name="R_CURRENT",
                    route="R",
                    model_id=str(config["policy_model_id"]),
                    repetition=repetition,
                    timeout=args.timeout,
                )
            )
            records.append(
                run_online_case(
                    base_url=base_url,
                    token=token,
                    config=config,
                    jwks=jwks,
                    case_name="O_CURRENT",
                    route="O*",
                    model_id=str(config["policy_model_id"]),
                    repetition=repetition,
                    timeout=args.timeout,
                )
            )
            records.append(
                run_online_case(
                    base_url=base_url,
                    token=token,
                    config=config,
                    jwks=jwks,
                    case_name="O_STALE_MODEL",
                    route="O*",
                    model_id="intentionally-stale-model-id",
                    repetition=repetition,
                    timeout=args.timeout,
                )
            )

    if bundle is not None:
        if str(bundle["source_host_sha256"]) != str(config["source_host_sha256"]):
            parser.error("C bundle source host does not match the PEP source host")
        if str(bundle["implementation_commit"]) != str(config["implementation_commit"]):
            parser.error("C bundle implementation commit does not match the PEP commit")
        if str(bundle["issuer"]) != str(config["issuer"]):
            parser.error("C bundle issuer does not match the PEP issuer")
        for repetition in range(1, args.repetitions + 1):
            records.append(run_cached_c(bundle, repetition))

    for record in records:
        record["expected"] = expected(record, config)
    client_host_sha256 = host_fingerprint()
    source_host_sha256 = str(config["source_host_sha256"])
    host_separation_observed = client_host_sha256 != source_host_sha256
    if args.two_physical_hosts and not host_separation_observed:
        parser.error("source and client host fingerprints are identical")
    direct_probe = probe_direct_source(args.direct_source_probe_url, min(args.timeout, 3))
    if direct_probe is not None and base_url is not None:
        direct_probe["target_matches_pep"] = probe_matches_pep(base_url, args.direct_source_probe_url)
    direct_probe_passed = direct_probe is None or direct_probe["reachable"] is False
    if args.two_physical_hosts:
        direct_probe_passed = direct_probe is not None and direct_probe["reachable"] is False
        if base_url is not None:
            direct_probe_passed = direct_probe_passed and direct_probe.get("target_matches_pep") is True
    result = {
        "schema_version": 1,
        "experiment": "jip-two-physical-host-remediation",
        "phase": config["phase"],
        "enforcement_mode": config["enforcement_mode"],
        "allowed_routes": config["allowed_routes"],
        "policy_model_id_sha256": hashlib.sha256(str(config["policy_model_id"]).encode()).hexdigest(),
        "environment": {
            "role": "Region B lightweight verifier and measurement client",
            "system": platform.system(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "synthetic_data_only": True,
            "client_host_sha256": client_host_sha256,
            "source_host_sha256": source_host_sha256,
            "host_separation_observed": host_separation_observed,
        },
        "parameters": {
            "repetitions": args.repetitions,
            "air_runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "c_bundle_sha256": bundle_hash,
            "implementation_commit": config["implementation_commit"],
            "tls_ca_bundle_sha256": hashlib.sha256(Path(certifi.where()).read_bytes()).hexdigest(),
            "c_credential_issued_at": bundle.get("credential_issued_at") if bundle else None,
            "c_credential_expires_at": bundle.get("credential_expires_at") if bundle else None,
            "c_credential_lifetime_seconds": bundle.get("credential_lifetime_seconds") if bundle else None,
            "c_credential_seconds_remaining_at_start": (
                int(bundle["credential_expires_at"]) - int(time.time()) if bundle else None
            ),
            "tokens_or_credentials_persisted_in_result": False,
        },
        "direct_source_probe": direct_probe,
        "records": records,
        "summary": summarize(records),
        "all_expectations_passed": (
            all(bool(record["expected"]) for record in records)
            and direct_probe_passed
            and (not args.two_physical_hosts or host_separation_observed)
        ),
        "claim_boundary": {
            "separate_physical_hosts": args.two_physical_hosts and host_separation_observed,
            "host_separation_is_fingerprint_based_not_attested": True,
            "independent_reproduction": False,
            "geographic_or_legal_separation": False,
            "latency_is_descriptive": True,
            "byte_count_is_not_a_privacy_metric": True,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    print(json.dumps({"output": str(args.output), "sha256": digest, "all_expectations_passed": result["all_expectations_passed"]}))
    if not result["all_expectations_passed"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
