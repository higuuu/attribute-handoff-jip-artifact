from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


PHASES = {
    "baseline": "baseline-deny-raw",
    "remediated": "remediated-deny-raw",
    "measurement": "measurement-allow-r-o-c",
    "offline_c": "c-source-offline",
}

ONLINE_EVENT_EXPECTATIONS: dict[str, dict[str, dict[str, Any]]] = {
    "baseline-deny-raw": {
        "R_CURRENT": {
            "route": "R",
            "status": 200,
            "decision": "ISSUED",
            "warnings": ["ROUTE_DENIED_OBSERVED"],
            "policy_called": True,
            "issuer_called": True,
            "evidence_present": True,
            "disclosure_fields": ["birth_date"],
        },
        "O_CURRENT": {
            "route": "O*",
            "status": 200,
            "decision": "ISSUED",
            "warnings": [],
            "policy_called": True,
            "issuer_called": True,
            "evidence_present": True,
            "disclosure_fields": ["age_over_18"],
        },
        "O_STALE_MODEL": {
            "route": "O*",
            "status": 200,
            "decision": "ISSUED",
            "warnings": ["STALE_POLICY_OBSERVED"],
            "policy_called": True,
            "issuer_called": True,
            "evidence_present": True,
            "disclosure_fields": ["age_over_18"],
        },
    },
    "remediated-deny-raw": {
        "R_CURRENT": {
            "route": "R",
            "status": 403,
            "decision": "ROUTE_DENIED",
            "warnings": [],
            "policy_called": True,
            "issuer_called": False,
            "evidence_present": False,
            "disclosure_fields": [],
        },
        "O_CURRENT": {
            "route": "O*",
            "status": 200,
            "decision": "ISSUED",
            "warnings": [],
            "policy_called": True,
            "issuer_called": True,
            "evidence_present": True,
            "disclosure_fields": ["age_over_18"],
        },
        "O_STALE_MODEL": {
            "route": "O*",
            "status": 409,
            "decision": "STALE_POLICY_MODEL",
            "warnings": [],
            "policy_called": False,
            "issuer_called": False,
            "evidence_present": False,
            "disclosure_fields": [],
        },
    },
    "measurement-allow-r-o-c": {
        "R_CURRENT": {
            "route": "R",
            "status": 200,
            "decision": "ISSUED",
            "warnings": [],
            "policy_called": True,
            "issuer_called": True,
            "evidence_present": True,
            "disclosure_fields": ["birth_date"],
        },
        "O_CURRENT": {
            "route": "O*",
            "status": 200,
            "decision": "ISSUED",
            "warnings": [],
            "policy_called": True,
            "issuer_called": True,
            "evidence_present": True,
            "disclosure_fields": ["age_over_18"],
        },
        "O_STALE_MODEL": {
            "route": "O*",
            "status": 409,
            "decision": "STALE_POLICY_MODEL",
            "warnings": [],
            "policy_called": False,
            "issuer_called": False,
            "evidence_present": False,
            "disclosure_fields": [],
        },
    },
}


def load_result(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object in {path}")
    return value


def load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text().splitlines(), start=1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"expected JSON object at {path}:{line_number}")
        events.append(value)
    return events


def is_hex_digest(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def case_matches(
    result: dict[str, Any],
    case: str,
    *,
    count: int,
    status: int,
    disclosure_fields: list[str],
) -> bool:
    item = result.get("summary", {}).get(case, {})
    return (
        item.get("count") == count
        and item.get("status_counts") == {str(status): count}
        and item.get("disclosure_fields") == disclosure_fields
        and item.get("expectations_passed") is True
    )


def records_match(
    result: dict[str, Any],
    expectations: dict[str, dict[str, Any]],
    *,
    expected_repetitions: int,
) -> bool:
    records = result.get("records")
    if not isinstance(records, list) or len(records) != len(expectations) * expected_repetitions:
        return False
    indexed: dict[tuple[str, int], dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict):
            return False
        key = (str(record.get("case")), record.get("repetition"))
        if not isinstance(key[1], int) or key in indexed:
            return False
        indexed[key] = record
    expected_keys = {
        (case, repetition)
        for case in expectations
        for repetition in range(1, expected_repetitions + 1)
    }
    if set(indexed) != expected_keys:
        return False
    for key, record in indexed.items():
        expected = expectations[key[0]]
        if record.get("expected") is not True:
            return False
        for field in ("route", "status", "disclosure_fields", "signature_verified", "issuer_verified"):
            if record.get(field) != expected[field]:
                return False
        evidence_bytes = record.get("evidence_bytes")
        if not isinstance(evidence_bytes, int):
            return False
        if expected["evidence_present"] != (evidence_bytes > 0):
            return False
        if record.get("reason") != expected.get("reason"):
            return False
        expected_warning = expected.get("warning")
        warnings = record.get("warnings")
        expected_warnings = [expected_warning] if expected_warning is not None else []
        if warnings != expected_warnings:
            return False
        if expected.get("source_requests_required") is not None:
            if record.get("source_requests_required") != expected["source_requests_required"]:
                return False
    return True


def validate_event_log(events: list[dict[str, Any]], *, expected_repetitions: int) -> dict[str, bool]:
    expected: dict[str, dict[str, Any]] = {}
    for phase, cases in ONLINE_EVENT_EXPECTATIONS.items():
        for case, expectation in cases.items():
            for repetition in range(1, expected_repetitions + 1):
                expected[f"{phase}:{case}:{repetition:03d}"] = {"phase": phase, **expectation}

    indexed: dict[str, dict[str, Any]] = {}
    duplicate_ids = False
    for event in events:
        request_id = event.get("request_id")
        if not isinstance(request_id, str) or request_id in indexed:
            duplicate_ids = True
            continue
        indexed[request_id] = event

    checks = {
        "event_ids_exact": not duplicate_ids and set(indexed) == set(expected),
        "event_count_exact": len(events) == len(expected),
        "event_log_contains_no_evidence_material": all(
            not ({"evidence", "token", "credential", "authorization", "holder_private_key"} & {str(key).lower() for key in event})
            for event in events
        ),
    }
    checks["event_semantics"] = checks["event_ids_exact"] and all(
        event.get("phase") == registered["phase"]
        and event.get("route") == registered["route"]
        and event.get("status") == registered["status"]
        and event.get("decision") == registered["decision"]
        and event.get("warnings") == registered["warnings"]
        and event.get("policy_called") is registered["policy_called"]
        and event.get("issuer_called") is registered["issuer_called"]
        and event.get("disclosure_fields") == registered["disclosure_fields"]
        and isinstance(event.get("evidence_bytes"), int)
        and (event["evidence_bytes"] > 0) is registered["evidence_present"]
        for request_id, registered in expected.items()
        for event in [indexed[request_id]]
    )
    return checks


def validate_result_set(
    results: dict[str, dict[str, Any]],
    *,
    expected_repetitions: int,
    expected_source_port: int,
) -> dict[str, bool]:
    checks: dict[str, bool] = {}
    for name, expected_phase in PHASES.items():
        result = results[name]
        checks[f"{name}_phase"] = result.get("phase") == expected_phase
        checks[f"{name}_overall"] = result.get("all_expectations_passed") is True
        checks[f"{name}_repetitions"] = result.get("parameters", {}).get("repetitions") == expected_repetitions
        checks[f"{name}_separate_hosts"] = (
            result.get("claim_boundary", {}).get("separate_physical_hosts") is True
            and result.get("environment", {}).get("host_separation_observed") is True
        )
        probe = result.get("direct_source_probe")
        checks[f"{name}_source_unreachable"] = (
            isinstance(probe, dict)
            and probe.get("reachable") is False
            and probe.get("target_port") == expected_source_port
        )
        if name != "offline_c":
            checks[f"{name}_probe_matches_pep"] = isinstance(probe, dict) and probe.get("target_matches_pep") is True

    source_hosts = {result.get("environment", {}).get("source_host_sha256") for result in results.values()}
    client_hosts = {result.get("environment", {}).get("client_host_sha256") for result in results.values()}
    probe_hosts = {
        (result.get("direct_source_probe") or {}).get("target_host_sha256")
        for result in results.values()
    }
    commits = {result.get("parameters", {}).get("implementation_commit") for result in results.values()}
    air_runners = {result.get("parameters", {}).get("air_runner_sha256") for result in results.values()}
    tls_ca_bundles = {result.get("parameters", {}).get("tls_ca_bundle_sha256") for result in results.values()}
    bundles = {result.get("parameters", {}).get("c_bundle_sha256") for result in results.values()}
    checks["one_source_host"] = len(source_hosts) == 1 and all(is_hex_digest(value, 64) for value in source_hosts)
    checks["one_client_host"] = len(client_hosts) == 1 and all(is_hex_digest(value, 64) for value in client_hosts)
    checks["source_and_client_differ"] = checks["one_source_host"] and checks["one_client_host"] and source_hosts != client_hosts
    checks["one_direct_probe_target"] = len(probe_hosts) == 1 and all(is_hex_digest(value, 64) for value in probe_hosts)
    checks["one_implementation_commit"] = (
        len(commits) == 1
        and all(is_hex_digest(value, 40) for value in commits)
    )
    checks["one_air_runner"] = (
        len(air_runners) == 1
        and all(is_hex_digest(value, 64) for value in air_runners)
    )
    checks["one_tls_ca_bundle"] = (
        len(tls_ca_bundles) == 1
        and all(is_hex_digest(value, 64) for value in tls_ca_bundles)
    )
    checks["one_c_bundle"] = len(bundles) == 1 and all(is_hex_digest(value, 64) for value in bundles)
    checks["credential_lifetime"] = all(
        isinstance(result.get("parameters", {}).get("c_credential_issued_at"), int)
        and isinstance(result.get("parameters", {}).get("c_credential_expires_at"), int)
        and isinstance(result.get("parameters", {}).get("c_credential_lifetime_seconds"), int)
        and isinstance(result.get("parameters", {}).get("c_credential_seconds_remaining_at_start"), int)
        and result["parameters"]["c_credential_expires_at"] - result["parameters"]["c_credential_issued_at"]
        == result["parameters"]["c_credential_lifetime_seconds"]
        and result["parameters"]["c_credential_lifetime_seconds"] >= 3600
        and 600 <= result["parameters"]["c_credential_seconds_remaining_at_start"]
        <= result["parameters"]["c_credential_lifetime_seconds"]
        for result in results.values()
    )

    baseline_model = results["baseline"].get("policy_model_id_sha256")
    remediated_model = results["remediated"].get("policy_model_id_sha256")
    measurement_model = results["measurement"].get("policy_model_id_sha256")
    checks["same_deny_model"] = baseline_model is not None and baseline_model == remediated_model
    checks["new_measurement_model"] = measurement_model is not None and measurement_model != baseline_model
    checks["policy_model_hashes"] = all(
        is_hex_digest(result.get("policy_model_id_sha256"), 64)
        for result in results.values()
    )

    online_cases = ("R_CURRENT", "O_CURRENT", "O_STALE_MODEL", "C_OFFLINE")
    for name in ("baseline", "remediated", "measurement"):
        checks[f"{name}_case_set"] = set(results[name].get("summary", {})) == set(online_cases)
    checks["offline_case_set"] = set(results["offline_c"].get("summary", {})) == {"C_OFFLINE"}

    checks["baseline_r"] = case_matches(
        results["baseline"], "R_CURRENT", count=expected_repetitions, status=200, disclosure_fields=["birth_date"]
    )
    checks["baseline_stale_o"] = case_matches(
        results["baseline"], "O_STALE_MODEL", count=expected_repetitions, status=200, disclosure_fields=["age_over_18"]
    )
    checks["remediated_r"] = case_matches(
        results["remediated"], "R_CURRENT", count=expected_repetitions, status=403, disclosure_fields=[]
    )
    checks["remediated_stale_o"] = case_matches(
        results["remediated"], "O_STALE_MODEL", count=expected_repetitions, status=409, disclosure_fields=[]
    )
    checks["measurement_r"] = case_matches(
        results["measurement"], "R_CURRENT", count=expected_repetitions, status=200, disclosure_fields=["birth_date"]
    )
    checks["measurement_stale_o"] = case_matches(
        results["measurement"], "O_STALE_MODEL", count=expected_repetitions, status=409, disclosure_fields=[]
    )
    for name in ("baseline", "remediated", "measurement"):
        checks[f"{name}_current_o"] = case_matches(
            results[name], "O_CURRENT", count=expected_repetitions, status=200, disclosure_fields=["age_over_18"]
        )
        checks[f"{name}_cached_c"] = case_matches(
            results[name], "C_OFFLINE", count=expected_repetitions, status=200, disclosure_fields=["age_over_18"]
        )
    checks["offline_cached_c"] = case_matches(
        results["offline_c"], "C_OFFLINE", count=expected_repetitions, status=200, disclosure_fields=["age_over_18"]
    )

    current_o = {
        "route": "O*",
        "status": 200,
        "disclosure_fields": ["age_over_18"],
        "signature_verified": True,
        "issuer_verified": True,
        "evidence_present": True,
    }
    cached_c = {
        "route": "C",
        "status": 200,
        "disclosure_fields": ["age_over_18"],
        "signature_verified": True,
        "issuer_verified": True,
        "evidence_present": True,
        "source_requests_required": 0,
    }
    record_expectations = {
        "baseline": {
            "R_CURRENT": {
                "route": "R", "status": 200, "disclosure_fields": ["birth_date"],
                "signature_verified": True, "issuer_verified": True, "evidence_present": True,
                "warning": "ROUTE_DENIED_OBSERVED",
            },
            "O_CURRENT": current_o,
            "O_STALE_MODEL": {
                **current_o,
                "warning": "STALE_POLICY_OBSERVED",
            },
            "C_OFFLINE": cached_c,
        },
        "remediated": {
            "R_CURRENT": {
                "route": "R", "status": 403, "disclosure_fields": [],
                "signature_verified": False, "issuer_verified": False, "evidence_present": False,
                "reason": "ROUTE_DENIED",
            },
            "O_CURRENT": current_o,
            "O_STALE_MODEL": {
                "route": "O*", "status": 409, "disclosure_fields": [],
                "signature_verified": False, "issuer_verified": False, "evidence_present": False,
                "reason": "STALE_POLICY_MODEL",
            },
            "C_OFFLINE": cached_c,
        },
        "measurement": {
            "R_CURRENT": {
                "route": "R", "status": 200, "disclosure_fields": ["birth_date"],
                "signature_verified": True, "issuer_verified": True, "evidence_present": True,
            },
            "O_CURRENT": current_o,
            "O_STALE_MODEL": {
                "route": "O*", "status": 409, "disclosure_fields": [],
                "signature_verified": False, "issuer_verified": False, "evidence_present": False,
                "reason": "STALE_POLICY_MODEL",
            },
            "C_OFFLINE": cached_c,
        },
        "offline_c": {"C_OFFLINE": cached_c},
    }
    for name, expectations in record_expectations.items():
        checks[f"{name}_record_semantics"] = records_match(
            results[name], expectations, expected_repetitions=expected_repetitions
        )

    checks["all_successful_evidence_has_issuer_binding"] = all(
        record.get("status") != 200
        or (
            record.get("signature_verified") is True
            and record.get("issuer_verified") is True
        )
        for result in results.values()
        for record in result.get("records", [])
    )
    return checks


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate the complete registered two-host result set")
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--remediated", type=Path, required=True)
    parser.add_argument("--measurement", type=Path, required=True)
    parser.add_argument("--offline-c", type=Path, required=True)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--expected-repetitions", type=int, default=10)
    parser.add_argument("--expected-source-port", type=int, default=18080)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error(f"refusing to overwrite existing validation: {args.output}")
    paths = {
        "baseline": args.baseline,
        "remediated": args.remediated,
        "measurement": args.measurement,
        "offline_c": args.offline_c,
    }
    results = {name: load_result(path) for name, path in paths.items()}
    events = load_events(args.events)
    checks = validate_result_set(
        results,
        expected_repetitions=args.expected_repetitions,
        expected_source_port=args.expected_source_port,
    )
    checks.update(validate_event_log(events, expected_repetitions=args.expected_repetitions))
    value = {
        "schema_version": 1,
        "experiment": "jip-two-physical-host-remediation-final-validation",
        "input_sha256": {
            name: hashlib.sha256(path.read_bytes()).hexdigest()
            for name, path in paths.items()
        },
        "event_log_sha256": hashlib.sha256(args.events.read_bytes()).hexdigest(),
        "checks": checks,
        "all_registered_checks_passed": all(checks.values()),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    print(json.dumps({"output": str(args.output), "sha256": digest, "passed": value["all_registered_checks_passed"]}))
    if not value["all_registered_checks_passed"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
