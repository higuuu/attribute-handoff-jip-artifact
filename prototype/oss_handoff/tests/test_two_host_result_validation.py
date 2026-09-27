from __future__ import annotations

from copy import deepcopy
from typing import Any

from prototype.oss_handoff.two_host.validate_results import (
    ONLINE_EVENT_EXPECTATIONS,
    validate_event_log,
    validate_result_set,
)


REPETITIONS = 10


def summary_case(status: int, fields: list[str]) -> dict[str, Any]:
    return {
        "count": REPETITIONS,
        "status_counts": {str(status): REPETITIONS},
        "disclosure_fields": fields,
        "expectations_passed": True,
    }


def result(phase: str, model: str, *, offline: bool = False) -> dict[str, Any]:
    if offline:
        summary = {"C_OFFLINE": summary_case(200, ["age_over_18"])}
    else:
        r_status = 403 if phase == "remediated-deny-raw" else 200
        r_fields = [] if r_status == 403 else ["birth_date"]
        stale_status = 200 if phase == "baseline-deny-raw" else 409
        stale_fields = ["age_over_18"] if stale_status == 200 else []
        summary = {
            "R_CURRENT": summary_case(r_status, r_fields),
            "O_CURRENT": summary_case(200, ["age_over_18"]),
            "O_STALE_MODEL": summary_case(stale_status, stale_fields),
            "C_OFFLINE": summary_case(200, ["age_over_18"]),
        }
    records = []
    for case, item in summary.items():
        status = int(next(iter(item["status_counts"])))
        for repetition in range(1, REPETITIONS + 1):
            route = "R" if case == "R_CURRENT" else "C" if case == "C_OFFLINE" else "O*"
            record = {
                "case": case,
                "repetition": repetition,
                "route": route,
                "status": status,
                "disclosure_fields": item["disclosure_fields"],
                "signature_verified": status == 200,
                "issuer_verified": status == 200,
                "evidence_bytes": 300 if status == 200 else 0,
                "warnings": [],
                "reason": None,
                "expected": True,
            }
            if phase == "baseline-deny-raw" and case == "R_CURRENT":
                record["warnings"] = ["ROUTE_DENIED_OBSERVED"]
            if phase == "baseline-deny-raw" and case == "O_STALE_MODEL":
                record["warnings"] = ["STALE_POLICY_OBSERVED"]
            if case == "R_CURRENT" and status == 403:
                record["reason"] = "ROUTE_DENIED"
            if case == "O_STALE_MODEL" and status == 409:
                record["reason"] = "STALE_POLICY_MODEL"
            if case == "C_OFFLINE":
                record["source_requests_required"] = 0
            records.append(record)
    probe = {
        "reachable": False,
        "target_port": 18080,
        "target_host_sha256": "c" * 64,
    }
    if not offline:
        probe["target_matches_pep"] = True
    return {
        "phase": phase,
        "all_expectations_passed": True,
        "policy_model_id_sha256": model,
        "summary": summary,
        "records": records,
        "direct_source_probe": probe,
        "environment": {
            "source_host_sha256": "d" * 64,
            "client_host_sha256": "e" * 64,
            "host_separation_observed": True,
        },
        "parameters": {
            "repetitions": REPETITIONS,
            "air_runner_sha256": "b" * 64,
            "tls_ca_bundle_sha256": "9" * 64,
            "implementation_commit": "a" * 40,
            "c_bundle_sha256": "f" * 64,
            "c_credential_issued_at": 1_000,
            "c_credential_expires_at": 8_200,
            "c_credential_lifetime_seconds": 7_200,
            "c_credential_seconds_remaining_at_start": 6_900,
        },
        "claim_boundary": {"separate_physical_hosts": True},
    }


def valid_results() -> dict[str, dict[str, Any]]:
    return {
        "baseline": result("baseline-deny-raw", "1" * 64),
        "remediated": result("remediated-deny-raw", "1" * 64),
        "measurement": result("measurement-allow-r-o-c", "2" * 64),
        "offline_c": result("c-source-offline", "3" * 64, offline=True),
    }


def valid_events() -> list[dict[str, Any]]:
    events = []
    for phase, cases in ONLINE_EVENT_EXPECTATIONS.items():
        for case, expectation in cases.items():
            for repetition in range(1, REPETITIONS + 1):
                events.append(
                    {
                        "request_id": f"{phase}:{case}:{repetition:03d}",
                        "phase": phase,
                        "route": expectation["route"],
                        "status": expectation["status"],
                        "decision": expectation["decision"],
                        "warnings": expectation["warnings"],
                        "policy_called": expectation["policy_called"],
                        "issuer_called": expectation["issuer_called"],
                        "evidence_bytes": 300 if expectation["evidence_present"] else 0,
                        "disclosure_fields": expectation["disclosure_fields"],
                    }
                )
    return events


def test_complete_registered_result_set_passes() -> None:
    checks = validate_result_set(valid_results(), expected_repetitions=10, expected_source_port=18080)
    assert all(checks.values())


def test_changed_deny_model_is_rejected() -> None:
    results = deepcopy(valid_results())
    results["remediated"]["policy_model_id_sha256"] = "4" * 64
    checks = validate_result_set(results, expected_repetitions=10, expected_source_port=18080)
    assert checks["same_deny_model"] is False


def test_changed_tls_ca_bundle_is_rejected() -> None:
    results = deepcopy(valid_results())
    results["measurement"]["parameters"]["tls_ca_bundle_sha256"] = "8" * 64
    checks = validate_result_set(results, expected_repetitions=10, expected_source_port=18080)
    assert checks["one_tls_ca_bundle"] is False


def test_missing_direct_probe_is_rejected() -> None:
    results = deepcopy(valid_results())
    results["offline_c"]["direct_source_probe"] = None
    checks = validate_result_set(results, expected_repetitions=10, expected_source_port=18080)
    assert checks["offline_c_source_unreachable"] is False


def test_tampered_record_is_rejected_even_if_summary_still_passes() -> None:
    results = deepcopy(valid_results())
    results["remediated"]["records"][0]["evidence_bytes"] = 100
    checks = validate_result_set(results, expected_repetitions=10, expected_source_port=18080)
    assert checks["remediated_record_semantics"] is False


def test_registered_pep_events_pass() -> None:
    assert all(validate_event_log(valid_events(), expected_repetitions=10).values())


def test_missing_or_changed_pep_event_is_rejected() -> None:
    events = valid_events()
    events[0]["issuer_called"] = False
    checks = validate_event_log(events, expected_repetitions=10)
    assert checks["event_semantics"] is False
    assert validate_event_log(events[:-1], expected_repetitions=10)["event_ids_exact"] is False
