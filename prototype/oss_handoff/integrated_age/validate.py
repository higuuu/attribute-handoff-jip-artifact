"""Cross-check the registered two-phase response and PEP event matrix."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from prototype.oss_handoff.two_host.common import write_json_atomic


EXPECTED = {
    ("baseline", "R_CURRENT"): (200, True, True, ["birth_date"]),
    ("baseline", "O_LIVE_STALE"): (200, True, True, ["age_over_18"]),
    ("baseline", "O_LIVE_CURRENT"): (200, True, True, ["age_over_18"]),
    ("enforced", "R_CURRENT"): (403, True, False, []),
    ("enforced", "O_LIVE_STALE"): (409, False, False, []),
    ("enforced", "O_LIVE_CURRENT"): (200, True, True, ["age_over_18"]),
}


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"expected object: {path}")
    return value


def validate(
    baseline: dict[str, Any], enforced: dict[str, Any],
    boundary: dict[str, Any], events: list[dict[str, Any]],
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    checks["phase_names"] = baseline.get("phase") == "baseline" and enforced.get("phase") == "enforced"
    checks["modes"] = baseline.get("enforcement_mode") == "observe-only" and enforced.get("enforcement_mode") == "enforce"
    checks["same_model"] = baseline.get("model_id_sha256") == enforced.get("model_id_sha256")
    checks["same_adapter_key"] = baseline.get("adapter_jwk_sha256") == enforced.get("adapter_jwk_sha256")
    checks["same_implementation"] = baseline.get("implementation_commit") == enforced.get("implementation_commit")
    checks["same_realm"] = baseline.get("realm_sha256") == enforced.get("realm_sha256")
    checks["same_source"] = baseline.get("source_host_sha256") == enforced.get("source_host_sha256")
    checks["same_client"] = baseline.get("client_host_sha256") == enforced.get("client_host_sha256")
    checks["both_individual_pass"] = baseline.get("all_expectations_passed") is True and enforced.get("all_expectations_passed") is True
    checks["negative_controls"] = all(
        result.get("controls") == {"wrong_nonce_rejected": True, "tampered_assertion_rejected": True}
        for result in (baseline, enforced)
    )
    checks["fixed_calendar_control"] = (
        boundary.get("all_expectations_passed") is True
        and boundary.get("actual_keycloak_source_token_used") is True
        and boundary.get("realm_sha256") == baseline.get("realm_sha256")
        and [(case.get("case"), case.get("observed"), case.get("pass")) for case in boundary.get("cases", [])]
        == [
            ("before_18th_birthday", False, True),
            ("on_18th_birthday", True, True),
            ("after_18th_birthday", True, True),
        ]
    )
    expected_events = {}
    for result in (baseline, enforced):
        phase = result.get("phase")
        for record in result.get("records", []):
            request_id = record.get("request_id")
            if not isinstance(request_id, str) or request_id in expected_events:
                checks["unique_request_ids"] = False
                continue
            expected_events[request_id] = (phase, record)
    checks.setdefault("unique_request_ids", True)
    repetitions = baseline.get("parameters", {}).get("repetitions")
    checks["same_repetition_count"] = isinstance(repetitions, int) and repetitions == enforced.get("parameters", {}).get("repetitions")
    checks["registered_counts"] = all(
        sum(record.get("case") == case for record in result.get("records", [])) == repetitions
        for result in (baseline, enforced) for case in ("R_CURRENT", "O_LIVE_STALE", "O_LIVE_CURRENT")
    )
    checks["event_count"] = len(events) == len(expected_events) == 6 * repetitions if isinstance(repetitions, int) else False
    event_by_id = {event.get("request_id"): event for event in events}
    checks["event_id_match"] = len(event_by_id) == len(events) and set(event_by_id) == set(expected_events)
    for request_id, (phase, record) in expected_events.items():
        case = record.get("case")
        expectation = EXPECTED.get((phase, case))
        event = event_by_id.get(request_id)
        if expectation is None or event is None:
            checks[f"event:{request_id}"] = False
            continue
        status, policy_called, issuer_called, fields = expectation
        checks[f"event:{request_id}"] = (
            record.get("status") == status
            and record.get("disclosure_fields") == fields
            and event.get("status") == status
            and event.get("phase") == phase
            and event.get("route") == record.get("route")
            and event.get("policy_called") is policy_called
            and event.get("issuer_called") is issuer_called
            and event.get("disclosure_fields") == fields
            and event.get("evidence_bytes") == record.get("evidence_bytes")
        )
    return {
        "experiment": "integrated-live-age-handoff-validation",
        "checks_total": len(checks),
        "checks_passed": sum(checks.values()),
        "all_passed": all(checks.values()),
        "failed_checks": sorted(key for key, passed in checks.items() if not passed),
        "event_count": len(events),
        "baseline_records": len(baseline.get("records", [])),
        "enforced_records": len(enforced.get("records", [])),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--enforced", type=Path, required=True)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--boundary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("refusing to overwrite existing validator output")
    baseline = load(args.baseline)
    enforced = load(args.enforced)
    events = [json.loads(line) for line in args.events.read_text().splitlines() if line.strip()]
    result = validate(baseline, enforced, load(args.boundary), events)
    result["input_sha256"] = {
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in (("baseline", args.baseline), ("enforced", args.enforced),
                           ("boundary", args.boundary), ("events", args.events))
    }
    write_json_atomic(args.output, result)
    print(json.dumps({"output": str(args.output), "sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(), **{key: result[key] for key in ("checks_total", "checks_passed", "all_passed")}}))
    if not result["all_passed"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
