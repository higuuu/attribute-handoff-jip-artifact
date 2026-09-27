from __future__ import annotations

import ssl
from unittest import mock

from prototype.oss_handoff.two_host.air_runner import expected, probe_matches_pep, request_json, summarize


def base_record(case: str, status: int, **updates):  # noqa: ANN003,ANN201
    value = {
        "case": case,
        "status": status,
        "signature_verified": False,
        "issuer_verified": False,
        "disclosure_fields": [],
        "warnings": [],
        "reason": None,
        "evidence_bytes": 0,
        "elapsed_ms": 1.0,
        "request_bytes": 100,
        "response_bytes": 200,
    }
    value.update(updates)
    return value


def test_expectations_capture_fail_to_pass_delta() -> None:
    baseline = {"enforcement_mode": "observe-only", "allowed_routes": ["O", "C"]}
    remediated = {"enforcement_mode": "enforce", "allowed_routes": ["O", "C"]}
    assert expected(
        base_record(
            "R_CURRENT",
            200,
            signature_verified=True,
            issuer_verified=True,
            disclosure_fields=["birth_date"],
            warnings=["ROUTE_DENIED_OBSERVED"],
            evidence_bytes=300,
        ),
        baseline,
    )
    assert expected(base_record("R_CURRENT", 403, reason="ROUTE_DENIED"), remediated)
    assert expected(
        base_record(
            "O_STALE_MODEL",
            200,
            signature_verified=True,
            issuer_verified=True,
            disclosure_fields=["age_over_18"],
            evidence_bytes=300,
            warnings=["STALE_POLICY_OBSERVED"],
        ),
        baseline,
    )
    assert expected(base_record("O_STALE_MODEL", 409, reason="STALE_POLICY_MODEL"), remediated)


def test_stale_baseline_requires_valid_issuer_bound_evidence() -> None:
    baseline = {"enforcement_mode": "observe-only", "allowed_routes": ["O", "C"]}
    invalid = base_record(
        "O_STALE_MODEL",
        200,
        warnings=["STALE_POLICY_OBSERVED"],
    )
    assert expected(invalid, baseline) is False


def test_summary_reports_latency_bytes_and_semantic_fields() -> None:
    records = [
        {
            **base_record(
                "O_CURRENT",
                200,
                signature_verified=True,
                issuer_verified=True,
                disclosure_fields=["age_over_18"],
                evidence_bytes=300,
            ),
            "expected": True,
        },
        {
            **base_record(
                "O_CURRENT",
                200,
                signature_verified=True,
                issuer_verified=True,
                disclosure_fields=["age_over_18"],
                evidence_bytes=320,
                elapsed_ms=3.0,
            ),
            "expected": True,
        },
    ]
    summary = summarize(records)["O_CURRENT"]
    assert summary["latency_ms"]["p50"] == 2.0
    assert summary["evidence_bytes_p50"] == 310
    assert summary["disclosure_fields"] == ["age_over_18"]
    assert summary["expectations_passed"] is True


def test_direct_probe_target_must_match_pep_address() -> None:
    assert probe_matches_pep("https://127.0.0.1", "http://127.0.0.1:18080/realms/region-a") is True
    assert probe_matches_pep("https://127.0.0.1", "http://127.0.0.2:18080/realms/region-a") is False


def test_https_requests_use_explicit_verified_ca_context() -> None:
    response = mock.MagicMock()
    response.status = 200
    response.read.return_value = b"{}"
    response.__enter__.return_value = response
    with mock.patch(
        "prototype.oss_handoff.two_host.air_runner.urllib.request.urlopen",
        return_value=response,
    ) as urlopen:
        status, value, _, _, error = request_json("https://pep.example.test/v1/config")

    assert status == 200
    assert value == {}
    assert error is None
    context = urlopen.call_args.kwargs["context"]
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert context.get_ca_certs()
