from __future__ import annotations

from typing import Any

from prototype.oss_handoff.two_host.pep import evaluate_handoff


def config(mode: str = "enforce") -> dict[str, Any]:
    return {
        "phase": "test",
        "enforcement_mode": mode,
        "audience": "region-b-service",
        "purpose": "regional-service-eligibility",
        "policy_model_id": "model-current",
    }


def request(*, route: str = "R", model: str = "model-current") -> dict[str, Any]:
    return {
        "request_id": "test-001",
        "route": route,
        "audience": "region-b-service",
        "purpose": "regional-service-eligibility",
        "policy_model_id": model,
    }


def test_enforced_policy_denial_never_calls_issuer() -> None:
    calls = {"policy": 0, "issuer": 0}

    def deny(_config: dict[str, Any], _route: str) -> tuple[bool, float]:
        calls["policy"] += 1
        return False, 1.0

    def issuer(_config: dict[str, Any], _route: str):  # noqa: ANN202
        calls["issuer"] += 1
        raise AssertionError("issuer must not be called")

    result = evaluate_handoff(
        request(),
        config=config("enforce"),
        request_bytes=100,
        policy_check=deny,
        issue_evidence=issuer,
    )
    assert result.status == 403
    assert result.body["error"] == "ROUTE_DENIED"
    assert result.event["evidence_bytes"] == 0
    assert result.event["policy_called"] is True
    assert result.event["issuer_called"] is False
    assert calls == {"policy": 1, "issuer": 0}


def test_observe_only_reproduces_policy_bypass_without_logging_token() -> None:
    calls = {"policy": 0, "issuer": 0}

    def deny(_config: dict[str, Any], _route: str) -> tuple[bool, float]:
        calls["policy"] += 1
        return False, 1.0

    def issuer(_config: dict[str, Any], _route: str) -> tuple[str, dict[str, Any], float]:
        calls["issuer"] += 1
        return "synthetic.signed.token", {"birth_date": "2000-01-01"}, 2.0

    result = evaluate_handoff(
        request(),
        config=config("observe-only"),
        request_bytes=100,
        policy_check=deny,
        issue_evidence=issuer,
    )
    assert result.status == 200
    assert result.body["evidence"] == "synthetic.signed.token"
    assert result.body["warnings"] == ["ROUTE_DENIED_OBSERVED"]
    assert result.event["disclosure_fields"] == ["birth_date"]
    assert result.event["issuer_called"] is True
    assert "evidence" not in result.event
    assert "token" not in result.event
    assert calls == {"policy": 1, "issuer": 1}


def test_enforced_stale_model_rejects_before_policy_and_issuer() -> None:
    calls = {"policy": 0, "issuer": 0}

    def policy(_config: dict[str, Any], _route: str) -> tuple[bool, float]:
        calls["policy"] += 1
        return True, 1.0

    def issuer(_config: dict[str, Any], _route: str):  # noqa: ANN202
        calls["issuer"] += 1
        raise AssertionError("issuer must not be called")

    result = evaluate_handoff(
        request(route="O*", model="model-stale"),
        config=config("enforce"),
        request_bytes=100,
        policy_check=policy,
        issue_evidence=issuer,
    )
    assert result.status == 409
    assert result.body["error"] == "STALE_POLICY_MODEL"
    assert result.event["evidence_bytes"] == 0
    assert result.event["policy_called"] is False
    assert result.event["issuer_called"] is False
    assert calls == {"policy": 0, "issuer": 0}


def test_observe_only_reproduces_stale_detection_without_rejection() -> None:
    def policy(_config: dict[str, Any], route: str) -> tuple[bool, float]:
        assert route == "O"
        return True, 1.0

    def issuer(_config: dict[str, Any], route: str) -> tuple[str, dict[str, Any], float]:
        assert route == "O*"
        return "synthetic.signed.token", {"age_over_18": True}, 2.0

    result = evaluate_handoff(
        request(route="O*", model="model-stale"),
        config=config("observe-only"),
        request_bytes=100,
        policy_check=policy,
        issue_evidence=issuer,
    )
    assert result.status == 200
    assert result.body["warnings"] == ["STALE_POLICY_OBSERVED"]
    assert result.event["disclosure_fields"] == ["age_over_18"]


def test_audience_and_purpose_are_enforced_even_in_observe_only_mode() -> None:
    for field in ("audience", "purpose"):
        value = request()
        value[field] = "wrong"
        result = evaluate_handoff(
            value,
            config=config("observe-only"),
            request_bytes=100,
            policy_check=lambda *_: (_ for _ in ()).throw(AssertionError("policy called")),
            issue_evidence=lambda *_: (_ for _ in ()).throw(AssertionError("issuer called")),
        )
        assert result.status == 403


def test_policy_failure_is_fail_closed_in_both_modes() -> None:
    for mode in ("observe-only", "enforce"):
        result = evaluate_handoff(
            request(route="O*"),
            config=config(mode),
            request_bytes=100,
            policy_check=lambda *_: (_ for _ in ()).throw(RuntimeError("down")),
            issue_evidence=lambda *_: (_ for _ in ()).throw(AssertionError("issuer called")),
        )
        assert result.status == 503
        assert result.body["error"] == "POLICY_UNAVAILABLE"
