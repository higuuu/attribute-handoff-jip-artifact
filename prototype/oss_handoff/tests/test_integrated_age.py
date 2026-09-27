from __future__ import annotations

import os
from datetime import date

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec

from prototype.oss_handoff.crypto_utils import public_jwk, sign_es256
from prototype.oss_handoff.integrated_age.core import KEY_ID, issue_bound_assertion, verify_bound_assertion
from prototype.oss_handoff.integrated_age.prepare import prepare_realm
from prototype.oss_handoff.live_age.core import SOURCE_AUDIENCE
from prototype.oss_handoff.two_host.pep import evaluate_handoff


def synthetic_source_token(audience: str = SOURCE_AUDIENCE) -> tuple[str, dict[str, object], str]:
    key = ec.generate_private_key(ec.SECP256R1())
    jwk = {**public_jwk(key), "kid": "source"}
    issuer = "http://127.0.0.1:18880/realms/live-age"
    token = sign_es256(
        {"alg": "ES256", "kid": "source"},
        {"iss": issuer, "aud": audience, "sub": "synthetic-user",
         "birth_date": "2008-09-27", "iat": 1000, "exp": 2000},
        key,
    )
    return token, {"keys": [jwk]}, issuer


def test_bound_assertion_derives_without_dob_and_checks_nonce() -> None:
    token, jwks, issuer = synthetic_source_token()
    key = ec.generate_private_key(ec.SECP256R1())
    assertion, claims = issue_bound_assertion(
        token, jwks, source_issuer=issuer, signing_key=key,
        subject_salt=os.urandom(32), as_of=date(2026, 9, 27),
        issued_at=1100, nonce="random-request-id",
    )
    destination_jwk = {**public_jwk(key), "kid": KEY_ID}
    verified = verify_bound_assertion(assertion, destination_jwk, nonce="random-request-id", now=1100)
    assert verified == claims
    assert verified["age_over_18"] is True
    assert "birth_date" not in verified
    assert "2008-09-27" not in assertion
    with pytest.raises(ValueError, match="nonce"):
        verify_bound_assertion(assertion, destination_jwk, nonce="different", now=1100)
    with pytest.raises(ValueError, match="expired"):
        verify_bound_assertion(assertion, destination_jwk, nonce="random-request-id", now=1220)


def test_source_token_tamper_and_wrong_issuer_fail_closed() -> None:
    token, jwks, issuer = synthetic_source_token()
    key = ec.generate_private_key(ec.SECP256R1())
    signed, signature = token.rsplit(".", 1)
    bad = signed + "." + ("A" if signature[0] != "A" else "B") + signature[1:]
    kwargs = dict(source_issuer=issuer, signing_key=key, subject_salt=os.urandom(32),
                  as_of=date(2026, 9, 27), issued_at=1100, nonce="request")
    with pytest.raises(InvalidSignature):
        issue_bound_assertion(bad, jwks, **kwargs)
    with pytest.raises(ValueError, match="issuer"):
        issue_bound_assertion(token, jwks, **{**kwargs, "source_issuer": "wrong"})
    wrong_audience_token, wrong_audience_jwks, _ = synthetic_source_token("wrong-audience")
    with pytest.raises(ValueError, match="audience"):
        issue_bound_assertion(wrong_audience_token, wrong_audience_jwks, **kwargs)


def test_live_route_policy_denial_and_stale_stop_before_issuer() -> None:
    config = {"phase": "test", "enforcement_mode": "enforce", "audience": "region-b-service",
              "purpose": "regional-service-eligibility", "policy_model_id": "current"}
    request = {"request_id": "request-1", "route": "O_live", "audience": config["audience"],
               "purpose": config["purpose"], "policy_model_id": "current"}
    calls: list[str] = []

    def policy(_config, route):  # noqa: ANN001, ANN202
        calls.append("policy:" + route)
        return False, 1.0

    def issuer(_config, _route):  # noqa: ANN001, ANN202
        calls.append("issuer")
        raise AssertionError("must not issue")

    denied = evaluate_handoff(request, config=config, request_bytes=100, policy_check=policy, issue_evidence=issuer)
    assert denied.status == 403 and denied.event["issuer_called"] is False
    assert calls == ["policy:O"]
    calls.clear()
    stale = evaluate_handoff(
        {**request, "policy_model_id": "old"}, config=config, request_bytes=100,
        policy_check=policy, issue_evidence=issuer,
    )
    assert stale.status == 409 and stale.event["policy_called"] is False
    assert calls == []


def test_generated_realm_has_no_stored_predicate(tmp_path) -> None:  # noqa: ANN001
    from prototype.oss_handoff.integrated_age.prepare import SOURCE_REALM

    target = tmp_path / "realm.json"
    prepare_realm(SOURCE_REALM, target)
    import json
    realm = json.loads(target.read_text())
    assert "age_over_18" not in realm["users"][0]["attributes"]
    clients = {client["clientId"]: client for client in realm["clients"]}
    assert set(clients) == {"source-internal-adapter", "region-b-raw"}
    audiences = [mapper["config"].get("included.client.audience")
                 for mapper in clients["region-b-raw"]["protocolMappers"]]
    assert "region-b-service" in audiences
