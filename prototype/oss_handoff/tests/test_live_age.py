from __future__ import annotations

import os
from datetime import date

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from prototype.oss_handoff.crypto_utils import public_jwk, sign_es256
from prototype.oss_handoff.live_age.core import (
    DESTINATION_AUDIENCE,
    SOURCE_AUDIENCE,
    issue_for_verified_source_token,
    over_18,
    verify_destination_assertion,
)


@pytest.mark.parametrize(
    ("birth", "as_of", "expected"),
    [
        ("2008-09-27", date(2026, 9, 26), False),
        ("2008-09-27", date(2026, 9, 27), True),
        ("2008-09-27", date(2026, 9, 28), True),
        ("2008-02-29", date(2026, 2, 28), False),
        ("2008-02-29", date(2026, 3, 1), True),
    ],
)
def test_boundary(birth: str, as_of: date, expected: bool) -> None:
    assert over_18(birth, as_of) is expected


@pytest.mark.parametrize("birth", [None, "", "2008-02-30", "2008-9-27", "2027-01-01"])
def test_invalid_birth_date_fails_closed(birth: str | None) -> None:
    with pytest.raises(ValueError):
        over_18(birth, date(2026, 9, 27))


def test_source_derives_and_destination_verifies_without_dob() -> None:
    source_key = ec.generate_private_key(ec.SECP256R1())
    source_jwk = public_jwk(source_key)
    source_jwk["kid"] = "source-key"
    issuer = "http://127.0.0.1:18880/realms/live-age"
    source_token = sign_es256(
        {"alg": "ES256", "kid": "source-key"},
        {
            "iss": issuer, "aud": SOURCE_AUDIENCE, "sub": "synthetic-user",
            "birth_date": "2008-09-27", "iat": 1000, "exp": 2000,
        },
        source_key,
    )
    destination_key = ec.generate_private_key(ec.SECP256R1())
    assertion = issue_for_verified_source_token(
        source_token, {"keys": [source_jwk]}, source_issuer=issuer,
        signing_key=destination_key, subject_salt=os.urandom(32),
        as_of=date(2026, 9, 27), issued_at=1100,
    )
    destination_jwk = public_jwk(destination_key)
    destination_jwk["kid"] = "live-age-local"
    claims = verify_destination_assertion(assertion, destination_jwk, now=1100)
    assert claims["age_over_18"] is True
    assert claims["aud"] == DESTINATION_AUDIENCE
    assert "birth_date" not in claims
    assert "synthetic-user" not in claims.values()
    with pytest.raises(ValueError, match="expired"):
        verify_destination_assertion(assertion, destination_jwk, now=1220)
    with pytest.raises(Exception):
        wrong_key = public_jwk(ec.generate_private_key(ec.SECP256R1()))
        wrong_key["kid"] = "live-age-local"
        verify_destination_assertion(assertion, wrong_key, now=1100)


def test_near_expiry_source_token_cannot_issue_longer_lived_assertion() -> None:
    source_key = ec.generate_private_key(ec.SECP256R1())
    source_jwk = public_jwk(source_key)
    source_jwk["kid"] = "source-key"
    issuer = "http://127.0.0.1:18880/realms/live-age"
    source_token = sign_es256(
        {"alg": "ES256", "kid": "source-key"},
        {
            "iss": issuer, "aud": SOURCE_AUDIENCE, "sub": "synthetic-user",
            "birth_date": "2008-09-27", "iat": 1000, "exp": 1150,
        },
        source_key,
    )
    with pytest.raises(ValueError, match="expires before assertion"):
        issue_for_verified_source_token(
            source_token, {"keys": [source_jwk]}, source_issuer=issuer,
            signing_key=ec.generate_private_key(ec.SECP256R1()),
            subject_salt=os.urandom(32), as_of=date(2026, 9, 27),
            issued_at=1100,
        )


def test_destination_rejects_extra_audience() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    jwk = public_jwk(key)
    jwk["kid"] = "live-age-local"
    assertion = sign_es256(
        {"alg": "ES256", "kid": "live-age-local"},
        {
            "iss": "urn:synthetic:source-age-adapter",
            "aud": [DESTINATION_AUDIENCE, "other-service"],
            "sub": "a" * 64, "age_over_18": True,
            "iat": 1100, "exp": 1220,
        },
        key,
    )
    with pytest.raises(ValueError, match="exactly one"):
        verify_destination_assertion(assertion, jwk, now=1100)
