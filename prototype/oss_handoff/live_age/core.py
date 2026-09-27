"""Request-time derivation in a source adapter; no raw attribute leaves it."""

from __future__ import annotations

import hashlib
import hmac
from datetime import date
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from prototype.oss_handoff.crypto_utils import sign_es256, verify_jwt


SOURCE_AUDIENCE = "source-internal-adapter"
DESTINATION_AUDIENCE = "region-b-service"
ASSERTION_ISSUER = "urn:synthetic:source-age-adapter"
ASSERTION_FIELDS = frozenset({"iss", "aud", "sub", "age_over_18", "iat", "exp"})


def over_18(birth_date: str, as_of: date) -> bool:
    """Attained age; Feb 29 maps to Mar 1 in a non-leap year."""

    if type(birth_date) is not str or len(birth_date) != 10:
        raise ValueError("invalid birth date")
    try:
        parsed = date.fromisoformat(birth_date)
    except ValueError as error:
        raise ValueError("invalid birth date") from error
    if parsed.isoformat() != birth_date or parsed > as_of:
        raise ValueError("invalid or future birth date")
    try:
        eighteenth_birthday = parsed.replace(year=parsed.year + 18)
    except ValueError:
        eighteenth_birthday = date(parsed.year + 18, 3, 1)
    return as_of >= eighteenth_birthday


def issue_for_verified_source_token(
    source_token: str,
    source_jwks: dict[str, Any],
    *,
    source_issuer: str,
    signing_key: ec.EllipticCurvePrivateKey,
    subject_salt: bytes,
    as_of: date,
    issued_at: int,
) -> str:
    """Validate the raw source JWT, then emit only a signed predicate."""

    if len(subject_salt) < 32:
        raise ValueError("subject salt too short")
    claims = verify_jwt(
        source_token,
        source_jwks,
        audience=SOURCE_AUDIENCE,
        issuer=source_issuer,
        now=issued_at,
    )
    if not isinstance(claims.get("exp"), int) or not isinstance(claims.get("iat"), int):
        raise ValueError("source token missing integer validity claims")
    if claims["iat"] > issued_at + 60:
        raise ValueError("source token issued in the future")
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject:
        raise ValueError("source token missing subject")
    predicate = over_18(claims.get("birth_date"), as_of)
    pseudonym = hmac.new(subject_salt, subject.encode(), hashlib.sha256).hexdigest()
    return sign_es256(
        {"alg": "ES256", "typ": "JWT", "kid": "live-age-local"},
        {
            "iss": ASSERTION_ISSUER,
            "aud": DESTINATION_AUDIENCE,
            "sub": pseudonym,
            "age_over_18": predicate,
            "iat": issued_at,
            "exp": issued_at + 120,
        },
        signing_key,
    )


def verify_destination_assertion(
    assertion: str, jwk: dict[str, Any], *, now: int
) -> dict[str, Any]:
    claims = verify_jwt(
        assertion,
        {"keys": [jwk]},
        audience=DESTINATION_AUDIENCE,
        issuer=ASSERTION_ISSUER,
        now=now,
    )
    if set(claims) != ASSERTION_FIELDS:
        raise ValueError("unexpected assertion claims")
    if type(claims["age_over_18"]) is not bool:
        raise ValueError("age predicate is not boolean")
    if not isinstance(claims["sub"], str) or len(claims["sub"]) != 64:
        raise ValueError("invalid pseudonym")
    if type(claims["iat"]) is not int or type(claims["exp"]) is not int:
        raise ValueError("invalid validity claims")
    if claims["exp"] - claims["iat"] != 120 or now < claims["iat"] - 60:
        raise ValueError("invalid assertion lifetime")
    return claims
