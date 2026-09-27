"""A nonce-bound destination assertion derived inside the source boundary."""

from __future__ import annotations

from datetime import date
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from prototype.oss_handoff.crypto_utils import sign_es256, verify_jwt
from prototype.oss_handoff.live_age.core import (
    ASSERTION_ISSUER,
    DESTINATION_AUDIENCE,
    derive_verified_source_predicate,
)


BOUND_FIELDS = frozenset({"iss", "aud", "sub", "age_over_18", "iat", "exp", "nonce"})
KEY_ID = "integrated-age-ephemeral"


def issue_bound_assertion(
    source_token: str,
    source_jwks: dict[str, Any],
    *,
    source_issuer: str,
    signing_key: ec.EllipticCurvePrivateKey,
    subject_salt: bytes,
    as_of: date,
    issued_at: int,
    nonce: str,
) -> tuple[str, dict[str, Any]]:
    if not isinstance(nonce, str) or not 1 <= len(nonce) <= 128:
        raise ValueError("invalid nonce")
    pseudonym, predicate = derive_verified_source_predicate(
        source_token,
        source_jwks,
        source_issuer=source_issuer,
        subject_salt=subject_salt,
        as_of=as_of,
        issued_at=issued_at,
    )
    claims = {
        "iss": ASSERTION_ISSUER,
        "aud": DESTINATION_AUDIENCE,
        "sub": pseudonym,
        "age_over_18": predicate,
        "iat": issued_at,
        "exp": issued_at + 120,
        "nonce": nonce,
    }
    return sign_es256({"alg": "ES256", "typ": "JWT", "kid": KEY_ID}, claims, signing_key), claims


def verify_bound_assertion(
    assertion: str,
    jwk: dict[str, Any],
    *,
    nonce: str,
    now: int,
) -> dict[str, Any]:
    claims = verify_jwt(
        assertion,
        {"keys": [jwk]},
        audience=DESTINATION_AUDIENCE,
        issuer=ASSERTION_ISSUER,
        now=now,
    )
    if set(claims) != BOUND_FIELDS:
        raise ValueError("unexpected assertion fields")
    if claims["aud"] != DESTINATION_AUDIENCE or claims["nonce"] != nonce:
        raise ValueError("destination or nonce mismatch")
    if type(claims["age_over_18"]) is not bool:
        raise ValueError("predicate must be boolean")
    if (not isinstance(claims["sub"], str) or len(claims["sub"]) != 64
            or any(char not in "0123456789abcdef" for char in claims["sub"])):
        raise ValueError("invalid pseudonym")
    if type(claims["iat"]) is not int or type(claims["exp"]) is not int:
        raise ValueError("invalid assertion times")
    if claims["exp"] - claims["iat"] != 120 or claims["iat"] > now + 60:
        raise ValueError("invalid assertion lifetime")
    return claims
