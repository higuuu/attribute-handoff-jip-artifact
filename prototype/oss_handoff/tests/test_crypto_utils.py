from cryptography.hazmat.primitives.asymmetric import ec

from prototype.oss_handoff.crypto_utils import (
    b64url_encode,
    build_key_binding_jwt,
    json_b64,
    parse_and_verify_sd_jwt,
    public_jwk,
    sign_es256,
    verify_es256_with_jwk,
    verify_jwt,
    verify_key_binding_jwt,
)
from prototype.oss_handoff.run_experiment import consume_presentation_nonce, issue_presentation_nonce


def test_es256_round_trip() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    token = sign_es256({"alg": "ES256", "typ": "JWT"}, {"purpose": "test"}, key)
    assert verify_es256_with_jwk(token, public_jwk(key))["purpose"] == "test"


def test_key_binding_rejects_wrong_nonce() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    compact = "issuer.jwt.value~disclosure~"
    token = build_key_binding_jwt(compact, key, audience="b", nonce="n1", issued_at=1)
    try:
        verify_key_binding_jwt(token, public_jwk(key), compact_without_kb=compact, audience="b", nonce="n2")
    except ValueError as exc:
        assert str(exc) == "key-binding nonce mismatch"
    else:
        raise AssertionError("wrong nonce was accepted")


def test_jwt_rejects_wrong_issuer() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    token = sign_es256(
        {"alg": "ES256", "kid": "issuer"},
        {"iss": "https://unexpected.invalid", "aud": "region-b-service", "exp": 4_102_444_800},
        key,
    )
    jwks = {"keys": [{"kid": "issuer", **public_jwk(key)}]}
    try:
        verify_jwt(
            token,
            jwks,
            audience="region-b-service",
            issuer="https://expected.invalid",
            now=1,
        )
    except ValueError as exc:
        assert str(exc) == "issuer mismatch"
    else:
        raise AssertionError("wrong issuer was accepted")


def test_sd_jwt_disclosure_digest_is_verified() -> None:
    import hashlib

    key = ec.generate_private_key(ec.SECP256R1())
    disclosure = json_b64(["salt", "age_over_18", True])
    digest = b64url_encode(hashlib.sha256(disclosure.encode()).digest())
    issuer = sign_es256(
        {"alg": "ES256", "kid": "issuer"},
        {"_sd_alg": "sha-256", "_sd": [digest]},
        key,
    )
    jwks = {"keys": [{"kid": "issuer", **public_jwk(key)}]}
    parsed = parse_and_verify_sd_jwt(f"{issuer}~{disclosure}~", jwks, now=1)
    assert parsed.disclosures == {"age_over_18": True}


def test_sd_jwt_tampered_disclosure_is_rejected() -> None:
    import hashlib

    key = ec.generate_private_key(ec.SECP256R1())
    original = json_b64(["salt", "age_over_18", True])
    digest = b64url_encode(hashlib.sha256(original.encode()).digest())
    issuer = sign_es256(
        {"alg": "ES256", "kid": "issuer"},
        {"_sd_alg": "sha-256", "_sd": [digest]},
        key,
    )
    jwks = {"keys": [{"kid": "issuer", **public_jwk(key)}]}
    tampered = json_b64(["salt", "age_over_18", False])
    try:
        parse_and_verify_sd_jwt(f"{issuer}~{tampered}~", jwks, now=1)
    except ValueError as exc:
        assert str(exc) == "SD-JWT disclosure digest mismatch"
    else:
        raise AssertionError("tampered disclosure was accepted")


def test_presentation_nonce_is_consumed_once(tmp_path) -> None:  # noqa: ANN001
    database = tmp_path / "nonces.sqlite3"
    issue_presentation_nonce(database, "n1")
    assert consume_presentation_nonce(database, "n1") is True
    assert consume_presentation_nonce(database, "n1") is False
