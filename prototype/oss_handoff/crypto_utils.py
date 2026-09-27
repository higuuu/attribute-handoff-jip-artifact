from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, load_pem_private_key


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def json_b64(value: Any) -> str:
    return b64url_encode(json.dumps(value, separators=(",", ":"), sort_keys=True).encode())


def decode_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("JWT must contain exactly three segments")
    return json.loads(b64url_decode(parts[0])), json.loads(b64url_decode(parts[1]))


def public_jwk(private_key: ec.EllipticCurvePrivateKey) -> dict[str, str]:
    numbers = private_key.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url_encode(numbers.x.to_bytes(32, "big")),
        "y": b64url_encode(numbers.y.to_bytes(32, "big")),
    }


def private_key_pem(private_key: ec.EllipticCurvePrivateKey) -> str:
    return private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()


def load_private_key(pem: str) -> ec.EllipticCurvePrivateKey:
    key = load_pem_private_key(pem.encode(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError("expected EC private key")
    return key


def sign_es256(header: dict[str, Any], payload: dict[str, Any], private_key: ec.EllipticCurvePrivateKey) -> str:
    encoded_header = json_b64(header)
    encoded_payload = json_b64(payload)
    signing_input = f"{encoded_header}.{encoded_payload}".encode()
    der = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{encoded_header}.{encoded_payload}.{b64url_encode(raw)}"


def _jwk_to_public_key(jwk: dict[str, Any]):
    if jwk.get("kty") == "RSA":
        return rsa.RSAPublicNumbers(
            int.from_bytes(b64url_decode(jwk["e"]), "big"),
            int.from_bytes(b64url_decode(jwk["n"]), "big"),
        ).public_key()
    if jwk.get("kty") == "EC" and jwk.get("crv") == "P-256":
        return ec.EllipticCurvePublicNumbers(
            int.from_bytes(b64url_decode(jwk["x"]), "big"),
            int.from_bytes(b64url_decode(jwk["y"]), "big"),
            ec.SECP256R1(),
        ).public_key()
    raise ValueError(f"unsupported JWK type: {jwk.get('kty')} {jwk.get('crv')}")


def verify_jwt(
    token: str,
    jwks: dict[str, Any],
    *,
    audience: str | None = None,
    issuer: str | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("JWT must contain exactly three segments")
    header, payload = decode_jwt(token)
    kid = header.get("kid")
    candidates = [key for key in jwks.get("keys", []) if key.get("kid") == kid]
    if not candidates:
        raise ValueError(f"no JWK for kid {kid}")
    key = _jwk_to_public_key(candidates[0])
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    signature = b64url_decode(parts[2])
    alg = header.get("alg")
    if alg == "RS256" and isinstance(key, rsa.RSAPublicKey):
        key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
    elif alg == "ES256" and isinstance(key, ec.EllipticCurvePublicKey):
        if len(signature) != 64:
            raise ValueError("invalid ES256 signature length")
        der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
        key.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
    else:
        raise ValueError(f"unsupported or mismatched signing algorithm {alg}")

    current = int(time.time()) if now is None else now
    if payload.get("exp") is not None and current >= int(payload["exp"]):
        raise ValueError("token expired")
    if payload.get("nbf") is not None and current < int(payload["nbf"]):
        raise ValueError("token not yet valid")
    if audience is not None:
        audiences = payload.get("aud", [])
        if isinstance(audiences, str):
            audiences = [audiences]
        if audience not in audiences:
            raise ValueError("audience mismatch")
    if issuer is not None and payload.get("iss") != issuer:
        raise ValueError("issuer mismatch")
    return payload


def verify_es256_with_jwk(token: str, jwk: dict[str, Any]) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("JWT must contain exactly three segments")
    header, payload = decode_jwt(token)
    if header.get("alg") != "ES256":
        raise ValueError("expected ES256")
    signature = b64url_decode(parts[2])
    if len(signature) != 64:
        raise ValueError("invalid ES256 signature length")
    key = _jwk_to_public_key(jwk)
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("expected EC public key")
    der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
    key.verify(der, f"{parts[0]}.{parts[1]}".encode(), ec.ECDSA(hashes.SHA256()))
    return payload


@dataclass(frozen=True)
class SdJwtCredential:
    issuer_jwt: str
    issuer_payload: dict[str, Any]
    disclosures: dict[str, Any]
    compact_without_kb: str


def parse_and_verify_sd_jwt(
    compact: str,
    jwks: dict[str, Any],
    *,
    issuer: str | None = None,
    now: int | None = None,
) -> SdJwtCredential:
    segments = compact.split("~")
    issuer_jwt = segments[0]
    payload = verify_jwt(issuer_jwt, jwks, issuer=issuer, now=now)
    digest_algorithm = payload.get("_sd_alg", "sha-256")
    if digest_algorithm != "sha-256":
        raise ValueError(f"unsupported SD-JWT digest algorithm {digest_algorithm}")
    expected_digests = payload.get("_sd", [])
    if not isinstance(expected_digests, list) or not all(isinstance(item, str) for item in expected_digests):
        raise ValueError("invalid SD-JWT digest list")
    disclosures: dict[str, Any] = {}
    for encoded in segments[1:]:
        if not encoded or encoded.count(".") == 2:
            continue
        digest = b64url_encode(hashlib.sha256(encoded.encode()).digest())
        if digest not in expected_digests:
            raise ValueError("SD-JWT disclosure digest mismatch")
        item = json.loads(b64url_decode(encoded))
        if not isinstance(item, list) or len(item) != 3:
            raise ValueError("unsupported SD-JWT disclosure")
        claim_name = str(item[1])
        if claim_name in disclosures:
            raise ValueError("duplicate SD-JWT disclosure claim")
        disclosures[claim_name] = item[2]
    without_kb = "~".join([issuer_jwt, *[part for part in segments[1:] if part and part.count(".") != 2]]) + "~"
    return SdJwtCredential(issuer_jwt, payload, disclosures, without_kb)


def build_key_binding_jwt(
    compact_without_kb: str,
    private_key: ec.EllipticCurvePrivateKey,
    *,
    audience: str,
    nonce: str,
    issued_at: int,
) -> str:
    return sign_es256(
        {"alg": "ES256", "typ": "kb+jwt"},
        {
            "aud": audience,
            "nonce": nonce,
            "iat": issued_at,
            "sd_hash": b64url_encode(hashlib.sha256(compact_without_kb.encode()).digest()),
        },
        private_key,
    )


def verify_key_binding_jwt(
    token: str,
    holder_jwk: dict[str, Any],
    *,
    compact_without_kb: str,
    audience: str,
    nonce: str,
) -> dict[str, Any]:
    payload = verify_es256_with_jwk(token, holder_jwk)
    if payload.get("aud") != audience:
        raise ValueError("key-binding audience mismatch")
    if payload.get("nonce") != nonce:
        raise ValueError("key-binding nonce mismatch")
    expected_hash = b64url_encode(hashlib.sha256(compact_without_kb.encode()).digest())
    if payload.get("sd_hash") != expected_hash:
        raise ValueError("key-binding sd_hash mismatch")
    return payload
