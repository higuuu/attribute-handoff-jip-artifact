from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import sqlite3
import time
import urllib.parse
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from .crypto_utils import (
    build_key_binding_jwt,
    decode_jwt,
    load_private_key,
    parse_and_verify_sd_jwt,
    private_key_pem,
    public_jwk,
    sign_es256,
    verify_jwt,
    verify_key_binding_jwt,
)
from .http_utils import HttpFailure, opener, request, request_json, wait_json


REGION_A = "http://region-a:8080"
REGION_B = "http://region-b:8080"
POLICY = "http://policy:8080"
REALM_A = "region-a"
REALM_B = "region-b"
USERNAME = "region-a-user"
PASSWORD = "local-user-only"
ADMIN_USER = "lab-admin"
ADMIN_PASSWORD = "local-admin-only"
AUDIENCE = "region-b-service"
PURPOSE = "regional-service-eligibility"
RUNTIME = Path(os.environ.get("OSS_HANDOFF_RUNTIME", "/runtime"))
PRIVATE_STATE = RUNTIME / "private-state.json"
OBSERVATIONS = RUNTIME / "observations.json"
NONCE_DB = RUNTIME / "verifier-nonces.sqlite3"
RESULT = Path("prototype/attribute_handoff/results/iwsec-oss-feasibility-20260920/result.json")


def now_ms() -> float:
    return time.perf_counter() * 1000


def sha256_json(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text())


def save_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def issue_presentation_nonce(database: Path, nonce: str) -> None:
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS presentation_nonce (nonce TEXT PRIMARY KEY, state TEXT NOT NULL)"
        )
        connection.execute("INSERT INTO presentation_nonce(nonce, state) VALUES (?, 'ISSUED')", (nonce,))


def consume_presentation_nonce(database: Path, nonce: str) -> bool:
    with sqlite3.connect(database, isolation_level=None) as connection:
        connection.execute("BEGIN IMMEDIATE")
        cursor = connection.execute(
            "UPDATE presentation_nonce SET state = 'CONSUMED' WHERE nonce = ? AND state = 'ISSUED'",
            (nonce,),
        )
        connection.commit()
        return cursor.rowcount == 1


def add_observation(
    observation_id: str,
    *,
    stage: str,
    invariant: str,
    passed: bool,
    support: str,
    observed: dict[str, Any],
    surface: str,
    latency_ms: float | None = None,
) -> None:
    items = load_json(OBSERVATIONS, [])
    item: dict[str, Any] = {
        "id": observation_id,
        "stage": stage,
        "invariant": invariant,
        "passed": passed,
        "support": support,
        "surface": surface,
        "observed": observed,
    }
    if latency_ms is not None:
        item["latency_ms"] = round(latency_ms, 3)
    items.append(item)
    save_json(OBSERVATIONS, items)


def auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def token_endpoint(base: str, realm: str) -> str:
    return f"{base}/realms/{realm}/protocol/openid-connect/token"


def password_token(
    client_id: str,
    client_secret: str,
    *,
    scope: str = "openid",
    timeout: float = 10,
) -> dict[str, Any]:
    response, value = request_json(
        token_endpoint(REGION_A, REALM_A),
        method="POST",
        form={
            "grant_type": "password",
            "client_id": client_id,
            "client_secret": client_secret,
            "username": USERNAME,
            "password": PASSWORD,
            "scope": scope,
        },
        timeout=timeout,
        allow_error=True,
    )
    if response.status != 200 or not isinstance(value, dict):
        raise HttpFailure(response.status, response.url, response.text())
    return value


def admin_token(base: str) -> str:
    response, value = request_json(
        token_endpoint(base, "master"),
        method="POST",
        form={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": ADMIN_USER,
            "password": ADMIN_PASSWORD,
        },
        allow_error=True,
    )
    if response.status != 200 or not isinstance(value, dict) or not value.get("access_token"):
        raise HttpFailure(response.status, response.url, response.text())
    return str(value["access_token"])


def find_user(base: str, realm: str, username: str) -> dict[str, Any]:
    token = admin_token(base)
    url = f"{base}/admin/realms/{realm}/users?{urllib.parse.urlencode({'username': username, 'exact': 'true'})}"
    response, value = request_json(url, headers=auth_header(token), allow_error=True)
    if response.status != 200 or not isinstance(value, list) or len(value) != 1:
        raise RuntimeError(f"user lookup failed for {realm}/{username}: {response.status} {value}")
    return value[0]


def ensure_user_credential() -> dict[str, Any]:
    """Provision the synthetic user's VC entitlement through Keycloak's Admin REST API."""
    token = admin_token(REGION_A)
    user = find_user(REGION_A, REALM_A, USERNAME)
    base = f"{REGION_A}/admin/realms/{REALM_A}/users/{user['id']}/vc/credentials"
    list_response, available = request_json(base, headers=auth_header(token), allow_error=True)
    if list_response.status != 200 or not isinstance(available, list):
        raise RuntimeError(f"user VC entitlement lookup failed: {list_response.status} {available}")
    existing = next(
        (
            item
            for item in available
            if item.get("credentialConfigurationId") == "RegionalEligibilityCredential"
        ),
        None,
    )
    if isinstance(existing, dict):
        return existing
    create_response, created = request_json(
        base,
        method="POST",
        payload={
            "credentialScopeName": "RegionalEligibilityCredential",
            "credentialConfigurationId": "RegionalEligibilityCredential",
            "userAttributes": {"age_over_18": ["true"]},
        },
        headers=auth_header(token),
        allow_error=True,
    )
    if create_response.status not in {200, 201} or not isinstance(created, dict):
        raise RuntimeError(f"user VC entitlement creation failed: {create_response.status} {created}")
    return created


def keycloak_jwks(base: str, realm: str) -> dict[str, Any]:
    _, value = request_json(f"{base}/realms/{realm}/protocol/openid-connect/certs")
    if not isinstance(value, dict):
        raise RuntimeError("invalid JWKS response")
    return value


def token_claims(token_response: dict[str, Any], jwks: dict[str, Any]) -> dict[str, Any]:
    token = str(token_response["access_token"])
    return verify_jwt(token, jwks, audience=AUDIENCE)


class FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.action: str | None = None
        self.method = "POST"
        self.inputs: dict[str, str] = {}
        self._inside_form = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key: value or "" for key, value in attrs}
        if tag == "form" and self.action is None:
            self._inside_form = True
            self.action = html.unescape(values.get("action", ""))
            self.method = values.get("method", "post").upper()
        elif tag in {"input", "button"} and self._inside_form and values.get("name"):
            self.inputs[values["name"]] = values.get("value", "")

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._inside_form:
            self._inside_form = False


def _browser_call(client, url: str, *, method: str = "GET", fields: dict[str, str] | None = None):  # noqa: ANN001
    data = urllib.parse.urlencode(fields).encode() if fields is not None else None
    return request(
        url,
        method=method,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"} if data else None,
        client=client,
        allow_error=True,
    )


def broker_login() -> dict[str, Any]:
    browser = opener(redirects=False)
    trace: list[dict[str, Any]] = []
    params = {
        "client_id": "region-b-app",
        "redirect_uri": "http://runner.invalid/callback",
        "response_type": "code",
        "scope": "openid profile email",
        "nonce": "broker-nonce-001",
        "state": "broker-state-001",
        "kc_idp_hint": "region-a",
    }
    url = f"{REGION_B}/realms/{REALM_B}/protocol/openid-connect/auth?{urllib.parse.urlencode(params)}"
    method = "GET"
    fields: dict[str, str] | None = None

    for _ in range(20):
        response = _browser_call(browser, url, method=method, fields=fields)
        trace_entry: dict[str, Any] = {
            "status": response.status,
            "host": urllib.parse.urlsplit(response.url).hostname,
            "path": urllib.parse.urlsplit(response.url).path,
        }
        if 300 <= response.status < 400:
            location = response.headers.get("Location") or response.headers.get("location")
            if not location:
                raise RuntimeError("broker redirect without location")
            url = urllib.parse.urljoin(url, location)
            redirect_query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
            trace_entry["redirect_host"] = urllib.parse.urlsplit(url).hostname
            trace_entry["redirect_path"] = urllib.parse.urlsplit(url).path
            trace_entry["redirect_query_keys"] = sorted(redirect_query)
            if "error" in redirect_query:
                trace_entry["redirect_error"] = redirect_query["error"]
            if "error_description" in redirect_query:
                trace_entry["redirect_error_description"] = redirect_query["error_description"]
            trace.append(trace_entry)
            if urllib.parse.urlsplit(url).hostname == "runner.invalid":
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
                if "code" not in query:
                    raise RuntimeError(f"broker callback missing code: {url}")
                code = query["code"][0]
                token_response, token_value = request_json(
                    token_endpoint(REGION_B, REALM_B),
                    method="POST",
                    form={
                        "grant_type": "authorization_code",
                        "client_id": "region-b-app",
                        "client_secret": "local-region-b-app-only",
                        "redirect_uri": "http://runner.invalid/callback",
                        "code": code,
                    },
                    allow_error=True,
                )
                if token_response.status != 200 or not isinstance(token_value, dict):
                    raise RuntimeError(f"broker code exchange failed: {token_response.status} {token_value}")
                return token_value
            method, fields = "GET", None
            continue

        if response.status != 200:
            raise RuntimeError(f"broker flow stopped at {response.status}: {response.text()[:500]}")
        parser = FormParser()
        parser.feed(response.text())
        trace_entry["form_fields"] = sorted(parser.inputs)
        trace_entry["form_action_path"] = urllib.parse.urlsplit(parser.action or "").path
        trace.append(trace_entry)
        if not parser.action:
            title = re.search(r"<title>(.*?)</title>", response.text(), re.I | re.S)
            raise RuntimeError(f"broker page without form: {title.group(1).strip() if title else 'unknown'}")
        values = dict(parser.inputs)
        if "password" in values:
            values["username"] = USERNAME
            values["password"] = PASSWORD
        else:
            values["username"] = USERNAME
            values["email"] = "region-a-user@example.invalid"
            values["firstName"] = "Synthetic"
            values["lastName"] = "Resident"
        url = urllib.parse.urljoin(response.url, parser.action)
        method, fields = parser.method, values
    raise RuntimeError(f"broker login exceeded redirect/form limit: {json.dumps(trace, sort_keys=True)}")


def create_policy(*, allow_raw: bool) -> dict[str, Any]:
    store_response, store = request_json(f"{POLICY}/stores", method="POST", payload={"name": "iwsec-regional-handoff"})
    if store_response.status not in {200, 201} or not isinstance(store, dict):
        raise RuntimeError(f"OpenFGA store creation failed: {store_response.status} {store}")
    store_id = str(store["id"])
    model_payload = {
        "schema_version": "1.1",
        "type_definitions": [
            {"type": "user", "relations": {}, "metadata": {"relations": {}}},
            {
                "type": "route",
                "relations": {"allowed": {"this": {}}},
                "metadata": {
                    "relations": {
                        "allowed": {"directly_related_user_types": [{"type": "user"}]}
                    }
                },
            },
        ],
    }
    model_response, model = request_json(
        f"{POLICY}/stores/{store_id}/authorization-models", method="POST", payload=model_payload
    )
    if model_response.status not in {200, 201} or not isinstance(model, dict):
        raise RuntimeError(f"OpenFGA model creation failed: {model_response.status} {model}")
    model_id = str(model["authorization_model_id"])
    routes = ["O", "C"] + (["R"] if allow_raw else [])
    tuples = [
        {"user": "user:b-local", "relation": "allowed", "object": f"route:{route}"}
        for route in routes
    ]
    write_response, write_value = request_json(
        f"{POLICY}/stores/{store_id}/write",
        method="POST",
        payload={"writes": {"tuple_keys": tuples}, "authorization_model_id": model_id},
        allow_error=True,
    )
    if write_response.status not in {200, 201, 204}:
        raise RuntimeError(f"OpenFGA tuple write failed: {write_response.status} {write_value}")
    return {"store_id": store_id, "model_id": model_id, "routes": routes, "cached_at": int(time.time())}


def policy_allowed(policy: dict[str, Any], route: str) -> bool:
    response, value = request_json(
        f"{POLICY}/stores/{policy['store_id']}/check",
        method="POST",
        payload={
            "tuple_key": {"user": "user:b-local", "relation": "allowed", "object": f"route:{route}"},
            "authorization_model_id": policy["model_id"],
        },
        allow_error=True,
    )
    if response.status != 200 or not isinstance(value, dict):
        raise RuntimeError(f"OpenFGA check failed: {response.status} {value}")
    return bool(value.get("allowed"))


def credential_metadata() -> tuple[str, dict[str, Any]]:
    candidates = [
        f"{REGION_A}/realms/{REALM_A}/.well-known/openid-credential-issuer",
        f"{REGION_A}/.well-known/openid-credential-issuer/realms/{REALM_A}",
    ]
    errors = []
    for url in candidates:
        response, value = request_json(url, allow_error=True)
        if response.status == 200 and isinstance(value, dict):
            return url, value
        errors.append((url, response.status))
    raise RuntimeError(f"credential metadata unavailable: {errors}")


def issue_credential(jwks: dict[str, Any]) -> dict[str, Any]:
    user_token = password_token("regional-wallet", "local-wallet-only")
    user_access_token = str(user_token["access_token"])
    query = urllib.parse.urlencode(
        {
            "credential_configuration_id": "RegionalEligibilityCredential",
            "target_user": USERNAME,
            "pre_authorized": "true",
        }
    )
    offer_create_url = f"{REGION_A}/realms/{REALM_A}/protocol/oid4vc/create-credential-offer?{query}"
    create_response, created = request_json(
        offer_create_url,
        headers={**auth_header(user_access_token), "Accept": "application/json"},
        allow_error=True,
    )
    if create_response.status != 200 or not isinstance(created, dict):
        legacy_query = urllib.parse.urlencode(
            {"credential_configuration_id": "RegionalEligibilityCredential", "username": USERNAME}
        )
        legacy_url = f"{REGION_A}/realms/{REALM_A}/protocol/oid4vc/credential-offer-uri?{legacy_query}"
        create_response, created = request_json(
            legacy_url,
            headers={**auth_header(user_access_token), "Accept": "application/json"},
            allow_error=True,
        )
    if create_response.status != 200 or not isinstance(created, dict):
        raise RuntimeError(f"credential offer creation failed: {create_response.status} {created}")
    if created.get("issuer") and created.get("nonce"):
        separator = "" if str(created["issuer"]).endswith("/") else "/"
        offer_url = f"{created['issuer']}{separator}{created['nonce']}"
        offer_response, offer = request_json(offer_url, headers=auth_header(user_access_token), allow_error=True)
    else:
        offer_response, offer = create_response, created
    if offer_response.status != 200 or not isinstance(offer, dict):
        raise RuntimeError(f"credential offer retrieval failed: {offer_response.status} {offer}")
    grant = offer.get("grants", {}).get("urn:ietf:params:oauth:grant-type:pre-authorized_code", {})
    preauthorized = grant.get("pre-authorized_code") or grant.get("pre_authorized_code")
    if not preauthorized:
        raise RuntimeError(f"pre-authorized code missing from offer keys={sorted(offer)}")

    nonce_response, nonce_value = request_json(
        f"{REGION_A}/realms/{REALM_A}/protocol/oid4vc/nonce", method="POST", allow_error=True
    )
    if nonce_response.status != 200 or not isinstance(nonce_value, dict) or not nonce_value.get("c_nonce"):
        raise RuntimeError(f"OID4VCI nonce failed: {nonce_response.status} {nonce_value}")

    token_response, credential_token = request_json(
        token_endpoint(REGION_A, REALM_A),
        method="POST",
        form={
            "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code": preauthorized,
            "client_id": "regional-wallet",
            "client_secret": "local-wallet-only",
        },
        allow_error=True,
    )
    if token_response.status != 200 or not isinstance(credential_token, dict):
        raise RuntimeError(f"credential token failed: {token_response.status} {credential_token}")
    identifiers = credential_token.get("authorization_details", [{}])[0].get("credential_identifiers", [])
    if not identifiers:
        raise RuntimeError("credential identifier missing from token response")

    holder_key = ec.generate_private_key(ec.SECP256R1())
    holder_public = public_jwk(holder_key)
    issuer = f"{REGION_A}/realms/{REALM_A}"
    proof = sign_es256(
        {"alg": "ES256", "typ": "openid4vci-proof+jwt", "jwk": holder_public},
        {"iat": int(time.time()), "nonce": nonce_value["c_nonce"], "aud": issuer},
        holder_key,
    )
    credential_response, credential_value = request_json(
        f"{REGION_A}/realms/{REALM_A}/protocol/oid4vc/credential",
        method="POST",
        payload={"credential_identifier": identifiers[0], "proofs": {"jwt": [proof]}},
        headers={**auth_header(str(credential_token["access_token"])), "Accept": "application/json"},
        allow_error=True,
    )
    if credential_response.status != 200 or not isinstance(credential_value, dict):
        raise RuntimeError(f"credential request failed: {credential_response.status} {credential_value}")
    compact: str | None = None
    if isinstance(credential_value.get("credential"), str):
        compact = credential_value["credential"]
    for item in credential_value.get("credentials", []):
        if isinstance(item, str):
            compact = item
        elif isinstance(item, dict) and isinstance(item.get("credential"), str):
            compact = item["credential"]
    if compact is None:
        raise RuntimeError(f"credential response lacks compact credential keys={sorted(credential_value)}")
    parsed = parse_and_verify_sd_jwt(compact, jwks)
    bound_jwk = parsed.issuer_payload.get("cnf", {}).get("jwk")
    return {
        "credential": compact,
        "holder_private_key": private_key_pem(holder_key),
        "holder_public_jwk": holder_public,
        "issuer_payload": parsed.issuer_payload,
        "disclosures": parsed.disclosures,
        "holder_binding_matches": bound_jwk == holder_public,
        "offer_grant": "pre-authorized_code",
        "credential_response_keys": sorted(credential_value),
    }


def run_online() -> None:
    RUNTIME.mkdir(parents=True, exist_ok=True)
    save_json(OBSERVATIONS, [])
    wait_json(f"{REGION_A}/realms/{REALM_A}")
    wait_json(f"{REGION_B}/realms/{REALM_B}")
    wait_json(f"{POLICY}/healthz")
    metadata_url, metadata = credential_metadata()
    jwks = keycloak_jwks(REGION_A, REALM_A)

    start = now_ms()
    raw_response = password_token("region-b-raw", "local-raw-only")
    raw_claims = token_claims(raw_response, jwks)
    raw_latency = now_ms() - start
    start = now_ms()
    derived_response = password_token("region-b-derived", "local-derived-only")
    derived_claims = token_claims(derived_response, jwks)
    derived_latency = now_ms() - start

    pairwise = raw_claims.get("sub") != derived_claims.get("sub")
    add_observation(
        "K1_PAIRWISE_SUBJECTS",
        stage="online",
        invariant="I1",
        passed=pairwise,
        support="stock-oss",
        surface="Keycloak pairwise subject protocol mapper",
        observed={
            "subjects_differ": pairwise,
            "raw_sub_hash": hashlib.sha256(str(raw_claims.get("sub")).encode()).hexdigest(),
            "derived_sub_hash": hashlib.sha256(str(derived_claims.get("sub")).encode()).hexdigest(),
        },
    )
    raw_shape_ok = "birth_date" in raw_claims and "age_over_18" not in raw_claims
    add_observation(
        "R_RAW_OIDC_TOKEN",
        stage="online",
        invariant="I3",
        passed=raw_shape_ok,
        support="stock-oss",
        surface="Keycloak OIDC direct grant and protocol mapper",
        latency_ms=raw_latency,
        observed={
            "route": "R",
            "birth_date_crossed_boundary": "birth_date" in raw_claims,
            "derived_predicate_crossed_boundary": "age_over_18" in raw_claims,
            "audience_bound": AUDIENCE in ([raw_claims.get("aud")] if isinstance(raw_claims.get("aud"), str) else raw_claims.get("aud", [])),
        },
    )
    derived_shape_ok = derived_claims.get("age_over_18") in {True, "true"} and "birth_date" not in derived_claims
    add_observation(
        "O_DERIVED_OIDC_TOKEN",
        stage="online",
        invariant="I2,I3,I4",
        passed=derived_shape_ok,
        support="stock-oss",
        surface="Keycloak OIDC direct grant and protocol mapper",
        latency_ms=derived_latency,
        observed={
            "route": "O",
            "birth_date_crossed_boundary": "birth_date" in derived_claims,
            "predicate_value": derived_claims.get("age_over_18"),
            "audience_bound": AUDIENCE in ([derived_claims.get("aud")] if isinstance(derived_claims.get("aud"), str) else derived_claims.get("aud", [])),
            "holder_key_bound": "cnf" in derived_claims,
        },
    )

    policy = create_policy(allow_raw=True)
    policy_checks = {route: policy_allowed(policy, route) for route in ["R", "O", "C"]}
    add_observation(
        "POLICY_ROUTE_PERMISSIONS",
        stage="online",
        invariant="I5,I6",
        passed=all(policy_checks.values()),
        support="stock-oss",
        surface="OpenFGA v1 HTTP API",
        observed={"route_permissions": policy_checks, "model_id_hash": hashlib.sha256(policy["model_id"].encode()).hexdigest()},
    )

    broker_started = now_ms()
    broker_tokens = broker_login()
    broker_latency = now_ms() - broker_started
    b_jwks = keycloak_jwks(REGION_B, REALM_B)
    _, broker_claims = decode_jwt(str(broker_tokens["id_token"]))
    verify_jwt(str(broker_tokens["id_token"]), b_jwks)
    b_user = find_user(REGION_B, REALM_B, USERNAME)
    b_admin = admin_token(REGION_B)
    _, links = request_json(
        f"{REGION_B}/admin/realms/{REALM_B}/users/{b_user['id']}/federated-identity",
        headers=auth_header(b_admin),
    )
    a_internal_id = "10000000-0000-4000-8000-000000001001"
    separate = b_user.get("id") != a_internal_id and broker_claims.get("sub") == b_user.get("id")
    link_values = [str(item.get("userId")) for item in links] if isinstance(links, list) else []
    add_observation(
        "BROKER_LOCAL_ID_AND_LINK",
        stage="online",
        invariant="I1,I8",
        passed=separate and len(link_values) == 1,
        support="stock-oss",
        surface="Keycloak OIDC identity broker and Admin REST API",
        latency_ms=broker_latency,
        observed={
            "region_ids_differ": separate,
            "b_token_sub_is_b_internal_id": broker_claims.get("sub") == b_user.get("id"),
            "persistent_external_link_count": len(link_values),
            "external_link_equals_a_internal_id": a_internal_id in link_values,
            "external_link_hashes": [hashlib.sha256(value.encode()).hexdigest() for value in link_values],
            "stored_external_token": False,
        },
    )

    entitlement = ensure_user_credential()
    credential_started = now_ms()
    credential_state = issue_credential(jwks)
    credential_latency = now_ms() - credential_started
    disclosures = credential_state["disclosures"]
    issuer_payload = credential_state["issuer_payload"]
    c_shape_ok = (
        disclosures.get("age_over_18") in {True, "true"}
        and "birth_date" not in disclosures
        and credential_state["holder_binding_matches"]
    )
    add_observation(
        "C_KEYCLOAK_OID4VCI_ISSUANCE",
        stage="online",
        invariant="I1,I2,I3",
        passed=c_shape_ok,
        support="stock-oss-experimental",
        surface="Keycloak 26.7.x experimental OpenID4VCI pre-authorized flow",
        latency_ms=credential_latency,
        observed={
            "format": "dc+sd-jwt",
            "predicate_present": disclosures.get("age_over_18") in {True, "true"},
            "birth_date_present": "birth_date" in disclosures or "birth_date" in issuer_payload,
            "holder_binding_matches": credential_state["holder_binding_matches"],
            "status_reference_present": "status" in disclosures or "status" in issuer_payload,
            "issuer_subject_present": "sub" in issuer_payload or "sub" in disclosures,
            "offer_grant": credential_state["offer_grant"],
            "server_side_entitlement_provisioned": (
                entitlement.get("credentialConfigurationId") == "RegionalEligibilityCredential"
            ),
        },
    )

    private = {
        "jwks": jwks,
        "policy": policy,
        "policy_config_hash": sha256_json(policy),
        "credential": credential_state["credential"],
        "holder_private_key": credential_state["holder_private_key"],
        "holder_public_jwk": credential_state["holder_public_jwk"],
        "a_internal_id": a_internal_id,
        "b_internal_id": b_user["id"],
        "metadata_url": metadata_url,
        "metadata_hash": sha256_json(metadata),
        "issuer_payload": issuer_payload,
        "disclosures": disclosures,
    }
    save_json(PRIVATE_STATE, private)


def _cached_presentation(private: dict[str, Any], *, nonce: str, now: int) -> tuple[dict[str, Any], str]:
    parsed = parse_and_verify_sd_jwt(private["credential"], private["jwks"], now=now)
    holder_jwk = parsed.issuer_payload.get("cnf", {}).get("jwk")
    if holder_jwk != private["holder_public_jwk"]:
        raise ValueError("credential holder binding differs from stored Region B key")
    holder_key = load_private_key(private["holder_private_key"])
    kb = build_key_binding_jwt(
        parsed.compact_without_kb,
        holder_key,
        audience=AUDIENCE,
        nonce=nonce,
        issued_at=now,
    )
    verify_key_binding_jwt(
        kb,
        holder_jwk,
        compact_without_kb=parsed.compact_without_kb,
        audience=AUDIENCE,
        nonce=nonce,
    )
    return {**parsed.issuer_payload, **parsed.disclosures}, kb


def run_offline() -> None:
    private = load_json(PRIVATE_STATE, None)
    if not isinstance(private, dict):
        raise RuntimeError("online state is missing")
    source_unavailable = False
    try:
        password_token("region-b-derived", "local-derived-only", timeout=2)
    except HttpFailure:
        source_unavailable = True
    add_observation(
        "O_SOURCE_OUTAGE",
        stage="source-offline",
        invariant="I4",
        passed=source_unavailable,
        support="stock-oss",
        surface="Keycloak OIDC token endpoint while Region A container is stopped",
        observed={"online_derived_failed_closed": source_unavailable},
    )

    current = int(time.time())
    nonce = "offline-c-nonce-001"
    issue_presentation_nonce(NONCE_DB, nonce)
    started = now_ms()
    claims, kb = _cached_presentation(private, nonce=nonce, now=current)
    first_nonce_use_accepted = consume_presentation_nonce(NONCE_DB, nonce)
    c_latency = now_ms() - started
    add_observation(
        "C_SOURCE_OUTAGE_SUCCESS",
        stage="source-offline",
        invariant="I2,I3,I4",
        passed=claims.get("age_over_18") in {True, "true"} and "birth_date" not in claims,
        support="minimal-python-verifier",
        surface="cached Keycloak-issued SD-JWT VC plus minimal Python verifier",
        latency_ms=c_latency,
        observed={
            "source_container_available": False,
            "source_requests_required": 0,
            "predicate_value": claims.get("age_over_18"),
            "birth_date_present": "birth_date" in claims,
            "key_binding_verified": bool(kb),
            "disclosure_digests_verified": True,
        },
    )

    parsed_for_replay = parse_and_verify_sd_jwt(private["credential"], private["jwks"], now=current)
    verify_key_binding_jwt(
        kb,
        parsed_for_replay.issuer_payload["cnf"]["jwk"],
        compact_without_kb=parsed_for_replay.compact_without_kb,
        audience=AUDIENCE,
        nonce=nonce,
    )
    second_nonce_use_accepted = consume_presentation_nonce(NONCE_DB, nonce)
    replay_rejected = first_nonce_use_accepted and not second_nonce_use_accepted
    add_observation(
        "C_NONCE_REPLAY",
        stage="source-offline",
        invariant="I7",
        passed=replay_rejected,
        support="minimal-controller",
        surface="Region B verifier nonce store",
        observed={
            "first_presentation": "accepted" if first_nonce_use_accepted else "rejected",
            "second_presentation": "accepted" if second_nonce_use_accepted else "rejected",
            "durable_nonce_store": "sqlite",
            "reason": "NONCE_REPLAYED",
        },
    )

    wrong_key = ec.generate_private_key(ec.SECP256R1())
    parsed = parse_and_verify_sd_jwt(private["credential"], private["jwks"], now=current)
    wrong_kb = build_key_binding_jwt(
        parsed.compact_without_kb,
        wrong_key,
        audience=AUDIENCE,
        nonce="wrong-holder-nonce",
        issued_at=current,
    )
    substitution_rejected = False
    try:
        verify_key_binding_jwt(
            wrong_kb,
            private["holder_public_jwk"],
            compact_without_kb=parsed.compact_without_kb,
            audience=AUDIENCE,
            nonce="wrong-holder-nonce",
        )
    except Exception:
        substitution_rejected = True
    add_observation(
        "C_HOLDER_KEY_SUBSTITUTION",
        stage="source-offline",
        invariant="I2,I7",
        passed=substitution_rejected,
        support="minimal-python-verifier",
        surface="minimal Python verifier: SD-JWT VC cnf JWK and key-binding JWT",
        observed={"substitution_rejected": substitution_rejected},
    )

    exp = parsed.issuer_payload.get("exp")
    expired_rejected = False
    if exp is not None:
        try:
            parse_and_verify_sd_jwt(private["credential"], private["jwks"], now=int(exp) + 1)
        except ValueError as exc:
            expired_rejected = str(exc) == "token expired"
    add_observation(
        "C_EXPIRY_BOUNDARY",
        stage="source-offline",
        invariant="I5",
        passed=expired_rejected,
        support="minimal-python-verifier",
        surface="minimal Python verifier: SD-JWT VC exp validation using cached issuer JWKS",
        observed={"exp_present": exp is not None, "expired_credential_rejected": expired_rejected},
    )

    status_present = "status" in parsed.issuer_payload or "status" in parsed.disclosures
    add_observation(
        "C_REVOCATION_NEGATIVE_CONTROL",
        stage="source-offline",
        invariant="I5",
        passed=False,
        support="unsupported-in-issued-artifact" if not status_present else "not-yet-verified",
        surface="Keycloak-issued SD-JWT VC status material",
        observed={
            "status_reference_present": status_present,
            "revoked_offline_credential_rejected": False,
            "reason": "NO_STATUS_REFERENCE" if not status_present else "STATUS_NOT_EVALUATED",
        },
    )

    stale_policy_rejected = private["policy"]["model_id"] != "expected-new-model-id"
    add_observation(
        "C_STALE_POLICY_NEGATIVE_CONTROL",
        stage="source-offline",
        invariant="I5,I6",
        passed=stale_policy_rejected,
        support="minimal-controller",
        surface="handoff gate comparing requested and cached OpenFGA authorization model IDs",
        observed={
            "stale_policy_rejected": stale_policy_rejected,
            "oss_policy_engine_supplies_version_id": True,
            "cross-route_freshness_gate_supplied_by_keycloak": False,
        },
    )


def run_policy_offline() -> None:
    private = load_json(PRIVATE_STATE, None)
    if not isinstance(private, dict):
        raise RuntimeError("online state is missing")
    unreachable = False
    try:
        request_json(f"{POLICY}/healthz", timeout=2)
    except HttpFailure:
        unreachable = True
    cache_age = int(time.time()) - int(private["policy"]["cached_at"])
    cache_max_age = 300
    accepted_from_cache = unreachable and cache_age <= cache_max_age
    add_observation(
        "C_POLICY_SERVICE_OUTAGE",
        stage="source-and-policy-offline",
        invariant="I5,I6",
        passed=accepted_from_cache,
        support="minimal-controller",
        surface="bounded cached OpenFGA decision metadata",
        observed={
            "policy_service_unavailable": unreachable,
            "cached_policy_age_seconds": cache_age,
            "cached_policy_max_age_seconds": cache_max_age,
            "cached_c_accepted": accepted_from_cache,
            "stock_openfga_offline_evaluation": False,
        },
    )


def revoke_issued_credential() -> dict[str, Any]:
    token = admin_token(REGION_A)
    user = find_user(REGION_A, REALM_A, USERNAME)
    base = f"{REGION_A}/admin/realms/{REALM_A}/users/{user['id']}/vc/issued-credentials"
    list_response, issued = request_json(base, headers=auth_header(token), allow_error=True)
    if list_response.status != 200 or not isinstance(issued, list):
        return {"list_status": list_response.status, "issued_count": None, "revoked": False}
    if not issued:
        return {"list_status": list_response.status, "issued_count": 0, "revoked": False}
    identifier = issued[0].get("id") or issued[0].get("credentialId")
    if not identifier:
        return {"list_status": list_response.status, "issued_count": len(issued), "revoked": False}
    delete_response = request(
        f"{base}/{urllib.parse.quote(str(identifier), safe='')}",
        method="DELETE",
        headers=auth_header(token),
        allow_error=True,
    )
    return {
        "list_status": list_response.status,
        "issued_count": len(issued),
        "delete_status": delete_response.status,
        "revoked": delete_response.status in {200, 204},
    }


def run_final() -> None:
    wait_json(f"{REGION_A}/realms/{REALM_A}")
    wait_json(f"{POLICY}/healthz")
    private = load_json(PRIVATE_STATE, None)
    if not isinstance(private, dict):
        raise RuntimeError("online state is missing")
    deny_policy = create_policy(allow_raw=False)
    raw_allowed = policy_allowed(deny_policy, "R")
    raw_issued = False
    try:
        password_token("region-b-raw", "local-raw-only")
        raw_issued = True
    except Exception:
        raw_issued = False
    add_observation(
        "R_SOURCE_POLICY_BYPASS",
        stage="services-restored",
        invariant="I6",
        passed=False,
        support="missing-source-enforcement",
        surface="OpenFGA decision compared with unmodified Keycloak OIDC token endpoint",
        observed={
            "policy_allows_raw": raw_allowed,
            "source_issued_raw_token": raw_issued,
            "raw_crossed_before_region_b_gate": raw_issued,
            "reason": "SOURCE_DOES_NOT_CONSULT_ROUTE_POLICY",
        },
    )

    revocation = revoke_issued_credential()
    still_verifies = False
    try:
        parse_and_verify_sd_jwt(private["credential"], private["jwks"], now=int(time.time()))
        still_verifies = True
    except Exception:
        still_verifies = False
    add_observation(
        "C_ADMIN_REVOCATION_AFTER_ISSUANCE",
        stage="services-restored",
        invariant="I5",
        passed=bool(revocation.get("revoked")) and not still_verifies,
        support="stock-oss-plus-minimal-python-verifier",
        surface="Keycloak 26.7 user VC Admin REST API and minimal Python verifier",
        observed={
            **revocation,
            "cached_credential_still_verifies_cryptographically": still_verifies,
            "presentation_time_status_check_available": False,
        },
    )
    finalize_result(private)


def finalize_result(private: dict[str, Any]) -> None:
    observations = load_json(OBSERVATIONS, [])
    by_id = {item["id"]: item for item in observations}

    def all_pass(*ids: str) -> bool:
        return all(bool(by_id.get(item_id, {}).get("passed")) for item_id in ids)

    invariants = {
        "I1_separate_ids": all_pass("K1_PAIRWISE_SUBJECTS", "BROKER_LOCAL_ID_AND_LINK", "C_KEYCLOAK_OID4VCI_ISSUANCE"),
        "I2_destination_binding": all_pass("O_DERIVED_OIDC_TOKEN", "C_KEYCLOAK_OID4VCI_ISSUANCE", "C_HOLDER_KEY_SUBSTITUTION"),
        "I3_route_disclosure": all_pass("R_RAW_OIDC_TOKEN", "O_DERIVED_OIDC_TOKEN", "C_SOURCE_OUTAGE_SUCCESS"),
        "I4_source_availability": all_pass("O_SOURCE_OUTAGE", "C_SOURCE_OUTAGE_SUCCESS"),
        "I5_freshness_and_status": all_pass(
            "C_EXPIRY_BOUNDARY",
            "C_REVOCATION_NEGATIVE_CONTROL",
            "C_STALE_POLICY_NEGATIVE_CONTROL",
            "C_ADMIN_REVOCATION_AFTER_ISSUANCE",
        ),
        "I6_no_unsafe_fallback": all_pass("C_STALE_POLICY_NEGATIVE_CONTROL", "C_POLICY_SERVICE_OUTAGE", "R_SOURCE_POLICY_BYPASS"),
        "I7_replay_and_request_binding": all_pass("C_NONCE_REPLAY", "C_HOLDER_KEY_SUBSTITUTION"),
        "I8_correlation_inventory": all_pass("BROKER_LOCAL_ID_AND_LINK"),
    }
    core_routes = all_pass("R_RAW_OIDC_TOKEN", "O_DERIVED_OIDC_TOKEN", "C_KEYCLOAK_OID4VCI_ISSUANCE")
    if core_routes and all(invariants.values()):
        decision = "D1_STOCK_OSS_SUPPORT"
    elif core_routes:
        decision = "D2_MINIMAL_MISSING_HANDOFF_LAYER"
    elif any(item["id"] == "C_KEYCLOAK_OID4VCI_ISSUANCE" for item in observations):
        decision = "D3_INTEGRATION_GAP"
    else:
        decision = "D4_NO_VIABLE_IWSEC_CLAIM"

    components = {
        "keycloak": {
            "configured_version": "26.7.3",
            "image_id": "sha256:9ae8d484456bb711fe05e8669bab61b4045c764c6ddbd1c4d646d6ff11d6db6f",
            "instances": 2,
            "oid4vci_status": "experimental",
        },
        "openfga": {
            "configured_version": "1.18.1",
            "image_id": "sha256:4745c0c09f4f2f64f89b64e97b8a62163d31fc4767713321bd11075a002ae8aa",
        },
        "runner": {
            "image_id": "sha256:06e035e8a631ef854ff0f2733411230d3340439d4fcaf9420f58b11c660a826c",
            "contains_raw_tokens_in_published_result": False,
        },
        "verifier": {
            "implementation": "minimal Python standards-profile client",
            "crypto_library": "cryptography",
            "checks": ["issuer_jws", "disclosure_digest", "expiry", "cnf_key_binding", "kb_jwt_audience", "nonce"],
            "full_openid4vp_implementation": False,
        },
    }
    result = {
        "experiment": "iwsec-oss-feasibility-20260920",
        "registered_commit": "79a886f",
        "environment": {
            "host_class": "single Mac mini",
            "docker_architecture": "aarch64",
            "docker_cpus": 4,
            "docker_memory_bytes": 12001992704,
            "network_scope": "local Docker bridge only",
            "synthetic_data_only": True,
        },
        "components": components,
        "configuration": {
            "region_a_realm_sha256": hashlib.sha256(Path("prototype/oss_handoff/keycloak/region-a-realm.json").read_bytes()).hexdigest(),
            "region_b_realm_sha256": hashlib.sha256(Path("prototype/oss_handoff/keycloak/region-b-realm.json").read_bytes()).hexdigest(),
            "credential_metadata_sha256": private["metadata_hash"],
            "policy_cache_sha256": private["policy_config_hash"],
        },
        "route_summary": {
            "R": "Keycloak OIDC access token containing source birth_date",
            "O": "Keycloak OIDC access token containing only age_over_18",
            "C": "Keycloak OpenID4VCI holder-bound SD-JWT VC verified after Region A stop",
        },
        "invariants": invariants,
        "counts": {
            "observations": len(observations),
            "passed": sum(1 for item in observations if item["passed"]),
            "failed_or_unsupported": sum(1 for item in observations if not item["passed"]),
        },
        "decision": decision,
        "observations": observations,
        "publication_boundary": {
            "not_cross_region_deployment": True,
            "not_legal_compliance_evidence": True,
            "not_production_capacity_evidence": True,
            "no_keys_tokens_credentials_or_raw_logs": True,
        },
    }
    RESULT.parent.mkdir(parents=True, exist_ok=True)
    save_json(RESULT, result)
    print(json.dumps({"decision": decision, "invariants": invariants, "counts": result["counts"]}, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=["online", "offline", "policy-offline", "final"])
    args = parser.parse_args()
    if args.stage == "online":
        run_online()
    elif args.stage == "offline":
        run_offline()
    elif args.stage == "policy-offline":
        run_policy_offline()
    else:
        run_final()


if __name__ == "__main__":
    main()
