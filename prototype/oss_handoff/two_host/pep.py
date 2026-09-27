from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable

from .common import AUDIENCE, PURPOSE, sha256_text


PolicyCheck = Callable[[dict[str, Any], str], tuple[bool, float]]
EvidenceIssue = Callable[[dict[str, Any], str], tuple[str, dict[str, Any], float]]


@dataclass(frozen=True)
class PEPResult:
    status: int
    body: dict[str, Any]
    event: dict[str, Any]


def _finish(
    *,
    started: float,
    status: int,
    request_id: str,
    route: str | None,
    decision: str,
    phase: str,
    mode: str,
    warnings: list[str],
    body: dict[str, Any],
    request_bytes: int,
    policy_latency_ms: float | None = None,
    issuer_latency_ms: float | None = None,
    evidence_bytes: int = 0,
    disclosure_fields: list[str] | None = None,
) -> PEPResult:
    total_ms = (time.perf_counter() - started) * 1000
    event = {
        "request_id": request_id,
        "phase": phase,
        "enforcement_mode": mode,
        "route": route,
        "decision": decision,
        "status": status,
        "warnings": warnings,
        "request_bytes": request_bytes,
        "evidence_bytes": evidence_bytes,
        "disclosure_fields": disclosure_fields or [],
        "policy_called": policy_latency_ms is not None,
        "issuer_called": issuer_latency_ms is not None,
        "policy_latency_ms": None if policy_latency_ms is None else round(policy_latency_ms, 3),
        "issuer_latency_ms": None if issuer_latency_ms is None else round(issuer_latency_ms, 3),
        "total_latency_ms": round(total_ms, 3),
    }
    return PEPResult(status=status, body=body, event=event)


def evaluate_handoff(
    request_value: dict[str, Any],
    *,
    config: dict[str, Any],
    request_bytes: int,
    policy_check: PolicyCheck,
    issue_evidence: EvidenceIssue,
) -> PEPResult:
    """Evaluate one R/O* request without ever recording the returned token."""

    started = time.perf_counter()
    request_id = str(request_value.get("request_id", ""))
    route = str(request_value.get("route", ""))
    phase = str(config.get("phase", "unspecified"))
    mode = str(config.get("enforcement_mode", "enforce"))
    warnings: list[str] = []

    if mode not in {"observe-only", "enforce"}:
        raise ValueError(f"unsupported enforcement mode: {mode}")
    if not request_id or len(request_id) > 128 or not all(char.isalnum() or char in "-_.:" for char in request_id):
        return _finish(
            started=started,
            status=400,
            request_id=request_id,
            route=route or None,
            decision="INVALID_REQUEST_ID",
            phase=phase,
            mode=mode,
            warnings=warnings,
            body={"error": "INVALID_REQUEST_ID"},
            request_bytes=request_bytes,
        )
    if route not in {"R", "O*"}:
        return _finish(
            started=started,
            status=400,
            request_id=request_id,
            route=route or None,
            decision="UNSUPPORTED_ROUTE",
            phase=phase,
            mode=mode,
            warnings=warnings,
            body={"request_id": request_id, "error": "UNSUPPORTED_ROUTE"},
            request_bytes=request_bytes,
        )
    if request_value.get("audience") != config.get("audience", AUDIENCE):
        return _finish(
            started=started,
            status=403,
            request_id=request_id,
            route=route,
            decision="AUDIENCE_MISMATCH",
            phase=phase,
            mode=mode,
            warnings=warnings,
            body={"request_id": request_id, "error": "AUDIENCE_MISMATCH"},
            request_bytes=request_bytes,
        )
    if request_value.get("purpose") != config.get("purpose", PURPOSE):
        return _finish(
            started=started,
            status=403,
            request_id=request_id,
            route=route,
            decision="PURPOSE_MISMATCH",
            phase=phase,
            mode=mode,
            warnings=warnings,
            body={"request_id": request_id, "error": "PURPOSE_MISMATCH"},
            request_bytes=request_bytes,
        )

    requested_model = str(request_value.get("policy_model_id", ""))
    current_model = str(config["policy_model_id"])
    stale = requested_model != current_model
    if stale and mode == "enforce":
        return _finish(
            started=started,
            status=409,
            request_id=request_id,
            route=route,
            decision="STALE_POLICY_MODEL",
            phase=phase,
            mode=mode,
            warnings=warnings,
            body={
                "request_id": request_id,
                "error": "STALE_POLICY_MODEL",
                "requested_model_id_sha256": sha256_text(requested_model),
                "current_model_id_sha256": sha256_text(current_model),
            },
            request_bytes=request_bytes,
        )
    if stale:
        warnings.append("STALE_POLICY_OBSERVED")

    try:
        allowed, policy_latency_ms = policy_check(config, "O" if route == "O*" else route)
    except Exception:
        return _finish(
            started=started,
            status=503,
            request_id=request_id,
            route=route,
            decision="POLICY_UNAVAILABLE",
            phase=phase,
            mode=mode,
            warnings=warnings,
            body={"request_id": request_id, "error": "POLICY_UNAVAILABLE"},
            request_bytes=request_bytes,
        )

    if not allowed and mode == "enforce":
        return _finish(
            started=started,
            status=403,
            request_id=request_id,
            route=route,
            decision="ROUTE_DENIED",
            phase=phase,
            mode=mode,
            warnings=warnings,
            body={"request_id": request_id, "error": "ROUTE_DENIED", "route": route},
            request_bytes=request_bytes,
            policy_latency_ms=policy_latency_ms,
        )
    if not allowed:
        warnings.append("ROUTE_DENIED_OBSERVED")

    try:
        evidence, claims, issuer_latency_ms = issue_evidence(config, route)
    except Exception:
        return _finish(
            started=started,
            status=502,
            request_id=request_id,
            route=route,
            decision="ISSUER_UNAVAILABLE",
            phase=phase,
            mode=mode,
            warnings=warnings,
            body={"request_id": request_id, "error": "ISSUER_UNAVAILABLE"},
            request_bytes=request_bytes,
            policy_latency_ms=policy_latency_ms,
        )

    disclosure_fields = sorted(field for field in ("birth_date", "age_over_18") if field in claims)
    body = {
        "request_id": request_id,
        "decision": "ISSUED",
        "route": route,
        "evidence_type": "oidc_access_token",
        "evidence": evidence,
        "policy": {
            "allowed": allowed,
            "current_model_id": current_model,
            "requested_model_id": requested_model,
        },
        "warnings": warnings,
    }
    return _finish(
        started=started,
        status=200,
        request_id=request_id,
        route=route,
        decision="ISSUED",
        phase=phase,
        mode=mode,
        warnings=warnings,
        body=body,
        request_bytes=request_bytes,
        policy_latency_ms=policy_latency_ms,
        issuer_latency_ms=issuer_latency_ms,
        evidence_bytes=len(evidence.encode()),
        disclosure_fields=disclosure_fields,
    )
