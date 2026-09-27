# JIP two-physical-host remediation preregistration

Status: implementation prepared; cross-host execution not yet performed

Date fixed: 2026-09-26 JST

Data: synthetic only
Operators: one author on two author-controlled Macs

## 1. Research question

Can a source-adjacent policy-enforcement point convert the two previously
narrowed controls into actual request-path enforcement while preserving the
working O* path, and can R/O*/C be exercised across two physical hosts without
moving Keycloak, OpenFGA, or Docker computation onto the MacBook Air?

This experiment evaluates a small integration component. It does not claim that
the component is a new protocol, a complete authorization architecture, an
independent reproduction, or evidence of legal/geographic separation.

## 2. Fixed topology

| Role | Host | Work |
| --- | --- | --- |
| Region A/source | Mac mini | Keycloak, OpenFGA, PEP, issuance, event log |
| Region B/consumer | MacBook Air | requests, signature checks, offline C verification, summary |
| Network boundary | Tailscale | tailnet-only encrypted transport; no Funnel/public ingress |

Keycloak and OpenFGA bind only to Mac mini loopback. The PEP binds only to
`127.0.0.1:8765` and is presented through Tailscale Serve. A failed direct
reachability probe from the Air is a required observation; it is not by itself
proof that every local process on the Mac mini cannot bypass the PEP.

The PEP and C bundle carry the fixed implementation commit and a SHA-256 host
fingerprint derived from the Mac mini host name. The Air records its own hashed
host name and must observe a different value. This prevents an accidental
same-host run from being labeled cross-host; it is not hardware attestation.
The direct probe target must resolve to an address also resolved for the PEP's
tailnet hostname during online phases.

## 3. Fixed routes

- `R`: a signed OIDC access token containing synthetic `birth_date`.
- `O*`: a signed OIDC access token containing stored `age_over_18` and no
  `birth_date`; this remains retrieval, not request-time derivation.
- `C`: a previously issued holder-bound SD-JWT VC verified on the Air without a
  presentation-time source request.

## 4. Hypotheses and controls

### H1: source-side route enforcement

With the same OpenFGA model denying R:

- observe-only baseline: R is issued despite denial, with
  `ROUTE_DENIED_OBSERVED`;
- enforced condition: R returns HTTP 403 `ROUTE_DENIED`, contains no evidence,
  and the issuer is not called.

H1 passes only if the Air detects the baseline disclosure and the remediated
request produces no access token or `birth_date` field.

### H2: live stale-policy rejection

With an intentionally mismatched request model ID:

- observe-only baseline: mismatch is recorded but O* is issued, with
  `STALE_POLICY_OBSERVED`; the Air must verify the issuer, signature, audience,
  and `age_over_18`-only disclosure shape;
- enforced condition: the same request returns HTTP 409
  `STALE_POLICY_MODEL`, contains no evidence, and neither OpenFGA nor Keycloak
  is called for that request.

H2 passes only if the difference is observed at the actual request API. A
standalone comparison of model identifiers is insufficient.

### H3: current O* remains functional

With the current model ID and O permission, O* returns an issuer-, signature-,
and audience-validated token containing `age_over_18` and no `birth_date` in
both observe-only and enforced conditions.

### H4: cached C remains source-independent at presentation

The Air verifies issuer signature, disclosure digest, expiry, holder key,
audience, and nonce binding using a freshly transferred synthetic credential
bundle. The verifier code performs zero source requests during C presentation.
This does not add credential-status support; the earlier status limitation
remains.

The two-host-specific synthetic realm sets C lifetime to 7,200 seconds without
changing the frozen base realm. The Air environment is prepared before the Mac
mini lab starts, and the runner refuses a two-host phase with fewer than 600
seconds remaining. One C bundle must be used across all four result files.

## 5. Measurement phase

After H1--H4, create a new policy fixture allowing R/O/C and keep enforcement
enabled. Run 10 repetitions per route by default, with a permitted range of
1--100. Report:

- client-observed latency p50 and p95;
- request, response, and signed-evidence byte counts;
- whether `birth_date` and/or `age_over_18` crossed the boundary;
- signature/audience verification result;
- presentation-time source request count for C.

No inferential statistics, reliability percentage, throughput, or production
capacity claim is permitted. Byte count must not be presented as a privacy
metric. If Tailscale uses the local LAN path, latency is a descriptive property
of that path only.

## 6. Execution order

1. prepare the Air Python environment before issuing any C credential;
2. fix a clean Git commit and let the start script record it;
3. generate the two-host-only realm, start Mac mini services, create a deny-R
   policy fixture, and issue the 7,200-second C bundle;
4. transfer the API token and C bundle outside Git, then run the Air baseline in
   observe-only mode;
5. change only PEP enforcement mode and run the same Air matrix;
6. create the allow-R/O/C measurement fixture and run the measurement matrix;
7. stop Region A and verify the same cached C again;
8. co-locate the four sanitized Air result files and the Mac mini PEP event log,
   then run the final cross-phase validator;
9. stop Tailscale Serve and containers even if one cleanup step fails;
10. secret-scan sanitized JSON, calculate SHA-256, and retain raw runtime
    secrets outside Git.

## 7. Failure and stop rules

- Stop if Tailscale Serve would require Funnel or public ingress.
- Stop if Keycloak or OpenFGA is reachable from the Air on its direct port.
- Stop if the Air cannot bind the direct-probe target to the PEP host, the
  source/client host fingerprints are equal, or any required probe is absent.
- Stop if fewer than 600 seconds of C validity remain at any phase.
- Stop if a result JSON contains a token, credential, API token, private key,
  nonce value, raw log, local user path, serial number, or hardware UUID.
- Stop if the baseline and remediated runs do not use the same deny-R policy
  model; repeat both phases under one new fixed model instead.
- Stop if the implementation commit or C bundle hash changes across phases, or
  if the final validator reports any failed registered check.
- Stop and mark H1/H2 failed if a denied/stale request returns evidence.
- Do not replace or rewrite the frozen 2026-09-20 result. The new experiment is
  a separate remediation result linked to its own commit and hashes.

## 8. Claim rules

If all registered expectations pass, claim only that one source-adjacent PEP
enforced route denial and model freshness at the tailnet-exposed request path in
this two-host synthetic configuration. Do not claim independent reproduction,
all-path non-bypassability, online predicate derivation, credential revocation,
geographic separation, legal compliance, or production readiness.

No individual phase's `all_expectations_passed` value is sufficient. A final
cross-phase validator must confirm exact phase names and counts, ten
repetitions, the same deny-policy model for baseline/remediation, a new
measurement model, one C bundle, Air-runner hash, and implementation commit,
distinct source and client fingerprints, one direct-probe target, issuer-bound
successful evidence, every registered record status/disclosure shape, and the
exact PEP policy/issuer call pattern for all online requests.
