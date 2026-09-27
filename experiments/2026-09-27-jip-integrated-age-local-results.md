# Integrated request-time age handoff: fixed local run

Status: **single physical host functional integration**; not a two-host run,
geographic deployment, or independent reproduction.

- Prospective protocol committed before implementation: `787d127862f7638e004795037034c0e5026b79ff`.
- Implementation committed before the registered 10-repetition run:
  `3275dd33ccb13334cdc944e745f9c9e9d5ef52e1`.
- Synthetic Keycloak 26.7.3 fixture has DOB `2008-09-27` and no stored age
  flag. The generated realm SHA-256 is
  `c098d9ec8612263e9d08d7df50522b838de284644519ae6d9821766d82c9fa36`.
- OpenFGA 1.18.1 used the same model ID across baseline and enforcement.
  Only PEP enforcement mode changed. Keycloak/OpenFGA and the PEP remained on
  source-host loopback; the destination client also ran locally for this run.

| Case | Observe only | Enforce | Destination disclosure |
| --- | --- | --- | --- |
| Denied R | 10/10 HTTP 200 | 10/10 HTTP 403 | Baseline DOB; enforced none |
| Stale `O_live` | 10/10 HTTP 200 | 10/10 HTTP 409 | Baseline predicate; enforced none |
| Current `O_live` | 10/10 HTTP 200 | 10/10 HTTP 200 | Signed Boolean predicate; no DOB |

Current `O_live` obtained a real source-only Keycloak DOB token inside the
source PEP, verified it, derived the age predicate at request time, and
returned a 120-second ES256 assertion with an audience and request nonce.
The destination verified its signature, exact field set, audience, expiry,
and nonce. Wrong-nonce and tampered-signature controls rejected. A separate
same-host fixed-date control using an actual Keycloak token produced
false/true/true before/on/after the synthetic 18th birthday. A development
control with OpenFGA stopped returned HTTP 503 `POLICY_UNAVAILABLE` without
evidence; it was outside the registered 60-event result set.

The registered final event set has 60 PEP events: 30 baseline and 30
enforcement. The validator matched their request IDs, status, route,
disclosure fields, evidence bytes, and policy/source-issuer call flags against
the client summaries. It passed **76/76** checks. No raw token, DOB value,
credential, key, or API bearer token is retained in the public result files.
The observed client p50 for current `O_live` was 31.765 ms baseline and
30.762 ms enforced; these are local functional timings, not a network or
production benchmark. Median signed assertion length was 520 bytes.

## Retained evidence (SHA-256)

All paths below are relative to `output/results/jip-integrated-age-20260927/`.

| File | SHA-256 |
| --- | --- |
| `final-baseline.json` | `3a11a8046619f2c9c43f93db2feb4dd419205c5a86212998a756c5dddc8e82f8` |
| `final-enforced.json` | `932b8d06489c91803e784fcc2a7f19830c783367191a7ba7e18160d06883a739` |
| `final-boundary.json` | `bc3534849d9a9fff5cf0bfc1b7f8f17aafb0311ad657b96f67d14ce9035d5998` |
| `final-events.jsonl` | `b9632765f684691ad399f8fde64418517e924142e54d7b52e5fe46de47547bc4` |
| `final-validation.json` | `42af3d837971c96f9c4c0bac70e7a0295fb89c791c8b273606c3ef4436aafc32` |

## Interpretation and unresolved work

This closes the previous *semantic integration* gap on a single host: the
enforced online API now returns a predicate derived from DOB at request time
instead of reading O*'s stored flag. It does **not** upgrade the historical
two-host O* result into a two-host `O_live` result. Source-token acquisition
and source-signature checking are internal PEP operations; the client receives
only the signed predicate. Direct alternate Keycloak endpoints have not been
exhaustively enumerated, and a local port bind is not a formal non-bypass
proof. Cached C still has no presentation-time status/revocation guarantee.
The signed assertion binds a request nonce, but no global replay database was
tested. No claim is made about independent operators, other attributes,
cross-border law, unlinkability, availability, or failure rates.
