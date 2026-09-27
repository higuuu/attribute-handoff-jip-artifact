# JIP integrated request-time age handoff: prospective protocol

Status: fixed before implementation or execution of this follow-up. This is a
new experiment, not a relabeling of historical O* or the single-host O_live
supplement. The preregistration file and its commit are to be recorded before
the first run.

## Research question

Can a source-adjacent enforcement API, backed by actual Keycloak and OpenFGA
endpoints, derive an age predicate from a source-held birth date at request
time while (a) not disclosing that birth date to the destination and (b)
rejecting denied raw and stale-policy requests before issuance? The primary
claim is about this one exposed API. It is not a claim about all Keycloak
endpoints, geographic residency, or independent operators.

## Fixed environment and intervention

- Keycloak 26.7.3 has one synthetic source subject with `birth_date` =
  `2008-09-27` and **no stored age predicate**. Its raw source token is issued
  only to a loopback source adapter client.
- OpenFGA 1.18.1 stores route decisions for a synthetic user. `O_live` maps
  to policy route `O`; R maps to route `R`.
- A source-side PEP checks audience, purpose, supplied model ID, and policy
  before calling Keycloak. It verifies the source token, derives the age
  predicate using the current UTC calendar date (or a clearly labeled
  fixed-date boundary test), and signs a short-lived destination assertion.
- The assertion contains only issuer, destination audience, pseudonymous
  subject, Boolean predicate, issue/expiry times, and a request nonce. It
  contains no `birth_date` or raw source token. The destination checks the
  signature, exact audience, issuer, expiry, fields, and nonce.
- PEP and OSS run on one Mac mini for initial functional verification. If a
  second physical host is available, the same client runs there over
  authenticated tailnet HTTPS; that run is separately identified and is
  required before any paper claim of two-host integrated O_live evidence.

## Registered cases (10 distinct requests per case)

Use the same OpenFGA deny-R/allow-O model for baseline and enforcement. Change
only the PEP mode between these phases. Every request has a fresh random
nonce, and the client uses one pinned adapter public JWK for a run.

| Case | Observe-only baseline | Enforcement |
| --- | --- | --- |
| R current model, policy denies R | 200, Keycloak-signed raw DOB token, denial warning | 403, no evidence, no source-token request |
| O_live stale model, policy allows O | 200, signed Boolean assertion, stale warning | 409, no evidence, no policy or source-token request |
| O_live current model, policy allows O | 200, signed Boolean assertion | 200, signed Boolean assertion |

The `O_live` assertion must have exactly the registered fields, contain no
DOB, verify at the destination, bind the request nonce, and give the expected
predicate for the date of execution. One additional fixed-date boundary
control checks before/on/after the synthetic 18th birthday as false/true/true
without changing the live-run clock. A nonce mismatch and signature tamper
must be rejected. Source-token validation failure and policy backend failure
must fail closed. The raw route is a registered negative control, never a
recommended service route.

## Measurements and decision rule

Record per-case HTTP status, verified disclosure-field names, assertion/token
byte length, client-observed elapsed time, and PEP event flags for policy and
source issuance. Do not persist bearer tokens, raw DOB, credentials, signing
keys, or raw HTTP bodies in results. Report descriptive p50/p95 only; ten
repetitions are correctness checks, not independent samples or reliability
estimates. A run passes only if all registered statuses, fields, signatures,
nonce bindings, backend-call expectations, and negative controls match.

## Scope and possible negative outcomes

The new path does not make credential C status-aware, prevent all alternate
Keycloak access, prove unlinkability, or demonstrate legal cross-border
compliance. If any condition fails, retain the failure and do not update the
paper with an integrated-success claim. A single-host pass may be reported
only as local integration; an actual Air-side result is required for a
two-host claim. We will compare the resulting integration with Keycloak's
existing policy-enforcer capability; the existence of a PEP is not novel.
