# Prospective protocol: request-time age predicate (2026-09-27)

This is a **new, separate** focused experiment. It does not amend the frozen
original audit or the two-host R/O*/C follow-up. It is specified before its
implementation and run. A passing local run must not be described as a
geographic, independent-host, all-route, or production result.

## Question and boundary

Can a source-side service read a synthetic date of birth from a real Keycloak
26.7.3 token, derive an over-18 predicate at request time, and send only a
signed predicate assertion to a verifier? The requester must never receive
the raw source token or birth date. This is `O_live`, not the historical O*
stored flag. The source and verifier are local processes; Keycloak is an
actual OSS endpoint, not a mock.

## Frozen fixture and oracle

- Dedicated realm: `live-age`; synthetic DOB `2008-09-27`; no stored
  `age_over_18` attribute. A raw-only confidential client represents the
  internal source adapter, not the destination.
- Boundary rule: attained age on an ISO calendar date is at least 18. A
  February-29 birth in a non-leap year reaches the birthday on March 1.
- Deterministic dates for the fixed fixture: 2026-09-26 => false;
  2026-09-27 => true; 2026-09-28 => true. Separate pure-function cases:
  2008-02-29 / 2026-02-28 => false; 2008-02-29 / 2026-03-01 => true.
- The source validates Keycloak signature, issuer, audience and expiry before
  derivation. An invalid/missing/future DOB, tampered source JWT, and wrong
  source audience must fail closed with no destination assertion.
- A newly generated P-256 source signing key signs a minimal, short-lived
  ES256 assertion; the verifier checks signature, issuer, destination
  audience, expiry, and exactly the expected claim schema. Neither key nor
  token is saved in the retained result.

## Pass/fail and retention

Pass requires the actual Keycloak token endpoint to answer, all three fixed
fixture dates to match the oracle, both leap-day pure-function cases to match,
all negative controls to reject, and each issued destination assertion to
contain `age_over_18` but neither `birth_date` nor the source token. A
sanitized JSON result records the software/image identity, case verdicts,
assertion field names and byte counts, and checks only; it stores no bearer,
raw birth date, signing key, or raw logs. A secret scan must pass. Any missing
endpoint or failed check means **not demonstrated**. Do not pool this case
count with the earlier 16/90-event results or call it a registered two-host
trial. If it passes, report it in the manuscript as a post-hoc supplemental
feasibility test with these scope limits.
