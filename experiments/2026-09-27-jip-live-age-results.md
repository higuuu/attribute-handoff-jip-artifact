# Supplemental request-time age derivation: execution record

The prospective protocol was committed as `f41612334945e8529e6bd7f8aa7241d85de38891`
before implementation. This is a **post-original-study local supplement**, not a
revision of the 16-case audit or 90-event two-host follow-up.

## Actual setup and result

- Keycloak 26.7.3 was run from `quay.io/keycloak/keycloak@sha256:29be7252db0a106f1cd2ac17b9a56ff2668073da645638a38b9fc67deeb2d6c4`
  on loopback port 18880 in a dedicated disposable container. The source
  adapter used its actual token and JWKS endpoints. The verifier was a
  separate local Python process receiving only a signed predicate assertion
  and public JWK via stdin, not a raw token or DOB.
- The fixture held `birth_date=2008-09-27` but **no stored age flag**. For
  reference dates 2026-09-26, 2026-09-27, 2026-09-28, observed results were
  false/true/true (3/3). Signed assertions contained exactly `iss`, `aud`,
  `sub`, `age_over_18`, `iat`, and `exp`; the separate verifier accepted their
  ES256 signature, destination audience, issuer, expiry, and schema.
- Seven controls passed: February-29 boundary before/after March 1, invalid,
  missing, and future DOB rejection, tampered source signature rejection,
  and source-audience mismatch rejection. Unit test suite: 11 passed.
- Retained `output/results/live-age-supplement.json` SHA-256:
  `617bc5bf8debda51e1a95069dd19abc7eae22b8de4dbb1110f6d5362c8cc949b`.
  It includes per-file source hashes and passed a scan for JWT-like material,
  PEM keys, test passwords, raw DOB, and the `birth_date` field name.

The first disposable realm import omitted required synthetic user profile
fields and Keycloak rejected password grant with `resolve_required_actions`.
After correcting the fixture, the final run passed. This setup correction is
not hidden or counted as a successful trial. The test container was removed
afterward; the unrelated running DB was untouched.

## What this does **not** establish

The adapter and verifier ran on the same physical host; stdin was the
process boundary. It did not test geographic separation, network interception,
independent operators, actual-age identity proofing, stale source-attribute
updates, a Keycloak plug-in, request authorization policy, all-path bypass,
credential status/revocation, or performance. The test injects reference
dates to check the calendar boundary; it does not simulate the passage of
real time. The old O* path remains a stored flag, and the two studies must not
be pooled.
