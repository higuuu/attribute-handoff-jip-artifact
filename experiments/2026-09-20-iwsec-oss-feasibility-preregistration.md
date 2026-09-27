# IWSEC 2026 OSS feasibility experiment preregistration

**Registered:** 2026-09-20 JST
**Branch point:** `codex/iwsec-novelty-audit@29b7703177d2b8c123fb5e82182369a404ae856b`
**Status at registration:** no OSS feasibility result has been generated
**Scope:** local synthetic experiment on one Mac mini; no real person, production tenant, cloud region, or legal-compliance claim

## 1. Research question

Can existing open-source identity, credential, and policy components support cross-region attribute handoff while Region A and Region B retain separate user identifiers? If they cannot, what is the smallest missing control needed to make Raw (`R`), online-derived (`O`), and cached-proof (`C`) routes obey the same location, binding, freshness, and outage rules?

The experiment does not test whether a new cryptographic primitive is required. It tests an implementation claim made by the prior novelty audit: that a strong federation/Wallet baseline plus an application gate can express the proposed behavior.

## 2. Components fixed before implementation

- Two independently configured Keycloak 26.7.x instances: Region A and Region B.
- OpenID Connect identity brokering and pairwise subject identifiers for the federation baseline.
- Keycloak's experimental OpenID4VCI surface if it can be configured reproducibly from the pinned image.
- A standards-oriented Wallet/credential library or, if that cannot be integrated reproducibly, an independently identified library gap plus the existing research Wallet only as a clearly separated fallback.
- A versioned policy decision point using an existing OSS engine when available locally; otherwise a signed, versioned application gate whose non-OSS status is reported as a missing layer rather than attributed to the OSS stack.
- Docker-local networking and synthetic attributes only.

Component versions, image identifiers, configuration hashes, and any deviation from this list must be recorded in the result manifest.

## 3. Attribute and identity fixture

One synthetic person has:

- Region A internal ID `A-1001` and a source date of birth that satisfies `age_over_18`.
- Region B internal ID `B-9001`, distinct from the Region A ID.
- a destination-specific holder key generated for Region B.

Neither Region A's internal ID nor Region B's internal ID may appear as a shared subject identifier in the opposite region's issued application token or credential. A region-local link record is allowed but must be inventoried and classified as persistent correlation state.

The common relying-party question is `age_over_18 == true` for audience `region-b-service` and purpose `regional-service-eligibility`.

## 4. Route definitions

- `R`: Region B receives the source date of birth (or an encrypted envelope that decrypts to it at B) and evaluates the predicate at B.
- `O`: Region A is online, evaluates the predicate, and sends only `age_over_18=true` bound to the Region B audience/request.
- `C`: a previously issued holder-bound credential or proof is presented to Region B without contacting Region A during presentation.

A route is not counted as implemented merely because a local Python branch has the same name. The record must identify the actual OSS protocol endpoint and the fields that crossed the A/B boundary.

## 5. Invariants

`I1 Separate IDs`: A and B keep distinct internal user IDs; no global internal user ID is copied across regions.

`I2 Destination binding`: accepted O/C evidence is bound to the Region B audience and the B-specific holder key when the selected credential format supports holder binding.

`I3 Route disclosure`: R may expose the source attribute to B; O/C must not expose the source date of birth for the registered predicate request.

`I4 Source availability`: O must fail when A is unavailable. C may succeed only from already stored evidence and must not make a presentation-time request to A.

`I5 Freshness and status`: expired evidence, revoked evidence, and evidence evaluated under an unacceptable policy version must be rejected.

`I6 No unsafe fallback`: loss of A or of a policy/status service must not cause a transition to a route with greater disclosure or weaker policy than the signed request permits.

`I7 Replay/request binding`: nonce replay, audience change, purpose change, or holder-key substitution is rejected.

`I8 Correlation inventory`: persistent A-to-B mappings, stable cross-service identifiers, stored external tokens, and user-specific decision logs are measured rather than assumed absent.

## 6. Experimental conditions

The runner must cover at least these deterministic conditions:

1. pairwise subjects for two Region A clients are different;
2. Region A and Region B internal IDs are different after brokered login;
3. the Region B broker retains or does not retain an A-side linking identifier;
4. R succeeds only when raw transfer is allowed;
5. O succeeds while A is online and fails while A is stopped;
6. C succeeds while A is stopped when credential, status, and policy are within bounds;
7. expired C is rejected;
8. revoked C is rejected;
9. stale policy is rejected;
10. B-holder-key substitution is rejected;
11. nonce replay is rejected;
12. disabling raw transfer cannot be bypassed by source outage or route fallback.

Normal and negative-control cases must be run. Expected rejection is a pass only when the observed reason matches the registered invariant.

## 7. Measurements

- invariant pass/fail per condition;
- actual route and protocol surface;
- fields crossing the A/B boundary;
- persistent identifiers and user-specific state stored by each component;
- source calls made during C presentation;
- added configuration, plugin, and custom controller surface;
- decision latency as descriptive local evidence only;
- image/version/configuration digest and runner environment.

No acceptance-rate or production-capacity inference is made from deterministic correctness cases or one-host latency.

## 8. Decision rules

### D1: stock-OSS support

Use this conclusion only if the unmodified OSS components satisfy `I1` through `I8`, apart from declarative configuration and test orchestration.

### D2: minimal missing handoff layer

Use this conclusion if identity brokering and credential exchange work, but route authorization, cross-route freshness, or safe fallback requires one small component. The paper contribution must be limited to the missing contract and its measured failure boundary.

### D3: integration gap

Use this conclusion if the pinned components cannot interoperate for one or more routes without issuer/verifier modification, or if their stored mapping defeats the stated identity-separation goal. The result is an empirical gap report, not a claim that all OSS has the same limitation.

### D4: no viable IWSEC claim

Use this conclusion if only the pre-existing research prototype can be exercised, if actual OSS endpoints are not observed, or if negative controls are not detected reliably.

## 9. Kill conditions

- Do not call the experiment cross-region deployment evidence: both regions run on one Mac mini.
- Do not call a precomputed boolean a zero-knowledge predicate.
- Do not describe Keycloak OpenID4VCI as production-stable while its upstream status is experimental.
- Do not treat a signed JWT alone as proof of holder possession.
- Do not infer absence of correlation from different visible `sub` values without inspecting the broker's stored link.
- Do not claim that C is offline if presentation triggers issuer, status, policy, schema, or metadata network access not covered by a bounded cache.
- Do not claim legal data-residency compliance from Docker network placement.
- Do not replace a failed OSS integration silently with a custom simulation.

## 10. Publication outputs

After results are frozen, produce:

1. a machine-readable result manifest without keys, tokens, credentials, raw logs, or personal paths;
2. a Japanese experiment report separating confirmed, unconfirmed, problems, and next actions;
3. a 300--500 word English IWSEC poster abstract;
4. a Japanese abstract/reader version;
5. a Go/Narrow/No-Go conclusion derived from D1--D4.
