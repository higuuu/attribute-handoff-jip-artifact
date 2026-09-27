# JIP two-physical-host remediation result

Date: 2026-09-27 JST

Pre-registration: `experiments/2026-09-26-jip-two-host-remediation-preregistration.md`

Fixed implementation commit: `817838415303a0e4bcf6036f1059218edcade659`

## Scope

One author ran the synthetic Region A/source services (Keycloak 26.7.3,
OpenFGA 1.18.1, and a source-adjacent PEP) on a Mac mini. A MacBook Air ran the
lightweight request and verifier client across the author's Tailscale tailnet.
Each online case and the cached-C verification had ten repetitions. The source
ports remained bound to Mac mini loopback; the Air's direct-source probe was
unreachable in all four phases. Host separation is based on different hashed
host names, not hardware attestation.

## Registered outcomes

| Condition | Baseline observe-only | Remediated enforce | Measurement allow-R/O/C |
| --- | --- | --- | --- |
| Current R | 10/10 HTTP 200; `birth_date` disclosed despite deny-R policy | 10/10 HTTP 403; no evidence; issuer not called | 10/10 HTTP 200; `birth_date` disclosed under a new allow-R model |
| Current O* | 10/10 HTTP 200; only stored `age_over_18` | 10/10 HTTP 200; only stored `age_over_18` | 10/10 HTTP 200; only stored `age_over_18` |
| Stale-model O* | 10/10 HTTP 200 with warning; `age_over_18` disclosed | 10/10 HTTP 409; no evidence; neither policy backend nor issuer called | 10/10 HTTP 409; no evidence |
| Cached C | 10/10 verified without a presentation-time source request | 10/10 verified | 10/10 verified |

The baseline and remediated phases used the same denying OpenFGA model. The
measurement phase created a new model allowing R, O, and C. After Region A was
stopped, the Air verified the same cached C bundle 10/10 times, with zero
presentation-time source requests and a failed direct-source probe
(`ConnectionRefusedError`). The model and bundle continuity, exact 90 PEP
events, record semantics, and policy/issuer call patterns were checked by the
registered cross-phase validator: **61/61 checks passed**.

The measurement phase reported client-observed medians (p50/p95): current R
315.865/496.681 ms; current O* 326.071/593.266 ms; cached C local verification
0.450/16.227 ms. Median signed-evidence sizes were 877, 873, and 2,716 bytes,
respectively. C's local verification excludes an online request and is not an
equivalent latency path. These ten-repeat figures are descriptive; byte counts
are not privacy metrics. The semantic crossing fields above are the disclosure
observation.

## Evidence and integrity

Sanitized artifacts are in `output/two-host/2026-09-27-cross-host/`:

| Artifact | SHA-256 |
| --- | --- |
| `baseline-deny-raw.json` | `94f87d1ab30f5466020d09e9d57eae93a9bdcd887d4b0bf399a65205db649b6a` |
| `remediated-deny-raw.json` | `8ad15ca3bf5a567659347e473b2bffc87611c6691a7e4229aaad5b0b69992c8c` |
| `measurement-allow-r-o-c.json` | `369b4c86dec58e66f1a362cdb8d6c393db288fc76bf070e55041351de7065c8f` |
| `c-source-offline.json` | `10b9cc3b4782ca13ad6e5252f08c0227255c3458cd76d05d16cbfe505331284e` |
| `pep-events.jsonl` | `e7f8d7a25fabd4227b96beee4833dcddd3a8cc042ec7233cf517156faf7ce923` |
| `final-validation.json` | `9a4828b4da7aab6a28b48f46337f829c8eb4bc6db12a047e4338383be20cbe72` |

All four Air results recorded one client code hash
(`1b304ff774894edbc4548e27e95c1bf2e72d0612bf7d438692807f9785a7074b`),
one C-bundle hash
(`9e093ce4fd6e64eeb86eceb025d21c025d4c22cd8868d3c423e001e690a9a5da`),
and one pinned CA-bundle hash
(`9cc2a774b5198dcff14d9be1e66091f538975d867ce029a96bce15a55dfd730f`).
The copied result files, event log, and validator output passed a scan for
private-key markers, sensitive value keys, and the live PEP bearer value. No
token, credential, or holder key was committed.

## Claim boundary

This is one controlled fail-to-pass integration result on two physical Macs
operated by the same author. It shows enforcement at the exposed PEP request
path, not all-path non-bypassability. O* still retrieves a stored predicate;
the original credential-status and administrative-deletion findings remain
unresolved. It does not establish independent reproduction, geographic or
legal separation, production capacity, or general reliability. The original
frozen 13/16 audit labels are historical results and were not rewritten.
