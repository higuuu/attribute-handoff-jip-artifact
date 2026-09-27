# Attribute-handoff audit: reviewer artifact

Author: Shuya Higuchi (independent researcher, Japan)

This repository is a deliberately limited disclosure package for the JIP
Technical Note *Minimizing Personal-Attribute Disclosure:
An Age-Check Case Study*. It contains synthetic
configuration, the experiment source, preregistrations, sanitized result
records, and the cross-phase
validator. It is not the author's complete private working repository and does
not contain the manuscript PDF, credentials, raw tokens, holder keys, private
runtime state, or Tailscale configuration. The retained result files contain
SHA-256 fingerprints of host names. These are pseudonymous consistency checks,
not a guarantee of anonymity or hardware identity.

## Evidence map

| Claim or step | File |
| --- | --- |
| Original fixed protocol | `experiments/2026-09-20-iwsec-oss-feasibility-preregistration.md` |
| Original hardened audit, 13/16 labels | `prototype/attribute_handoff/results/iwsec-oss-feasibility-20260920/result.json` |
| Two-host fixed protocol | `experiments/2026-09-26-jip-two-host-remediation-preregistration.md` |
| Two-host phase records and PEP event log | `output/two-host/2026-09-27-cross-host/` |
| Cross-phase 61-check validator | `prototype/oss_handoff/two_host/validate_results.py` |
| Bounded interpretation and artifact hashes | `experiments/2026-09-27-jip-two-host-results.md` |
| Local request-time age protocol and result | `experiments/2026-09-27-jip-live-age-protocol.md`, `experiments/2026-09-27-jip-live-age-results.md`, `output/results/live-age-supplement.json` |
| Local source adapter and separate verifier | `prototype/oss_handoff/live_age/` |
| Integrated local follow-up protocol and result | `experiments/2026-09-27-jip-integrated-live-age-preregistration.md`, `experiments/2026-09-27-jip-integrated-age-local-results.md` |
| Integrated PEP/client/validator and 60-event result | `prototype/oss_handoff/integrated_age/`, `output/results/jip-integrated-age-20260927/` |
| Prior-art and novelty assessment | `experiments/2026-09-27-jip-prior-art-assessment.md` |

`MANIFEST.sha256` lists the byte-level hashes of every copied source and
evidence file. The original audit result is SHA-256
`ae2c874c823095b952d3b2caf57cf95f3a4d0961bf10dc4180b183e3303ddc42`.
The final two-host validation output is SHA-256
`9a4828b4da7aab6a28b48f46337f829c8eb4bc6db12a047e4338383be20cbe72`.
The two-host implementation was fixed at the source repository commit
`817838415303a0e4bcf6036f1059218edcade659`. The copied implementation
files were checked against that commit before packaging. That commit belongs
to an author-controlled private repository; this package supplies the source
files needed to inspect it, not the private Git history.
The later local age-derivation protocol was fixed in commit
`f41612334945e8529e6bd7f8aa7241d85de38891`. Its result has SHA-256
`cc8257bd7f64bf071505dfbe3ccd2c307a95fe5a0ae41e0a997c67a4cabb8876`
and records hashes of the exact source/fixture files. Its original source is
preserved in this repository's earlier public commit
`8190570a39e933a4122dffcf3ea2bb95eb792fec`; the current
`live_age/core.py` was refactored for the later integrated experiment.
This supplement is not part of the historical two-host trial.

The subsequent integrated single-host experiment was prospectively fixed at
source commits `787d127862f7638e004795037034c0e5026b79ff` (protocol) and
`3275dd33ccb13334cdc944e745f9c9e9d5ef52e1` (implementation). Its
60-event cross-phase validator passed 76/76 checks. The fixed validator
output SHA-256 is
`42af3d837971c96f9c4c0bac70e7a0295fb89c791c8b273606c3ef4436aafc32`.
The result files contain sanitized client records and PEP events, not tokens
or raw source attributes. This new run was on one Mini, not the Air.

## Verify retained results without running the services

From this repository root, run:

```sh
shasum -a 256 -c MANIFEST.sha256
python3 -m prototype.oss_handoff.two_host.validate_results \
  --baseline output/two-host/2026-09-27-cross-host/baseline-deny-raw.json \
  --remediated output/two-host/2026-09-27-cross-host/remediated-deny-raw.json \
  --measurement output/two-host/2026-09-27-cross-host/measurement-allow-r-o-c.json \
  --offline-c output/two-host/2026-09-27-cross-host/c-source-offline.json \
  --events output/two-host/2026-09-27-cross-host/pep-events.jsonl \
  --output /tmp/jip-two-host-validation-recheck.json
shasum -a 256 /tmp/jip-two-host-validation-recheck.json
```

The last digest should be
`9a4828b4da7aab6a28b48f46337f829c8eb4bc6db12a047e4338383be20cbe72`.
Use a different output path if that temporary file already exists; the
validator refuses to overwrite it. This rechecks the retained records, not
the physical experiment.

The local supplement can be inspected without starting Keycloak by checking
its result against the manifest and reviewing the source/test files. A fresh
run requires Docker and the loopback-only synthetic fixture.

The integrated local result can be rechecked without services:

```sh
python3 -m prototype.oss_handoff.integrated_age.validate \
  --baseline output/results/jip-integrated-age-20260927/final-baseline.json \
  --enforced output/results/jip-integrated-age-20260927/final-enforced.json \
  --boundary output/results/jip-integrated-age-20260927/final-boundary.json \
  --events output/results/jip-integrated-age-20260927/final-events.jsonl \
  --output /tmp/jip-integrated-validation-recheck.json
shasum -a 256 /tmp/jip-integrated-validation-recheck.json
```

The digest should be
`42af3d837971c96f9c4c0bac70e7a0295fb89c791c8b273606c3ef4436aafc32`.

## Re-execution boundary

The code under `prototype/oss_handoff/two_host/` includes the historical
follow-up source plus a backward-compatible `O_live` dispatch addition. Its
original implementation is preserved at the earlier public commit named
above. `prototype/oss_handoff/live_age/` began as a separate local
supplement; the current `core.py` exposes its verified derivation function to
the new `integrated_age/` source PEP. The later run and historical results
must not be pooled.
Its synthetic Keycloak realm files contain deliberately local-only demo
passwords and client secrets, not live credentials. Never deploy them to an
Internet-exposed service. The two-host procedure requires an author-controlled
tailnet, two physical hosts, Keycloak 26.7.3, OpenFGA 1.18.1, and a local
Keycloak image tagged `oidc-load-lab-keycloak:26.7.3`. The latter image itself
is **not** included here; the recorded image ID is in the original result.
Consequently this package supports source and retained-record review, but is
not a one-command, independently reproducible environment. Running the
protocol afresh requires rebuilding and validating the service images and
supplying new local secrets. Do not reuse any old credential bundle or assume
that fresh results will have the same hashes or timings.

The original Region A/B roles ran on one physical host. The follow-up used two
separate physical hosts controlled by one author: Host A ran the source stack,
and Host B ran only a lightweight request/verifier client. The exposed PEP path was tested;
all-path non-bypassability, independent reproduction, geographic separation,
legal compliance, and presentation-time credential status were not established.
Request-time predicate derivation was first demonstrated in a same-host,
separate-process supplement and then integrated with a same-host PEP using
actual Keycloak/OpenFGA endpoints. It has **not** been run on the Air-side
two-host enforced path. The integrated assertion is request-nonce bound, but
no global replay database or all-path non-bypassability was demonstrated.
Latency measurements are descriptive
for this small sample and are not performance benchmarks.

No reuse license is specified for this disclosure package. Visibility alone
does not grant permission to redistribute or incorporate its contents into
another project; contact the author if you need such permission.
