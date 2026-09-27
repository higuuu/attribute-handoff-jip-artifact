# JIP two-physical-host remediation experiment

This directory prepares a controlled fail-to-pass experiment for the JIP
Technical Note. The Mac mini is the source-side system; the MacBook Air is a
lightweight Region B verifier and measurement client.

The experiment is not evidence of independent reproduction, geographic
deployment, data residency, legal compliance, or production capacity. Both
hosts are operated by the same author, use synthetic data, and communicate
through one tailnet.

## Allocation

### Mac mini (source side)

- Keycloak 26.7.3 Region A container
- OpenFGA 1.18.1 container
- source-adjacent PEP on loopback port 8765
- credential issuance, policy checks, and sanitized event logging
- Tailscale Serve for tailnet-only HTTPS termination

Keycloak and OpenFGA publish only to `127.0.0.1` on the Mac mini. They are not
reachable directly from the MacBook Air. The PEP is also loopback-only and is
exposed to the tailnet with Tailscale Serve. Never use Tailscale Funnel.

### MacBook Air (consumer side)

- one Python process
- HTTPS request generation and response byte counting
- certificate verification against the pinned Air-bundle CA set
- OIDC token signature/audience verification
- cached SD-JWT VC signature, disclosure, and holder-binding verification
- JSON result generation

No Docker service or JVM runs on the Air. The default run performs ten
repetitions per case. The only third-party packages are `cryptography` and the
pinned `certifi` CA bundle; HTTPS verification is never disabled.

## What is tested

The same API and request matrix is used in three phases.

1. `baseline-deny-raw` / `observe-only`
   - OpenFGA denies R, but the PEP records the denial and deliberately forwards
     the request as a registered negative control.
   - a stale model ID is detected but deliberately not enforced.
   - expected observations: R returns a signed token containing `birth_date`;
     stale O* returns a token with a warning.
2. `remediated-deny-raw` / `enforce`
   - the policy store and model remain unchanged; only enforcement changes.
   - expected observations: R returns 403 with no evidence; stale O* returns
     409 with no evidence; current O* remains successful.
3. `measurement-allow-r-o-c` / `enforce`
   - a new policy permits R, O, and C so descriptive R/O*/C latency and byte
     counts can be collected without conflating expected denial with latency.

The first two phases establish a controlled fail-to-pass delta. The third is
descriptive only. Byte count is not treated as a privacy metric; the semantic
fields crossing the boundary remain the primary disclosure observation.

## Files

- `pep.py`: pure decision logic used by unit tests and the HTTP service
- `pep_server.py`: bearer-authenticated loopback HTTP service
- `macmini_control.py`: OpenFGA fixture and observe/enforce phase control
- `prepare_c_bundle.py`: fresh synthetic C credential for offline Air checks
- `prepare_two_host_realm.py`: generated two-host realm with a 7,200-second
  synthetic C lifetime; the frozen base realm remains unchanged
- `air_runner.py`: lightweight Region B runner with secret-free results
- `validate_results.py`: cross-phase registered-condition validator
- `compose.macmini.yaml`: loopback-only Keycloak/OpenFGA port overlay
- `start_macmini_lab.sh`, `set_macmini_phase.sh`, `stop_macmini_lab.sh`: operator
  runbook commands
- `build_air_bundle.py`: deterministic, credential-free client ZIP builder

## Safety properties of the harness

- the server refuses a non-loopback bind;
- remote transport must be tailnet HTTPS; the Air runner rejects remote HTTP;
- every experiment, configuration, and JWKS API call requires a random bearer
  token stored with mode `0600`; only `/healthz` is unauthenticated;
- audience and purpose mismatches are always rejected, including observe-only
  mode;
- policy backend failure returns 503 and never falls through to issuance;
- event logs and Air results never persist access tokens, credentials, holder
  keys, or API bearer tokens;
- direct Keycloak reachability is probed from the Air and is expected to fail;
- a two-host result requires the probe, distinct hashed host names, the same
  fixed implementation commit, and the same C bundle across all phases;
- generated runtime secrets are ignored by Git.
- startup refuses to replace a pre-existing Tailscale Serve configuration, and
  shutdown resets Serve only when this harness created the mapping;

## Prepared execution sequence

First complete the Air virtual-environment setup in `AIR-README.md`. All
remaining commands below are run only after reviewing the preregistration at
`experiments/2026-09-26-jip-two-host-remediation-preregistration.md`.

### 1. Mac mini: start baseline

```bash
prototype/oss_handoff/two_host/start_macmini_lab.sh
tailscale serve status
```

The start script refuses a dirty Git tree, creates a two-host-specific realm,
and creates ignored runtime files at
`prototype/oss_handoff/.runtime/two-host/`. Transfer `api-token` and
`air-c-bundle.json` to the Air through an approved tailnet file-transfer method;
do not add either file to Git.

Build the credential-free Air package when needed:

```bash
python3 -m prototype.oss_handoff.two_host.build_air_bundle
```

### 2. MacBook Air: run baseline

Follow `AIR-README.md` from the client ZIP and save to a new filename such as
`results/baseline-deny-raw.json`.

### 3. Mac mini: change only enforcement

```bash
prototype/oss_handoff/two_host/set_macmini_phase.sh remediated
```

Run the same Air command with output
`results/remediated-deny-raw.json`.

### 4. Mac mini: enable measurement policy

```bash
prototype/oss_handoff/two_host/set_macmini_phase.sh measurement
```

Run the Air command with output `results/measurement-allow-r-o-c.json`.

Then stop only Region A and run the Air client's `--offline-c-only` command:

```bash
docker compose \
  -f prototype/oss_handoff/compose.yaml \
  -f prototype/oss_handoff/two_host/compose.macmini.yaml \
  stop region-a
```

The offline command does not contact the PEP or fetch JWKS; it uses only the
fresh C bundle already held by the Air. Its direct-source probe must fail.

### 5. Stop and preserve only sanitized evidence

```bash
prototype/oss_handoff/two_host/stop_macmini_lab.sh
```

Co-locate the four sanitized Air result files with this run's ignored
`pep-events.jsonl`, then run the bundled `validate_results.py` command from
`AIR-README.md`. The validator requires the exact 9 x repetition PEP events and
checks the registered policy/issuer call pattern as well as the Air records.
Before committing results, check that the Air JSON files contain no `evidence`,
`credential`, `holder_private_key`, `Authorization`, or bearer-token value.
Record hashes of the four sanitized result files, final validation JSON, and
the fixed commit. A failed Serve reset must not prevent local PEP/container
cleanup; any ownership mismatch is left for explicit manual review.
