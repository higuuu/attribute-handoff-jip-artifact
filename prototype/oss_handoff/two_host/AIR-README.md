# MacBook Air client

This bundle is the lightweight Region B side of the two-physical-host JIP
experiment. It does not run Docker, Keycloak, OpenFGA, or the PEP. Its
third-party dependencies are `cryptography`, used to verify the signed R/O*
token and cached C credential, and a pinned `certifi` CA bundle used for PEP
HTTPS certificate verification. Certificate verification is never disabled.
The CA bundle SHA-256 is recorded in every result.

## One-time setup — complete before starting the Mac mini lab

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-air.txt
```

The Mac mini operator separately transfers two ignored runtime files:

- `api-token` — bearer token for the tailnet-only PEP;
- `air-c-bundle.json` — fresh synthetic C credential and synthetic holder key.

Both files are experiment secrets. Keep them outside Git and delete them after
the run.

The two-host-specific synthetic C credential is valid for 7,200 seconds. The
runner refuses a two-host phase when fewer than 600 seconds remain. Do not start
the Mac mini lab until this Python environment is ready.

## Run one phase

```bash
.venv/bin/python air_runner.py \
  --base-url https://MAC-MINI-TAILNET-NAME \
  --token-file api-token \
  --c-bundle air-c-bundle.json \
  --direct-source-probe-url http://MAC-MINI-TAILSCALE-IP:18080/realms/region-a \
  --two-physical-hosts \
  --repetitions 10 \
  --output results/PHASE.json
```

Use a new output filename for every phase. The result contains no token,
credential, private key, or API bearer token. It records only statuses,
latencies, byte counts, disclosed field names, hashes, and claim boundaries.
For a two-host run, the direct-source probe and C bundle are mandatory. The
runner also requires the Air host fingerprint to differ from the source
fingerprint supplied by the Mac mini PEP.

After Region A is stopped on the Mac mini, verify C without contacting the PEP:

```bash
.venv/bin/python air_runner.py \
  --offline-c-only \
  --c-bundle air-c-bundle.json \
  --direct-source-probe-url http://MAC-MINI-TAILSCALE-IP:18080/realms/region-a \
  --two-physical-hosts \
  --repetitions 10 \
  --output results/c-source-offline.json
```

## Validate the complete result set

No individual phase is sufficient evidence. After all four commands finish,
co-locate the four sanitized Air result files with the Mac mini's ignored
`pep-events.jsonl` by transferring either set through the approved tailnet file
transfer method. Do not use Git for this transfer. Then run the bundled
cross-phase validator:

```bash
.venv/bin/python validate_results.py \
  --baseline results/baseline-deny-raw.json \
  --remediated results/remediated-deny-raw.json \
  --measurement results/measurement-allow-r-o-c.json \
  --offline-c results/c-source-offline.json \
  --events pep-events.jsonl \
  --expected-repetitions 10 \
  --expected-source-port 18080 \
  --output results/final-validation.json
```

This rejects changed deny-policy models, Air-runner code, C bundles or commits,
missing phases, PEP events or probes, wrong repetition counts, non-distinct host
fingerprints, unexpected record/event status, disclosure or call shapes, and
insufficient credential lifetime. In particular, the event check requires the
remediated R rejection to avoid the issuer and the remediated stale-model
rejection to avoid both the policy backend and issuer.
