# Integrated live-age: lightweight destination run

This package has no API token, private key, result, or credential. Run only
after the Mac mini operator explicitly identifies the current experiment
phase. Do not reuse output filenames or infer two-host success from a local
Mini run. The second host needs Python, `cryptography`, `certifi`, and
authenticated tailnet HTTPS; no Docker or JVM.

From the extracted ZIP root, create a virtual environment and install
`prototype/oss_handoff/two_host/requirements-air.txt`. Place the one-time API
token in a separate mode-0600 file outside the bundle. The Mac mini operator
must supply the HTTPS PEP URL and a direct-source probe URL on the same Mini
tailnet IP (for example, port 18880; it must be unreachable).

For each phase, run:

```sh
python3 -m prototype.oss_handoff.integrated_age.client \
  --base-url "$PEP_HTTPS_URL" \
  --token-file "$API_TOKEN_FILE" \
  --direct-source-probe-url "$DIRECT_SOURCE_PROBE_URL" \
  --two-physical-hosts \
  --output results/integrated-baseline.json
```

Use a fresh `integrated-enforced.json` output name for the enforcement phase.
Do not switch phases independently. Each run makes 30 small requests and
verifies signed evidence; it writes only sanitized JSON. It does not upload
anything automatically. Confirm `all_expectations_passed: true`, hash the
output, scan it for tokens/secrets, and return only the sanitized result to
the Mac mini operator. Never include the API token in the result package.

The initial current-date predicate must be true for the synthetic fixture on
or after 2026-09-27 UTC. If run before that date, this registered protocol
cannot pass. The PEP key is ephemeral; both phases must use the same running
PEP process. Its JWK hash in the two results must match.
