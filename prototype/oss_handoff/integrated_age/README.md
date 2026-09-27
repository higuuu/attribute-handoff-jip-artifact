# Prospective integrated age-check handoff

This is the *new* experiment preregistered at
`experiments/2026-09-27-jip-integrated-live-age-preregistration.md`. It does
not modify the historical O* results. The source stack uses one synthetic
Keycloak realm with birth date only, OpenFGA policy decisions, and a Python
PEP that holds an ephemeral signing key. No real personal information is
present. Keep the Keycloak and OpenFGA ports on loopback; never use Funnel.

From the repository root on the Mac mini:

```sh
python3 -m prototype.oss_handoff.integrated_age.prepare prepare-realm
docker compose -f prototype/oss_handoff/integrated_age/compose.yaml up -d
python3 -m prototype.oss_handoff.integrated_age.prepare setup
python3 -m prototype.oss_handoff.integrated_age.pep_server \
  --events prototype/oss_handoff/.runtime/integrated-age/final-events.jsonl
```

Keep the PEP process running in that terminal. In another terminal, run the
baseline client (or have the Air operator run the bundled client over Tailscale
Serve HTTPS). This loopback example is **single-host** evidence only:

```sh
python3 -m prototype.oss_handoff.integrated_age.client \
  --base-url http://127.0.0.1:18882 \
  --token-file prototype/oss_handoff/.runtime/integrated-age/api-token \
  --output prototype/oss_handoff/.runtime/integrated-age/final-baseline.json
```

Then change only PEP mode and run the same client with a new output:

```sh
python3 -m prototype.oss_handoff.two_host.macmini_control set-mode enforce \
  --phase enforced \
  --config prototype/oss_handoff/.runtime/integrated-age/pep-config.json
python3 -m prototype.oss_handoff.integrated_age.client \
  --base-url http://127.0.0.1:18882 \
  --token-file prototype/oss_handoff/.runtime/integrated-age/api-token \
  --output prototype/oss_handoff/.runtime/integrated-age/final-enforced.json
python3 -m prototype.oss_handoff.integrated_age.boundary \
  --output prototype/oss_handoff/.runtime/integrated-age/final-boundary.json
python3 -m prototype.oss_handoff.integrated_age.validate \
  --baseline prototype/oss_handoff/.runtime/integrated-age/final-baseline.json \
  --enforced prototype/oss_handoff/.runtime/integrated-age/final-enforced.json \
  --boundary prototype/oss_handoff/.runtime/integrated-age/final-boundary.json \
  --events prototype/oss_handoff/.runtime/integrated-age/final-events.jsonl \
  --output prototype/oss_handoff/.runtime/integrated-age/final-validation.json
```

The PEP must not restart between phases because its signing key changes on
restart. The validator checks the same policy model, source, implementation,
adapter JWK, all 60 response/event pairs, and policy/issuer call flags. The
results contain no evidence tokens or raw attribute values. Preserve exact
file hashes and code commit for any publication claim.

For an actual two-host run, build the credential-free package with
`python3 -m prototype.oss_handoff.integrated_age.build_air_bundle`; see
`AIR-README.md`. Set up Tailscale Serve on the Mac mini only after checking
and preserving any existing Serve mapping. Transfer the bearer token through
an approved tailnet channel, never Git. If the Air remains offline, report
only the local result. At the end, stop the PEP and run
`docker compose -f prototype/oss_handoff/integrated_age/compose.yaml down`;
this only removes this isolated experiment's containers/network.
