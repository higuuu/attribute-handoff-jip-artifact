# Supplemental `O_live` study

This is a separate, local Keycloak-endpoint feasibility test. It does not
replace historical O* (stored flag), reuse its case count, or demonstrate
remote/geographic deployment. The fixture contains synthetic local-only
passwords. Never deploy this compose file beyond loopback.

From the repository root:

```sh
docker compose -f prototype/oss_handoff/live_age/compose.yaml up -d
python3 -m prototype.oss_handoff.live_age.run --output output/results/live-age-supplement.json
docker compose -f prototype/oss_handoff/live_age/compose.yaml down
```

The runner retains only summary fields. It does not write the Keycloak token,
signed assertion, DOB, key, or raw HTTP response. Check the fixed prospective
protocol in `experiments/2026-09-27-jip-live-age-protocol.md` before reporting.
