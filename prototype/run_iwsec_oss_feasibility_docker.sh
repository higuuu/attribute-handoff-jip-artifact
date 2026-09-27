#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
compose_file="$repo_root/prototype/oss_handoff/compose.yaml"
runtime_dir="$repo_root/prototype/oss_handoff/.runtime"
project_name="dsfia-iwsec-oss"

mkdir -p "$runtime_dir"
find "$runtime_dir" -mindepth 1 -maxdepth 1 -type f -delete

cleanup() {
  docker compose -p "$project_name" -f "$compose_file" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker compose -p "$project_name" -f "$compose_file" up -d
docker compose -p "$project_name" -f "$compose_file" exec -T runner \
  python -m prototype.oss_handoff.run_experiment online

docker compose -p "$project_name" -f "$compose_file" stop region-a
docker compose -p "$project_name" -f "$compose_file" exec -T runner \
  python -m prototype.oss_handoff.run_experiment offline

docker compose -p "$project_name" -f "$compose_file" stop policy
docker compose -p "$project_name" -f "$compose_file" exec -T runner \
  python -m prototype.oss_handoff.run_experiment policy-offline

docker compose -p "$project_name" -f "$compose_file" start region-a policy
docker compose -p "$project_name" -f "$compose_file" exec -T runner \
  python -m prototype.oss_handoff.run_experiment final

python3 -m json.tool "$repo_root/prototype/attribute_handoff/results/iwsec-oss-feasibility-20260920/result.json" >/dev/null
echo "OSS feasibility result written to prototype/attribute_handoff/results/iwsec-oss-feasibility-20260920/result.json"
