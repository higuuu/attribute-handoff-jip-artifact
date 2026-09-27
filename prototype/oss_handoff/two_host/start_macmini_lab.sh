#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository=$(CDPATH= cd -- "$here/../../.." && pwd)
runtime="$repository/prototype/oss_handoff/.runtime/two-host"
compose_base="$repository/prototype/oss_handoff/compose.yaml"
compose_override="$repository/prototype/oss_handoff/two_host/compose.macmini.yaml"

mkdir -p "$runtime"
cd "$repository"

if test -n "$(git status --porcelain --untracked-files=normal)"; then
  echo "Refusing to start from a dirty Git working tree; commit or stash the experiment changes first." >&2
  exit 1
fi

serve_state=$(tailscale serve status --json)
if test "$serve_state" != "{}"; then
  echo "Refusing to replace an existing Tailscale Serve configuration." >&2
  echo "Review 'tailscale serve status' and clear it manually if appropriate." >&2
  exit 1
fi

PYTHONPATH=. python3 -m prototype.oss_handoff.two_host.prepare_two_host_realm

if test -s "$runtime/pep-events.jsonl"; then
  archive="$runtime/archive/$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$archive"
  mv "$runtime/pep-events.jsonl" "$archive/pep-events.jsonl"
  echo "Archived the previous ignored event log at $archive"
fi

pep_pid=""
serve_started=0
cleanup_on_error() {
  original_status=$?
  trap - EXIT INT TERM
  if test "$serve_started" = "1"; then
    tailscale serve reset >/dev/null 2>&1 || true
  fi
  if test -n "$pep_pid"; then
    kill "$pep_pid" 2>/dev/null || true
  fi
  rm -f "$runtime/pep-server.pid"
  docker compose -f "$compose_base" -f "$compose_override" down >/dev/null 2>&1 || true
  exit "$original_status"
}
trap cleanup_on_error EXIT INT TERM

docker compose -f "$compose_base" -f "$compose_override" up -d region-a policy

PYTHONPATH=. python3 -m prototype.oss_handoff.two_host.macmini_control setup \
  --mode observe-only \
  --phase baseline-deny-raw
PYTHONPATH=. python3 -m prototype.oss_handoff.two_host.prepare_c_bundle

if test -f "$runtime/pep-server.pid" && kill -0 "$(cat "$runtime/pep-server.pid")" 2>/dev/null; then
  echo "PEP server is already running" >&2
  exit 1
fi

PYTHONPATH=. nohup python3 -m prototype.oss_handoff.two_host.pep_server \
  >"$runtime/pep-server.stdout" 2>&1 &
pep_pid=$!
echo "$pep_pid" >"$runtime/pep-server.pid"

attempt=0
until test "$(curl --fail --silent http://127.0.0.1:8765/healthz 2>/dev/null || true)" = \
  '{"service":"two-host-handoff-pep","status":"ok"}'; do
  attempt=$((attempt + 1))
  if test "$attempt" -ge 30; then
    echo "PEP did not become ready; inspect $runtime/pep-server.stdout" >&2
    exit 1
  fi
  sleep 1
done
if ! kill -0 "$pep_pid" 2>/dev/null; then
  echo "PEP process exited after the health check" >&2
  exit 1
fi

tailscale serve --bg 8765
serve_started=1
tailscale serve status --json >"$runtime/tailscale-serve-owned.json"
touch "$runtime/tailscale-serve-owned"
trap - EXIT INT TERM

echo "Mac mini lab is ready in observe-only baseline mode."
echo "Do not use Tailscale Funnel."
echo "Runtime files to transfer to the Air:"
echo "  $runtime/api-token"
echo "  $runtime/air-c-bundle.json"
echo "Next, run the Air client once, then execute:"
echo "  $here/set_macmini_phase.sh remediated"
