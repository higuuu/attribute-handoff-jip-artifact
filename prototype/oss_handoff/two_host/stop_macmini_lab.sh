#!/bin/sh
set -u

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository=$(CDPATH= cd -- "$here/../../.." && pwd)
runtime="$repository/prototype/oss_handoff/.runtime/two-host"
compose_base="$repository/prototype/oss_handoff/compose.yaml"
compose_override="$repository/prototype/oss_handoff/two_host/compose.macmini.yaml"

cleanup_failed=0

if test -f "$runtime/tailscale-serve-owned"; then
  current_serve=""
  if ! current_serve=$(mktemp "$runtime/tailscale-serve-current.XXXXXX"); then
    echo "Could not create a temporary Serve-state file; leaving Serve unchanged." >&2
    cleanup_failed=1
  elif ! tailscale serve status --json >"$current_serve"; then
    echo "Could not read Tailscale Serve state; leaving it unchanged for manual review." >&2
    cleanup_failed=1
  elif ! test -f "$runtime/tailscale-serve-owned.json"; then
    echo "Serve ownership snapshot is missing; refusing a broad reset." >&2
    cleanup_failed=1
  elif ! cmp -s "$runtime/tailscale-serve-owned.json" "$current_serve"; then
    echo "Serve configuration changed after startup; refusing to reset unrelated mappings." >&2
    cleanup_failed=1
  elif tailscale serve reset; then
    rm -f "$runtime/tailscale-serve-owned" "$runtime/tailscale-serve-owned.json"
  else
    echo "Tailscale Serve reset failed; continue with local cleanup and review Serve manually." >&2
    cleanup_failed=1
  fi
  if test -n "$current_serve"; then
    rm -f "$current_serve"
  fi
else
  echo "No experiment-owned Tailscale Serve mapping; leaving Serve configuration unchanged."
fi

if test -f "$runtime/pep-server.pid"; then
  pep_pid=$(cat "$runtime/pep-server.pid")
  if kill -0 "$pep_pid" 2>/dev/null; then
    pep_command=$(ps -p "$pep_pid" -o command= 2>/dev/null || true)
    case "$pep_command" in
      *prototype.oss_handoff.two_host.pep_server*)
        if ! kill "$pep_pid" 2>/dev/null; then
          echo "Could not stop the recorded PEP process $pep_pid." >&2
          cleanup_failed=1
        fi
        ;;
      *)
        echo "Recorded PEP PID $pep_pid belongs to another process; refusing to kill it." >&2
        cleanup_failed=1
        ;;
    esac
  fi
  rm -f "$runtime/pep-server.pid"
fi

if ! docker compose -f "$compose_base" -f "$compose_override" down; then
  echo "Docker Compose cleanup failed." >&2
  cleanup_failed=1
fi

echo "Completed the local PEP and Mac mini container cleanup attempt."
echo "Synthetic token and C-bundle files remain under $runtime for evidence handling."
if test "$cleanup_failed" -ne 0; then
  echo "One or more cleanup steps require manual review." >&2
  exit 1
fi
