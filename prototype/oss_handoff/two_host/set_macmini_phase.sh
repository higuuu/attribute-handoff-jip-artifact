#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository=$(CDPATH= cd -- "$here/../../.." && pwd)
phase=${1:-}

cd "$repository"
case "$phase" in
  baseline)
    PYTHONPATH=. python3 -m prototype.oss_handoff.two_host.macmini_control set-mode observe-only \
      --phase baseline-deny-raw
    ;;
  remediated)
    PYTHONPATH=. python3 -m prototype.oss_handoff.two_host.macmini_control set-mode enforce \
      --phase remediated-deny-raw
    ;;
  measurement)
    PYTHONPATH=. python3 -m prototype.oss_handoff.two_host.macmini_control setup \
      --allow-raw \
      --mode enforce \
      --phase measurement-allow-r-o-c
    ;;
  *)
    echo "usage: $0 baseline|remediated|measurement" >&2
    exit 2
    ;;
esac
