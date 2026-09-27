"""Deterministic, credential-free bundle for the lightweight second host."""

from __future__ import annotations

import argparse
import hashlib
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
OUTPUT = ROOT / "output/two-host/jip-integrated-age-air-client-v0.1.zip"
FILES = (
    "prototype/oss_handoff/__init__.py",
    "prototype/oss_handoff/crypto_utils.py",
    "prototype/oss_handoff/live_age/__init__.py",
    "prototype/oss_handoff/live_age/core.py",
    "prototype/oss_handoff/two_host/__init__.py",
    "prototype/oss_handoff/two_host/common.py",
    "prototype/oss_handoff/two_host/air_runner.py",
    "prototype/oss_handoff/integrated_age/__init__.py",
    "prototype/oss_handoff/integrated_age/core.py",
    "prototype/oss_handoff/integrated_age/client.py",
    "prototype/oss_handoff/two_host/requirements-air.txt",
    "prototype/oss_handoff/integrated_age/AIR-README.md",
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for relative in FILES:
            source = ROOT / relative
            info = zipfile.ZipInfo(relative, date_time=(2026, 9, 27, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, source.read_bytes())
    print(f"output: {args.output}")
    print(f"sha256: {hashlib.sha256(args.output.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    main()
