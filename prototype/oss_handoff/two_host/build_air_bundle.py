from __future__ import annotations

import argparse
import hashlib
import zipfile
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
DEFAULT_OUTPUT = ROOT / "output" / "two-host" / "jip-two-host-air-client-v0.1.zip"


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the credential-free MacBook Air client bundle")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    files = {
        HERE / "air_runner.py": "air_runner.py",
        HERE / "validate_results.py": "validate_results.py",
        HERE.parent / "crypto_utils.py": "crypto_utils.py",
        HERE / "requirements-air.txt": "requirements-air.txt",
        HERE / "AIR-README.md": "README.md",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for source, destination in files.items():
            info = zipfile.ZipInfo(destination, date_time=(2026, 9, 26, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, source.read_bytes())
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    print(f"wrote {args.output}")
    print(f"sha256 {digest}")


if __name__ == "__main__":
    main()
