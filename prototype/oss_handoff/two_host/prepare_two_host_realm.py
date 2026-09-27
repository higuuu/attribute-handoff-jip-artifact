from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from .common import RUNTIME, write_json_atomic


HERE = Path(__file__).resolve().parent
DEFAULT_SOURCE = HERE.parent / "keycloak" / "region-a-realm.json"
DEFAULT_OUTPUT = RUNTIME / "region-a-realm.json"
CREDENTIAL_LIFETIME_SECONDS = 7200


def prepare_realm(source: Path, output: Path, credential_lifetime_seconds: int) -> dict[str, Any]:
    realm = json.loads(source.read_text())
    matching = [
        scope
        for scope in realm.get("clientScopes", [])
        if scope.get("name") == "RegionalEligibilityCredential"
    ]
    if len(matching) != 1:
        raise ValueError("expected exactly one RegionalEligibilityCredential client scope")
    matching[0].setdefault("attributes", {})["vc.expiry_in_seconds"] = str(credential_lifetime_seconds)
    write_json_atomic(output, realm)
    return {
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "output_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "credential_lifetime_seconds": credential_lifetime_seconds,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the two-host-specific synthetic Keycloak realm")
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--credential-lifetime-seconds", type=int, default=CREDENTIAL_LIFETIME_SECONDS)
    args = parser.parse_args()
    if args.credential_lifetime_seconds < 3600:
        parser.error("credential lifetime must be at least 3600 seconds for the cross-host procedure")
    result = prepare_realm(args.source, args.output, args.credential_lifetime_seconds)
    print(json.dumps({"output": str(args.output), **result}, sort_keys=True))


if __name__ == "__main__":
    main()
