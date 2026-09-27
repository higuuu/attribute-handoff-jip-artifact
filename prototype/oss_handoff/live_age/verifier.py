"""Separate local destination process; accepts only a minimal assertion."""

from __future__ import annotations

import json
import sys

from prototype.oss_handoff.live_age.core import verify_destination_assertion


def main() -> None:
    request = json.load(sys.stdin)
    if set(request) != {"assertion", "jwk", "now"}:
        raise ValueError("unexpected verifier input")
    claims = verify_destination_assertion(
        request["assertion"], request["jwk"], now=request["now"]
    )
    json.dump(
        {
            "age_over_18": claims["age_over_18"],
            "assertion_fields": sorted(claims),
            "signature_valid": True,
        },
        sys.stdout,
    )


if __name__ == "__main__":
    main()
