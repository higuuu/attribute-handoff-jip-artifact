from __future__ import annotations

import json

from prototype.oss_handoff.two_host.prepare_two_host_realm import prepare_realm


def test_two_host_realm_extends_only_the_generated_copy(tmp_path) -> None:  # noqa: ANN001
    source = tmp_path / "source.json"
    output = tmp_path / "output.json"
    source.write_text(
        json.dumps(
            {
                "clientScopes": [
                    {
                        "name": "RegionalEligibilityCredential",
                        "attributes": {"vc.expiry_in_seconds": "120"},
                    }
                ]
            }
        )
    )
    result = prepare_realm(source, output, 7200)
    assert json.loads(source.read_text())["clientScopes"][0]["attributes"]["vc.expiry_in_seconds"] == "120"
    assert json.loads(output.read_text())["clientScopes"][0]["attributes"]["vc.expiry_in_seconds"] == "7200"
    assert result["credential_lifetime_seconds"] == 7200
