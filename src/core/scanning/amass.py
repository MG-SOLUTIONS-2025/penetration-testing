"""OWASP Amass output parser — JSONL format."""

import hashlib
import json


def parse_amass_jsonl(jsonl_str: str, engagement_id: str) -> list[dict]:
    findings = []
    for line in jsonl_str.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        name = data.get("name", "")
        record_type = data.get("type", "subdomain")
        addresses = data.get("addresses", [])

        if not name:
            continue

        fp_input = f"amass|{name.lower()}|{record_type}"
        fingerprint = hashlib.sha256(fp_input.encode()).hexdigest()

        finding_type = "dns_record" if record_type != "subdomain" else "subdomain"

        findings.append(
            {
                "engagement_id": engagement_id,
                "title": f"Amass: {name} ({record_type})",
                "severity": "info",
                "finding_type": finding_type,
                "target_value": name,
                "detail": {
                    "name": name,
                    "type": record_type,
                    "addresses": addresses,
                    "source": data.get("source", "amass"),
                },
                "fingerprint": fingerprint,
            }
        )

    return findings
