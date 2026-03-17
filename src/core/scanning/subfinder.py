import hashlib
import json


def parse_subfinder_jsonl(jsonl_str: str, engagement_id: str) -> list[dict]:
    findings = []
    for line in jsonl_str.strip().splitlines():
        line = line.strip()
        if not line:
            continue

        try:
            data = json.loads(line)
            host = data.get("host", line)
        except json.JSONDecodeError:
            host = line

        fp_input = f"subdomain|{host.lower()}"
        fingerprint = hashlib.sha256(fp_input.encode()).hexdigest()

        findings.append(
            {
                "engagement_id": engagement_id,
                "title": f"Subdomain discovered: {host}",
                "severity": "info",
                "finding_type": "subdomain",
                "target_value": host,
                "detail": {"subdomain": host, "source": data.get("source", "subfinder")},
                "fingerprint": fingerprint,
            }
        )

    return findings
