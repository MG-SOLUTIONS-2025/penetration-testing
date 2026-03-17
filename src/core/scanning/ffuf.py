"""ffuf JSON output parser."""

import hashlib
import json


def parse_ffuf_json(json_str: str, engagement_id: str) -> list[dict]:
    findings = []

    try:
        data = json.loads(json_str)
    except json.JSONDecodeError:
        return []

    results = data.get("results", [])

    for result in results:
        url = result.get("url", "")
        status = result.get("status", 0)
        length = result.get("length", 0)
        words = result.get("words", 0)
        input_val = result.get("input", {}).get("FUZZ", "")

        fp_input = f"ffuf|{url}|{status}"
        fingerprint = hashlib.sha256(fp_input.encode()).hexdigest()

        severity = "info"
        if status in (200, 301, 302):
            severity = "low"
        if status in (401, 403):
            severity = "info"

        findings.append(
            {
                "engagement_id": engagement_id,
                "title": f"ffuf: {input_val} -> {url} (HTTP {status})",
                "severity": severity,
                "finding_type": "content_discovery",
                "target_value": url,
                "detail": {
                    "fuzz_input": input_val,
                    "status_code": status,
                    "content_length": length,
                    "word_count": words,
                    "scanner": "ffuf",
                },
                "fingerprint": fingerprint,
            }
        )

    return findings
