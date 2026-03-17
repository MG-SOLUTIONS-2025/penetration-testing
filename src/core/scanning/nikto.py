"""Nikto JSON output parser."""

import hashlib
import json


def parse_nikto_json(json_str: str, engagement_id: str) -> list[dict]:
    findings = []

    try:
        data = json.loads(json_str)
    except json.JSONDecodeError:
        return []

    # Nikto JSON wraps results in various structures
    vulnerabilities = []
    if isinstance(data, dict):
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            # Try alternate format
            for host_data in data.get("host", []) if isinstance(data.get("host"), list) else [data]:
                vulnerabilities.extend(host_data.get("vulnerabilities", []))

    for vuln in vulnerabilities:
        osvdb_id = vuln.get("OSVDB", vuln.get("id", "0"))
        url = vuln.get("url", "")
        method = vuln.get("method", "GET")
        msg = vuln.get("msg", vuln.get("description", ""))

        fp_input = f"nikto|{osvdb_id}|{url}"
        fingerprint = hashlib.sha256(fp_input.encode()).hexdigest()

        severity = "medium"
        if "XSS" in msg.upper() or "INJECTION" in msg.upper():
            severity = "high"
        elif "INFORMATION" in msg.upper() or "HEADER" in msg.upper():
            severity = "low"

        findings.append(
            {
                "engagement_id": engagement_id,
                "title": f"Nikto: {msg[:120]}",
                "severity": severity,
                "finding_type": "web_vuln",
                "target_value": url,
                "detail": {
                    "osvdb": osvdb_id,
                    "method": method,
                    "description": msg,
                    "scanner": "nikto",
                },
                "fingerprint": fingerprint,
            }
        )

    return findings
