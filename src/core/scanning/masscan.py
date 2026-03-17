"""Masscan JSON output parser with safety controls."""

import hashlib
import json

MAX_RATE_PPS = 10000


def validate_masscan_rate(rate: int) -> int:
    """Enforce hard cap on scan rate."""
    if rate > MAX_RATE_PPS:
        return MAX_RATE_PPS
    return max(1, rate)


def parse_masscan_json(json_str: str, engagement_id: str) -> list[dict]:
    findings = []

    # Masscan JSON output is an array of objects
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError:
        return []

    if not isinstance(data, list):
        return []

    for entry in data:
        ip = entry.get("ip", "unknown")
        ports = entry.get("ports", [])

        for port_info in ports:
            portid = port_info.get("port", 0)
            protocol = port_info.get("proto", "tcp")
            status = port_info.get("status", "")

            if status != "open":
                continue

            service = port_info.get("service", {})
            service_name = service.get("name", "unknown")

            fp_input = f"masscan|{ip}|{portid}/{protocol}"
            fingerprint = hashlib.sha256(fp_input.encode()).hexdigest()

            findings.append(
                {
                    "engagement_id": engagement_id,
                    "title": f"Open port {portid}/{protocol} on {ip}",
                    "severity": "info",
                    "finding_type": "open_port",
                    "target_value": ip,
                    "detail": {
                        "port": portid,
                        "protocol": protocol,
                        "service": service_name,
                        "scanner": "masscan",
                    },
                    "fingerprint": fingerprint,
                }
            )

    return findings
