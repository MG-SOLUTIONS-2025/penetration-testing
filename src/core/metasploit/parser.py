"""Parse Metasploit session/exploit output into findings."""

import hashlib


def parse_exploit_result(
    module_name: str,
    target_value: str,
    session_data: dict | None,
    engagement_id: str,
) -> dict | None:
    """Convert a successful exploit attempt into a finding dict."""
    if not session_data:
        return None

    fp_input = f"exploit|{module_name}|{target_value}"
    fingerprint = hashlib.sha256(fp_input.encode()).hexdigest()

    return {
        "engagement_id": engagement_id,
        "title": f"Exploited: {module_name} on {target_value}",
        "severity": "critical",
        "finding_type": "exploit",
        "target_value": target_value,
        "detail": {
            "module": module_name,
            "session_type": session_data.get("type"),
            "session_info": session_data.get("info"),
        },
        "fingerprint": fingerprint,
    }
