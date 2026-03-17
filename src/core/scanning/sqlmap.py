"""SQLMap JSON output parser with safety restrictions."""

import hashlib
import json

# Safety: restrict dangerous options
BLOCKED_OPTIONS = frozenset({"--os-shell", "--os-cmd", "--os-pwn", "--priv-esc", "--file-write"})
MAX_LEVEL = 3
MAX_RISK = 2


def validate_sqlmap_options(options: dict) -> dict:
    """Validate and sanitize SQLMap options."""
    level = options.get("level", 1)
    risk = options.get("risk", 1)

    if level > MAX_LEVEL:
        options["level"] = MAX_LEVEL
    if risk > MAX_RISK:
        options["risk"] = MAX_RISK

    # Block dangerous flags
    for key in list(options.keys()):
        if f"--{key}" in BLOCKED_OPTIONS or key in BLOCKED_OPTIONS:
            raise ValueError(f"Blocked SQLMap option: {key}")

    return options


def parse_sqlmap_json(json_str: str, engagement_id: str) -> list[dict]:
    findings = []

    try:
        data = json.loads(json_str)
    except json.JSONDecodeError:
        return []

    # SQLMap outputs results per URL
    if isinstance(data, dict):
        items = [data]
    elif isinstance(data, list):
        items = data
    else:
        return []

    for item in items:
        url = item.get("url", item.get("target", "unknown"))
        injections = item.get("data", item.get("injections", []))

        if isinstance(injections, dict):
            injections = list(injections.values())

        for inj in injections:
            if isinstance(inj, dict):
                param = inj.get("parameter", inj.get("place", "unknown"))
                inj_type = inj.get("type", inj.get("title", "SQL Injection"))
                payload = inj.get("payload", "")

                fp_input = f"sqlmap|{url}|{param}|{inj_type}"
                fingerprint = hashlib.sha256(fp_input.encode()).hexdigest()

                findings.append(
                    {
                        "engagement_id": engagement_id,
                        "title": f"SQL Injection: {param} on {url}",
                        "severity": "critical",
                        "finding_type": "sqli",
                        "target_value": url,
                        "detail": {
                            "parameter": param,
                            "injection_type": inj_type,
                            "payload": payload[:500],
                            "scanner": "sqlmap",
                        },
                        "fingerprint": fingerprint,
                    }
                )

    return findings
