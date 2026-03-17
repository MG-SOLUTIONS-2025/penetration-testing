import hashlib
import json


def parse_nuclei_jsonl(jsonl_str: str, engagement_id: str) -> list[dict]:
    findings = []
    for line in jsonl_str.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        template_id = data.get("template-id", "unknown")
        matched_at = data.get("matched-at", "unknown")
        severity = data.get("info", {}).get("severity", "info").lower()
        name = data.get("info", {}).get("name", template_id)
        description = data.get("info", {}).get("description", "")
        tags = data.get("info", {}).get("tags", [])
        matcher_name = data.get("matcher-name", "")
        extracted = data.get("extracted-results", [])

        title = f"{name} - {matched_at}"

        fp_input = f"nuclei|{template_id}|{matched_at}"
        fingerprint = hashlib.sha256(fp_input.encode()).hexdigest()

        # Map nuclei severity to our severity
        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "info",
            "unknown": "info",
        }
        severity = severity_map.get(severity, "info")

        findings.append(
            {
                "engagement_id": engagement_id,
                "title": title,
                "severity": severity,
                "finding_type": "vuln",
                "target_value": matched_at,
                "detail": {
                    "template_id": template_id,
                    "name": name,
                    "description": description,
                    "tags": tags,
                    "matcher_name": matcher_name,
                    "extracted_results": extracted,
                    "type": data.get("type", ""),
                },
                "raw_output": json.dumps(data)[:5000],
                "fingerprint": fingerprint,
            }
        )

    return findings
