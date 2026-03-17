"""OWASP ZAP JSON report parser."""

import hashlib
import json


def parse_zap_json(json_str: str, engagement_id: str) -> list[dict]:
    findings = []

    try:
        data = json.loads(json_str)
    except json.JSONDecodeError:
        return []

    # ZAP JSON report structure
    sites = data.get("site", [])
    if isinstance(sites, dict):
        sites = [sites]

    for site in sites:
        site_name = site.get("@name", "unknown")
        alerts = site.get("alerts", [])

        for alert in alerts:
            name = alert.get("name", alert.get("alert", "Unknown"))
            risk_str = alert.get("riskdesc", alert.get("risk", "")).lower()
            cwe_id = alert.get("cweid", None)
            wasc_id = alert.get("wascid", None)
            description = alert.get("desc", "")
            solution = alert.get("solution", "")
            instances = alert.get("instances", [])

            severity = _map_zap_risk(risk_str)

            for instance in instances:
                url = instance.get("uri", site_name)
                method = instance.get("method", "GET")
                param = instance.get("param", "")

                fp_input = f"zap|{name}|{url}|{param}"
                fingerprint = hashlib.sha256(fp_input.encode()).hexdigest()

                findings.append(
                    {
                        "engagement_id": engagement_id,
                        "title": f"ZAP: {name} on {url}",
                        "severity": severity,
                        "finding_type": "web_vuln",
                        "target_value": url,
                        "detail": {
                            "alert_name": name,
                            "method": method,
                            "parameter": param,
                            "description": description[:2000],
                            "solution": solution[:1000],
                            "cwe_id": cwe_id,
                            "wasc_id": wasc_id,
                            "evidence": instance.get("evidence", "")[:500],
                            "scanner": "zap",
                        },
                        "fingerprint": fingerprint,
                    }
                )

            # If no instances, still record the alert
            if not instances:
                fp_input = f"zap|{name}|{site_name}"
                fingerprint = hashlib.sha256(fp_input.encode()).hexdigest()

                findings.append(
                    {
                        "engagement_id": engagement_id,
                        "title": f"ZAP: {name} on {site_name}",
                        "severity": severity,
                        "finding_type": "web_vuln",
                        "target_value": site_name,
                        "detail": {
                            "alert_name": name,
                            "description": description[:2000],
                            "solution": solution[:1000],
                            "cwe_id": cwe_id,
                            "scanner": "zap",
                        },
                        "fingerprint": fingerprint,
                    }
                )

    return findings


def _map_zap_risk(risk_str: str) -> str:
    if "high" in risk_str:
        return "high"
    if "medium" in risk_str:
        return "medium"
    if "low" in risk_str:
        return "low"
    if "informational" in risk_str or "info" in risk_str:
        return "info"
    return "medium"
