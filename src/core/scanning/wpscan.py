"""WPScan JSON output parser."""

import hashlib
import json


def parse_wpscan_json(json_str: str, engagement_id: str) -> list[dict]:
    findings = []

    try:
        data = json.loads(json_str)
    except json.JSONDecodeError:
        return []

    target_url = data.get("target_url", "unknown")

    # WordPress version vulnerabilities
    wp_version = data.get("version", {})
    if wp_version:
        ver_num = wp_version.get("number", "unknown")
        vulns = wp_version.get("vulnerabilities", [])
        for vuln in vulns:
            _add_vuln_finding(findings, vuln, target_url, engagement_id, f"WordPress {ver_num}")

    # Plugin vulnerabilities
    plugins = data.get("plugins", {})
    for plugin_name, plugin_data in plugins.items():
        vulns = plugin_data.get("vulnerabilities", [])
        for vuln in vulns:
            _add_vuln_finding(findings, vuln, target_url, engagement_id, f"Plugin: {plugin_name}")

    # Theme vulnerabilities
    themes = data.get("themes", data.get("main_theme", {}))
    if isinstance(themes, dict) and "vulnerabilities" in themes:
        themes = {"main": themes}
    if isinstance(themes, dict):
        for theme_name, theme_data in themes.items():
            if isinstance(theme_data, dict):
                vulns = theme_data.get("vulnerabilities", [])
                for vuln in vulns:
                    _add_vuln_finding(
                        findings, vuln, target_url, engagement_id, f"Theme: {theme_name}"
                    )

    # Interesting findings (e.g., exposed files)
    for item in data.get("interesting_findings", []):
        url = item.get("url", target_url)
        desc = item.get("to_s", item.get("type", "Interesting finding"))

        fp_input = f"wpscan|interesting|{url}"
        fingerprint = hashlib.sha256(fp_input.encode()).hexdigest()

        findings.append(
            {
                "engagement_id": engagement_id,
                "title": f"WPScan: {desc}",
                "severity": "info",
                "finding_type": "wordpress",
                "target_value": url,
                "detail": {
                    "type": item.get("type"),
                    "references": item.get("references", {}),
                    "scanner": "wpscan",
                },
                "fingerprint": fingerprint,
            }
        )

    return findings


def _add_vuln_finding(
    findings: list[dict],
    vuln: dict,
    target_url: str,
    engagement_id: str,
    component: str,
):
    title = vuln.get("title", "Unknown vulnerability")
    references = vuln.get("references", {})
    fixed_in = vuln.get("fixed_in")

    severity = "high"
    if vuln.get("cvss", {}).get("score", 0) >= 9.0:
        severity = "critical"

    fp_input = f"wpscan|{component}|{title}"
    fingerprint = hashlib.sha256(fp_input.encode()).hexdigest()

    findings.append(
        {
            "engagement_id": engagement_id,
            "title": f"WPScan: {component} - {title}",
            "severity": severity,
            "finding_type": "wordpress",
            "target_value": target_url,
            "detail": {
                "component": component,
                "vulnerability": title,
                "fixed_in": fixed_in,
                "references": references,
                "scanner": "wpscan",
            },
            "fingerprint": fingerprint,
        }
    )
