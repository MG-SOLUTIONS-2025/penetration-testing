"""CVSS v3.1 scoring utilities."""


def compute_cvss(vector: str) -> tuple[float, str]:
    """Compute CVSS score and severity from a CVSS v3.1 vector string.

    Returns (score, severity).
    """
    try:
        from cvss import CVSS3

        c = CVSS3(vector)
        score = c.base_score
        severity = _score_to_severity(score)
        return score, severity
    except Exception:
        return 0.0, "info"


def _score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 0.1:
        return "low"
    return "info"


def enrich_finding_with_cvss(finding: dict, cvss_vector: str | None) -> dict:
    """Add CVSS fields to a finding dict if vector is available."""
    if cvss_vector:
        score, severity = compute_cvss(cvss_vector)
        finding["cvss_vector"] = cvss_vector
        finding["cvss_score"] = score
        # Optionally override severity from CVSS
        if severity != "info":
            finding["severity"] = severity
    return finding
