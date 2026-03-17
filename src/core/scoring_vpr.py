"""Vulnerability Priority Rating (VPR) scoring.

Computes VPR from CVSS base score + exploit maturity + threat intel + asset criticality.
"""


def compute_vpr(
    cvss_score: float = 0.0,
    exploit_maturity: str = "unproven",  # unproven, poc, functional, high
    threat_intel_active: bool = False,
    asset_criticality: str = "medium",  # low, medium, high, critical
) -> tuple[float, dict]:
    """Compute VPR score (0-10) and factor breakdown."""
    # Base: start from CVSS
    base = cvss_score

    # Exploit maturity modifier
    maturity_mod = {
        "unproven": 0.0,
        "poc": 0.5,
        "functional": 1.5,
        "high": 2.5,
    }.get(exploit_maturity, 0.0)

    # Threat intelligence modifier
    threat_mod = 1.0 if threat_intel_active else 0.0

    # Asset criticality modifier
    asset_mod = {
        "low": -1.0,
        "medium": 0.0,
        "high": 1.0,
        "critical": 2.0,
    }.get(asset_criticality, 0.0)

    # Combine and clamp to [0, 10]
    vpr = min(10.0, max(0.0, base + maturity_mod + threat_mod + asset_mod))

    factors = {
        "cvss_base": cvss_score,
        "exploit_maturity": exploit_maturity,
        "maturity_modifier": maturity_mod,
        "threat_intel_active": threat_intel_active,
        "threat_modifier": threat_mod,
        "asset_criticality": asset_criticality,
        "asset_modifier": asset_mod,
    }

    return round(vpr, 1), factors
