"""Historical scan diffing — compare findings between scans."""

from dataclasses import dataclass, field


@dataclass
class DiffResult:
    new: list[dict] = field(default_factory=list)
    resolved: list[dict] = field(default_factory=list)
    unchanged: list[dict] = field(default_factory=list)


def diff_scans(
    current_findings: list[dict],
    baseline_findings: list[dict],
) -> DiffResult:
    """Diff current findings against a baseline.

    Uses fingerprint as the identity key.
    """
    baseline_fps = {f["fingerprint"]: f for f in baseline_findings}
    current_fps = {f["fingerprint"]: f for f in current_findings}

    result = DiffResult()

    for fp, finding in current_fps.items():
        if fp in baseline_fps:
            result.unchanged.append(finding)
        else:
            result.new.append(finding)

    for fp, finding in baseline_fps.items():
        if fp not in current_fps:
            result.resolved.append(finding)

    return result
