"""Map findings to compliance frameworks based on CWE ID."""

from .mappings import CWE_FRAMEWORK_MAP, FRAMEWORKS


def map_finding_to_frameworks(cwe_id: int | None) -> dict[str, list[str]]:
    """Return framework references for a given CWE ID."""
    if cwe_id is None:
        return {fw: [] for fw in FRAMEWORKS}

    return CWE_FRAMEWORK_MAP.get(cwe_id, {fw: [] for fw in FRAMEWORKS})


def get_all_frameworks() -> list[str]:
    return list(FRAMEWORKS)
