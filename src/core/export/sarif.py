"""SARIF 2.1.0 export for findings."""

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.core.models import Finding


def findings_to_sarif(db: Session, engagement_id: uuid.UUID) -> dict:
    """Convert findings for an engagement to SARIF 2.1.0 format."""
    findings = (
        db.execute(
            select(Finding)
            .where(Finding.engagement_id == engagement_id)
            .order_by(Finding.created_at)
        )
        .scalars()
        .all()
    )

    rules = {}
    results = []

    for f in findings:
        rule_id = f.finding_type
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": f.finding_type},
            }

        severity_map = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note",
        }

        result = {
            "ruleId": rule_id,
            "level": severity_map.get(f.severity, "note"),
            "message": {"text": f.title},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.target_value},
                    }
                }
            ],
            "properties": {
                "severity": f.severity,
                "fingerprint": f.fingerprint,
            },
        }

        if f.cvss_score is not None:
            result["properties"]["cvss_score"] = f.cvss_score
        if f.cvss_vector:
            result["properties"]["cvss_vector"] = f.cvss_vector
        if f.cwe_id:
            result["properties"]["cwe_id"] = f.cwe_id

        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PenTest Platform",
                        "version": "0.1.0",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    return sarif
