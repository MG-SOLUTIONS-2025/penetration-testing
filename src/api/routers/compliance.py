"""Compliance mapping endpoints."""

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.compliance.mapper import get_all_frameworks, map_finding_to_frameworks
from src.core.models import Finding

from ..deps import get_db, get_engagement_or_403

router = APIRouter(prefix="/api/v1/compliance", tags=["compliance"])


@router.get("/frameworks")
async def list_frameworks():
    """List available compliance frameworks."""
    return {"frameworks": get_all_frameworks()}


@router.get("/engagement/{engagement_id}")
async def engagement_compliance(
    engagement_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get compliance mapping summary for an engagement."""
    await get_engagement_or_403(db, engagement_id)

    result = await db.execute(select(Finding).where(Finding.engagement_id == engagement_id))
    findings = result.scalars().all()

    framework_findings: dict[str, list[dict]] = {}
    for f in findings:
        if f.cwe_id:
            mappings = map_finding_to_frameworks(f.cwe_id)
            for framework, refs in mappings.items():
                if refs:
                    framework_findings.setdefault(framework, []).append(
                        {
                            "finding_id": str(f.id),
                            "title": f.title,
                            "severity": f.severity,
                            "cwe_id": f.cwe_id,
                            "references": refs,
                        }
                    )

    return {
        "engagement_id": str(engagement_id),
        "total_findings": len(findings),
        "mapped_findings": sum(len(v) for v in framework_findings.values()),
        "frameworks": framework_findings,
    }
