import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.models import Scan, Target, User
from src.core.schemas import ScanCreate, ScanRead
from src.core.scope import EngagementExpiredError, check_engagement_active
from src.worker.celery_app import celery_app

from ..deps import get_current_user, get_db

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])
limiter = Limiter(key_func=get_remote_address)

SCAN_TASK_MAP = {
    "nmap": "src.core.tasks.run_nmap_scan",
    "subfinder": "src.core.tasks.run_subfinder_scan",
    "nuclei": "src.core.tasks.run_nuclei_scan",
    "sslyze": "src.core.tasks.run_sslyze_scan",
    "headers": "src.core.tasks.run_headers_scan",
    "amass": "src.core.tasks.run_amass_scan",
    "masscan": "src.core.tasks.run_masscan_scan",
    "nikto": "src.core.tasks.run_nikto_scan",
    "ffuf": "src.core.tasks.run_ffuf_scan",
    "sqlmap": "src.core.tasks.run_sqlmap_scan",
    "wpscan": "src.core.tasks.run_wpscan_scan",
    "zap": "src.core.tasks.run_zap_scan",
}


@router.post("/", response_model=ScanRead, status_code=201)
@limiter.limit("10/minute")
async def create_scan(
    request: Request,
    body: ScanCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if body.scan_type not in SCAN_TASK_MAP:
        raise HTTPException(status_code=400, detail=f"Invalid scan type: {body.scan_type}")

    # Validate engagement is active
    try:
        await check_engagement_active(db, body.engagement_id)
    except (EngagementExpiredError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Validate target exists and is in scope
    if body.target_id:
        result = await db.execute(
            select(Target).where(
                Target.id == body.target_id,
                Target.engagement_id == body.engagement_id,
            )
        )
        target = result.scalar_one_or_none()
        if not target:
            raise HTTPException(status_code=404, detail="Target not found in engagement")
        if not target.is_in_scope:
            raise HTTPException(status_code=400, detail="Target is out of scope")

    scan = Scan(
        engagement_id=body.engagement_id,
        target_id=body.target_id,
        scan_type=body.scan_type,
        status="pending",
        config=body.config,
        created_by=user.id,
    )
    db.add(scan)
    await db.flush()
    await db.refresh(scan)

    # Dispatch Celery task
    task_name = SCAN_TASK_MAP[body.scan_type]
    task = celery_app.send_task(task_name, args=[str(scan.id)])
    scan.celery_task_id = task.id
    await db.flush()

    return scan


@router.get("/", response_model=list[ScanRead])
async def list_scans(
    engagement_id: uuid.UUID | None = None,
    status: str | None = None,
    scan_type: str | None = None,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = select(Scan)
    if engagement_id:
        query = query.where(Scan.engagement_id == engagement_id)
    if status:
        query = query.where(Scan.status == status)
    if scan_type:
        query = query.where(Scan.scan_type == scan_type)
    query = query.order_by(Scan.created_at.desc())

    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{scan_id}", response_model=ScanRead)
async def get_scan(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.post("/{scan_id}/cancel", status_code=200)
async def cancel_scan(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.celery_task_id:
        celery_app.control.revoke(scan.celery_task_id, terminate=True)

    scan.status = "cancelled"
    await db.flush()
    return {"status": "cancelled", "scan_id": str(scan_id)}


@router.get("/{scan_id}/diff")
async def scan_diff(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get diff between this scan and its baseline."""
    from src.core.diffing import diff_scans
    from src.core.models import Finding

    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Get current findings
    current = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    current_findings = [
        {"fingerprint": f.fingerprint, "title": f.title, "severity": f.severity}
        for f in current.scalars().all()
    ]

    # Get baseline findings
    baseline_findings = []
    if scan.baseline_scan_id:
        baseline = await db.execute(select(Finding).where(Finding.scan_id == scan.baseline_scan_id))
        baseline_findings = [
            {"fingerprint": f.fingerprint, "title": f.title, "severity": f.severity}
            for f in baseline.scalars().all()
        ]

    diff_result = diff_scans(current_findings, baseline_findings)
    return {
        "new": diff_result.new,
        "resolved": diff_result.resolved,
        "unchanged": diff_result.unchanged,
    }


@router.get("/export/sarif")
async def export_sarif(
    engagement_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Export findings as SARIF 2.1.0 JSON."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session as SyncSession

    from src.core.config import settings
    from src.core.export.sarif import findings_to_sarif

    sync_engine = create_engine(settings.database_url_sync)
    with SyncSession(sync_engine) as sync_db:
        sarif = findings_to_sarif(sync_db, engagement_id)

    return sarif
