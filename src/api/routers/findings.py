import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.models import Finding, User
from src.core.schemas import FindingRead, PaginatedResponse
from src.worker.celery_app import celery_app

from ..deps import get_current_user, get_db

router = APIRouter(prefix="/api/v1/findings", tags=["findings"])


@router.get("/", response_model=PaginatedResponse[FindingRead])
async def list_findings(
    engagement_id: uuid.UUID | None = None,
    scan_id: uuid.UUID | None = None,
    severity: str | None = None,
    finding_type: str | None = None,
    page: int = 1,
    page_size: int = 50,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = select(Finding)
    count_query = select(func.count(Finding.id))

    if engagement_id:
        query = query.where(Finding.engagement_id == engagement_id)
        count_query = count_query.where(Finding.engagement_id == engagement_id)
    if scan_id:
        query = query.where(Finding.scan_id == scan_id)
        count_query = count_query.where(Finding.scan_id == scan_id)
    if severity:
        query = query.where(Finding.severity == severity)
        count_query = count_query.where(Finding.severity == severity)
    if finding_type:
        query = query.where(Finding.finding_type == finding_type)
        count_query = count_query.where(Finding.finding_type == finding_type)

    total = (await db.execute(count_query)).scalar() or 0

    query = query.order_by(Finding.created_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    items = result.scalars().all()

    return PaginatedResponse(items=items, total=total, page=page, page_size=page_size)


@router.get("/{finding_id}", response_model=FindingRead)
async def get_finding(
    finding_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.post("/sync-defectdojo", status_code=202)
async def sync_to_defectdojo(
    engagement_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    task = celery_app.send_task("src.core.tasks.push_to_defectdojo", args=[str(engagement_id)])
    return {"task_id": task.id, "status": "dispatched"}
