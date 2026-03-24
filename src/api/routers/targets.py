import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.models import Target
from src.core.scanning.sanitize import SanitizationError, validate_target_value
from src.core.schemas import PaginatedResponse, TargetCreate, TargetRead

from ..deps import get_db, get_engagement_or_403

router = APIRouter(prefix="/api/v1/engagements/{engagement_id}/targets", tags=["targets"])


@router.post("/", response_model=TargetRead, status_code=201)
async def create_target(
    engagement_id: uuid.UUID,
    body: TargetCreate,
    db: AsyncSession = Depends(get_db),
):
    await get_engagement_or_403(db, engagement_id)

    # Validate target value against injection
    try:
        validated_value = validate_target_value(body.value, body.target_type)
    except SanitizationError as e:
        raise HTTPException(status_code=422, detail=str(e))

    target = Target(
        engagement_id=engagement_id,
        target_type=body.target_type,
        value=validated_value,
        is_in_scope=body.is_in_scope,
        metadata_=body.metadata,
    )
    db.add(target)
    await db.flush()
    await db.refresh(target)
    return target


@router.get("/", response_model=PaginatedResponse[TargetRead])
async def list_targets(
    engagement_id: uuid.UUID,
    page: int = 1,
    page_size: int = 50,
    db: AsyncSession = Depends(get_db),
):
    await get_engagement_or_403(db, engagement_id)

    query = select(Target).where(
        Target.engagement_id == engagement_id,
        Target.deleted_at.is_(None),
    )
    count_query = select(func.count(Target.id)).where(
        Target.engagement_id == engagement_id,
        Target.deleted_at.is_(None),
    )
    total = (await db.execute(count_query)).scalar() or 0
    query = query.order_by(Target.created_at.desc()).offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    items = result.scalars().all()
    return PaginatedResponse(items=items, total=total, page=page, page_size=page_size)


@router.delete("/{target_id}", status_code=204)
async def delete_target(
    engagement_id: uuid.UUID,
    target_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    await get_engagement_or_403(db, engagement_id)

    result = await db.execute(
        select(Target).where(
            Target.id == target_id,
            Target.engagement_id == engagement_id,
            Target.deleted_at.is_(None),
        )
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    target.deleted_at = datetime.now(UTC)
    db.add(target)
    await db.flush()
