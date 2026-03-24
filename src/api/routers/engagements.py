import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.models import Engagement
from src.core.schemas import EngagementCreate, EngagementRead, EngagementUpdate, PaginatedResponse

from ..deps import get_db

router = APIRouter(prefix="/api/v1/engagements", tags=["engagements"])


@router.post("/", response_model=EngagementRead, status_code=201)
async def create_engagement(
    body: EngagementCreate,
    db: AsyncSession = Depends(get_db),
):
    engagement = Engagement(**body.model_dump())
    db.add(engagement)
    await db.flush()
    await db.refresh(engagement)
    return engagement


@router.get("/", response_model=PaginatedResponse[EngagementRead])
async def list_engagements(
    page: int = 1,
    page_size: int = 50,
    db: AsyncSession = Depends(get_db),
):
    query = select(Engagement)
    count_query = select(func.count(Engagement.id))

    total = (await db.execute(count_query)).scalar() or 0
    query = query.order_by(Engagement.created_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    items = result.scalars().all()
    return PaginatedResponse(items=items, total=total, page=page, page_size=page_size)


@router.get("/{engagement_id}", response_model=EngagementRead)
async def get_engagement(
    engagement_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Engagement).where(Engagement.id == engagement_id)
    )
    engagement = result.scalar_one_or_none()
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return engagement


@router.patch("/{engagement_id}", response_model=EngagementRead)
async def update_engagement(
    engagement_id: uuid.UUID,
    body: EngagementUpdate,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Engagement).where(Engagement.id == engagement_id)
    )
    engagement = result.scalar_one_or_none()
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")

    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(engagement, field, value)

    await db.flush()
    await db.refresh(engagement)
    return engagement
