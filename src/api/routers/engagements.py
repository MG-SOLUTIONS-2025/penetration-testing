import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.models import Engagement, User
from src.core.schemas import EngagementCreate, EngagementRead, EngagementUpdate

from ..deps import get_current_user, get_db

router = APIRouter(prefix="/api/v1/engagements", tags=["engagements"])


@router.post("/", response_model=EngagementRead, status_code=201)
async def create_engagement(
    body: EngagementCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    engagement = Engagement(**body.model_dump(), created_by=user.id)
    db.add(engagement)
    await db.flush()
    await db.refresh(engagement)
    return engagement


@router.get("/", response_model=list[EngagementRead])
async def list_engagements(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Engagement).order_by(Engagement.created_at.desc()))
    return result.scalars().all()


@router.get("/{engagement_id}", response_model=EngagementRead)
async def get_engagement(
    engagement_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Engagement).where(Engagement.id == engagement_id))
    engagement = result.scalar_one_or_none()
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return engagement


@router.patch("/{engagement_id}", response_model=EngagementRead)
async def update_engagement(
    engagement_id: uuid.UUID,
    body: EngagementUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Engagement).where(Engagement.id == engagement_id))
    engagement = result.scalar_one_or_none()
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")

    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(engagement, field, value)

    await db.flush()
    await db.refresh(engagement)
    return engagement
