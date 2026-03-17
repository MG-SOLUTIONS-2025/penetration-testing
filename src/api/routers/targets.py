import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.models import Engagement, Target, User
from src.core.schemas import TargetCreate, TargetRead

from ..deps import get_current_user, get_db

router = APIRouter(prefix="/api/v1/engagements/{engagement_id}/targets", tags=["targets"])


@router.post("/", response_model=TargetRead, status_code=201)
async def create_target(
    engagement_id: uuid.UUID,
    body: TargetCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Engagement).where(Engagement.id == engagement_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Engagement not found")

    target = Target(
        engagement_id=engagement_id,
        target_type=body.target_type,
        value=body.value,
        is_in_scope=body.is_in_scope,
        metadata_=body.metadata,
    )
    db.add(target)
    await db.flush()
    await db.refresh(target)
    return target


@router.get("/", response_model=list[TargetRead])
async def list_targets(
    engagement_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Target)
        .where(Target.engagement_id == engagement_id)
        .order_by(Target.created_at.desc())
    )
    return result.scalars().all()


@router.delete("/{target_id}", status_code=204)
async def delete_target(
    engagement_id: uuid.UUID,
    target_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Target).where(Target.id == target_id, Target.engagement_id == engagement_id)
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    await db.delete(target)
