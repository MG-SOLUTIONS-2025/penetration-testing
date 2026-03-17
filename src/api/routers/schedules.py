"""Celery Beat scheduled scan CRUD endpoints."""

import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.models import ScanSchedule, User

from ..deps import get_current_user, get_db

router = APIRouter(prefix="/api/v1/schedules", tags=["schedules"])


class ScheduleCreate(BaseModel):
    engagement_id: uuid.UUID
    target_id: uuid.UUID
    scan_type: str
    config: dict | None = None
    cron_expression: str


class ScheduleUpdate(BaseModel):
    cron_expression: str | None = None
    config: dict | None = None
    is_active: bool | None = None


class ScheduleRead(BaseModel):
    id: uuid.UUID
    engagement_id: uuid.UUID
    target_id: uuid.UUID
    scan_type: str
    config: dict | None
    cron_expression: str
    is_active: bool
    last_run_at: str | None = None
    next_run_at: str | None = None

    model_config = {"from_attributes": True}


@router.post("/", response_model=ScheduleRead, status_code=201)
async def create_schedule(
    body: ScheduleCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    schedule = ScanSchedule(
        engagement_id=body.engagement_id,
        target_id=body.target_id,
        scan_type=body.scan_type,
        config=body.config,
        cron_expression=body.cron_expression,
        created_by=user.id,
    )
    db.add(schedule)
    await db.flush()
    await db.refresh(schedule)
    return schedule


@router.get("/", response_model=list[ScheduleRead])
async def list_schedules(
    engagement_id: uuid.UUID | None = None,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = select(ScanSchedule)
    if engagement_id:
        query = query.where(ScanSchedule.engagement_id == engagement_id)
    result = await db.execute(query)
    return result.scalars().all()


@router.patch("/{schedule_id}", response_model=ScheduleRead)
async def update_schedule(
    schedule_id: uuid.UUID,
    body: ScheduleUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(ScanSchedule).where(ScanSchedule.id == schedule_id))
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(schedule, field, value)

    await db.flush()
    await db.refresh(schedule)
    return schedule


@router.delete("/{schedule_id}", status_code=204)
async def delete_schedule(
    schedule_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(ScanSchedule).where(ScanSchedule.id == schedule_id))
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    await db.delete(schedule)
