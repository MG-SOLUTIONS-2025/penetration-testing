"""DDoS resilience testing endpoints."""

import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.ddos.controller import ResilienceController
from src.core.models import Engagement
from src.worker.celery_app import celery_app

from ..deps import get_db

router = APIRouter(prefix="/api/v1/resilience", tags=["resilience"])

controller = ResilienceController()


class ResilienceTestRequest(BaseModel):
    engagement_id: uuid.UUID
    target_url: str
    rps: int = 100
    duration_seconds: int = 60


@router.post("/test", status_code=202)
async def start_resilience_test(
    body: ResilienceTestRequest,
    db: AsyncSession = Depends(get_db),
):
    """Start a DDoS resilience test — requires engagement flag."""
    result = await db.execute(select(Engagement).where(Engagement.id == body.engagement_id))
    engagement = result.scalar_one_or_none()
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")
    if not engagement.allow_ddos_testing:
        raise HTTPException(status_code=403, detail="DDoS testing not enabled for this engagement")

    try:
        controller.validate_config(body.rps, body.duration_seconds)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    task = celery_app.send_task(
        "src.core.tasks.run_ddos_test",
        args=[str(body.engagement_id), body.target_url, body.rps, body.duration_seconds],
    )
    return {"status": "dispatched", "task_id": task.id}
