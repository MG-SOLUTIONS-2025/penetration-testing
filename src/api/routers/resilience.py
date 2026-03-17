"""DDoS resilience testing endpoints — admin-only, requires engagement flag."""

import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.ddos.controller import ResilienceController
from src.core.models import Engagement, User

from ..deps import get_current_admin_user, get_db

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
    admin: User = Depends(get_current_admin_user),
):
    """Start a DDoS resilience test — admin only, requires engagement flag."""
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

    # Validate command can be built (validates config)
    controller.build_k6_command(body.target_url, body.rps, body.duration_seconds)

    # TODO: dispatch via Celery task with real-time WebSocket updates
    return {
        "status": "dispatched",
        "config": {
            "target_url": body.target_url,
            "rps": body.rps,
            "duration_seconds": body.duration_seconds,
        },
    }
