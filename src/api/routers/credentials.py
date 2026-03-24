"""HIBP credential leak checking endpoints."""

import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.models import CredentialExposure

from ..deps import get_db, get_engagement_or_404

router = APIRouter(prefix="/api/v1/credentials", tags=["credentials"])


class CredentialCheckRequest(BaseModel):
    engagement_id: uuid.UUID
    email: EmailStr


class ExposureRead(BaseModel):
    id: uuid.UUID
    engagement_id: uuid.UUID
    email: str
    breach_name: str
    breach_date: str | None
    data_classes: dict | None

    model_config = {"from_attributes": True}


@router.post("/check")
async def check_credentials(
    body: CredentialCheckRequest,
    db: AsyncSession = Depends(get_db),
):
    """Check an email against HIBP for known breaches."""
    await get_engagement_or_404(db, body.engagement_id)

    from src.core.hibp.checker import check_email_breaches

    try:
        breaches = await check_email_breaches(body.email)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=429, detail=str(e))

    # Save exposures
    saved = []
    for breach in breaches:
        exposure = CredentialExposure(
            engagement_id=body.engagement_id,
            email=body.email,
            breach_name=breach["breach_name"],
            breach_date=breach.get("breach_date"),
            data_classes={"classes": breach.get("data_classes", [])},
        )
        db.add(exposure)
        saved.append(breach)

    await db.flush()

    return {"email": body.email, "breaches_found": len(saved), "breaches": saved}


@router.get("/exposures", response_model=list[ExposureRead])
async def list_exposures(
    engagement_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    await get_engagement_or_404(db, engagement_id)

    result = await db.execute(
        select(CredentialExposure)
        .where(CredentialExposure.engagement_id == engagement_id)
        .order_by(CredentialExposure.created_at.desc())
    )
    return result.scalars().all()
