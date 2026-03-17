"""Report generation endpoints."""

import uuid

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.models import User
from src.worker.celery_app import celery_app

from ..deps import get_current_user, get_db

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])


class ReportGenerateRequest(BaseModel):
    engagement_id: uuid.UUID
    template: str = "full.html"
    output_format: str = "html"  # html or pdf


@router.post("/generate", status_code=202)
async def generate_report(
    body: ReportGenerateRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Dispatch async report generation via Celery."""
    task = celery_app.send_task(
        "src.core.tasks.generate_report",
        args=[str(body.engagement_id), body.template, body.output_format],
    )
    return {"task_id": task.id, "status": "dispatched"}


@router.get("/{engagement_id}/html", response_class=HTMLResponse)
async def get_report_html(
    engagement_id: uuid.UUID,
    template: str = "full.html",
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Generate and return HTML report synchronously (for small reports)."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from src.core.config import settings
    from src.core.reports.generator import ReportGenerator

    sync_engine = create_engine(settings.database_url_sync)
    generator = ReportGenerator()

    with Session(sync_engine) as sync_db:
        try:
            html = generator.generate_html(sync_db, engagement_id, template)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    return HTMLResponse(content=html)


@router.get("/{engagement_id}/pdf")
async def get_report_pdf(
    engagement_id: uuid.UUID,
    template: str = "full.html",
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Generate and return PDF report."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from src.core.config import settings
    from src.core.reports.generator import ReportGenerator

    sync_engine = create_engine(settings.database_url_sync)
    generator = ReportGenerator()

    with Session(sync_engine) as sync_db:
        try:
            pdf_bytes = generator.generate_pdf(sync_db, engagement_id, template)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=report_{engagement_id}.pdf"},
    )
