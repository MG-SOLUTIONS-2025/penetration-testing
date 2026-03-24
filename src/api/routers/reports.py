"""Report generation endpoints."""

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.models import Report
from src.worker.celery_app import celery_app

from ..deps import get_db, get_engagement_or_403

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])


class ReportGenerateRequest(BaseModel):
    engagement_id: uuid.UUID
    template: str = "full.html"
    output_format: str = "html"  # html or pdf


class ReportRead(BaseModel):
    id: uuid.UUID
    engagement_id: uuid.UUID
    format: str
    template: str
    generated_at: datetime | None
    celery_task_id: str | None

    model_config = {"from_attributes": True}


@router.post("/generate", status_code=202)
async def generate_report(
    body: ReportGenerateRequest,
    db: AsyncSession = Depends(get_db),
):
    """Dispatch async report generation via Celery."""
    await get_engagement_or_403(db, body.engagement_id)

    task = celery_app.send_task(
        "src.core.tasks.generate_report",
        args=[str(body.engagement_id), body.template, body.output_format, None],
    )
    return {"task_id": task.id, "status": "dispatched"}


@router.get("/{engagement_id}/list", response_model=list[ReportRead])
async def list_reports(
    engagement_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """List persisted reports for an engagement."""
    await get_engagement_or_403(db, engagement_id)

    result = await db.execute(
        select(Report)
        .where(Report.engagement_id == engagement_id)
        .order_by(Report.generated_at.desc())
    )
    return result.scalars().all()


@router.get("/download/{report_id}")
async def download_report(
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Download a persisted report (streams content)."""
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    await get_engagement_or_403(db, report.engagement_id)

    if report.format == "pdf" and report.content_bytes:
        return Response(
            content=report.content_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=report_{report.engagement_id}.pdf"
            },
        )
    elif report.content:
        return HTMLResponse(content=report.content)
    else:
        raise HTTPException(status_code=404, detail="Report content not available")


@router.get("/{engagement_id}/html", response_class=HTMLResponse)
async def get_report_html(
    engagement_id: uuid.UUID,
    template: str = "full.html",
    db: AsyncSession = Depends(get_db),
):
    """Generate and return HTML report synchronously (for small reports)."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from src.core.config import settings
    from src.core.reports.generator import ReportGenerator

    await get_engagement_or_403(db, engagement_id)

    sync_engine = create_engine(settings.database_url_sync)
    generator = ReportGenerator()

    try:
        with Session(sync_engine) as sync_db:
            try:
                html = generator.generate_html(sync_db, engagement_id, template)
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
    finally:
        sync_engine.dispose()

    return HTMLResponse(content=html)


@router.get("/{engagement_id}/pdf")
async def get_report_pdf(
    engagement_id: uuid.UUID,
    template: str = "full.html",
    db: AsyncSession = Depends(get_db),
):
    """Generate and return PDF report."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from src.core.config import settings
    from src.core.reports.generator import ReportGenerator

    await get_engagement_or_403(db, engagement_id)

    sync_engine = create_engine(settings.database_url_sync)
    generator = ReportGenerator()

    try:
        with Session(sync_engine) as sync_db:
            try:
                pdf_bytes = generator.generate_pdf(sync_db, engagement_id, template)
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
    finally:
        sync_engine.dispose()

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=report_{engagement_id}.pdf"},
    )
