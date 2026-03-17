"""Report generation — PDF and HTML output via Jinja2 + WeasyPrint."""

import uuid
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from sqlalchemy import select
from sqlalchemy.orm import Session

from src.core.models import Engagement, Finding, Scan

TEMPLATE_DIR = Path(__file__).parent / "templates"


class ReportGenerator:
    def __init__(self):
        self.env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)

    def _gather_data(self, db: Session, engagement_id: uuid.UUID) -> dict:
        engagement = db.execute(
            select(Engagement).where(Engagement.id == engagement_id)
        ).scalar_one()

        findings = (
            db.execute(
                select(Finding)
                .where(Finding.engagement_id == engagement_id)
                .order_by(Finding.severity, Finding.created_at)
            )
            .scalars()
            .all()
        )

        scans = db.execute(select(Scan).where(Scan.engagement_id == engagement_id)).scalars().all()

        severity_counts = {}
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        return {
            "engagement": engagement,
            "findings": findings,
            "scans": scans,
            "severity_counts": severity_counts,
            "generated_at": datetime.now(UTC).isoformat(),
            "total_findings": len(findings),
        }

    def generate_html(
        self,
        db: Session,
        engagement_id: uuid.UUID,
        template_name: str = "full.html",
    ) -> str:
        data = self._gather_data(db, engagement_id)
        template = self.env.get_template(template_name)
        return template.render(**data)

    def generate_pdf(
        self,
        db: Session,
        engagement_id: uuid.UUID,
        template_name: str = "full.html",
    ) -> bytes:
        html = self.generate_html(db, engagement_id, template_name)
        try:
            from weasyprint import HTML

            return HTML(string=html).write_pdf()
        except ImportError:
            raise RuntimeError("weasyprint is required for PDF generation")
