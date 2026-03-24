"""Database-backed Celery Beat scheduler reading from ScanSchedule table."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from src.core.config import SCAN_TASK_MAP, settings
from src.core.models import Scan, ScanSchedule

sync_engine = create_engine(settings.database_url_sync)


def get_due_schedules() -> list[ScanSchedule]:
    """Get all active schedules that are due to run."""
    now = datetime.now(UTC)
    with Session(sync_engine) as db:
        schedules = (
            db.execute(
                select(ScanSchedule).where(
                    ScanSchedule.is_active.is_(True),
                    (ScanSchedule.next_run_at.is_(None)) | (ScanSchedule.next_run_at <= now),
                )
            )
            .scalars()
            .all()
        )
        # Detach from session
        for s in schedules:
            db.expunge(s)
        return schedules


def dispatch_scheduled_scan(schedule: ScanSchedule) -> str | None:
    """Create a scan from a schedule and dispatch it."""
    from src.worker.celery_app import celery_app

    task_name = SCAN_TASK_MAP.get(schedule.scan_type)
    if not task_name:
        return None

    with Session(sync_engine) as db:
        scan = Scan(
            engagement_id=schedule.engagement_id,
            target_id=schedule.target_id,
            scan_type=schedule.scan_type,
            status="pending",
            config=schedule.config,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        task = celery_app.send_task(task_name, args=[str(scan.id)])
        scan.celery_task_id = task.id
        db.commit()

        # Update schedule
        sched = db.execute(select(ScanSchedule).where(ScanSchedule.id == schedule.id)).scalar_one()
        sched.last_run_at = datetime.now(UTC)
        db.commit()

        return str(scan.id)
