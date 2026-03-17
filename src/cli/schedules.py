import uuid

import typer
from rich.console import Console
from rich.table import Table
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from src.core.config import settings
from src.core.models import ScanSchedule

app = typer.Typer(help="Manage scan schedules")
console = Console()
engine = create_engine(settings.database_url_sync)


@app.command("create")
def create_schedule(
    engagement_id: str = typer.Option(..., "--engagement-id", "-e"),
    target_id: str = typer.Option(..., "--target-id", "-t"),
    scan_type: str = typer.Option(..., "--type", "-T"),
    cron: str = typer.Option(..., "--cron", "-c", help="Cron expression"),
    user_id: str = typer.Option(..., "--user-id", "-u"),
):
    """Create a scan schedule."""
    with Session(engine) as db:
        schedule = ScanSchedule(
            engagement_id=uuid.UUID(engagement_id),
            target_id=uuid.UUID(target_id),
            scan_type=scan_type,
            cron_expression=cron,
            created_by=uuid.UUID(user_id),
        )
        db.add(schedule)
        db.commit()
        db.refresh(schedule)
        console.print(f"[green]Schedule created:[/green] {schedule.id}")


@app.command("list")
def list_schedules(engagement_id: str = typer.Option(None, "--engagement-id", "-e")):
    """List scan schedules."""
    with Session(engine) as db:
        query = select(ScanSchedule)
        if engagement_id:
            query = query.where(ScanSchedule.engagement_id == uuid.UUID(engagement_id))

        schedules = db.execute(query).scalars().all()

        table = Table(title="Scan Schedules")
        table.add_column("ID", style="dim")
        table.add_column("Type")
        table.add_column("Cron")
        table.add_column("Active")

        for s in schedules:
            table.add_row(str(s.id)[:8], s.scan_type, s.cron_expression, str(s.is_active))

        console.print(table)


@app.command("delete")
def delete_schedule(schedule_id: str):
    """Delete a schedule."""
    with Session(engine) as db:
        result = db.execute(select(ScanSchedule).where(ScanSchedule.id == uuid.UUID(schedule_id)))
        schedule = result.scalar_one_or_none()
        if not schedule:
            console.print("[red]Schedule not found[/red]")
            raise typer.Exit(1)
        db.delete(schedule)
        db.commit()
        console.print(f"[green]Schedule deleted:[/green] {schedule_id}")
