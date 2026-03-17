import uuid

import typer
from rich.console import Console
from rich.table import Table
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from src.core.config import settings
from src.core.models import Finding
from src.worker.celery_app import celery_app

app = typer.Typer(help="Manage findings")
console = Console()
engine = create_engine(settings.database_url_sync)

SEVERITY_COLORS = {
    "critical": "red bold",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "dim",
}


@app.command("list")
def list_findings(
    engagement_id: str = typer.Option(None, "--engagement-id", "-e"),
    severity: str = typer.Option(None, "--severity", "-s"),
    finding_type: str = typer.Option(None, "--type", "-t"),
    limit: int = typer.Option(50, "--limit", "-l"),
):
    """List findings."""
    with Session(engine) as db:
        query = select(Finding)
        if engagement_id:
            query = query.where(Finding.engagement_id == uuid.UUID(engagement_id))
        if severity:
            query = query.where(Finding.severity == severity)
        if finding_type:
            query = query.where(Finding.finding_type == finding_type)
        query = query.order_by(Finding.created_at.desc()).limit(limit)

        findings = db.execute(query).scalars().all()

        table = Table(title="Findings")
        table.add_column("ID", style="dim")
        table.add_column("Severity")
        table.add_column("Type")
        table.add_column("Title")
        table.add_column("Target")

        for f in findings:
            style = SEVERITY_COLORS.get(f.severity, "")
            table.add_row(
                str(f.id)[:8],
                f"[{style}]{f.severity}[/{style}]",
                f.finding_type,
                f.title[:60],
                f.target_value,
            )

        console.print(table)
        console.print(f"\n[dim]Total: {len(findings)} findings[/dim]")


@app.command("sync")
def sync_defectdojo(
    engagement_id: str = typer.Option(..., "--engagement-id", "-e"),
):
    """Push findings to DefectDojo."""
    task = celery_app.send_task("src.core.tasks.push_to_defectdojo", args=[engagement_id])
    console.print(f"[green]Sync dispatched:[/green] task {task.id}")
