import uuid

import typer
from rich.console import Console
from rich.table import Table
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from src.core.config import SCAN_TASK_MAP, settings
from src.core.models import Scan, Target
from src.worker.celery_app import celery_app

app = typer.Typer(help="Manage scans")
console = Console()
engine = create_engine(settings.database_url_sync)


@app.command("run")
def run_scan(
    scan_type: str = typer.Argument(help="nmap|subfinder|nuclei|sslyze|headers"),
    target_id: str = typer.Option(..., "--target-id", "-t"),
    config: str = typer.Option(None, "--config", "-c", help="JSON config string"),
):
    """Dispatch a scan."""
    if scan_type not in SCAN_TASK_MAP:
        console.print(f"[red]Invalid scan type:[/red] {scan_type}")
        raise typer.Exit(1)

    with Session(engine) as db:
        stmt = select(Target).where(Target.id == uuid.UUID(target_id))
        target = db.execute(stmt).scalar_one_or_none()
        if not target:
            console.print("[red]Target not found[/red]")
            raise typer.Exit(1)

        import json as json_mod

        scan_config = json_mod.loads(config) if config else None

        scan = Scan(
            engagement_id=target.engagement_id,
            target_id=target.id,
            scan_type=scan_type,
            status="pending",
            config=scan_config,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        task = celery_app.send_task(SCAN_TASK_MAP[scan_type], args=[str(scan.id)])
        scan.celery_task_id = task.id
        db.commit()

        console.print(f"[green]Scan dispatched:[/green] {scan.id}")
        console.print(f"[dim]Task ID:[/dim] {task.id}")


@app.command("status")
def scan_status(scan_id: str):
    """Check scan status."""
    with Session(engine) as db:
        scan = db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id))).scalar_one_or_none()
        if not scan:
            console.print("[red]Scan not found[/red]")
            raise typer.Exit(1)

        console.print(f"[bold]Scan:[/bold] {scan.id}")
        console.print(f"[bold]Type:[/bold] {scan.scan_type}")
        console.print(f"[bold]Status:[/bold] {scan.status}")
        if scan.error_message:
            console.print(f"[red]Error:[/red] {scan.error_message}")


@app.command("list")
def list_scans(
    engagement_id: str = typer.Option(None, "--engagement-id", "-e"),
):
    """List scans."""
    with Session(engine) as db:
        query = select(Scan)
        if engagement_id:
            query = query.where(Scan.engagement_id == uuid.UUID(engagement_id))
        query = query.order_by(Scan.created_at.desc())

        scans = db.execute(query).scalars().all()

        table = Table(title="Scans")
        table.add_column("ID", style="dim")
        table.add_column("Type")
        table.add_column("Status")
        table.add_column("Created")

        for s in scans:
            table.add_row(str(s.id)[:8], s.scan_type, s.status, str(s.created_at))

        console.print(table)


@app.command("cancel")
def cancel_scan(scan_id: str):
    """Cancel a running scan."""
    with Session(engine) as db:
        scan = db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id))).scalar_one_or_none()
        if not scan:
            console.print("[red]Scan not found[/red]")
            raise typer.Exit(1)

        if scan.celery_task_id:
            celery_app.control.revoke(scan.celery_task_id, terminate=True)

        scan.status = "cancelled"
        db.commit()
        console.print(f"[green]Scan cancelled:[/green] {scan_id}")
