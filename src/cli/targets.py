import uuid

import typer
from rich.console import Console
from rich.table import Table
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from src.core.config import settings
from src.core.models import Target

app = typer.Typer(help="Manage targets")
console = Console()
engine = create_engine(settings.database_url_sync)


@app.command("add")
def add_target(
    value: str,
    engagement_id: str = typer.Option(..., "--engagement-id", "-e"),
    target_type: str = typer.Option("domain", "--type", "-t", help="domain|ip|cidr|url"),
):
    """Add a target to an engagement."""
    with Session(engine) as db:
        target = Target(
            engagement_id=uuid.UUID(engagement_id),
            target_type=target_type,
            value=value,
        )
        db.add(target)
        db.commit()
        db.refresh(target)
        console.print(f"[green]Target added:[/green] {target.id}")


@app.command("list")
def list_targets(
    engagement_id: str = typer.Option(..., "--engagement-id", "-e"),
):
    """List targets for an engagement."""
    with Session(engine) as db:
        result = db.execute(select(Target).where(Target.engagement_id == uuid.UUID(engagement_id)))
        targets = result.scalars().all()

        table = Table(title="Targets")
        table.add_column("ID", style="dim")
        table.add_column("Type")
        table.add_column("Value")
        table.add_column("In Scope")

        for t in targets:
            table.add_row(str(t.id)[:8], t.target_type, t.value, str(t.is_in_scope))

        console.print(table)


@app.command("remove")
def remove_target(target_id: str):
    """Remove a target."""
    with Session(engine) as db:
        result = db.execute(select(Target).where(Target.id == uuid.UUID(target_id)))
        target = result.scalar_one_or_none()
        if not target:
            console.print("[red]Target not found[/red]")
            raise typer.Exit(1)
        db.delete(target)
        db.commit()
        console.print(f"[green]Target removed:[/green] {target_id}")
