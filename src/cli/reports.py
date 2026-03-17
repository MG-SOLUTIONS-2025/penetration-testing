import uuid
from pathlib import Path

import typer
from rich.console import Console
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from src.core.config import settings
from src.core.reports.generator import ReportGenerator

app = typer.Typer(help="Generate reports")
console = Console()
engine = create_engine(settings.database_url_sync)


@app.command("generate")
def generate(
    engagement_id: str = typer.Option(..., "--engagement-id", "-e"),
    output: str = typer.Option("report.html", "--output", "-o"),
    template: str = typer.Option("full.html", "--template", "-t"),
    pdf: bool = typer.Option(False, "--pdf", help="Generate PDF instead of HTML"),
):
    """Generate a report for an engagement."""
    generator = ReportGenerator()
    out_path = Path(output)

    with Session(engine) as db:
        if pdf:
            content = generator.generate_pdf(db, uuid.UUID(engagement_id), template)
            if out_path.suffix != ".pdf":
                out_path = out_path.with_suffix(".pdf")
            out_path.write_bytes(content)
        else:
            content = generator.generate_html(db, uuid.UUID(engagement_id), template)
            out_path.write_text(content)

    console.print(f"[green]Report generated:[/green] {out_path}")


@app.command("sarif")
def export_sarif(
    engagement_id: str = typer.Option(..., "--engagement-id", "-e"),
    output: str = typer.Option("findings.sarif", "--output", "-o"),
):
    """Export findings as SARIF 2.1.0."""
    import json

    from src.core.export.sarif import findings_to_sarif

    with Session(engine) as db:
        sarif = findings_to_sarif(db, uuid.UUID(engagement_id))

    Path(output).write_text(json.dumps(sarif, indent=2))
    console.print(f"[green]SARIF exported:[/green] {output}")
