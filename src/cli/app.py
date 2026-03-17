import typer

from .findings import app as findings_app
from .scans import app as scans_app
from .targets import app as targets_app

app = typer.Typer(name="pentest", help="Penetration Testing Platform CLI")

app.add_typer(targets_app, name="target")
app.add_typer(scans_app, name="scan")
app.add_typer(findings_app, name="findings")


@app.command()
def version():
    """Show version."""
    typer.echo("PenTest Platform v0.1.0")


if __name__ == "__main__":
    app()
