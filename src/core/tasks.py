import json
import uuid
from datetime import UTC, datetime

import redis as redis_lib
from celery import shared_task
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from src.core.config import settings
from src.core.models import Engagement, Finding, Scan, Target
from src.core.scanning.headers import check_headers
from src.core.scanning.nmap import parse_nmap_xml
from src.core.scanning.nuclei import parse_nuclei_jsonl
from src.core.scanning.runner import ToolRunner
from src.core.scanning.subfinder import parse_subfinder_jsonl

# Sync engine for Celery workers (Celery doesn't support async)
sync_engine = create_engine(settings.database_url_sync)
redis_client = redis_lib.from_url(settings.redis_url)
runner = ToolRunner()


def _publish_progress(scan_id: str, percent: int, message: str):
    redis_client.publish(
        f"scan:{scan_id}",
        json.dumps({"percent": percent, "message": message, "scan_id": scan_id}),
    )


def _validate_scope_sync(db: Session, target_value: str, engagement_id: uuid.UUID) -> bool:
    from src.core.scope import ScopeViolationError, target_matches_scope

    engagement = db.execute(
        select(Engagement).where(Engagement.id == engagement_id)
    ).scalar_one_or_none()
    if not engagement:
        raise ValueError(f"Engagement {engagement_id} not found")

    now = datetime.now(UTC)
    starts = engagement.starts_at.replace(tzinfo=UTC)
    ends = engagement.ends_at.replace(tzinfo=UTC)
    if now < starts or now > ends:
        raise ScopeViolationError("Engagement authorization is not active")

    targets = (
        db.execute(
            select(Target).where(
                Target.engagement_id == engagement_id, Target.is_in_scope.is_(True)
            )
        )
        .scalars()
        .all()
    )

    for t in targets:
        if target_matches_scope(target_value, t):
            return True

    raise ScopeViolationError(f"Target {target_value} is not in scope")


def _save_findings(db: Session, scan_id: str, findings_data: list[dict]):
    for f in findings_data:
        existing = db.execute(
            select(Finding).where(
                Finding.engagement_id == uuid.UUID(f["engagement_id"]),
                Finding.fingerprint == f["fingerprint"],
            )
        ).scalar_one_or_none()

        if existing:
            continue

        finding = Finding(
            scan_id=uuid.UUID(scan_id),
            engagement_id=uuid.UUID(f["engagement_id"]),
            title=f["title"],
            severity=f["severity"],
            finding_type=f["finding_type"],
            target_value=f["target_value"],
            detail=f.get("detail"),
            raw_output=f.get("raw_output"),
            fingerprint=f["fingerprint"],
        )
        db.add(finding)

    db.commit()


def _update_scan_status(db: Session, scan_id: str, status: str, error: str | None = None):
    scan = db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id))).scalar_one()
    scan.status = status
    if status == "running":
        scan.started_at = datetime.now(UTC)
    elif status in ("completed", "failed"):
        scan.completed_at = datetime.now(UTC)
    if error:
        scan.error_message = error
    db.commit()


@shared_task(bind=True, name="src.core.tasks.run_nmap_scan")
def run_nmap_scan(self, scan_id: str):
    with Session(sync_engine) as db:
        scan = db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id))).scalar_one()
        target = db.execute(select(Target).where(Target.id == scan.target_id)).scalar_one()

        try:
            _update_scan_status(db, scan_id, "running")
            _publish_progress(scan_id, 10, "Validating scope...")
            _validate_scope_sync(db, target.value, scan.engagement_id)

            _publish_progress(scan_id, 20, "Starting Nmap scan...")

            # Build nmap command
            config = scan.config or {}
            ports = config.get("ports", "1-1000")
            extra_args = config.get("extra_args", "")
            cmd = f"-sV -sC --script=vuln -p {ports} {extra_args} -oX - {target.value}"

            result = runner.run_in_container("instrumentisto/nmap", cmd, timeout=600)

            if result.returncode != 0 and not result.stdout:
                raise RuntimeError(f"Nmap failed: {result.stderr}")

            _publish_progress(scan_id, 70, "Parsing results...")
            findings = parse_nmap_xml(result.stdout, str(scan.engagement_id))

            _publish_progress(scan_id, 90, f"Saving {len(findings)} findings...")
            _save_findings(db, scan_id, findings)

            _update_scan_status(db, scan_id, "completed")
            _publish_progress(scan_id, 100, f"Completed with {len(findings)} findings")

        except Exception as e:
            _update_scan_status(db, scan_id, "failed", str(e))
            _publish_progress(scan_id, -1, f"Failed: {e}")
            raise


@shared_task(bind=True, name="src.core.tasks.run_subfinder_scan")
def run_subfinder_scan(self, scan_id: str):
    with Session(sync_engine) as db:
        scan = db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id))).scalar_one()
        target = db.execute(select(Target).where(Target.id == scan.target_id)).scalar_one()

        try:
            _update_scan_status(db, scan_id, "running")
            _publish_progress(scan_id, 10, "Validating scope...")
            _validate_scope_sync(db, target.value, scan.engagement_id)

            _publish_progress(scan_id, 20, "Starting Subfinder scan...")
            cmd = f"-d {target.value} -json -silent"
            result = runner.run_in_container("projectdiscovery/subfinder", cmd, timeout=300)

            _publish_progress(scan_id, 70, "Parsing results...")
            findings = parse_subfinder_jsonl(result.stdout, str(scan.engagement_id))

            _publish_progress(scan_id, 90, f"Saving {len(findings)} findings...")
            _save_findings(db, scan_id, findings)

            _update_scan_status(db, scan_id, "completed")
            _publish_progress(scan_id, 100, f"Completed with {len(findings)} subdomains")

        except Exception as e:
            _update_scan_status(db, scan_id, "failed", str(e))
            _publish_progress(scan_id, -1, f"Failed: {e}")
            raise


@shared_task(bind=True, name="src.core.tasks.run_nuclei_scan")
def run_nuclei_scan(self, scan_id: str):
    with Session(sync_engine) as db:
        scan = db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id))).scalar_one()
        target = db.execute(select(Target).where(Target.id == scan.target_id)).scalar_one()

        try:
            _update_scan_status(db, scan_id, "running")
            _publish_progress(scan_id, 10, "Validating scope...")
            _validate_scope_sync(db, target.value, scan.engagement_id)

            _publish_progress(scan_id, 20, "Starting Nuclei scan...")
            config = scan.config or {}
            severity = config.get("severity", "critical,high,medium,low")
            templates = config.get("templates", "")
            cmd = f"-u {target.value} -jsonl -severity {severity}"
            if templates:
                cmd += f" -t {templates}"

            result = runner.run_in_container("projectdiscovery/nuclei", cmd, timeout=900)

            _publish_progress(scan_id, 70, "Parsing results...")
            findings = parse_nuclei_jsonl(result.stdout, str(scan.engagement_id))

            _publish_progress(scan_id, 90, f"Saving {len(findings)} findings...")
            _save_findings(db, scan_id, findings)

            _update_scan_status(db, scan_id, "completed")
            _publish_progress(scan_id, 100, f"Completed with {len(findings)} findings")

        except Exception as e:
            _update_scan_status(db, scan_id, "failed", str(e))
            _publish_progress(scan_id, -1, f"Failed: {e}")
            raise


@shared_task(bind=True, name="src.core.tasks.run_sslyze_scan")
def run_sslyze_scan(self, scan_id: str):
    from src.core.scanning.sslyze_scan import run_sslyze_scan as _run_sslyze

    with Session(sync_engine) as db:
        scan = db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id))).scalar_one()
        target = db.execute(select(Target).where(Target.id == scan.target_id)).scalar_one()

        try:
            _update_scan_status(db, scan_id, "running")
            _publish_progress(scan_id, 10, "Validating scope...")
            _validate_scope_sync(db, target.value, scan.engagement_id)

            _publish_progress(scan_id, 20, "Starting SSLyze scan...")
            config = scan.config or {}
            port = config.get("port", 443)

            findings_data = _run_sslyze(target.value, port)
            for f in findings_data:
                f["engagement_id"] = str(scan.engagement_id)

            _publish_progress(scan_id, 90, f"Saving {len(findings_data)} findings...")
            _save_findings(db, scan_id, findings_data)

            _update_scan_status(db, scan_id, "completed")
            _publish_progress(scan_id, 100, f"Completed with {len(findings_data)} findings")

        except Exception as e:
            _update_scan_status(db, scan_id, "failed", str(e))
            _publish_progress(scan_id, -1, f"Failed: {e}")
            raise


@shared_task(bind=True, name="src.core.tasks.run_headers_scan")
def run_headers_scan(self, scan_id: str):
    with Session(sync_engine) as db:
        scan = db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id))).scalar_one()
        target = db.execute(select(Target).where(Target.id == scan.target_id)).scalar_one()

        try:
            _update_scan_status(db, scan_id, "running")
            _publish_progress(scan_id, 10, "Validating scope...")
            _validate_scope_sync(db, target.value, scan.engagement_id)

            _publish_progress(scan_id, 20, "Checking security headers...")
            url = target.value if "://" in target.value else f"https://{target.value}"
            findings_data = check_headers(url)
            for f in findings_data:
                f["engagement_id"] = str(scan.engagement_id)

            _publish_progress(scan_id, 90, f"Saving {len(findings_data)} findings...")
            _save_findings(db, scan_id, findings_data)

            _update_scan_status(db, scan_id, "completed")
            _publish_progress(scan_id, 100, f"Completed with {len(findings_data)} findings")

        except Exception as e:
            _update_scan_status(db, scan_id, "failed", str(e))
            _publish_progress(scan_id, -1, f"Failed: {e}")
            raise


@shared_task(bind=True, name="src.core.tasks.push_to_defectdojo")
def push_to_defectdojo(self, engagement_id: str):
    import asyncio

    from src.core.defectdojo import DefectDojoClient

    client = DefectDojoClient()

    async def _push():
        with Session(sync_engine) as db:
            engagement = db.execute(
                select(Engagement).where(Engagement.id == uuid.UUID(engagement_id))
            ).scalar_one()

            product_id = await client.ensure_product(engagement.client_name)
            dojo_engagement_id = await client.ensure_engagement(
                product_id,
                engagement.name,
                engagement.starts_at.isoformat()[:10],
                engagement.ends_at.isoformat()[:10],
            )

            # Gather scans and import raw output where available
            scans = (
                db.execute(
                    select(Scan).where(
                        Scan.engagement_id == uuid.UUID(engagement_id),
                        Scan.status == "completed",
                    )
                )
                .scalars()
                .all()
            )

            for scan in scans:
                scan_type_map = {
                    "nmap": "Nmap Scan",
                    "nuclei": "Nuclei Scan",
                }
                if scan.scan_type in scan_type_map:
                    findings = (
                        db.execute(select(Finding).where(Finding.scan_id == scan.id))
                        .scalars()
                        .all()
                    )
                    if findings and findings[0].raw_output:
                        await client.import_scan(
                            dojo_engagement_id,
                            scan_type_map[scan.scan_type],
                            findings[0].raw_output.encode(),
                            f"{scan.scan_type}_output",
                        )

    asyncio.run(_push())
