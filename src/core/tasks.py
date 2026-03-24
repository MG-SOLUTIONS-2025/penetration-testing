import json
import uuid
from datetime import UTC, datetime

import redis as redis_lib
from celery import shared_task
from sqlalchemy import create_engine, select, update as sa_update
from sqlalchemy.orm import Session

from src.core.config import settings
from src.core.models import Engagement, ExploitAttempt, Finding, Report, Scan, Target
from src.core.scanning.headers import check_headers
from src.core.scanning.nmap import parse_nmap_xml
from src.core.scanning.nuclei import parse_nuclei_jsonl
from src.core.scanning.runner import ToolRunner
from src.core.scanning.sanitize import (
    validate_nuclei_severity,
    validate_nuclei_templates,
    validate_ports,
    validate_target_value,
)
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
    from src.core.scoring_vpr import compute_vpr

    for f in findings_data:
        existing = db.execute(
            select(Finding).where(
                Finding.engagement_id == uuid.UUID(f["engagement_id"]),
                Finding.fingerprint == f["fingerprint"],
            )
        ).scalar_one_or_none()

        if existing:
            # Mark as recurring rather than skipping
            existing.status = "recurring"
            existing.scan_id = uuid.UUID(scan_id)
            if existing.first_seen_at is None:
                existing.first_seen_at = datetime.now(UTC)
            # Recalculate VPR if CVSS score available
            if f.get("cvss_score") is not None:
                vpr, factors = compute_vpr(
                    cvss_score=f["cvss_score"],
                    exploit_maturity=f.get("exploit_maturity", "unproven"),
                    threat_intel_active=f.get("threat_intel_active", False),
                    asset_criticality=f.get("asset_criticality", "medium"),
                )
                existing.vpr_score = vpr
                existing.vpr_factors = factors
            db.add(existing)
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
            first_seen_at=datetime.now(UTC),
        )

        # Wire VPR scoring
        if f.get("cvss_score") is not None:
            vpr, factors = compute_vpr(
                cvss_score=f["cvss_score"],
                exploit_maturity=f.get("exploit_maturity", "unproven"),
                threat_intel_active=f.get("threat_intel_active", False),
                asset_criticality=f.get("asset_criticality", "medium"),
            )
            finding.vpr_score = vpr
            finding.vpr_factors = factors

        db.add(finding)

    db.commit()


def _update_scan_status(db: Session, scan_id: str, status: str, error: str | None = None):
    values: dict = {"status": status}
    if status == "running":
        values["started_at"] = datetime.now(UTC)
    elif status in ("completed", "failed"):
        values["completed_at"] = datetime.now(UTC)
    if error:
        values["error_message"] = error
    db.execute(sa_update(Scan).where(Scan.id == uuid.UUID(scan_id)).values(**values))
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

            # Sanitize inputs
            validated_target = validate_target_value(target.value, target.target_type)

            config = scan.config or {}
            ports = validate_ports(config.get("ports", "1-1000"))
            extra_args = validate_nmap_args(config.get("extra_args", ""))

            _publish_progress(scan_id, 20, "Starting Nmap scan...")

            # Build command as list (no shell injection possible)
            cmd = [
                "-sV",
                "-sC",
                "--script=vuln",
                "-p",
                ports,
                *extra_args,
                "-oX",
                "-",
                validated_target,
            ]

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


def validate_nmap_args(args_str: str) -> list[str]:
    """Wrapper to handle string->list conversion for nmap args from config."""
    from src.core.scanning.sanitize import validate_nmap_args as _validate

    if not args_str:
        return []
    return _validate(args_str)


@shared_task(bind=True, name="src.core.tasks.run_subfinder_scan")
def run_subfinder_scan(self, scan_id: str):
    with Session(sync_engine) as db:
        scan = db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id))).scalar_one()
        target = db.execute(select(Target).where(Target.id == scan.target_id)).scalar_one()

        try:
            _update_scan_status(db, scan_id, "running")
            _publish_progress(scan_id, 10, "Validating scope...")
            _validate_scope_sync(db, target.value, scan.engagement_id)

            # Sanitize inputs
            validated_target = validate_target_value(target.value, target.target_type)

            _publish_progress(scan_id, 20, "Starting Subfinder scan...")
            cmd = ["-d", validated_target, "-json", "-silent"]
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

            # Sanitize inputs
            validated_target = validate_target_value(target.value, target.target_type)

            config = scan.config or {}
            severity = validate_nuclei_severity(config.get("severity", "critical,high,medium,low"))
            templates = validate_nuclei_templates(config.get("templates", ""))

            _publish_progress(scan_id, 20, "Starting Nuclei scan...")
            cmd = ["-u", validated_target, "-jsonl", "-severity", severity]
            if templates:
                cmd.extend(["-t", templates])

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

            # Sanitize target
            validated_target = validate_target_value(target.value, target.target_type)

            _publish_progress(scan_id, 20, "Starting SSLyze scan...")
            config = scan.config or {}
            port = config.get("port", 443)

            findings_data = _run_sslyze(validated_target, port)
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

            # Sanitize target
            validated_target = validate_target_value(target.value, target.target_type)

            _publish_progress(scan_id, 20, "Checking security headers...")
            url = validated_target if "://" in validated_target else f"https://{validated_target}"
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


def _run_container_scan(
    scan_id: str,
    image: str,
    cmd: list[str],
    parse_fn,
    timeout: int = 600,
    scan_label: str = "scan",
):
    """Generic helper for container-based scans."""
    with Session(sync_engine) as db:
        scan = db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id))).scalar_one()
        target = db.execute(select(Target).where(Target.id == scan.target_id)).scalar_one()

        try:
            _update_scan_status(db, scan_id, "running")
            _publish_progress(scan_id, 10, "Validating scope...")
            _validate_scope_sync(db, target.value, scan.engagement_id)

            validated_target = validate_target_value(target.value, target.target_type)

            _publish_progress(scan_id, 20, f"Starting {scan_label}...")
            # Replace placeholder in command with validated target
            final_cmd = [validated_target if c == "__TARGET__" else c for c in cmd]

            result = runner.run_in_container(image, final_cmd, timeout=timeout)

            _publish_progress(scan_id, 70, "Parsing results...")
            findings = parse_fn(result.stdout, str(scan.engagement_id))

            _publish_progress(scan_id, 90, f"Saving {len(findings)} findings...")
            _save_findings(db, scan_id, findings)

            _update_scan_status(db, scan_id, "completed")
            _publish_progress(scan_id, 100, f"Completed with {len(findings)} findings")

        except Exception as e:
            _update_scan_status(db, scan_id, "failed", str(e))
            _publish_progress(scan_id, -1, f"Failed: {e}")
            raise


@shared_task(bind=True, name="src.core.tasks.run_amass_scan")
def run_amass_scan(self, scan_id: str):
    from src.core.scanning.amass import parse_amass_jsonl

    _run_container_scan(
        scan_id,
        "caffix/amass",
        ["enum", "-d", "__TARGET__", "-json", "-"],
        parse_amass_jsonl,
        timeout=900,
        scan_label="Amass",
    )


@shared_task(bind=True, name="src.core.tasks.run_masscan_scan")
def run_masscan_scan(self, scan_id: str):
    from src.core.scanning.masscan import parse_masscan_json, validate_masscan_rate

    with Session(sync_engine) as db:
        scan = db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id))).scalar_one()
        config = scan.config or {}
        rate = validate_masscan_rate(config.get("rate", 1000))
        ports = validate_ports(config.get("ports", "1-65535"))

    _run_container_scan(
        scan_id,
        "adguard/masscan",
        ["-p", ports, "--rate", str(rate), "-oJ", "-", "__TARGET__"],
        parse_masscan_json,
        timeout=600,
        scan_label="Masscan",
    )


@shared_task(bind=True, name="src.core.tasks.run_nikto_scan")
def run_nikto_scan(self, scan_id: str):
    from src.core.scanning.nikto import parse_nikto_json

    _run_container_scan(
        scan_id,
        "sullo/nikto",
        ["-h", "__TARGET__", "-Format", "json", "-o", "-"],
        parse_nikto_json,
        timeout=900,
        scan_label="Nikto",
    )


@shared_task(bind=True, name="src.core.tasks.run_ffuf_scan")
def run_ffuf_scan(self, scan_id: str):
    from src.core.scanning.ffuf import parse_ffuf_json

    with Session(sync_engine) as db:
        scan = db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id))).scalar_one()
        config = scan.config or {}
        wordlist = config.get("wordlist", "/usr/share/wordlists/common.txt")
        rate = min(config.get("rate", 100), 500)  # Safety cap

    _run_container_scan(
        scan_id,
        "ghcr.io/ffuf/ffuf",
        [
            "-u",
            "__TARGET__/FUZZ",
            "-w",
            wordlist,
            "-of",
            "json",
            "-o",
            "/dev/stdout",
            "-rate",
            str(rate),
        ],
        parse_ffuf_json,
        timeout=600,
        scan_label="ffuf",
    )


@shared_task(bind=True, name="src.core.tasks.run_sqlmap_scan")
def run_sqlmap_scan(self, scan_id: str):
    from src.core.scanning.sqlmap import parse_sqlmap_json, validate_sqlmap_options

    with Session(sync_engine) as db:
        scan = db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id))).scalar_one()
        config = scan.config or {}
        options = validate_sqlmap_options(config.get("options", {}))

    cmd = ["-u", "__TARGET__", "--batch", "--output-dir=/tmp/sqlmap"]
    if options.get("level"):
        cmd.extend(["--level", str(options["level"])])
    if options.get("risk"):
        cmd.extend(["--risk", str(options["risk"])])

    _run_container_scan(
        scan_id,
        "sqlmapproject/sqlmap",
        cmd,
        parse_sqlmap_json,
        timeout=900,
        scan_label="SQLMap",
    )


@shared_task(bind=True, name="src.core.tasks.run_wpscan_scan")
def run_wpscan_scan(self, scan_id: str):
    from src.core.scanning.wpscan import parse_wpscan_json

    _run_container_scan(
        scan_id,
        "wpscanteam/wpscan",
        ["--url", "__TARGET__", "--format", "json", "--no-banner"],
        parse_wpscan_json,
        timeout=600,
        scan_label="WPScan",
    )


@shared_task(bind=True, name="src.core.tasks.run_zap_scan")
def run_zap_scan(self, scan_id: str):
    from src.core.scanning.zap import parse_zap_json

    _run_container_scan(
        scan_id,
        "zaproxy/zap-stable",
        ["zap-baseline.py", "-t", "__TARGET__", "-J", "/dev/stdout"],
        parse_zap_json,
        timeout=1800,
        scan_label="OWASP ZAP",
    )


@shared_task(bind=True, name="src.core.tasks.generate_report")
def generate_report(
    self,
    engagement_id: str,
    template: str = "full.html",
    output_format: str = "html",
    user_id: str | None = None,
):
    """Generate a report and persist it to the database."""
    from src.core.reports.generator import ReportGenerator

    generator = ReportGenerator()
    with Session(sync_engine) as db:
        report = Report(
            engagement_id=uuid.UUID(engagement_id),
            format=output_format,
            template=template,
            generated_by=uuid.UUID(user_id) if user_id else None,
            celery_task_id=self.request.id,
        )
        db.add(report)
        db.flush()

        if output_format == "pdf":
            content_bytes = generator.generate_pdf(db, uuid.UUID(engagement_id), template)
            report.content_bytes = content_bytes
        else:
            content = generator.generate_html(db, uuid.UUID(engagement_id), template)
            report.content = content

        report.generated_at = datetime.now(UTC)
        db.commit()
        db.refresh(report)

    return {"report_id": str(report.id)}


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

            findings = (
                db.execute(
                    select(Finding).where(Finding.engagement_id == uuid.UUID(engagement_id))
                )
                .scalars()
                .all()
            )

            for f in findings:
                await client.push_finding({
                    "title": f.title,
                    "severity": f.severity.capitalize(),
                    "cvss_score": f.cvss_score,
                    "cwe": f.cwe_id,
                    "description": f.detail or {},
                    "target": f.target_value,
                })

    asyncio.run(_push())


@shared_task(bind=True, name="src.core.tasks.run_metasploit_exploit")
def run_metasploit_exploit(self, attempt_id: str, module_name: str, options: dict):
    """Run a Metasploit exploit module via RPC and record outcome."""
    from src.core.metasploit import MetasploitClient

    with Session(sync_engine) as db:
        attempt = db.execute(
            select(ExploitAttempt).where(ExploitAttempt.id == uuid.UUID(attempt_id))
        ).scalar_one()

        try:
            attempt.status = "running"
            db.commit()

            client = MetasploitClient(
                settings.metasploit_host,
                settings.metasploit_port,
                settings.metasploit_password,
            )
            result = client.run_exploit(module_name, options)

            attempt.status = "success"
            attempt.output = json.dumps(result)
            db.commit()

        except Exception as e:
            attempt.status = "failed"
            attempt.output = str(e)
            db.commit()
            raise


@shared_task(bind=True, name="src.core.tasks.run_ddos_test")
def run_ddos_test(
    self, engagement_id: str, target_url: str, rps: int, duration_seconds: int
):
    """Run a k6-based DDoS resilience test."""
    from src.core.ddos.controller import ResilienceController

    controller = ResilienceController()
    controller.validate_config(rps, duration_seconds)
    cmd = controller.build_k6_command(target_url, rps, duration_seconds)
    result = runner.run_in_container(
        "grafana/k6", cmd, timeout=duration_seconds + 60
    )
    _publish_progress(engagement_id, 100, f"DDoS test completed: {result.stdout[:200]}")
    return {"output": result.stdout}
