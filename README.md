# PenTest Platform

Self-hosted penetration testing platform. Manage engagements, run scans via containerized tools, track findings with CVSS/VPR scoring, map to compliance frameworks, and generate reports.

## Features

- **Engagement management** -- scoped authorization windows with client details and audit trails
- **12 scanner integrations** -- Nmap, Nuclei, Subfinder, SSLyze, Amass, Masscan, Nikto, Ffuf, SQLMap, WPScan, ZAP, and HTTP header analysis (all run in isolated Docker containers)
- **Finding deduplication** -- fingerprint-based dedup across scans with status tracking (new/recurring/resolved)
- **CVSS v3.1 + VPR scoring** -- automated severity scoring with exploit maturity and threat intel factors
- **Compliance mapping** -- findings mapped to OWASP Top 10, PCI DSS 4, NIST 800-53, CIS Controls
- **Report generation** -- HTML and PDF reports via Jinja2 + WeasyPrint
- **SARIF export** -- standard Static Analysis Results format for CI/CD integration
- **Credential leak detection** -- HIBP breach and password k-anonymity checks
- **Metasploit integration** -- RPC-based exploit execution (admin-gated)
- **DDoS resilience testing** -- k6-based load testing with circuit breaker safety limits
- **DefectDojo sync** -- push findings to DefectDojo for centralized vulnerability management
- **Immutable audit log** -- WORM hash-chained audit trail for compliance
- **Scheduled scans** -- cron-based recurring scans via Celery Beat
- **Real-time progress** -- WebSocket scan progress streaming via Redis pub/sub
- **React dashboard** -- frontend for engagement management and scan monitoring

## Architecture

```
                  ┌──────────┐
  Browser ──────► │  Nginx   │ :3102
                  └──┬───┬───┘
             /api/   │   │   /
          ┌──────────┘   └──────────┐
          ▼                         ▼
     ┌─────────┐             ┌──────────┐
     │ FastAPI  │             │ Frontend │
     │  (API)   │             │ (React)  │
     └────┬─────┘             └──────────┘
          │
     ┌────┴─────┐
     │          │
     ▼          ▼
┌─────────┐ ┌───────┐    ┌────────────────┐
│Postgres │ │ Redis │◄───│ Celery Worker   │
│  (DB)   │ │(queue)│    │ (scan runner)   │
└─────────┘ └───────┘    └───────┬────────┘
                                 │
                          ┌──────┴──────┐
                          │   Docker    │
                          │ (nmap, zap, │
                          │  nuclei...) │
                          └─────────────┘
```

| Service   | Role                                         |
|-----------|----------------------------------------------|
| postgres  | Primary datastore (16-alpine)                |
| redis     | Task broker, pub/sub, caching (7-alpine)     |
| api       | FastAPI REST API (uvicorn, 2 workers)         |
| worker    | Celery worker -- runs scans in Docker containers |
| beat      | Celery Beat -- dispatches scheduled scans     |
| flower    | Celery monitoring UI at `/flower/`            |
| frontend  | React + Vite dashboard                       |
| nginx     | Reverse proxy, security headers              |
| migrate   | One-shot Alembic migration runner             |

## Quick Start

### Prerequisites

- Docker and Docker Compose v2
- Port 3102 available
- (Optional) Pull scanner images ahead of time: `make pull-scanners`

### Clone and Deploy

```bash
git clone git@mguan:MG-SOLUTIONS-2025/penetration-testing.git
cd penetration-testing
cp .env.example .env      # edit passwords/keys as needed
make deploy               # builds, migrates, starts everything
```

First deploy takes a few minutes to build images and run migrations. Once complete:

- Dashboard: `http://localhost:3102`
- API docs (Swagger): `http://localhost:3102/docs`
- Celery monitor: `http://localhost:3102/flower/` (default login: `admin` / `flower_dev_2026`)

### Verify

```bash
curl http://localhost:3102/health
# {"api":"ok","database":"ok","redis":"ok"}
```

### Stop / Restart

```bash
make down                 # stop all services (data preserved)
make up                   # restart
make logs                 # tail all logs
```

## API Reference

All endpoints are under `/api/v1/`. Full OpenAPI schema available at `/api/docs`.

### Engagements

| Method | Path | Description |
|--------|------|-------------|
| POST | `/engagements/` | Create engagement |
| GET | `/engagements/` | List engagements (paginated) |
| GET | `/engagements/{id}` | Get engagement |
| PATCH | `/engagements/{id}` | Update engagement |

### Targets

| Method | Path | Description |
|--------|------|-------------|
| POST | `/engagements/{id}/targets/` | Add target (domain/ip/cidr/url) |
| GET | `/engagements/{id}/targets/` | List targets (paginated) |
| DELETE | `/engagements/{id}/targets/{id}` | Soft-delete target |

### Scans

| Method | Path | Description |
|--------|------|-------------|
| POST | `/scans/` | Dispatch scan (rate-limited: 10/min) |
| GET | `/scans/` | List scans (filterable by engagement, status, type) |
| GET | `/scans/{id}` | Get scan details |
| POST | `/scans/{id}/cancel` | Cancel running scan |
| GET | `/scans/export/sarif?engagement_id=` | Export as SARIF 2.1.0 |
| GET | `/scans/{id}/diff` | Diff against baseline scan |

**Scan types:** `nmap`, `subfinder`, `nuclei`, `sslyze`, `headers`, `amass`, `masscan`, `nikto`, `ffuf`, `sqlmap`, `wpscan`, `zap`

### Findings

| Method | Path | Description |
|--------|------|-------------|
| GET | `/findings/` | List findings (filterable) |
| GET | `/findings/{id}` | Get finding detail |
| POST | `/findings/sync-defectdojo?engagement_id=` | Sync to DefectDojo |

### Schedules

| Method | Path | Description |
|--------|------|-------------|
| POST | `/schedules/` | Create cron schedule |
| GET | `/schedules/` | List schedules |
| PATCH | `/schedules/{id}` | Update schedule |
| DELETE | `/schedules/{id}` | Soft-delete schedule |

### Reports

| Method | Path | Description |
|--------|------|-------------|
| POST | `/reports/generate` | Async report generation (202) |
| GET | `/reports/{engagement_id}/list` | List reports |
| GET | `/reports/download/{report_id}` | Download report |
| GET | `/reports/{engagement_id}/html` | Sync HTML report |
| GET | `/reports/{engagement_id}/pdf` | Sync PDF report |

### Compliance

| Method | Path | Description |
|--------|------|-------------|
| GET | `/compliance/frameworks` | List available frameworks |
| GET | `/compliance/engagement/{id}` | Compliance mapping for engagement |

### Credentials (HIBP)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/credentials/check` | Check email against HIBP |
| GET | `/credentials/exposures?engagement_id=` | List known exposures |

### Exploits (Metasploit)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/exploits/run` | Run exploit (requires `allow_exploitation`) |
| GET | `/exploits/?engagement_id=` | List exploit attempts |

### Resilience (DDoS)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/resilience/test` | Start load test (requires `allow_ddos_testing`) |

### WebSocket

| Protocol | Path | Description |
|----------|------|-------------|
| WS | `/ws/scans/{scan_id}` | Real-time scan progress |

## Configuration

All configuration is via environment variables. See `.env.example` for the full list with descriptions.

### Required

| Variable | Description |
|----------|-------------|
| `POSTGRES_PASSWORD` | PostgreSQL password |
| `REDIS_PASSWORD` | Redis password |

### Optional Integrations

| Variable | Description |
|----------|-------------|
| `HIBP_API_KEY` | Have I Been Pwned API key for credential checks |
| `DEFECTDOJO_URL` / `DEFECTDOJO_API_KEY` | DefectDojo instance for finding sync |
| `METASPLOIT_HOST` / `METASPLOIT_PASSWORD` | Metasploit RPC for exploit execution |
| `CELERY_FERNET_KEY` | Encrypt Celery task payloads (generate: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`) |

## Development

```bash
# Local dev server (requires postgres + redis running)
make dev          # uvicorn with --reload on :8000
make worker       # celery worker

# Testing
make test         # pytest
make lint         # ruff check
make format       # ruff format

# Database
make migrate      # alembic upgrade head
make revision msg="add foo"  # generate migration
```

## CLI

```bash
pentest --help    # all commands
```

## Security Controls

- **Scope enforcement** -- every scan validates targets against engagement scope before execution
- **Input sanitization** -- target values, ports, nmap args, nuclei templates validated against injection
- **Container isolation** -- scanners run with `no-new-privileges`, all capabilities dropped, read-only FS, pid limit 256
- **Audit logging** -- dual-write to mutable `audit_log` and immutable `audit_log_worm` (SHA-256 hash-chained)
- **Rate limiting** -- scan creation capped at 10/min per IP
- **Safety gates** -- exploitation and DDoS testing require explicit engagement flags
- **DDoS circuit breaker** -- auto-stops load tests on high error rates or response time spikes

## License

Apache License 2.0. See [LICENSE](LICENSE).
