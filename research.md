# Building a self-hosted penetration testing platform from open-source components

**A senior engineer can assemble a production-grade pentest and threat detection platform by combining DefectDojo for vulnerability management, FastAPI + Celery for orchestration, and purpose-built Docker containers for each scanning module.** The most effective architecture avoids a monolithic Kali image in favor of lightweight, tool-specific containers orchestrated through a Python backend with a React dashboard and Typer CLI. This report covers every module needed — from port scanning to compliance reporting — with specific tool recommendations, integration patterns, and architectural decisions validated against current open-source ecosystems.

The platform spans 12 functional modules. Each section below provides the recommended tools, their programmatic APIs, integration complexity, and the patterns that connect them into a unified system.

---

## 1. Port scanning and service detection form the reconnaissance foundation

The optimal strategy combines a fast discovery scanner with a deep enumeration engine in a two-phase pipeline. **Masscan** (25.4k GitHub stars, AGPL v3) handles initial discovery at up to **1.6 million packets per second** on Linux using its custom asynchronous TCP/IP stack. It scans all 65,535 ports across large networks in minutes but provides only basic banner information. **Nmap** (the industry standard, custom license) then performs deep service version detection (`-sV`), OS fingerprinting (`-O`), and vulnerability scripting via its 600+ NSE scripts on the open ports Masscan discovered.

For programmatic integration, `python-nmap` (PyPI: `python-nmap`) provides both synchronous and asynchronous scanning interfaces. The `PortScannerAsync` class accepts a callback function, enabling non-blocking scan execution within a Celery task. Nmap's `-oX` XML output is the most reliable machine-parseable format, and the library handles parsing internally. An alternative, `python3-nmap`, returns native JSON and maps each Nmap command to a Python function — cleaner for new projects.

**RustScan** (15k+ stars, GPL v3) offers a middle path: it scans all 65,535 ports in **3–8 seconds**, then automatically pipes open ports into Nmap for detailed enumeration. It works well for smaller target sets and CTF-style engagements but is not recommended for sensitive production networks due to its aggressive connection behavior.

Performance tuning for non-disruptive scanning is critical. Use Nmap's `-T2` or `-T3` timing templates for production networks, combine with `--max-rate 3000` to cap packet rate, and prefer SYN scans (`-sS`) over full TCP connect scans. Masscan's `--rate` flag is the primary control — set it conservatively (1,000–5,000 pps) for authorized engagements. Always use `--exclude` to protect sensitive hosts.

The recommended pipeline for the platform:

```
Phase 1: Masscan --rate 3000 -p1-65535 → JSON output → list of host:port pairs
Phase 2: Nmap -sV -sC --script=vuln → XML output → parsed via python-nmap → stored in PostgreSQL
Phase 3: ZGrab2 (optional) → application-layer handshakes (TLS, HTTP, SSH) → structured JSON
```

**Integration complexity: Low.** Both tools produce structured output (JSON/XML), and Python wrappers exist for Nmap. Masscan requires subprocess orchestration with JSON output parsing.

---

## 2. DNS and subdomain enumeration: passive first, active second

Subdomain discovery splits cleanly into passive enumeration (querying third-party data sources without touching the target) and active enumeration (DNS brute-forcing and zone transfers directly against target nameservers). Always run passive first — it is stealthy, fast, and often sufficient for initial reconnaissance.

**Subfinder** (ProjectDiscovery, 13k+ stars, MIT license) is the fastest passive enumerator, querying **40+ data sources** including crt.sh, SecurityTrails, Shodan, and VirusTotal. It completes enumeration in roughly one minute per domain and outputs JSON natively (`-json` flag). Configuration lives in `$HOME/.config/subfinder/provider-config.yaml` where API keys are stored. **OWASP Amass** (12k+ stars, Apache 2.0) is slower but more thorough, querying **87+ data sources** and supporting an internal graph database for tracking asset relationships over time. Amass's `enum -passive` mode is the broadest passive approach available, while its `-active` and `-brute` modes handle active enumeration.

For active brute-forcing at scale, **MassDNS** (3.5k+ stars) resolves **350,000+ names per second** using public resolvers. Wrap it with **puredns** (2k+ stars) for automatic wildcard filtering and DNS poisoning detection — this combination produces the cleanest active enumeration results. Use Assetnote's `best-dns-wordlist.txt` (9M entries) for comprehensive brute-forcing or SecLists' `subdomains-top1million-5000.txt` for quick scans.

Direct API integration complements tool-based enumeration. **crt.sh** provides free Certificate Transparency log searches without an API key (`https://crt.sh/?q=%.example.com&output=json`). **SecurityTrails** offers a REST API at `https://api.securitytrails.com/v1/domain/{domain}/subdomains` with 50 free queries per month. **Shodan's** Python library (`pip install shodan`) supports domain lookups via `api.dns.domain_info()`. **VirusTotal API v3** returns subdomains at 4 requests per minute on the free tier.

The recommended enumeration pipeline chains tools through STDIN/STDOUT:

```
subfinder -d target.com -silent → merge with → amass enum -passive -d target.com
→ sort -u → puredns resolve -r resolvers.txt → alive_subdomains.txt
→ feed into port scanning phase
```

**Integration complexity: Low.** All tools support JSON output and STDIN/STDOUT piping. Subfinder and Amass run as Go binaries in Docker; API calls use standard HTTP requests.

---

## 3. SSL/TLS configuration auditing catches cryptographic weaknesses

SSL/TLS auditing must cover certificate validity, protocol versions, cipher suites, and known vulnerabilities. **sslyze** (Python, MIT license) is the recommended primary tool because it provides a native Python API — not just a CLI wrapper.

```python
from sslyze import Scanner, ServerScanRequest, ServerNetworkLocation
from sslyze.plugins.scan_commands import ScanCommand

server = ServerNetworkLocation("example.com", 443)
scanner = Scanner()
scanner.queue_scans([ServerScanRequest(server, {
    ScanCommand.CERTIFICATE_INFO,
    ScanCommand.SSL_2_0_CIPHER_SUITES,
    ScanCommand.SSL_3_0_CIPHER_SUITES,
    ScanCommand.TLS_1_0_CIPHER_SUITES,
    ScanCommand.TLS_1_2_CIPHER_SUITES,
    ScanCommand.TLS_1_3_CIPHER_SUITES,
    ScanCommand.HEARTBLEED,
    ScanCommand.ROBOT,
    ScanCommand.TLS_COMPRESSION,
    ScanCommand.HTTP_HEADERS,  # HSTS check
})])

for result in scanner.get_results():
    cert_info = result.scan_result.certificate_info
    # Extract: chain validity, SANs, expiry, CT SCTs, OCSP stapling
```

sslyze checks all the critical areas: **certificate chain validation** (expiry, CA trust, SANs), **protocol support** (flagging SSLv2, SSLv3, TLS 1.0/1.1 as deprecated), **cipher suite analysis** (identifying weak ciphers, checking for forward secrecy and AEAD modes), and **known vulnerabilities** (Heartbleed, ROBOT, TLS compression/CRIME). It also checks HSTS headers and OCSP stapling status.

**testssl.sh** (Bash, GPL v2) is the most comprehensive CLI-based auditor, checking over 370 cipher suites and all known TLS vulnerabilities. Its `--jsonfile output.json` flag produces structured JSON output suitable for automated parsing. Run it in Docker: `docker run --rm drwetter/testssl.sh --jsonfile /output/result.json target.com:443`. testssl.sh checks items sslyze may miss, including Certificate Transparency enforcement, HSTS preload status, and DNS CAA records.

The critical checks for the platform's TLS audit module should include certificate expiry (warn at 30 days), deprecated protocol versions (SSLv2/3, TLS 1.0/1.1 should fail), weak cipher suites (RC4, DES, NULL ciphers), missing forward secrecy, absent HSTS header, disabled OCSP stapling, known vulnerabilities (Heartbleed, POODLE, BEAST, ROBOT, DROWN), and insufficient key lengths (RSA < 2048 bits, ECDSA < 256 bits).

**Integration complexity: Low for sslyze** (native Python library), **Medium for testssl.sh** (subprocess + JSON parsing).

---

## 4. HTTP security headers reveal misconfigurations in minutes

A complete security headers audit checks **10 key headers** that modern web applications should implement. Building a custom checker is straightforward with Python's `requests` library — fetch the URL, inspect response headers, and score each against known-good values.

The headers to audit and their recommended configurations:

**Strict-Transport-Security** should specify `max-age=31536000; includeSubDomains; preload` to enforce HTTPS for one year across all subdomains. **Content-Security-Policy** is the most complex header — at minimum it should restrict `default-src` and avoid `unsafe-inline` and `unsafe-eval` directives. **X-Content-Type-Options** must be set to `nosniff` to prevent MIME-type sniffing. **X-Frame-Options** should be `DENY` or `SAMEORIGIN` to prevent clickjacking (being superseded by CSP's `frame-ancestors` directive). **Referrer-Policy** should be `strict-origin-when-cross-origin` or stricter. **Permissions-Policy** (formerly Feature-Policy) should explicitly disable unused browser features like camera, microphone, and geolocation. **Cross-Origin-Opener-Policy** should be `same-origin` for cross-origin isolation. **Cross-Origin-Resource-Policy** and **Cross-Origin-Embedder-Policy** complete the cross-origin isolation triplet. **X-XSS-Protection** is now deprecated — modern browsers have removed their XSS auditors, and setting it to `1; mode=block` can actually introduce vulnerabilities in older browsers.

For external validation, **Mozilla Observatory** provides a free API at `https://observatory.mozilla.org/api/v2/analyze?host=example.com` that returns a letter grade (A+ through F) with detailed per-header analysis. The OWASP Secure Headers Project maintains the reference list of recommended headers and values.

A custom checker implementation takes roughly 200 lines of Python: fetch with `requests.get()`, extract headers case-insensitively, validate each against a scoring rubric, and produce a JSON report with per-header pass/fail status and remediation guidance. Weight scoring by header importance — missing CSP and HSTS are critical, while missing Permissions-Policy is moderate.

**Integration complexity: Very low.** Pure HTTP requests with header parsing — no external tools needed.

---

## 5. Leaked credential detection requires careful API orchestration

Credential breach checking serves two purposes in a pentest platform: assessing organizational exposure and validating password hygiene. The approach must balance data access with legal and ethical constraints.

**Have I Been Pwned (HIBP) API v3** is the primary recommended service. Its Pwned Passwords endpoint uses a **k-Anonymity model** — you send only the first 5 characters of a SHA-1 hash, receive ~800 matching suffixes, and check locally. This endpoint is **free with no API key and no rate limit**. For email breach checking, HIBP requires a paid subscription ($4.50–$3,912/month depending on rate limits). The domain search endpoint (`/breacheddomain/{domain}`) returns all breached email aliases for a verified domain, making it ideal for organizational exposure assessments. The **Pwned 5** tier ($326/month) adds stealer log data — credentials captured by info-stealing malware.

For the self-hosted password checking component, **download the full Pwned Passwords database** using the official `haveibeenpwned-downloader` .NET tool. The uncompressed dataset is ~26–35 GB containing roughly 2 billion password hashes. Implement a **Bloom filter** for efficient lookups — at **0.1% false positive rate, the filter requires only ~1.7 GB of RAM** with O(1) lookup time and zero false negatives. This provides unlimited offline password checking at zero marginal cost.

**DeHashed** complements HIBP by returning actual credential data (emails, usernames, passwords, hashed passwords) from **13.3+ billion records**. Its API requires authentication and credits (~$0.02–0.50 per query). This is the tool for pentests where demonstrating actual credential exposure is in scope. **LeakCheck** ($9.99/month) and **Snusbase** serve as cross-validation sources.

Legal constraints are significant. HIBP is clearly legal (returns no passwords, CC 4.0 licensed). DeHashed is used by 1,000+ law enforcement agencies but returns actual passwords — ensure your engagement contract explicitly authorizes credential breach checking. Raw breach compilation databases are potentially illegal to possess in many jurisdictions. **Never store plaintext passwords from breach data longer than the engagement requires**, encrypt all breach findings at rest with AES-256, and redact actual passwords in reports (use patterns like `P@ss****`).

The recommended service stack for the platform: self-hosted Bloom filter for password checking ($0/month), HIBP Pwned 3 for email/domain breach lookups ($37.50/month), DeHashed for detailed credential recovery ($30/month in credits), and LeakCheck as a secondary source ($9.99/month) — totaling approximately **$87.50/month** for comprehensive breach detection.

**Integration complexity: Medium.** HIBP and DeHashed are REST APIs. The Bloom filter requires initial setup (download, generate filter) but provides the best ongoing performance.

---

## 6. DDoS resilience testing demands strict safety controls

Resilience testing assesses how a target degrades under load without actually causing a denial of service. The methodology requires written authorization, gradual ramp-up, real-time monitoring, and instant kill capabilities.

**k6** (Grafana, Go-based, AGPL v3) is the recommended primary load testing tool. It executes JavaScript test scripts in a highly efficient Go runtime, consuming far fewer resources than JMeter. k6 provides **built-in pass/fail thresholds** (`thresholds: { 'http_req_duration': ['p(95)<500'] }`), JSON output, a real-time REST API at `localhost:6565` for programmatic control (pause, resume, scale virtual users), and native integration with Prometheus, InfluxDB, and Grafana. Its `handleSummary()` callback enables custom output formats. **Locust** (Python-based) is the secondary choice when Python-native integration is preferred — its event-driven architecture uses 70% fewer resources than JMeter, and it can be imported as a library for embedding tests directly into the platform.

For protocol-level resilience assessment (authorized use only), **hping3** simulates SYN floods and ICMP testing. **slowhttptest** (Google project) combines Slowloris, slow POST, slow read, and Apache Range Header attacks into a single tool for application-layer resilience testing. These tools must run in isolated Docker containers with strict rate limits.

The testing methodology follows a five-phase gradual ramp-up: baseline measurement (5–10 minutes at minimal load), low load at 25% capacity, medium load at 50–75%, high load at 100–150%, and peak stress beyond capacity. Key metrics include **response time degradation curves** (p50/p95/p99), error rates, time-to-detect (how fast mitigation activates), time-to-mitigate, and recovery time after load removal.

Safety mechanisms are non-negotiable. Implement hard timeouts on all tests, rate caps at the tool level, circuit breakers that halt testing when error rates exceed a threshold (e.g., >50%), and human oversight requirements for any protocol-level testing. k6's `--duration` and `--vus` flags enforce limits, and its REST API enables instant shutdown via `PATCH /v1/status`.

**Integration complexity: Low for k6/Locust** (CLI + JSON output), **Medium for protocol-level tools** (require Docker isolation and additional safety wrappers).

---

## 7. Microservice containers beat monolithic Kali for production platforms

The most common mistake in platform design is building around a monolithic Kali Docker image. The official `kalilinux/kali-rolling` image ships with **no tools installed** — you must install meta-packages, and the resulting image ranges from 2 GB (`kali-linux-headless`) to **26 GB** (full tool images). This creates slow startup times, a broad attack surface, dependency conflicts, and update complexity.

**The recommended approach is individual tool containers spawned on-demand.** ProjectDiscovery provides pre-built Docker images for each tool — `projectdiscovery/nuclei`, `projectdiscovery/subfinder`, `projectdiscovery/httpx` — each weighing 10–100 MB. Nmap has `instrumentisto/nmap`, Nikto has `sullo/nikto`, and most other tools publish official images. This microservice approach provides isolated execution environments, independent updates per tool, minimal attack surface per container, and pay-per-use resource consumption.

Orchestrate tool containers from Python using the Docker SDK (`pip install docker`) or subprocess management with `shlex.split()` for command sanitization. Every tool invocation must include a `timeout` parameter, capture both stdout and stderr, and parse structured output (JSON preferred). The platform's Celery workers spawn tool containers, collect results, and push findings to the database.

```python
class ToolRunner:
    def run_in_container(self, image: str, command: str, timeout: int = 300):
        safe_cmd = shlex.split(command)
        result = subprocess.run(
            ['docker', 'run', '--rm', '--net=scan_network',
             '--memory=1g', '--cpus=1.0', image] + safe_cmd,
            capture_output=True, text=True, timeout=timeout
        )
        return result
```

Tools with the best structured output for automation: **Nuclei** (`-jsonl`), **httpx** (`-json`), **Nmap** (`-oX`), **ffuf** (`-of json`), **Masscan** (`-oJ`), **SQLMap** (REST API on port 8775), and **WPScan** (`--format json`). Tools like gobuster produce only plain text and require custom parsing.

For development and tool exploration, a custom Kali Docker image with curated tools remains useful. Install only the needed meta-packages (`kali-tools-web`, `kali-tools-information-gathering`) and run as non-root with dropped capabilities, adding back only `NET_RAW` and `NET_ADMIN` for network scanning.

**Integration complexity: Medium.** Requires Docker SDK knowledge and per-tool output parsers, but the pattern is consistent across tools.

---

## 8. Web vulnerability scanning chains multiple specialized tools

No single scanner covers all vulnerability classes well. The recommended architecture chains four tools in sequence, each handling what it does best.

**OWASP ZAP** (Apache 2.0, Java) serves as the primary DAST engine. Its full REST API supports spider, active scan, passive scan, and report generation endpoints. The Python client (`pip install zaproxy`) wraps all API calls. ZAP's **Automation Framework** (YAML-based) is the recommended integration path for non-trivial scanning — define environments, contexts, authentication, and scan jobs in a YAML file, then execute via `zap.sh -cmd -autorun zap.yaml`. ZAP detects XSS (reflected, stored, DOM), SQL injection, CSRF, path traversal, command injection, SSRF, and insecure configurations. Docker images: `zaproxy/zap-stable` for production, `zaproxy/zap-weekly` for latest rules.

**Nuclei** (ProjectDiscovery, 33k+ stars, MIT license) complements ZAP with template-based detection of known CVEs, misconfigurations, exposed panels, and default credentials. Its **9,000+ community templates** achieve near-zero false positives because each template includes multi-step verification logic. Nuclei excels at breadth — scanning large numbers of targets against thousands of known issues — while ZAP excels at depth on individual applications. Output is newline-delimited JSON (`-jsonl`), ideal for pipeline processing.

**SQLMap** provides deep SQL injection testing that surpasses ZAP's injection engine. Its built-in REST API (`sqlmapapi.py -s` on port 8775) supports task creation, scan management, and result retrieval via HTTP endpoints — suitable for automated platform integration. Use SQLMap selectively: feed it only the parameters that initial scanners flag as potentially injectable.

**Nikto** handles server-level checks against **6,700+ potentially dangerous files and programs**, including outdated server versions, default files, and misconfigurations. It is fast but noisy (high false positive rate) and limited to server-level issues. Output supports JSON and XML.

Additional specialized tools worth integrating: **WPScan** for WordPress targets (JSON output, API-backed vulnerability database), **ffuf** for directory and parameter fuzzing (JSON output, extremely fast), **Commix** for command injection depth testing, and **Wapiti** (Python-based, 30+ attack modules) for additional injection fuzzing.

The four-phase scan pipeline:

```
Phase 1 (Discovery): ffuf → directory/file discovery + Nuclei tech detection
Phase 2 (Broad scan): ZAP active scan + Nuclei full templates + Nikto server audit
Phase 3 (Deep scan): SQLMap on flagged SQLi params + WPScan if WordPress detected
Phase 4 (Aggregation): All results → DefectDojo API for dedup + correlation
```

False positive management leverages multi-tool correlation: findings confirmed by two or more scanners receive higher confidence scores. Nuclei's template design inherently minimizes false positives. DefectDojo's deduplication engine merges overlapping findings across tools.

**Integration complexity: Low for Nuclei and Nikto** (CLI + JSON), **Low-Medium for ZAP** (REST API, well-documented), **Medium for SQLMap** (REST API requires task management).

---

## 9. The architecture centers on FastAPI, Celery, PostgreSQL, and React

The platform architecture uses a service-oriented design where a FastAPI backend orchestrates scanning tools through Celery task queues, stores results in PostgreSQL, and serves both a React dashboard and Typer CLI.

**Backend: FastAPI + Celery + Redis.** FastAPI handles HTTP and WebSocket requests asynchronously. When a user initiates a scan, the API endpoint dispatches a Celery task via `task.delay()`, immediately returning a `task_id`. The Celery worker executes the scan pipeline (spawning tool containers, collecting results, parsing output) and updates progress via `self.update_state()`. Redis serves triple duty as Celery's message broker, result backend, and pub/sub channel for real-time updates. FastAPI's native WebSocket support (`@app.websocket("/ws/scans/{task_id}")`) pushes progress updates to the dashboard by subscribing to Redis pub/sub.

Celery's **Canvas workflow primitives** are essential for scan pipelines. Use `chain()` to sequence phases (recon → port scan → vuln scan), `group()` to parallelize independent tasks (scanning multiple targets simultaneously), and `chord()` to aggregate parallel results before proceeding to report generation.

**Database: PostgreSQL 16 with JSONB.** PostgreSQL beats MongoDB for this use case because scan management requires ACID transactions (scan state transitions must be atomic), while JSONB columns provide document-style flexibility for variable-structure data like evidence payloads and scan configurations. GIN indexes on JSONB columns enable fast querying. The core schema needs four tables: `targets` (what to scan), `scans` (scan jobs with status and config), `findings` (vulnerability results with severity and evidence), and `users` (authentication and RBAC). Use SQLAlchemy 2.0 async with the asyncpg driver and Alembic for migrations.

**Frontend: React (Vite) with Recharts.** Since this is an internal tool behind authentication, SEO is irrelevant — a React SPA provides maximum flexibility for interactive dashboards without Next.js SSR overhead. Key components include a scan initiation panel, real-time WebSocket-driven progress tracking, findings tables with severity filtering, and vulnerability distribution charts (Recharts is React-native and SVG-based, integrating cleanly with React state). Use Zustand for state management and TanStack Query for API data fetching with caching.

**CLI: Typer + Rich.** Typer (by the same author as FastAPI) uses Python type hints for argument declaration, auto-generates help docs and shell completion, and is built on Click internally. The Rich library provides beautiful terminal tables, progress bars, and syntax highlighting. The critical design pattern is a **shared `core/` module** containing all business logic (scan orchestration, database access, task dispatch), with both the FastAPI routes and Typer commands acting as thin interface layers that call into `core/`.

**Report generation** flows through Jinja2 HTML templates rendered to PDF via WeasyPrint. Reports run as Celery tasks (CPU-intensive for large reports) and store completed files for API-served download. Export formats include PDF, HTML, JSON, and CSV.

The Docker Compose deployment runs **7 services**: Nginx (reverse proxy + SSL termination), FastAPI (API server), Celery workers (horizontally scalable via `deploy.replicas`), Celery Beat (scheduled scans), Flower (task monitoring on port 5555), PostgreSQL 16, and Redis 7. Scanner tools run as ephemeral containers spawned by Celery workers.

**REST API design** follows standard patterns: JWT authentication (access + refresh tokens), UUID primary keys, ISO 8601 timestamps, and paginated responses. Core endpoints cover CRUD for targets, scans, and findings, plus `POST /api/v1/scans/{id}/report` for async report generation and `WS /ws/scans/{task_id}` for real-time progress. Webhooks notify external systems on scan completion using HMAC-SHA256 signed payloads.

---

## 10. Results management turns raw findings into actionable intelligence

Professional pentest platforms require severity scoring, deduplication, historical tracking, and compliance mapping to transform raw scanner output into decision-ready intelligence.

**CVSS scoring** uses the `cvss` Python library from Red Hat (supports CVSS v2, v3.1, and v4.0 — listed on FIRST.org's official FAQ). For known CVEs, look up scores from NVD. For custom findings, maintain a mapping table of common finding types to CVSS vector templates. CVSS v4.0 replaces the Scope metric with separate Vulnerable/Subsequent system impact metrics and adds Attack Requirements — adopt it for new platforms. Supplement CVSS with **EPSS (Exploit Prediction Scoring System)** scores to prioritize findings by actual exploitation probability.

**DefectDojo's deduplication engine** is the gold standard. It supports three algorithms per parser: `unique_id_from_tool` (uses the scanner's internal finding ID), `hash_code` (computes SHA-256 from configurable fields per scanner), and a hybrid that tries tool ID first. Cross-tool deduplication uses hash codes since different tools rarely share compatible IDs. This **reduces noise by up to 90%** when aggregating findings from multiple scanners. Deduplication runs asynchronously via Celery workers.

For a custom implementation, generate fingerprints by hashing normalized fields (vulnerability type + affected component + location + severity). When multiple tools agree on the same finding, increase confidence using the formula: `confidence = 1 - (1-p₁)(1-p₂)...(1-pₙ)` where pᵢ is each tool's confidence score.

**Historical tracking** enables trend analysis and regression detection. DefectDojo's reimport feature compares new scan results against existing findings, identifying new vulnerabilities, unchanged issues, and mitigated items. Track mean-time-to-remediate (MTTR) and SLA compliance rates per product. PCI DSS 4.0 requires retaining penetration test results and remediation activities for **at least 12 months**.

**Compliance mapping** automates the connection between findings and regulatory requirements. Build a CWE-to-framework lookup table in JSON or YAML. Most scanners report CWE IDs, which map to OWASP Top 10 2021 categories (e.g., CWE-89 → A03:Injection), PCI DSS requirements (e.g., application-layer vulnerabilities map to Requirement 11.4), CIS Benchmarks, and NIST CSF. DefectDojo already provides compliance-based reporting for PCI DSS and other frameworks.

**Export formats** should include PDF (executive and technical reports via WeasyPrint), HTML (interactive with filtering), JSON (for API integration and DefectDojo import), and **SARIF** (Static Analysis Results Interchange Format, OASIS standard) for CI/CD pipeline integration. SARIF is JSON-based and natively consumed by GitHub Code Scanning. Map CVSS scores to SARIF's `security-severity` property for consistent severity propagation.

---

## 11. DefectDojo is the strongest foundation; learn from Osmedeus and ReconFTW

Among existing open-source platforms, **DefectDojo** (BSD 3-Clause, Python/Django, 3.8k+ stars) is the clear recommendation as the vulnerability management backbone. It provides **200+ scanner integrations** (parsers for ZAP, Nuclei, Nikto, Nmap, SQLMap, and virtually every other tool), the most sophisticated open-source deduplication engine, SLA enforcement, EPSS enrichment, bidirectional Jira/ServiceNow integration, a comprehensive REST API, and Docker Compose deployment. Its BSD license permits commercial use without restrictions.

**Faraday** (6.1k stars, GPL, Python/Flask) is the strongest alternative for pentest-specific workflows. Its Agent Dispatcher system enables remote tool execution — write executors in any language that Faraday orchestrates and collects results from. Faraday is more pentest-workflow-oriented than DefectDojo (real-time collaboration, workspace-based organization) but has weaker deduplication and a GPL license that limits commercial use.

For **scan orchestration patterns**, study **Osmedeus** (5.4k+ stars, MIT, Go) — its YAML-based workflow engine with `depends_on` dependency chains and Redis-based distributed execution is an excellent architectural pattern to adopt for building a custom orchestration layer. **ReconFTW** (7.3k stars, MIT, Bash) is the most comprehensive automated reconnaissance framework, chaining dozens of tools through well-designed shell scripts — study its tool selection and pipeline design, but don't use Bash as a platform foundation.

**OpenVAS/Greenbone** (commercially backed, 160,000+ vulnerability tests) serves as a powerful network vulnerability scanning component integrated via its Greenbone Management Protocol. Use it alongside, not instead of, the web application scanners.

The recommended hybrid architecture:

- **DefectDojo** as the central finding database, deduplication engine, and reporting backbone
- **Custom FastAPI orchestration layer** (inspired by Osmedeus's YAML workflows) for scan pipeline management
- **Individual scanner containers** (Nmap, Nuclei, ZAP, Nikto, etc.) as execution components
- **DefectDojo's REST API** as the integration backbone — all scanners push results to DefectDojo for normalization

Do not build vulnerability management from scratch. DefectDojo alone would take years to replicate. Build the orchestration and interface layers around it.

---

## 12. Legal and ethical guardrails are load-bearing architecture

Authorization enforcement is not a feature — it is the foundational constraint that every other module must respect. **No scan can execute without verified, non-expired authorization documentation** stored in the platform with tamper-evident checksums.

**Scope management** requires a multi-layer enforcement system. Store authorized targets (IP ranges, CIDR blocks, domains) in a scope database linked to signed authorization letters. Before every scan task dispatches, validate the target against the authorized scope — if a target falls outside scope, block execution and log the attempt. Implement DNS resolution verification to catch targets that resolve to out-of-scope infrastructure. Accessing out-of-scope systems — even accidentally — may constitute unauthorized access under the **Computer Fraud and Abuse Act (CFAA, 18 U.S.C. § 1030)**.

Authorization documentation must include a signed letter from an individual with demonstrable authority over target systems (C-level or legal counsel), specifying exact systems authorized, testing dates, prohibited techniques, and emergency contacts. The 2021 Supreme Court ruling in *Van Buren v. United States* narrowed "exceeds authorized access" under CFAA, but the DOJ's 2022 policy revision clarifying good-faith security research creates prosecutorial discretion, not a statutory safe harbor. **Written authorization is mandatory — verbal authorization is never legally sufficient.**

**Rate limiting** must be adaptive. Monitor target response latency and error rates during scanning. If response time increases beyond 200% of baseline or error rate exceeds a configurable threshold, automatically throttle or pause. Implement configurable connection limits per target (5–25 concurrent connections), request spacing (100ms–5s between requests), and bandwidth caps. Respect `Retry-After` headers on HTTP 429 responses.

**Kill switches** operate at three levels: global (halt all scans), per-scan (terminate individual jobs), and per-target (stop all activity against a specific target). Automatic triggers should fire when targets become unresponsive, error rates spike, out-of-scope access is attempted, or authorization expires during an active scan. Celery's `revoke(task_id, terminate=True)` provides immediate task cancellation.

**Audit trails** must log every action with tamper-evident integrity. Log all user authentication events, scan configurations, every request sent to a target, every response received, vulnerability discoveries, and report access. Use JSON structured logging as the primary format with CEF/LEEF export for SIEM integration. Store logs in append-only, cryptographically chained storage separate from the scanning infrastructure. PCI DSS requires minimum **1-year retention with 3 months immediately accessible**.

**Compliance mapping** for the platform itself spans multiple frameworks. PCI DSS 4.0 Requirement 11.4 mandates annual external and internal penetration testing with documented methodology, scope, and remediation verification. SOC 2 Trust Services Criteria CC4.1 specifically mentions penetration testing as an evaluation method. GDPR Article 32 requires "regularly testing, assessing and evaluating the effectiveness of technical and organisational measures" — regulators interpret this to include penetration testing. The proposed HIPAA rule update (December 2024 NPRM) is expected to make annual penetration testing mandatory for covered entities.

The platform itself is a high-value target containing vulnerability data, credentials, and attack tools. Secure it accordingly: network isolation for scanning infrastructure, encryption everywhere (TLS 1.3 in transit, AES-256 at rest), mandatory MFA for all users, secrets management via HashiCorp Vault or similar, and complete data isolation between clients in multi-tenant deployments.

---

## Conclusion: a practical assembly order for senior engineers

The platform assembles in four construction phases. **Phase 1** deploys the infrastructure skeleton: Docker Compose with FastAPI, Celery, Redis, PostgreSQL, and DefectDojo — this gives you a working API, task queue, and vulnerability management backend within days. **Phase 2** integrates the scanning modules one at a time, starting with the highest-value tools: Nmap + Masscan for port scanning, Subfinder for subdomain enumeration, Nuclei for vulnerability detection, and sslyze for TLS auditing. Each tool runs in its own Docker container with JSON output parsed into DefectDojo via its import API. **Phase 3** adds the interface layers: React dashboard for visualization and scan management, Typer CLI for automation, and WebSocket progress streaming. **Phase 4** hardens operations: authorization enforcement, scope validation, adaptive rate limiting, kill switches, tamper-evident logging, and compliance-aware report generation.

The critical architectural insight is that DefectDojo eliminates the need to build vulnerability management from scratch — it provides deduplication, tracking, compliance mapping, and 200+ scanner parsers out of the box. The custom platform layers orchestration, interface design, and operational controls on top of this foundation. Total estimated standing costs are under $100/month for external APIs (HIBP, DeHashed, LeakCheck), with all scanning tools running self-hosted at no licensing cost.

This approach produces a platform that is modular (swap any tool without architectural changes), extensible (add new scanners by writing a container wrapper and DefectDojo parser), and legally defensible (authorization-first design with comprehensive audit trails).