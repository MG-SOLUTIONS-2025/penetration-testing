from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}

    # Database
    database_url: str = "postgresql+asyncpg://pentest:pentest@localhost:5432/pentest"
    database_url_sync: str = "postgresql://pentest:pentest@localhost:5432/pentest"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # DefectDojo
    defectdojo_url: str = "http://localhost:8080"
    defectdojo_api_key: str = ""

    # App
    app_name: str = "PenTest Platform"
    debug: bool = False

    # Redis auth
    redis_password: str = ""

    # Celery encryption
    celery_fernet_key: str = ""

    # HIBP
    hibp_api_key: str = ""

    # Database connection pooling
    db_pool_size: int = 10
    db_max_overflow: int = 20
    db_pool_recycle: int = 3600

    # SSL verification for header scans
    headers_scan_verify_ssl: bool = True

    # Metasploit RPC
    metasploit_host: str = "msfrpcd"
    metasploit_port: int = 55553
    metasploit_password: str = ""


settings = Settings()

# Canonical mapping of scan type names to Celery task paths.
# Used by API router, CLI, and beat scheduler.
SCAN_TASK_MAP: dict[str, str] = {
    "nmap": "src.core.tasks.run_nmap_scan",
    "subfinder": "src.core.tasks.run_subfinder_scan",
    "nuclei": "src.core.tasks.run_nuclei_scan",
    "sslyze": "src.core.tasks.run_sslyze_scan",
    "headers": "src.core.tasks.run_headers_scan",
    "amass": "src.core.tasks.run_amass_scan",
    "masscan": "src.core.tasks.run_masscan_scan",
    "nikto": "src.core.tasks.run_nikto_scan",
    "ffuf": "src.core.tasks.run_ffuf_scan",
    "sqlmap": "src.core.tasks.run_sqlmap_scan",
    "wpscan": "src.core.tasks.run_wpscan_scan",
    "zap": "src.core.tasks.run_zap_scan",
}
