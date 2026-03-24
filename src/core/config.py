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
