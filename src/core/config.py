from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}

    # Database
    database_url: str = "postgresql+asyncpg://pentest:pentest@localhost:5432/pentest"
    database_url_sync: str = "postgresql://pentest:pentest@localhost:5432/pentest"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # JWT
    secret_key: str = "changeme"
    access_token_expire_minutes: int = 30
    algorithm: str = "HS256"

    # DefectDojo
    defectdojo_url: str = "http://localhost:8080"
    defectdojo_api_key: str = ""

    # App
    app_name: str = "PenTest Platform"
    debug: bool = False
    registration_enabled: bool = False

    # Redis auth
    redis_password: str = ""

    # Celery encryption
    celery_fernet_key: str = ""

    # HIBP
    hibp_api_key: str = ""


settings = Settings()
