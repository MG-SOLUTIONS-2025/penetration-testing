from celery import Celery

from src.core.config import settings

celery_app = Celery(
    "pentest",
    broker=settings.redis_url,
    backend=settings.redis_url,
)

# Configure serialization — use Fernet if key is provided
accept_content = ["json"]
task_serializer = "json"
result_serializer = "json"

if settings.celery_fernet_key:
    try:
        from cryptography.fernet import Fernet
        from kombu.serialization import register
        from kombu.utils.encoding import bytes_to_str, str_to_bytes

        _fernet = Fernet(settings.celery_fernet_key.encode())

        import json

        def fernet_dumps(obj):
            return bytes_to_str(_fernet.encrypt(str_to_bytes(json.dumps(obj))))

        def fernet_loads(s):
            return json.loads(_fernet.decrypt(str_to_bytes(s)))

        register(
            "fernet_json",
            fernet_dumps,
            fernet_loads,
            content_type="application/x-fernet-json",
            content_encoding="utf-8",
        )

        task_serializer = "fernet_json"
        result_serializer = "fernet_json"
        accept_content = ["json", "fernet_json"]
    except ImportError:
        pass  # kombu[fernet] or cryptography not installed, fall back to json

celery_app.conf.update(
    task_serializer=task_serializer,
    result_serializer=result_serializer,
    accept_content=accept_content,
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_soft_time_limit=600,
    task_time_limit=660,
    worker_prefetch_multiplier=1,
    task_routes={
        "src.core.tasks.*": {"queue": "scans"},
    },
)

celery_app.autodiscover_tasks(["src.core"])
