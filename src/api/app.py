from contextlib import asynccontextmanager

import redis.asyncio as aioredis
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy import text

from src.core.config import settings
from src.core.database import async_session, engine

from .middleware import AuditLogMiddleware
from .routers.compliance import router as compliance_router
from .routers.credentials import router as credentials_router
from .routers.engagements import router as engagements_router
from .routers.exploits import router as exploits_router
from .routers.findings import router as findings_router
from .routers.reports import router as reports_router
from .routers.resilience import router as resilience_router
from .routers.scans import router as scans_router
from .routers.schedules import router as schedules_router
from .routers.targets import router as targets_router
from .routers.ws import router as ws_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await engine.dispose()


limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="PenTest Platform",
    version="0.1.0",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(AuditLogMiddleware)

app.include_router(engagements_router)
app.include_router(targets_router)
app.include_router(scans_router)
app.include_router(findings_router)
app.include_router(ws_router)
app.include_router(schedules_router)
app.include_router(reports_router)
app.include_router(compliance_router)
app.include_router(credentials_router)
app.include_router(exploits_router)
app.include_router(resilience_router)


@app.get("/health")
async def health():
    checks = {"api": "ok", "database": "unknown", "redis": "unknown"}
    try:
        async with async_session() as db:
            await db.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as e:
        checks["database"] = f"error: {e}"
    try:
        r = aioredis.from_url(settings.redis_url)
        await r.ping()
        await r.aclose()
        checks["redis"] = "ok"
    except Exception as e:
        checks["redis"] = f"error: {e}"
    status_code = 200 if all(v == "ok" for v in checks.values()) else 503
    return JSONResponse(content=checks, status_code=status_code)
