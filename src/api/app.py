from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from src.core.database import engine

from .auth import router as auth_router
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

limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await engine.dispose()


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

app.include_router(auth_router)
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
    return {"status": "ok"}
