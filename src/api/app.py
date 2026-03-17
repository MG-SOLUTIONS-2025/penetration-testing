from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.core.database import engine

from .auth import router as auth_router
from .middleware import AuditLogMiddleware
from .routers.engagements import router as engagements_router
from .routers.findings import router as findings_router
from .routers.scans import router as scans_router
from .routers.targets import router as targets_router
from .routers.ws import router as ws_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await engine.dispose()


app = FastAPI(
    title="PenTest Platform",
    version="0.1.0",
    lifespan=lifespan,
)

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


@app.get("/health")
async def health():
    return {"status": "ok"}
