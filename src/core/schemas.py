import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr


# --- Auth ---
class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserRead(BaseModel):
    id: uuid.UUID
    email: str
    full_name: str
    is_active: bool
    is_admin: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: str


# --- Engagements ---
class EngagementCreate(BaseModel):
    name: str
    client_name: str
    authorized_by: str
    auth_document_hash: str | None = None
    starts_at: datetime
    ends_at: datetime
    notes: str | None = None


class EngagementUpdate(BaseModel):
    name: str | None = None
    client_name: str | None = None
    authorized_by: str | None = None
    starts_at: datetime | None = None
    ends_at: datetime | None = None
    notes: str | None = None


class EngagementRead(BaseModel):
    id: uuid.UUID
    name: str
    client_name: str
    authorized_by: str
    auth_document_hash: str | None
    starts_at: datetime
    ends_at: datetime
    notes: str | None
    created_by: uuid.UUID
    created_at: datetime

    model_config = {"from_attributes": True}


# --- Targets ---
class TargetCreate(BaseModel):
    target_type: str  # domain, ip, cidr, url
    value: str
    is_in_scope: bool = True
    metadata: dict | None = None


class TargetRead(BaseModel):
    id: uuid.UUID
    engagement_id: uuid.UUID
    target_type: str
    value: str
    is_in_scope: bool
    metadata_: dict | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


# --- Scans ---
class ScanCreate(BaseModel):
    engagement_id: uuid.UUID
    target_id: uuid.UUID | None = None
    scan_type: str  # nmap, subfinder, nuclei, sslyze, headers
    config: dict | None = None


class ScanRead(BaseModel):
    id: uuid.UUID
    engagement_id: uuid.UUID
    target_id: uuid.UUID | None
    scan_type: str
    status: str
    celery_task_id: str | None
    config: dict | None
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None
    created_by: uuid.UUID
    created_at: datetime

    model_config = {"from_attributes": True}


# --- Findings ---
class FindingRead(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    engagement_id: uuid.UUID
    title: str
    severity: str
    finding_type: str
    target_value: str
    detail: dict | None
    raw_output: str | None
    fingerprint: str
    defectdojo_finding_id: int | None
    created_at: datetime

    model_config = {"from_attributes": True}


# --- Pagination ---
class PaginatedResponse[T](BaseModel):
    items: list[T]
    total: int
    page: int
    page_size: int
