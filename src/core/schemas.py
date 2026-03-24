import uuid
from datetime import datetime

from pydantic import BaseModel


# --- Engagements ---
class EngagementCreate(BaseModel):
    name: str
    client_name: str
    authorized_by: str
    auth_document_hash: str | None = None
    starts_at: datetime
    ends_at: datetime
    notes: str | None = None
    allow_ddos_testing: bool = False
    allow_exploitation: bool = False


class EngagementUpdate(BaseModel):
    name: str | None = None
    client_name: str | None = None
    authorized_by: str | None = None
    starts_at: datetime | None = None
    ends_at: datetime | None = None
    notes: str | None = None
    allow_ddos_testing: bool | None = None
    allow_exploitation: bool | None = None


class EngagementRead(BaseModel):
    id: uuid.UUID
    name: str
    client_name: str
    authorized_by: str
    auth_document_hash: str | None
    starts_at: datetime
    ends_at: datetime
    notes: str | None
    allow_ddos_testing: bool
    allow_exploitation: bool
    created_by: uuid.UUID | None
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
    scan_type: str
    config: dict | None = None


class ScanRead(BaseModel):
    id: uuid.UUID
    engagement_id: uuid.UUID
    target_id: uuid.UUID | None
    scan_type: str
    status: str
    celery_task_id: str | None
    config: dict | None
    baseline_scan_id: uuid.UUID | None = None
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None
    created_by: uuid.UUID | None = None
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
    cvss_vector: str | None = None
    cvss_score: float | None = None
    vpr_score: float | None = None
    vpr_factors: dict | None = None
    cwe_id: int | None = None
    compliance_mappings: dict | None = None
    status: str = "new"
    first_seen_at: datetime | None = None
    resolved_at: datetime | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


# --- Pagination ---
class PaginatedResponse[T](BaseModel):
    items: list[T]
    total: int
    page: int
    page_size: int
