"""WORM (Write-Once-Read-Many) audit log with hash-chain integrity."""

import hashlib
import json
import uuid
from datetime import UTC, datetime

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.models import AuditLogWORM


def _compute_hash(previous_hash: str, action: str, detail: dict | None, timestamp: str) -> str:
    data = json.dumps(
        {"prev": previous_hash, "action": action, "detail": detail, "ts": timestamp},
        sort_keys=True,
    )
    return hashlib.sha256(data.encode()).hexdigest()


async def write_worm_entry(
    db: AsyncSession,
    action: str,
    user_id: uuid.UUID | None = None,
    resource_type: str | None = None,
    resource_id: uuid.UUID | None = None,
    detail: dict | None = None,
    client_ip: str | None = None,
) -> AuditLogWORM:
    """Write a hash-chained audit log entry."""
    # Get the previous entry's hash
    result = await db.execute(
        select(AuditLogWORM).order_by(desc(AuditLogWORM.sequence_number)).limit(1)
    )
    prev_entry = result.scalar_one_or_none()
    previous_hash = prev_entry.entry_hash if prev_entry else "0" * 64

    timestamp = datetime.now(UTC).isoformat()
    entry_hash = _compute_hash(previous_hash, action, detail, timestamp)

    entry = AuditLogWORM(
        previous_hash=previous_hash,
        entry_hash=entry_hash,
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        detail=detail,
        client_ip=client_ip,
    )
    db.add(entry)
    await db.flush()
    return entry
