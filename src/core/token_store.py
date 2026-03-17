"""Refresh token management with rotation and revocation."""

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.models import RefreshToken


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def create_refresh_token(
    db: AsyncSession, user_id, expire_days: int = 30
) -> tuple[str, RefreshToken]:
    """Create a new refresh token, returning (raw_token, db_record)."""
    raw_token = secrets.token_urlsafe(48)
    token_hash = _hash_token(raw_token)

    record = RefreshToken(
        user_id=user_id,
        token_hash=token_hash,
        expires_at=datetime.now(UTC) + timedelta(days=expire_days),
    )
    db.add(record)
    await db.flush()
    return raw_token, record


async def rotate_refresh_token(
    db: AsyncSession, raw_token: str, expire_days: int = 30
) -> tuple[str, RefreshToken] | None:
    """Revoke old token and issue a new one (rotation)."""
    token_hash = _hash_token(raw_token)

    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.token_hash == token_hash,
            RefreshToken.revoked_at.is_(None),
        )
    )
    old = result.scalar_one_or_none()
    if not old:
        return None

    if old.expires_at.replace(tzinfo=UTC) < datetime.now(UTC):
        old.revoked_at = datetime.now(UTC)
        await db.flush()
        return None

    # Revoke old
    old.revoked_at = datetime.now(UTC)

    # Issue new
    new_raw, new_record = await create_refresh_token(db, old.user_id, expire_days)
    return new_raw, new_record


async def revoke_refresh_token(db: AsyncSession, raw_token: str) -> bool:
    token_hash = _hash_token(raw_token)
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.token_hash == token_hash,
            RefreshToken.revoked_at.is_(None),
        )
    )
    record = result.scalar_one_or_none()
    if not record:
        return False

    record.revoked_at = datetime.now(UTC)
    await db.flush()
    return True
