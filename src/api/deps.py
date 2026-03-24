import uuid
from collections.abc import AsyncGenerator

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import async_session
from src.core.models import Engagement


async def get_db() -> AsyncGenerator[AsyncSession]:
    async with async_session() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def get_engagement_or_404(
    db: AsyncSession,
    engagement_id: uuid.UUID,
) -> Engagement:
    """Fetch engagement, raising 404 if not found."""
    result = await db.execute(
        select(Engagement).where(Engagement.id == engagement_id)
    )
    engagement = result.scalar_one_or_none()
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return engagement
