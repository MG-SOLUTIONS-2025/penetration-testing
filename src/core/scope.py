import ipaddress
import uuid
from datetime import UTC, datetime
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.models import AuditLog, Engagement, Target


class ScopeViolationError(Exception):
    pass


class EngagementExpiredError(Exception):
    pass


async def check_engagement_active(db: AsyncSession, engagement_id: uuid.UUID) -> Engagement:
    result = await db.execute(select(Engagement).where(Engagement.id == engagement_id))
    engagement = result.scalar_one_or_none()
    if not engagement:
        raise ValueError(f"Engagement {engagement_id} not found")

    now = datetime.now(UTC)
    if now < engagement.starts_at.replace(tzinfo=UTC):
        raise EngagementExpiredError("Engagement has not started yet")
    if now > engagement.ends_at.replace(tzinfo=UTC):
        raise EngagementExpiredError("Engagement authorization has expired")

    return engagement


def _extract_host(value: str) -> str:
    if "://" in value:
        return urlparse(value).hostname or value
    # Strip port if present (e.g. "example.com:8080") but not IPv6 literals
    if ":" in value and not value.startswith("["):
        return value.rsplit(":", 1)[0]
    return value


def _is_ip_in_cidr(ip_str: str, cidr_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str) in ipaddress.ip_network(cidr_str, strict=False)
    except ValueError:
        return False


def _is_subdomain_of(subdomain: str, domain: str) -> bool:
    subdomain = subdomain.lower().rstrip(".")
    domain = domain.lower().rstrip(".")
    return subdomain == domain or subdomain.endswith(f".{domain}")


def target_matches_scope(scan_target: str, scope_target: Target) -> bool:
    host = _extract_host(scan_target).lower()
    scope_value = scope_target.value.lower()

    if scope_target.target_type == "domain":
        return _is_subdomain_of(host, scope_value)
    elif scope_target.target_type == "ip":
        return host == scope_value
    elif scope_target.target_type == "cidr":
        return _is_ip_in_cidr(host, scope_value)
    elif scope_target.target_type == "url":
        scope_host = _extract_host(scope_value)
        return _is_subdomain_of(host, scope_host)

    return False


async def validate_target(
    db: AsyncSession,
    target_value: str,
    engagement_id: uuid.UUID,
    user_id: uuid.UUID | None = None,
) -> bool:
    await check_engagement_active(db, engagement_id)

    result = await db.execute(
        select(Target).where(
            Target.engagement_id == engagement_id,
            Target.is_in_scope.is_(True),
        )
    )
    scope_targets = result.scalars().all()

    for scope_target in scope_targets:
        if target_matches_scope(target_value, scope_target):
            return True

    # Log scope violation
    db.add(
        AuditLog(
            user_id=user_id,
            action="scope.violation",
            resource_type="target",
            detail={"target_value": target_value, "engagement_id": str(engagement_id)},
        )
    )
    await db.flush()

    raise ScopeViolationError(
        f"Target {target_value} is not in scope for engagement {engagement_id}"
    )
