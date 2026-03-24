import logging
import sys
from datetime import UTC, datetime

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from src.core.audit import write_worm_entry
from src.core.database import async_session
from src.core.models import AuditLog

logger = logging.getLogger(__name__)


class AuditLogMiddleware(BaseHTTPMiddleware):
    """Logs all mutating API requests to both audit_log and audit_log_worm tables."""

    MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)

        if request.method not in self.MUTATING_METHODS:
            return response

        path = request.url.path
        action = f"{request.method.lower()}.{path.strip('/').replace('/', '.')}"
        client_ip = request.client.host if request.client else None

        try:
            async with async_session() as session:
                session.add(AuditLog(
                    action=action,
                    resource_type=_extract_resource_type(path),
                    detail={
                        "method": request.method,
                        "path": path,
                        "status_code": response.status_code,
                        "client": client_ip,
                        "timestamp": datetime.now(UTC).isoformat(),
                    },
                ))

                await write_worm_entry(
                    session,
                    action=action,
                    user_id=None,
                    resource_type=_extract_resource_type(path),
                    detail={
                        "method": request.method,
                        "path": path,
                        "status_code": response.status_code,
                    },
                    client_ip=client_ip,
                )

                await session.commit()
        except Exception:
            logger.warning("Failed to write audit log", exc_info=True)

        return response


def _extract_resource_type(path: str) -> str | None:
    parts = path.strip("/").split("/")
    if len(parts) >= 3 and parts[0] == "api":
        return parts[2]
    return None
