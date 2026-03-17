import uuid
from datetime import UTC, datetime

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from src.core.database import async_session
from src.core.models import AuditLog


class AuditLogMiddleware(BaseHTTPMiddleware):
    """Logs all mutating API requests to the audit_log table."""

    MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)

        if request.method not in self.MUTATING_METHODS:
            return response

        # Extract user_id from JWT if available
        user_id = None
        auth = request.headers.get("authorization", "")
        if auth.startswith("Bearer "):
            try:
                from jose import jwt

                from src.core.config import settings

                payload = jwt.decode(
                    auth.removeprefix("Bearer "),
                    settings.secret_key,
                    algorithms=[settings.algorithm],
                )
                user_id = uuid.UUID(payload["sub"])
            except Exception:
                pass

        # Determine action from method + path
        path = request.url.path
        action = f"{request.method.lower()}.{path.strip('/').replace('/', '.')}"

        try:
            async with async_session() as session:
                log_entry = AuditLog(
                    user_id=user_id,
                    action=action,
                    resource_type=_extract_resource_type(path),
                    detail={
                        "method": request.method,
                        "path": path,
                        "status_code": response.status_code,
                        "client": request.client.host if request.client else None,
                        "timestamp": datetime.now(UTC).isoformat(),
                    },
                )
                session.add(log_entry)
                await session.commit()
        except Exception:
            pass  # Audit logging should never break the request

        return response


def _extract_resource_type(path: str) -> str | None:
    parts = path.strip("/").split("/")
    # /api/v1/{resource}/... -> resource
    if len(parts) >= 3 and parts[0] == "api":
        return parts[2]
    return None
