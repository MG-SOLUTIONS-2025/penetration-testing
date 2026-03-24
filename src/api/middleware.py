from datetime import UTC, datetime

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from src.core.database import async_session
from src.core.models import AuditLog


class AuditLogMiddleware(BaseHTTPMiddleware):
    """Logs all mutating API requests to both audit_log and audit_log_worm tables."""

    MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)

        if request.method not in self.MUTATING_METHODS:
            return response

        # Determine action from method + path
        path = request.url.path
        action = f"{request.method.lower()}.{path.strip('/').replace('/', '.')}"
        client_ip = request.client.host if request.client else None

        try:
            async with async_session() as session:
                # Write to standard audit log
                log_entry = AuditLog(
                    action=action,
                    resource_type=_extract_resource_type(path),
                    detail={
                        "method": request.method,
                        "path": path,
                        "status_code": response.status_code,
                        "client": client_ip,
                        "timestamp": datetime.now(UTC).isoformat(),
                    },
                )
                session.add(log_entry)

                # Write to WORM audit log (hash-chained)
                from src.core.audit import write_worm_entry

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
        except Exception as exc:
            import sys
            print(f"[AUDIT] Failed to write audit log: {exc!r}", file=sys.stderr)

        return response


def _extract_resource_type(path: str) -> str | None:
    parts = path.strip("/").split("/")
    # /api/v1/{resource}/... -> resource
    if len(parts) >= 3 and parts[0] == "api":
        return parts[2]
    return None
