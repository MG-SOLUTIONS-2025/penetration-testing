import asyncio
import json

import redis.asyncio as aioredis
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from jose import JWTError, jwt

from src.core.config import settings

router = APIRouter()


async def _authenticate_websocket(websocket: WebSocket) -> str | None:
    """Validate JWT from query param before accepting WebSocket."""
    token = websocket.query_params.get("token")
    if not token:
        return None
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        user_id: str = payload.get("sub")
        if user_id is None:
            return None
        return user_id
    except JWTError:
        return None


@router.websocket("/ws/scans/{task_id}")
async def scan_progress(websocket: WebSocket, task_id: str):
    # Authenticate before accepting
    user_id = await _authenticate_websocket(websocket)
    if user_id is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()

    r = aioredis.from_url(settings.redis_url)
    pubsub = r.pubsub()
    await pubsub.subscribe(f"scan:{task_id}")

    try:
        while True:
            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if message and message["type"] == "message":
                data = json.loads(message["data"])
                await websocket.send_json(data)

                # Close on completion or failure
                if data.get("percent", 0) in (100, -1):
                    break

            await asyncio.sleep(0.1)
    except WebSocketDisconnect:
        pass
    finally:
        await pubsub.unsubscribe(f"scan:{task_id}")
        await r.aclose()
