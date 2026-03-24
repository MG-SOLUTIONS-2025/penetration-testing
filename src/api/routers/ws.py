import asyncio
import json
import uuid

import redis.asyncio as aioredis
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from src.core.config import settings
from src.core.database import async_session
from src.core.models import Scan

router = APIRouter()


@router.websocket("/ws/scans/{scan_id}")
async def scan_progress(websocket: WebSocket, scan_id: str):
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        await websocket.close(code=1008)
        return

    async with async_session() as db:
        scan_result = await db.execute(select(Scan).where(Scan.id == scan_uuid))
        scan = scan_result.scalar_one_or_none()

    if scan is None:
        await websocket.close(code=1008)
        return

    await websocket.accept()

    r = aioredis.from_url(settings.redis_url)
    pubsub = r.pubsub()
    await pubsub.subscribe(f"scan:{scan_id}")

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
        await pubsub.unsubscribe(f"scan:{scan_id}")
        await r.aclose()
