"""
TRINETRA — Real-Time Event Streaming Router (SSE & WebSockets)

Streams live events for new email detection, processing state transitions,
risk fusion score updates, and response actions.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Set

from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse

logger = logging.getLogger(__name__)

router = APIRouter()


class EventBroadcaster:
    """Broadcaster for SSE and WebSocket connections."""

    def __init__(self) -> None:
        self.active_websockets: Set[WebSocket] = set()
        self.sse_queues: List[asyncio.Queue] = []

    async def connect_ws(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_websockets.add(websocket)
        logger.info(f"WebSocket client connected. Total clients: {len(self.active_websockets)}")

    def disconnect_ws(self, websocket: WebSocket) -> None:
        self.active_websockets.discard(websocket)
        logger.info("WebSocket client disconnected.")

    async def broadcast_event(self, event_type: str, data: Dict[str, Any]) -> None:
        payload = {
            "event": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data,
        }
        json_str = json.dumps(payload)

        # Broadcast to WebSockets
        disconnected = set()
        for ws in self.active_websockets:
            try:
                await ws.send_text(json_str)
            except Exception:
                disconnected.add(ws)

        for ws in disconnected:
            self.active_websockets.discard(ws)

        # Broadcast to SSE queues
        for q in list(self.sse_queues):
            try:
                q.put_nowait(payload)
            except Exception:
                pass


broadcaster = EventBroadcaster()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time SOC updates."""
    await broadcaster.connect_ws(websocket)
    try:
        while True:
            # Keep connection open & listen for client ping
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"event": "pong", "timestamp": datetime.now(timezone.utc).isoformat()}))
    except WebSocketDisconnect:
        broadcaster.disconnect_ws(websocket)
    except Exception as e:
        logger.warning(f"WebSocket error: {e}")
        broadcaster.disconnect_ws(websocket)


@router.get("/stream")
async def sse_event_stream(request: Request):
    """Server-Sent Events (SSE) endpoint for live streaming telemetry updates."""
    q: asyncio.Queue = asyncio.Queue()
    broadcaster.sse_queues.append(q)

    async def event_generator():
        try:
            # Initial connection event
            init_msg = json.dumps({"event": "CONNECTED", "timestamp": datetime.now(timezone.utc).isoformat(), "data": {"message": "TRINETRA Real-time Event Stream Active"}})
            yield f"data: {init_msg}\n\n"

            while True:
                if await request.is_disconnected():
                    break
                try:
                    event_data = await asyncio.wait_for(q.get(), timeout=15.0)
                    yield f"data: {json.dumps(event_data)}\n\n"
                except asyncio.TimeoutError:
                    # Heartbeat ping
                    ping_msg = json.dumps({"event": "HEARTBEAT", "timestamp": datetime.now(timezone.utc).isoformat()})
                    yield f"data: {ping_msg}\n\n"
        finally:
            if q in broadcaster.sse_queues:
                broadcaster.sse_queues.remove(q)

    return StreamingResponse(event_generator(), media_type="text/event-stream")
