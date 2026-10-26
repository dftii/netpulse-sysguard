"""WebSocket connection registry with concurrent, fault-tolerant broadcasting."""

from __future__ import annotations

import asyncio
import logging

from fastapi import WebSocket
from starlette.websockets import WebSocketState

logger = logging.getLogger(__name__)

SEND_TIMEOUT_SECONDS = 2.0


class ConnectionManager:
    """Tracks live WebSocket clients and fans out telemetry frames to all of them."""

    def __init__(self, max_clients: int) -> None:
        self._max_clients = max_clients
        self._clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    @property
    def client_count(self) -> int:
        return len(self._clients)

    async def connect(self, websocket: WebSocket) -> bool:
        """Accept a client. Returns False (and closes with 1013 Try Again Later) when at capacity."""
        await websocket.accept()
        async with self._lock:
            if len(self._clients) >= self._max_clients:
                await websocket.close(code=1013, reason="Server at maximum WebSocket capacity")
                logger.warning("Rejected WebSocket client: capacity of %d reached", self._max_clients)
                return False
            self._clients.add(websocket)
        logger.info("WebSocket client connected (%d active)", len(self._clients))
        return True

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            removed = websocket in self._clients
            self._clients.discard(websocket)
        if removed:
            logger.info("WebSocket client disconnected (%d active)", len(self._clients))

    async def send_to(self, websocket: WebSocket, message: str) -> bool:
        """Send one frame to one client; returns False if the client is gone or too slow."""
        if websocket.application_state != WebSocketState.CONNECTED:
            return False
        try:
            await asyncio.wait_for(websocket.send_text(message), timeout=SEND_TIMEOUT_SECONDS)
        except (TimeoutError, RuntimeError, ConnectionError, OSError) as exc:
            logger.debug("Dropping WebSocket client after send failure: %r", exc)
            return False
        except Exception as exc:  # starlette raises WebSocketDisconnect / ClientDisconnected subclasses
            logger.debug("Dropping WebSocket client after unexpected send error: %r", exc)
            return False
        return True

    async def broadcast(self, message: str) -> None:
        """Send the frame to every client concurrently and evict the ones that fail."""
        async with self._lock:
            clients = list(self._clients)
        if not clients:
            return
        results = await asyncio.gather(*(self.send_to(client, message) for client in clients))
        dead = [client for client, delivered in zip(clients, results, strict=True) if not delivered]
        if dead:
            async with self._lock:
                for client in dead:
                    self._clients.discard(client)
            logger.info("Evicted %d unresponsive WebSocket client(s)", len(dead))

    async def close_all(self) -> None:
        async with self._lock:
            clients = list(self._clients)
            self._clients.clear()
        for client in clients:
            try:
                await client.close(code=1001, reason="Server shutting down")
            except Exception as exc:
                logger.debug("Error while closing WebSocket client: %r", exc)
