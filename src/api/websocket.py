"""
WebSocket endpoint for real-time data push.

Maintains persistent connections with mobile app clients
and pushes updated metrics, device status, and alerts
whenever new data is available.

Instead of the mobile app polling GET /network/metrics every
5 seconds (generating HTTP overhead each time), the app opens
ONE WebSocket connection and receives updates automatically.

The server runs an internal loop that checks for changes
and broadcasts to all connected clients.

Flow:
    App connects → ws://server:8000/ws?token=<JWT>
    Server authenticates via the token query parameter
    Server pushes JSON messages when data changes
    Connection stays open until app disconnects
"""

import asyncio
import logging
from typing import Set

from fastapi import WebSocket, WebSocketDisconnect, APIRouter

from src.api.auth import verify_token

logger = logging.getLogger(__name__)

router = APIRouter()

class ConnectionManager:
    """Manages active WebSocket connections.

    Keeps a set of all connected clients and provides
    methods to broadcast messages to all of them at once.
    Thread-safe via asyncio (single event loop).
    """

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        """Accept a new WebSocket connection."""
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(
            f"WebSocket client connected "
            f"({len(self.active_connections)} total)"
        )

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a disconnected client."""
        self.active_connections.discard(websocket)
        logger.info(
            f"WebSocket client disconnected "
            f"({len(self.active_connections)} total)"
        )

    async def broadcast(self, message: dict) -> None:
        """Send a JSON message to all connected clients.

        If a send fails (client disconnected unexpectedly),
        removes that client silently.
        """
        dead = set()
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                dead.add(connection)

        for connection in dead:
            self.active_connections.discard(connection)


manager = ConnectionManager()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time data push.

    Authentication is done via query parameter because WebSocket
    connections cannot send custom headers in the browser.
    The mobile app connects as: ws://server:8000/ws?token=<JWT>

    After authentication, the client receives periodic updates
    with network metrics, device status, and alert counts.
    """
    # Authenticate via query parameter
    token = websocket.query_params.get("token")

    if not token:
        await websocket.close(code=4001, reason="Missing token")
        return

    payload = verify_token(token)
    if payload is None:
        await websocket.close(code=4003, reason="Invalid or expired token")
        return

    # Connection authenticated — accept and manage
    await manager.connect(websocket)

    try:
        # Keep connection alive by reading client messages
        # (the client might send pings or commands)
        while True:
            # This blocks until the client sends something
            # or disconnects. We don't expect messages from
            # the client, but we need to keep reading to
            # detect disconnections.
            await websocket.receive_text()

    except WebSocketDisconnect:
        manager.disconnect(websocket)

async def broadcast_loop(get_session) -> None:
    """Periodically read metrics from DB and push to all clients.

    Runs as a background asyncio task. Every 5 seconds, reads
    the current state from the database and broadcasts it to
    all connected WebSocket clients.

    Args:
        get_session: Callable that returns a new SQLAlchemy session.
    """
    from src.database.models import (
        NetworkCurrentMetrics, DeviceCurrentMetrics,
        Device, Alert, Network,
    )

    while True:
        await asyncio.sleep(5)

        if not manager.active_connections:
            continue

        session = get_session()
        try:
            # Network metrics
            network = session.query(Network).first()
            net_metrics = None
            if network:
                nm = session.query(NetworkCurrentMetrics).filter_by(
                    network_id=network.id
                ).first()
                if nm:
                    net_metrics = {
                        "isp_latency_avg": float(nm.isp_latency_avg) if nm.isp_latency_avg else None,
                        "packet_loss_pct": float(nm.packet_loss_pct) if nm.packet_loss_pct else None,
                        "jitter": float(nm.jitter) if nm.jitter else None,
                        "active_connections": nm.active_connections,
                        "failed_connections_global": nm.failed_connections_global,
                    }

            # Device summaries
            devices = session.query(Device).all()
            device_list = []
            for d in devices:
                dev_data = {
                    "id": d.id,
                    "ip": d.ip,
                    "hostname": d.hostname,
                    "status": d.status,
                    "has_agent": d.has_agent,
                }

                # Add metrics if available
                dm = session.query(DeviceCurrentMetrics).filter_by(
                    device_id=d.id
                ).first()
                if dm:
                    dev_data["cpu_pct"] = float(dm.cpu_pct) if dm.cpu_pct else None
                    dev_data["ram_pct"] = float(dm.ram_pct) if dm.ram_pct else None
                    dev_data["bandwidth_in"] = float(dm.bandwidth_in) if dm.bandwidth_in else None
                    dev_data["bandwidth_out"] = float(dm.bandwidth_out) if dm.bandwidth_out else None

                device_list.append(dev_data)

            # Unseen alert count
            unseen = session.query(Alert).filter_by(seen=False).count()

            # Broadcast
            message = {
                "type": "state_update",
                "network": net_metrics,
                "devices": device_list,
                "unseen_alerts": unseen,
            }

            await manager.broadcast(message)

        except Exception as e:
            logger.error(f"Broadcast loop error: {e}")
        finally:
            session.close()