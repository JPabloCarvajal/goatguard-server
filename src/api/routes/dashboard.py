"""
Dashboard endpoint for GOATGuard API.

GET /dashboard/summary — Quick overview of the entire system

Provides a single-call summary for the main screen of the
mobile app, avoiding multiple API calls on app startup.
"""

import logging

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional

from src.api.dependencies import get_db, get_current_user
from src.database.models import (
    User, Network, NetworkCurrentMetrics,
    Device, Alert, TopTalkerCurrent,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


class TopConsumer(BaseModel):
    """The device consuming the most bandwidth."""
    device_id: int
    label: str
    ip: str
    consumption: float


class DashboardSummary(BaseModel):
    """Complete system overview for the main screen."""
    network_status: str
    network_name: str
    devices_total: int
    devices_active: int
    devices_with_agent: int
    devices_disconnected: int
    unseen_alerts: int
    isp_latency_avg: Optional[float] = None
    packet_loss_pct: Optional[float] = None
    jitter: Optional[float] = None
    active_connections: Optional[int] = None
    top_consumer: Optional[TopConsumer] = None


def _calculate_network_status(latency, loss, jitter) -> str:
    """Determine network health from ISP metrics.

    Thresholds based on ITU-T G.114 recommendations:
        healthy:  latency < 50ms, loss < 1%, jitter < 10ms
        degraded: latency < 100ms, loss < 5%, jitter < 30ms
        critical: anything worse

    Returns "unknown" if metrics are not available yet.
    """
    if latency is None or jitter is None:
        return "unknown"

    # Treat None loss as 0 (no loss detected)
    loss_val = float(loss) if loss is not None else 0.0
    lat_val = float(latency)
    jit_val = float(jitter)

    if lat_val < 50 and loss_val < 1 and jit_val < 10:
        return "healthy"
    elif lat_val < 100 and loss_val < 5 and jit_val < 30:
        return "degraded"
    else:
        return "critical"


@router.get("/summary", response_model=DashboardSummary)
def get_dashboard_summary(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get a complete system overview in a single call.

    Designed for the mobile app's main screen. Returns
    everything needed to render the dashboard without
    making multiple API calls.
    """
    network = db.query(Network).first()
    if not network:
        return DashboardSummary(
            network_status="unknown",
            network_name="No network",
            devices_total=0, devices_active=0,
            devices_with_agent=0, devices_disconnected=0,
            unseen_alerts=0,
        )

    # Device counts
    total = db.query(Device).filter_by(network_id=network.id).count()
    active = db.query(Device).filter_by(
        network_id=network.id, status="active"
    ).count()
    with_agent = db.query(Device).filter_by(
        network_id=network.id, has_agent=True
    ).count()
    disconnected = db.query(Device).filter_by(
        network_id=network.id, status="disconnected"
    ).count()

    # Alerts
    unseen = db.query(Alert).filter_by(seen=False).count()

    # Network metrics
    metrics = db.query(NetworkCurrentMetrics).filter_by(
        network_id=network.id
    ).first()

    latency = None
    loss = None
    jitter = None
    connections = None

    if metrics:
        latency = float(metrics.isp_latency_avg) if metrics.isp_latency_avg is not None else None
        loss = float(metrics.packet_loss_pct) if metrics.packet_loss_pct is not None else None
        jitter = float(metrics.jitter) if metrics.jitter is not None else None
        connections = metrics.active_connections

    status = _calculate_network_status(latency, loss, jitter)

    # Top consumer
    top = db.query(TopTalkerCurrent).order_by(
        TopTalkerCurrent.rank
    ).first()

    top_consumer = None
    if top:
        device = db.query(Device).filter_by(id=top.device_id).first()
        if device:
            label = device.hostname or device.alias or device.detected_type or device.ip
            top_consumer = TopConsumer(
                device_id=device.id,
                label=label,
                ip=device.ip,
                consumption=float(top.total_consumption),
            )

    return DashboardSummary(
        network_status=status,
        network_name=network.name,
        devices_total=total,
        devices_active=active,
        devices_with_agent=with_agent,
        devices_disconnected=disconnected,
        unseen_alerts=unseen,
        isp_latency_avg=latency,
        packet_loss_pct=loss,
        jitter=jitter,
        active_connections=connections,
        top_consumer=top_consumer,
    )