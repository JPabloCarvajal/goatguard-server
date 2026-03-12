"""
Network endpoints for GOATGuard API.

GET /network/metrics      — Current network health and ISP status
GET /network/top-talkers  — Bandwidth consumption ranking

All endpoints require JWT authentication.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional, List

from src.api.dependencies import get_db, get_current_user
from src.database.models import (
    User, Network, NetworkCurrentMetrics,
    TopTalkerCurrent, Device,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/network", tags=["Network"])


class NetworkMetricsResponse(BaseModel):
    """Current network health metrics including ISP status."""
    network_name: str
    subnet: str
    isp_latency_avg: Optional[float] = None
    packet_loss_pct: Optional[float] = None
    jitter: Optional[float] = None
    dns_response_time_avg: Optional[float] = None
    active_connections: Optional[int] = None
    new_connections_per_min: Optional[int] = None
    failed_connections_global: int = 0
    internal_traffic_bytes: Optional[int] = None
    external_traffic_bytes: Optional[int] = None
    total_devices: int = 0
    devices_with_agent: int = 0
    devices_active: int = 0


class TopTalkerResponse(BaseModel):
    """A device in the bandwidth consumption ranking."""
    rank: int
    device_id: int
    ip: str
    hostname: Optional[str] = None
    alias: Optional[str] = None
    detected_type: Optional[str] = None
    total_consumption: float
    is_hog: bool


@router.get("/metrics", response_model=NetworkMetricsResponse)
def get_network_metrics(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get current network health metrics.

    Includes ISP health (latency, packet loss, jitter),
    traffic statistics (connections, internal/external split),
    and device counts.
    """
    network = db.query(Network).first()
    if not network:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No network configured",
        )

    metrics = db.query(NetworkCurrentMetrics).filter_by(
        network_id=network.id
    ).first()

    # Count devices
    total = db.query(Device).filter_by(network_id=network.id).count()
    with_agent = db.query(Device).filter_by(
        network_id=network.id, has_agent=True
    ).count()
    active = db.query(Device).filter_by(
        network_id=network.id, status="active"
    ).count()

    result = {
        "network_name": network.name,
        "subnet": network.subnet,
        "total_devices": total,
        "devices_with_agent": with_agent,
        "devices_active": active,
        "isp_latency_avg": None,
        "packet_loss_pct": None,
        "jitter": None,
        "dns_response_time_avg": None,
        "active_connections": None,
        "new_connections_per_min": None,
        "failed_connections_global": 0,
        "internal_traffic_bytes": None,
        "external_traffic_bytes": None,
    }

    if metrics:
        result.update({
            "isp_latency_avg": float(metrics.isp_latency_avg) if metrics.isp_latency_avg else None,
            "packet_loss_pct": float(metrics.packet_loss_pct) if metrics.packet_loss_pct else None,
            "jitter": float(metrics.jitter) if metrics.jitter else None,
            "dns_response_time_avg": float(metrics.dns_response_time_avg) if metrics.dns_response_time_avg else None,
            "active_connections": metrics.active_connections,
            "new_connections_per_min": metrics.new_connections_per_min,
            "failed_connections_global": metrics.failed_connections_global or 0,
            "internal_traffic_bytes": metrics.internal_traffic_bytes,
            "external_traffic_bytes": metrics.external_traffic_bytes,
        })

    return result


@router.get("/top-talkers", response_model=List[TopTalkerResponse])
def get_top_talkers(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get the current bandwidth consumption ranking.

    Devices consuming more than 2x the average are marked
    as 'hog' (bandwidth hog).
    """
    talkers = db.query(TopTalkerCurrent).order_by(
        TopTalkerCurrent.rank
    ).all()

    result = []
    for talker in talkers:
        device = db.query(Device).filter_by(id=talker.device_id).first()
        if device:
            result.append({
                "rank": talker.rank,
                "device_id": device.id,
                "ip": device.ip,
                "hostname": device.hostname,
                "alias": device.alias,
                "detected_type": device.detected_type,
                "total_consumption": float(talker.total_consumption),
                "is_hog": talker.is_hog,
            })

    return result