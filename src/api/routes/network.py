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
    TopTalkerCurrent, Device, NetworkSnapshot, TopTalker, RecentConnection
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/network", tags=["Network"])

KNOWN_PORTS = {
    443: "HTTPS", 80: "HTTP", 53: "DNS", 22: "SSH",
    21: "FTP", 25: "SMTP", 110: "POP3", 143: "IMAP",
    3306: "MySQL", 5432: "PostgreSQL", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 3389: "RDP", 5900: "VNC",
}

class ProtocolDistribution(BaseModel):
    """Traffic breakdown by protocol."""
    protocol: str
    bytes: int
    percentage: float


class PortDistribution(BaseModel):
    """Traffic breakdown by destination port."""
    port: int
    service: str
    bytes: int
    percentage: float


class TrafficDistributionResponse(BaseModel):
    """Complete traffic distribution for pie/donut charts."""
    by_protocol: List[ProtocolDistribution]
    by_direction: dict
    by_port: List[PortDistribution]

class TopTalkerSnapshotResponse(BaseModel):
    """Historical top talker entry."""
    timestamp: str
    device_id: int
    ip: str
    hostname: Optional[str] = None
    rank: int
    total_consumption: float
    is_hog: bool

class NetworkSnapshotResponse(BaseModel):
    """A single historical network metric point."""
    timestamp: str
    isp_latency_avg: Optional[float] = None
    packet_loss_pct: Optional[float] = None
    jitter: Optional[float] = None
    active_connections: Optional[int] = None
    failed_connections_global: int = 0

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

class MetricDetail(BaseModel):
    """Detailed ISP metric with historical context."""
    current: Optional[float] = None
    avg_1h: Optional[float] = None
    min_1h: Optional[float] = None
    max_1h: Optional[float] = None
    status: str


class IspHealthResponse(BaseModel):
    """Extended ISP health for gauge/speedometer widgets."""
    latency: MetricDetail
    packet_loss: MetricDetail
    jitter: MetricDetail

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
            "isp_latency_avg": float(metrics.isp_latency_avg) if metrics.isp_latency_avg is not None else None,
            "packet_loss_pct": float(metrics.packet_loss_pct) if metrics.packet_loss_pct is not None else None,
            "jitter": float(metrics.jitter) if metrics.jitter is not None else None,
            "dns_response_time_avg": float(metrics.dns_response_time_avg) if metrics.dns_response_time_avg is not None else None,
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
                "hostname": device.hostname or device.alias or device.detected_type,
                "alias": device.alias,
                "detected_type": device.detected_type,
                "total_consumption": float(talker.total_consumption),
                "is_hog": talker.is_hog,
            })

    return result

@router.get("/history", response_model=List[NetworkSnapshotResponse])
def get_network_history(
    hours: int = 4,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get historical network metrics.

    Returns snapshots from the last N hours (default 4).
    Used for ISP health trend graphs.
    """
    from datetime import datetime, timedelta, timezone

    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

    snapshots = db.query(NetworkSnapshot).filter(
        NetworkSnapshot.timestamp >= cutoff,
    ).order_by(NetworkSnapshot.timestamp.asc()).all()

    result = []
    for s in snapshots:
        result.append({
            "timestamp": str(s.timestamp),
            "isp_latency_avg": float(s.isp_latency_avg) if s.isp_latency_avg is not None else None,
            "packet_loss_pct": float(s.packet_loss_pct) if s.packet_loss_pct is not None else None,
            "jitter": float(s.jitter) if s.jitter is not None else None,
            "active_connections": s.active_connections,
            "failed_connections_global": s.failed_connections_global or 0,
        })

    return result

@router.get("/top-talkers/history", response_model=List[TopTalkerSnapshotResponse])
def get_top_talkers_history(
    hours: int = 4,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get historical top talker rankings.

    Returns snapshots from the last N hours (default 4).
    Each snapshot contains the full ranking for that cycle.
    Used for bandwidth consumption trend graphs.
    """
    from datetime import datetime, timedelta, timezone

    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

    snapshots = db.query(NetworkSnapshot).filter(
        NetworkSnapshot.timestamp >= cutoff,
    ).order_by(NetworkSnapshot.timestamp.asc()).all()

    result = []
    for snapshot in snapshots:
        talkers = db.query(TopTalker).filter_by(
            network_snapshot_id=snapshot.id
        ).order_by(TopTalker.rank).all()

        for t in talkers:
            device = db.query(Device).filter_by(id=t.device_id).first()
            if device:
                result.append({
                    "timestamp": str(snapshot.timestamp),
                    "device_id": device.id,
                    "ip": device.ip,
                    "hostname": device.hostname or device.alias or device.detected_type,
                    "rank": t.rank,
                    "total_consumption": float(t.total_consumption),
                    "is_hog": t.is_hog,
                })

    return result

@router.get("/traffic-distribution", response_model=TrafficDistributionResponse)
def get_traffic_distribution(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get traffic breakdown by protocol, direction, and port.

    Designed for pie charts and donut charts in the mobile app.
    Data comes from the most recent analysis cycle.
    """
    connections = db.query(RecentConnection).all()

    # By protocol
    proto_bytes = {}
    port_bytes = {}
    total_bytes = 0

    for c in connections:
        proto = c.proto or "unknown"
        proto_bytes[proto] = proto_bytes.get(proto, 0) + c.total_bytes
        port_bytes[c.dst_port] = port_bytes.get(c.dst_port, 0) + c.total_bytes
        total_bytes += c.total_bytes

    by_protocol = []
    for proto, bytes_val in sorted(proto_bytes.items(), key=lambda x: x[1], reverse=True):
        pct = (bytes_val / total_bytes * 100) if total_bytes > 0 else 0
        by_protocol.append({
            "protocol": proto,
            "bytes": bytes_val,
            "percentage": round(pct, 1),
        })

    # By port (top 10)
    by_port = []
    for port, bytes_val in sorted(port_bytes.items(), key=lambda x: x[1], reverse=True)[:10]:
        pct = (bytes_val / total_bytes * 100) if total_bytes > 0 else 0
        service = KNOWN_PORTS.get(port, f"Port {port}")
        by_port.append({
            "port": port,
            "service": service,
            "bytes": bytes_val,
            "percentage": round(pct, 1),
        })

    # By direction (from network_current_metrics)
    network = db.query(Network).first()
    internal = 0
    external = 0
    if network:
        metrics = db.query(NetworkCurrentMetrics).filter_by(
            network_id=network.id
        ).first()
        if metrics:
            internal = metrics.internal_traffic_bytes or 0
            external = metrics.external_traffic_bytes or 0

    dir_total = internal + external
    by_direction = {
        "internal": internal,
        "external": external,
        "internal_pct": round((internal / dir_total * 100) if dir_total > 0 else 0, 1),
        "external_pct": round((external / dir_total * 100) if dir_total > 0 else 0, 1),
    }

    return {
        "by_protocol": by_protocol,
        "by_direction": by_direction,
        "by_port": by_port,
    }

@router.get("/isp-health", response_model=IspHealthResponse)
def get_isp_health(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get detailed ISP health with 1-hour historical context.

    Includes current value, 1-hour average/min/max, and a
    status classification based on ITU-T G.114 thresholds.
    Designed for gauge/speedometer widgets.
    """
    from datetime import datetime, timedelta, timezone

    network = db.query(Network).first()

    # Current values
    current_latency = None
    current_loss = None
    current_jitter = None

    if network:
        metrics = db.query(NetworkCurrentMetrics).filter_by(
            network_id=network.id
        ).first()
        if metrics:
            current_latency = float(metrics.isp_latency_avg) if metrics.isp_latency_avg is not None else None
            current_loss = float(metrics.packet_loss_pct) if metrics.packet_loss_pct is not None else None
            current_jitter = float(metrics.jitter) if metrics.jitter is not None else None

    # 1-hour historical stats from snapshots
    cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
    snapshots = db.query(NetworkSnapshot).filter(
        NetworkSnapshot.timestamp >= cutoff,
    ).all()

    lat_values = [float(s.isp_latency_avg) for s in snapshots if s.isp_latency_avg is not None]
    loss_values = [float(s.packet_loss_pct) for s in snapshots if s.packet_loss_pct is not None]
    jit_values = [float(s.jitter) for s in snapshots if s.jitter is not None]

    def _stats(values):
        if not values:
            return None, None, None
        return (
            round(sum(values) / len(values), 2),
            round(min(values), 2),
            round(max(values), 2),
        )

    def _status(value, good_threshold, warn_threshold):
        if value is None:
            return "unknown"
        if value < good_threshold:
            return "good"
        elif value < warn_threshold:
            return "warning"
        else:
            return "critical"

    lat_avg, lat_min, lat_max = _stats(lat_values)
    loss_avg, loss_min, loss_max = _stats(loss_values)
    jit_avg, jit_min, jit_max = _stats(jit_values)

    return IspHealthResponse(
        latency=MetricDetail(
            current=current_latency,
            avg_1h=lat_avg,
            min_1h=lat_min,
            max_1h=lat_max,
            status=_status(current_latency, 50, 100),
        ),
        packet_loss=MetricDetail(
            current=current_loss,
            avg_1h=loss_avg,
            min_1h=loss_min,
            max_1h=loss_max,
            status=_status(current_loss, 1, 5),
        ),
        jitter=MetricDetail(
            current=current_jitter,
            avg_1h=jit_avg,
            min_1h=jit_min,
            max_1h=jit_max,
            status=_status(current_jitter, 10, 30),
        ),
    )