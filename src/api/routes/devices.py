"""
Device endpoints for GOATGuard API.

GET    /devices              — List all devices in the inventory
GET    /devices/{id}         — Device detail with current metrics
PATCH  /devices/{id}/alias   — Update device alias

All endpoints require JWT authentication.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional, List

from src.api.dependencies import get_db, get_current_user
from src.database.models import User, Device, DeviceCurrentMetrics, Agent, EndpointSnapshot, RecentConnection

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/devices", tags=["Devices"])

class ConnectionResponse(BaseModel):
    """An external connection from a device with resolved hostname."""
    dst_ip: str
    dst_hostname: Optional[str] = None
    dst_port: int
    proto: str
    total_bytes: int
    connection_count: int
    last_seen: str

class SnapshotResponse(BaseModel):
    """A single historical metric point for trend graphs."""
    timestamp: str
    cpu_pct: Optional[float] = None
    ram_pct: Optional[float] = None
    bandwidth_in: Optional[float] = None
    bandwidth_out: Optional[float] = None
    tcp_retransmissions: int = 0
    failed_connections: int = 0

class DeviceSummary(BaseModel):
    """Device info for the inventory list."""
    id: int
    ip: str
    mac: str
    hostname: Optional[str] = None
    alias: Optional[str] = None
    detected_type: Optional[str] = None
    device_type: Optional[str] = None
    has_agent: bool
    status: str

    class Config:
        from_attributes = True


class DeviceMetrics(BaseModel):
    """Current metrics for a device with agent."""
    cpu_pct: Optional[float] = None
    ram_pct: Optional[float] = None
    disk_usage_pct: Optional[float] = None
    link_speed: Optional[float] = None
    cpu_count: Optional[int] = None
    ram_total_bytes: Optional[int] = None
    ram_available_bytes: Optional[int] = None
    uptime_seconds: Optional[float] = None
    bandwidth_in: Optional[float] = None
    bandwidth_out: Optional[float] = None
    tcp_retransmissions: int = 0
    failed_connections: int = 0
    unique_destinations: Optional[int] = None
    bytes_ratio: Optional[float] = None
    dns_response_time: Optional[float] = None


class AgentInfo(BaseModel):
    """Agent information associated with a device."""
    uid: str
    status: str
    last_heartbeat: Optional[str] = None
    registered_at: Optional[str] = None


class DeviceDetail(BaseModel):
    """Full device detail with metrics and agent info."""
    id: int
    ip: str
    mac: str
    hostname: Optional[str] = None
    alias: Optional[str] = None
    detected_type: Optional[str] = None
    device_type: Optional[str] = None
    has_agent: bool
    status: str
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    metrics: Optional[DeviceMetrics] = None
    agent: Optional[AgentInfo] = None


class AliasRequest(BaseModel):
    """Request body for updating device alias."""
    alias: str

class DeviceComparisonEntry(BaseModel):
    """A device's value for a specific metric."""
    device_id: int
    label: str
    ip: str
    value: Optional[float] = None

@router.get("/", response_model=List[DeviceSummary])
def list_devices(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """List all devices in the network inventory.

    Returns both devices with agents (full monitoring) and
    devices discovered via ARP (basic presence detection).
    Ordered by IP address.
    """
    devices = db.query(Device).order_by(Device.ip).all()
    return devices

@router.get("/comparison", response_model=List[DeviceComparisonEntry])
def compare_devices(
    metric: str = "bandwidth_in",
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Compare all devices by a specific metric.

    Designed for bar charts. Valid metrics: cpu_pct, ram_pct,
    bandwidth_in, bandwidth_out, tcp_retransmissions,
    failed_connections, unique_destinations.
    """
    valid_metrics = [
        "cpu_pct", "ram_pct", "bandwidth_in", "bandwidth_out",
        "tcp_retransmissions", "failed_connections",
        "unique_destinations", "disk_usage_pct",
    ]

    if metric not in valid_metrics:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid metric. Valid options: {', '.join(valid_metrics)}",
        )

    devices = db.query(Device).filter_by(status="active").all()

    result = []
    for device in devices:
        label = device.hostname or device.alias or device.detected_type or device.ip

        value = None
        metrics_row = db.query(DeviceCurrentMetrics).filter_by(
            device_id=device.id
        ).first()

        if metrics_row:
            raw = getattr(metrics_row, metric, None)
            value = float(raw) if raw is not None else None

        result.append({
            "device_id": device.id,
            "label": label,
            "ip": device.ip,
            "value": value,
        })

    # Sort by value descending, None values at the end
    result.sort(key=lambda x: x["value"] if x["value"] is not None else -1, reverse=True)

    return result

@router.get("/{device_id}", response_model=DeviceDetail)
def get_device(
    device_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get full detail of a device including current metrics.

    For devices with agent: includes CPU, RAM, bandwidth,
    retransmissions, connections, and agent status.
    For devices without agent: only basic info (IP, MAC, vendor).
    """
    device = db.query(Device).filter_by(id=device_id).first()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )

    # Build response
    result = {
        "id": device.id,
        "ip": device.ip,
        "mac": device.mac,
        "hostname": device.hostname,
        "alias": device.alias,
        "detected_type": device.detected_type,
        "device_type": device.device_type,
        "has_agent": device.has_agent,
        "status": device.status,
        "first_seen": str(device.first_seen) if device.first_seen else None,
        "last_seen": str(device.last_seen) if device.last_seen else None,
        "metrics": None,
        "agent": None,
    }

    # Add metrics if device has agent
    if device.has_agent:
        metrics = db.query(DeviceCurrentMetrics).filter_by(
            device_id=device.id
        ).first()

        if metrics:
            result["metrics"] = {
                "cpu_pct": float(metrics.cpu_pct) if metrics.cpu_pct is not None else None,
                "ram_pct": float(metrics.ram_pct) if metrics.ram_pct is not None else None,
                "disk_usage_pct": float(metrics.disk_usage_pct) if metrics.disk_usage_pct is not None else None,
                "link_speed": float(metrics.link_speed) if metrics.link_speed is not None else None,
                "cpu_count": metrics.cpu_count,
                "ram_total_bytes": metrics.ram_total_bytes,
                "ram_available_bytes": metrics.ram_available_bytes,
                "uptime_seconds": float(metrics.uptime_seconds) if metrics.uptime_seconds is not None else None,
                "bandwidth_in": float(metrics.bandwidth_in) if metrics.bandwidth_in is not None else None,
                "bandwidth_out": float(metrics.bandwidth_out) if metrics.bandwidth_out is not None else None,
                "tcp_retransmissions": metrics.tcp_retransmissions,
                "failed_connections": metrics.failed_connections,
                "unique_destinations": metrics.unique_destinations,
                "bytes_ratio": float(metrics.bytes_ratio) if metrics.bytes_ratio is not None else None,
                "dns_response_time": float(metrics.dns_response_time) if metrics.dns_response_time is not None else None,
            }

        # Add agent info
        agent = db.query(Agent).filter_by(device_id=device.id).first()
        if agent:
            result["agent"] = {
                "uid": agent.uid,
                "status": agent.status,
                "last_heartbeat": str(agent.last_heartbeat) if agent.last_heartbeat else None,
                "registered_at": str(agent.registered_at) if agent.registered_at else None,
            }

    return result

@router.patch("/{device_id}/alias")
def update_alias(
    device_id: int,
    request: AliasRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Update the display alias of a device.

    The alias is a human-friendly name set by the administrator
    (e.g., "Printer 2nd Floor", "Juan's Laptop"). It appears
    alongside the hostname in the dashboard.
    """
    device = db.query(Device).filter_by(id=device_id).first()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )

    if len(request.alias) > 64:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Alias must be 64 characters or less",
        )

    device.alias = request.alias
    db.commit()

    logger.info(f"Device {device_id} alias updated to '{request.alias}'")

    return {"message": "Alias updated", "device_id": device_id, "alias": request.alias}

@router.get("/{device_id}/history", response_model=List[SnapshotResponse])
def get_device_history(
    device_id: int,
    hours: int = 4,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get historical metrics for a device.

    Returns snapshots from the last N hours (default 4).
    Used for trend graphs in the mobile app.

    Args:
        device_id: The device to query.
        hours: How many hours of history to return.
    """
    from datetime import datetime, timedelta

    cutoff = datetime.utcnow() - timedelta(hours=hours)

    snapshots = db.query(EndpointSnapshot).filter(
        EndpointSnapshot.device_id == device_id,
        EndpointSnapshot.timestamp >= cutoff,
    ).order_by(EndpointSnapshot.timestamp.asc()).all()

    result = []
    for s in snapshots:
        result.append({
            "timestamp": str(s.timestamp),
            "cpu_pct": float(s.cpu_pct) if s.cpu_pct is not None else None,
            "ram_pct": float(s.ram_pct) if s.ram_pct is not None else None,
            "bandwidth_in": float(s.bandwidth_in) if s.bandwidth_in is not None else None,
            "bandwidth_out": float(s.bandwidth_out) if s.bandwidth_out is not None else None,
            "tcp_retransmissions": s.tcp_retransmissions or 0,
            "failed_connections": s.failed_connections or 0,
        })

    return result

@router.get("/{device_id}/connections", response_model=List[ConnectionResponse])
def get_device_connections(
    device_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get external connections for a device with resolved hostnames.

    Shows who this device is communicating with. External IPs
    are resolved to domain names (e.g., 140.82.113.21 -> github.com).
    Grouped by destination, sorted by total bytes descending.
    """
    device = db.query(Device).filter_by(id=device_id).first()
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )

    connections = db.query(RecentConnection).filter_by(
        device_id=device_id
    ).order_by(RecentConnection.total_bytes.desc()).all()

    result = []
    for c in connections:
        result.append({
            "dst_ip": c.dst_ip,
            "dst_hostname": c.dst_hostname,
            "dst_port": c.dst_port,
            "proto": c.proto,
            "total_bytes": c.total_bytes,
            "connection_count": c.connection_count,
            "last_seen": str(c.last_seen),
        })

    return result

