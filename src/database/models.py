"""
SQLAlchemy ORM models for GOATGuard server.

Each class maps to a table in PostgreSQL. The column definitions
match the data dictionary (DICCIONARIO_DE_DATOS_GOATGuard.docx)
and the ER diagram.
"""

from datetime import datetime
from sqlalchemy import (
    Boolean, Column, DateTime, Integer, String, Text,
    BigInteger, ForeignKey, Numeric,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class Network(Base):
    """A monitored LAN segment."""
    __tablename__ = "network"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False)
    subnet = Column(String(45), nullable=False)
    gateway = Column(String(45), nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    devices = relationship("Device", back_populates="network")
    alerts = relationship("Alert", back_populates="network")

class Device(Base):
    """A device discovered in the network (with or without agent)."""
    __tablename__ = "device"

    id = Column(Integer, primary_key=True, autoincrement=True)
    network_id = Column(Integer, ForeignKey("network.id"), nullable=False)
    ip = Column(String(45), nullable=False)
    mac = Column(String(17), nullable=False)
    hostname = Column(String(255), nullable=True)
    alias = Column(String(64), nullable=True)
    detected_type = Column(String(50), nullable=True)
    device_type = Column(String(50), nullable=True)
    has_agent = Column(Boolean, nullable=False, default=False)
    status = Column(String(20), nullable=False, default="active")
    first_seen = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_seen = Column(DateTime, nullable=False, default=datetime.utcnow)

    network = relationship("Network", back_populates="devices")
    agent = relationship("Agent", back_populates="device", uselist=False)
    alerts = relationship("Alert", back_populates="device")

class Agent(Base):
    """A capture agent installed on an endpoint."""
    __tablename__ = "agent"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey("device.id"), nullable=False)
    uid = Column(String(100), nullable=False, unique=True)
    status = Column(String(20), nullable=False, default="active")
    last_heartbeat = Column(DateTime, nullable=False, default=datetime.utcnow)
    registered_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    device = relationship("Device", back_populates="agent")

class NetworkSnapshot(Base):
    """Periodic capture of global network health metrics."""
    __tablename__ = "network_snapshot"

    id = Column(Integer, primary_key=True, autoincrement=True)
    network_id = Column(Integer, ForeignKey("network.id"), nullable=False)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)
    isp_latency_avg = Column(Numeric(10, 2), nullable=True)
    packet_loss_pct = Column(Numeric(5, 2), nullable=True)
    jitter = Column(Numeric(10, 2), nullable=True)
    dns_response_time_avg = Column(Numeric(10, 2), nullable=True)
    failed_connections_global = Column(Integer, nullable=False, default=0)
    active_connections = Column(Integer, nullable=True)
    new_connections_per_min = Column(Integer, nullable=True)
    internal_traffic_bytes = Column(BigInteger, nullable=True)
    external_traffic_bytes = Column(BigInteger, nullable=True)

    network = relationship("Network")
    top_talkers = relationship("TopTalker", back_populates="network_snapshot")
    endpoint_snapshots = relationship("EndpointSnapshot", back_populates="network_snapshot")

class EndpointSnapshot(Base):
    """Periodic capture of a single endpoint's metrics."""
    __tablename__ = "endpoint_snapshot"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey("device.id"), nullable=False)
    network_snapshot_id = Column(Integer, ForeignKey("network_snapshot.id"), nullable=False)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)
    bandwidth_in = Column(Numeric(15, 2), nullable=True)
    bandwidth_out = Column(Numeric(15, 2), nullable=True)
    tcp_retransmissions = Column(Integer, nullable=False, default=0)
    failed_connections = Column(Integer, nullable=False, default=0)
    dns_response_time = Column(Numeric(10, 2), nullable=True)
    jitter = Column(Numeric(10, 2), nullable=True)
    cpu_pct = Column(Numeric(5, 2), nullable=True)
    ram_pct = Column(Numeric(5, 2), nullable=True)
    link_speed = Column(Numeric(10, 2), nullable=True)
    cpu_count = Column(Integer, nullable=True)
    ram_total_bytes = Column(BigInteger, nullable=True)
    ram_available_bytes = Column(BigInteger, nullable=True)
    disk_usage_pct = Column(Numeric(5, 2), nullable=True)
    uptime_seconds = Column(Numeric(15, 2), nullable=True)
    unique_destinations = Column(Integer, nullable=True)
    bytes_ratio = Column(Numeric(10, 4), nullable=True)

    device = relationship("Device")
    network_snapshot = relationship("NetworkSnapshot", back_populates="endpoint_snapshots")

class TopTalker(Base):
    """Bandwidth consumption ranking per analysis cycle."""
    __tablename__ = "top_talker"

    id = Column(Integer, primary_key=True, autoincrement=True)
    network_snapshot_id = Column(Integer, ForeignKey("network_snapshot.id"), nullable=False)
    device_id = Column(Integer, ForeignKey("device.id"), nullable=False)
    total_consumption = Column(Numeric(15, 2), nullable=False)
    rank = Column(Integer, nullable=False)
    is_hog = Column(Boolean, nullable=False, default=False)

    network_snapshot = relationship("NetworkSnapshot", back_populates="top_talkers")
    device = relationship("Device")

class Alert(Base):
    """Alert generated by the analysis engine or ML classifier."""
    __tablename__ = "alert"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey("device.id"), nullable=False)
    network_id = Column(Integer, ForeignKey("network.id"), nullable=False)
    anomaly_type = Column(String(50), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)
    seen = Column(Boolean, nullable=False, default=False)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)

    device = relationship("Device", back_populates="alerts")
    network = relationship("Network", back_populates="alerts")

class User(Base):
    """Administrator account for the mobile app."""
    __tablename__ = "user"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(50), nullable=False, unique=True)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    sessions = relationship("Session", back_populates="user")
    push_tokens = relationship("PushToken", back_populates="user")

class Session(Base):
    """Active JWT session for a user."""
    __tablename__ = "session"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("user.id"), nullable=False)
    jwt_token = Column(Text, nullable=False)
    mobile_device = Column(String(100), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)

    user = relationship("User", back_populates="sessions")

class PushToken(Base):
    """Firebase push notification token for a mobile device."""
    __tablename__ = "push_token"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("user.id"), nullable=False)
    token = Column(String(255), nullable=False)
    platform = Column(String(20), nullable=False, default="android")
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    user = relationship("User", back_populates="push_tokens")

class NetworkCurrentMetrics(Base):
    """Latest network metrics. One row per network, updated via UPSERT."""
    __tablename__ = "network_current_metrics"

    network_id = Column(Integer, ForeignKey("network.id"), primary_key=True)
    timestamp = Column(DateTime, nullable=False)
    isp_latency_avg = Column(Numeric(10, 2), nullable=True)
    packet_loss_pct = Column(Numeric(5, 2), nullable=True)
    jitter = Column(Numeric(10, 2), nullable=True)
    dns_response_time_avg = Column(Numeric(10, 2), nullable=True)
    failed_connections_global = Column(Integer, nullable=False, default=0)
    active_connections = Column(Integer, nullable=True)
    new_connections_per_min = Column(Integer, nullable=True)
    internal_traffic_bytes = Column(BigInteger, nullable=True)
    external_traffic_bytes = Column(BigInteger, nullable=True)


class DeviceCurrentMetrics(Base):
    """Latest endpoint metrics. One row per device with agent."""
    __tablename__ = "device_current_metrics"

    device_id = Column(Integer, ForeignKey("device.id"), primary_key=True)
    timestamp = Column(DateTime, nullable=False)
    bandwidth_in = Column(Numeric(15, 2), nullable=True)
    bandwidth_out = Column(Numeric(15, 2), nullable=True)
    tcp_retransmissions = Column(Integer, nullable=False, default=0)
    failed_connections = Column(Integer, nullable=False, default=0)
    dns_response_time = Column(Numeric(10, 2), nullable=True)
    jitter = Column(Numeric(10, 2), nullable=True)
    cpu_pct = Column(Numeric(5, 2), nullable=True)
    ram_pct = Column(Numeric(5, 2), nullable=True)
    link_speed = Column(Numeric(10, 2), nullable=True)
    cpu_count = Column(Integer, nullable=True)
    ram_total_bytes = Column(BigInteger, nullable=True)
    ram_available_bytes = Column(BigInteger, nullable=True)
    disk_usage_pct = Column(Numeric(5, 2), nullable=True)
    uptime_seconds = Column(Numeric(15, 2), nullable=True)
    unique_destinations = Column(Integer, nullable=True)
    bytes_ratio = Column(Numeric(10, 4), nullable=True)


class TopTalkerCurrent(Base):
    """Current bandwidth ranking. Replaced entirely each cycle."""
    __tablename__ = "top_talker_current"

    id = Column(Integer, primary_key=True, autoincrement=True)
    network_id = Column(Integer, ForeignKey("network.id"), nullable=False)
    device_id = Column(Integer, ForeignKey("device.id"), nullable=False)
    total_consumption = Column(Numeric(15, 2), nullable=False)
    rank = Column(Integer, nullable=False)
    is_hog = Column(Boolean, nullable=False, default=False)

class MLPrediction(Base):
    """Traffic classification result from the Random Forest model."""
    __tablename__ = "ml_prediction"

    id = Column(Integer, primary_key=True, autoincrement=True)
    network_id = Column(Integer, ForeignKey("network.id"), nullable=False)
    device_id = Column(Integer, ForeignKey("device.id"), nullable=False)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)
    src_ip = Column(String(45), nullable=False)
    dst_ip = Column(String(45), nullable=False)
    src_port = Column(Integer, nullable=False)
    dst_port = Column(Integer, nullable=False)
    protocol = Column(String(10), nullable=False)
    predicted_label = Column(String(50), nullable=False)
    confidence = Column(Numeric(5, 4), nullable=False)
    feature_snapshot = Column(Text, nullable=True)

    network = relationship("Network")
    device = relationship("Device")


class Insight(Base):
    """Human-readable observation about network or device state."""
    __tablename__ = "insight"

    id = Column(Integer, primary_key=True, autoincrement=True)
    network_id = Column(Integer, ForeignKey("network.id"), nullable=False)
    device_id = Column(Integer, ForeignKey("device.id"), nullable=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)
    category = Column(String(30), nullable=False)
    message = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)
    metric_name = Column(String(50), nullable=False)
    metric_value = Column(Numeric(15, 4), nullable=False)
    metric_baseline = Column(Numeric(15, 4), nullable=False)

    network = relationship("Network")
    device = relationship("Device")