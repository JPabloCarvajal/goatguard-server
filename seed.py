"""
Seed script — pobla la BD con datos de prueba equivalentes a MockData de Flutter.

Uso:
    docker compose -f ../docker-compose.yml up -d   # PostgreSQL
    python run_api.py &                              # crea tablas
    python seed.py                                   # pobla datos
"""

import sys
from datetime import datetime, timedelta

sys.path.insert(0, ".")

from src.config import load_config
from src.database.connection import Database
from src.database.models import (
    Base, Network, Device, Agent, Alert,
    NetworkCurrentMetrics, DeviceCurrentMetrics, TopTalkerCurrent, User,
)
from src.api.auth import hash_password

NOW = datetime.utcnow()


def seed(session):
    # --- Red por defecto ---
    network = Network(
        id=1, name="GOATGuard LAN", subnet="192.168.59.0/24",
        gateway="192.168.59.1", created_at=NOW,
    )
    session.merge(network)
    session.flush()

    # --- Usuario admin ---
    admin = session.query(User).filter_by(username="admin").first()
    if not admin:
        admin = User(
            username="admin",
            password_hash=hash_password("admin123"),
            created_at=NOW,
        )
        session.add(admin)
        session.flush()

    # --- Dispositivos (equivalentes a MockData.devices) ---
    devices_data = [
        dict(id=1, ip="192.168.59.255", mac="00:1A:2B:3C:4D:5E",
             hostname="PC-Admin", alias="Juan's MacBook",
             detected_type="Apple Inc.", device_type="laptop",
             has_agent=True, status="active"),
        dict(id=2, ip="192.168.59.10", mac="00:1A:2B:3C:4D:AA",
             hostname="Server-01", alias="Server-01",
             detected_type="Dell Inc.", device_type="server",
             has_agent=True, status="active"),
        dict(id=3, ip="192.168.59.12", mac="00:1A:2B:3C:5F:12",
             hostname="WS-Lab03", alias="Laptop Dell",
             detected_type="Dell Inc.", device_type="laptop",
             has_agent=True, status="active"),
        dict(id=4, ip="192.168.59.50", mac="00:1A:2B:AA:BB:CC",
             hostname="Printer-HP", alias="Printer HP",
             detected_type="HP Inc.", device_type="printer",
             has_agent=True, status="inactive"),
        dict(id=5, ip="192.168.59.100", mac="AA:BB:CC:DD:EE:01",
             hostname=None, alias="Smart TV",
             detected_type="Samsung", device_type="iot",
             has_agent=False, status="active"),
        dict(id=6, ip="192.168.59.120", mac="AA:BB:CC:DD:EE:02",
             hostname=None, alias="Unknown Device",
             detected_type=None, device_type="unknown",
             has_agent=False, status="active"),
        dict(id=7, ip="192.168.59.130", mac="AA:BB:CC:DD:EE:03",
             hostname=None, alias="Samsung S24",
             detected_type="Samsung", device_type="phone",
             has_agent=False, status="active"),
        dict(id=8, ip="192.168.59.131", mac="AA:BB:CC:DD:EE:04",
             hostname=None, alias="iPhone 15",
             detected_type="Apple Inc.", device_type="phone",
             has_agent=False, status="active"),
        dict(id=9, ip="192.168.59.200", mac="AA:BB:CC:DD:EE:05",
             hostname=None, alias="Camera IP",
             detected_type="Hikvision", device_type="camera",
             has_agent=False, status="active"),
        dict(id=10, ip="192.168.59.210", mac="AA:BB:CC:DD:EE:06",
             hostname="IoT-Sensor", alias="IoT Sensor",
             detected_type=None, device_type="iot",
             has_agent=True, status="inactive"),
    ]

    for d in devices_data:
        dev = Device(
            network_id=1,
            first_seen=NOW - timedelta(days=7),
            last_seen=NOW - timedelta(seconds=5),
            **d,
        )
        session.merge(dev)
    session.flush()

    # --- Agentes (equivalentes a MockData.agents) ---
    agents_data = [
        dict(device_id=1, uid="PC-Admin__00:1A:2B:3C:4D:5E",
             status="active", last_heartbeat=NOW - timedelta(seconds=5)),
        dict(device_id=2, uid="Server-01__00:1A:2B:3C:4D:AA",
             status="active", last_heartbeat=NOW - timedelta(seconds=5)),
        dict(device_id=3, uid="WS-Lab03__00:1A:2B:3C:5F:12",
             status="active", last_heartbeat=NOW - timedelta(seconds=10)),
        dict(device_id=4, uid="Printer-HP__00:1A:2B:AA:BB:CC",
             status="inactive", last_heartbeat=NOW - timedelta(hours=2)),
        dict(device_id=10, uid="IoT-Sensor__AA:BB:CC:DD:EE:06",
             status="inactive", last_heartbeat=NOW - timedelta(hours=5)),
    ]

    for i, a in enumerate(agents_data, start=1):
        agent = Agent(id=i, registered_at=NOW - timedelta(days=7), **a)
        session.merge(agent)
    session.flush()

    # --- Métricas de red actuales ---
    net_metrics = NetworkCurrentMetrics(
        network_id=1,
        timestamp=NOW,
        isp_latency_avg=32.0,
        packet_loss_pct=0.2,
        jitter=5.0,
        dns_response_time_avg=45.0,
        failed_connections_global=3,
        active_connections=156,
        new_connections_per_min=23,
        internal_traffic_bytes=52_428_800_000,
        external_traffic_bytes=104_857_600_000,
    )
    session.merge(net_metrics)

    # --- Métricas de dispositivos con agente ---
    device_metrics = [
        dict(device_id=1, cpu_pct=55, ram_pct=70, link_speed=200,
             bandwidth_in=15_234_567, bandwidth_out=8_765_432,
             tcp_retransmissions=12, failed_connections=3,
             dns_response_time=90, jitter=8.5),
        dict(device_id=2, cpu_pct=45, ram_pct=62, link_speed=940,
             bandwidth_in=5_000_000, bandwidth_out=2_000_000,
             tcp_retransmissions=0, failed_connections=0,
             dns_response_time=2, jitter=1.2),
        dict(device_id=3, cpu_pct=23, ram_pct=45, link_speed=240,
             bandwidth_in=3_000_000, bandwidth_out=1_500_000,
             tcp_retransmissions=1, failed_connections=0,
             dns_response_time=70, jitter=4.0),
    ]

    for dm in device_metrics:
        m = DeviceCurrentMetrics(timestamp=NOW, **dm)
        session.merge(m)

    # --- Top Talkers actuales ---
    session.query(TopTalkerCurrent).delete()
    top_talkers = [
        dict(device_id=5, total_consumption=42_300_000, rank=1, is_hog=True),
        dict(device_id=1, total_consumption=28_100_000, rank=2, is_hog=False),
        dict(device_id=2, total_consumption=15_700_000, rank=3, is_hog=False),
        dict(device_id=3, total_consumption=8_400_000, rank=4, is_hog=False),
        dict(device_id=6, total_consumption=5_200_000, rank=5, is_hog=False),
    ]

    for tt in top_talkers:
        session.add(TopTalkerCurrent(network_id=1, **tt))

    # --- Alertas (equivalentes a MockData.alerts) ---
    alerts_data = [
        dict(id=1, device_id=5, anomaly_type="bandwidth_hog",
             description="Smart TV is consuming 42.3 Mbps, significantly above the network average.",
             severity="high", seen=False,
             timestamp=NOW - timedelta(minutes=5)),
        dict(id=2, device_id=6, anomaly_type="port_scan",
             description="Sequential port scanning activity detected from Unknown Device. 847 ports probed in 60 seconds.",
             severity="critical", seen=False,
             timestamp=NOW - timedelta(minutes=12)),
        dict(id=3, device_id=1, anomaly_type="tcp_retransmissions",
             description="Juan's MacBook experiencing 12.8 retransmissions/min. Possible physical link issue.",
             severity="critical", seen=False,
             timestamp=NOW - timedelta(minutes=20)),
        dict(id=4, device_id=6, anomaly_type="new_device",
             description="A device with MAC AA:BB:CC:DD:EE:02 connected to the network. No agent installed.",
             severity="low", seen=False,
             timestamp=NOW - timedelta(hours=1)),
        dict(id=5, device_id=4, anomaly_type="agent_heartbeat_lost",
             description="Printer-HP agent stopped reporting heartbeats 2 hours ago.",
             severity="medium", seen=True,
             timestamp=NOW - timedelta(hours=2)),
        dict(id=6, device_id=9, anomaly_type="unusual_outbound",
             description="Camera IP attempting connections to 14 unique external IPs in the last 5 minutes.",
             severity="critical", seen=True,
             timestamp=NOW - timedelta(hours=3)),
    ]

    for a in alerts_data:
        alert = Alert(network_id=1, **a)
        session.merge(alert)

    session.commit()
    print(f"Seed completado: 10 devices, 5 agents, 6 alerts, métricas de red y Top Talkers.")


def main():
    config = load_config()
    db = Database(
        host=config.database.host, port=config.database.port,
        name=config.database.name, user=config.database.user,
        password=config.database.password,
    )
    db.create_tables(Base)

    # Inicializar auth para hash_password
    from src.api.auth import init_auth
    init_auth(
        jwt_secret=config.security.jwt_secret,
        jwt_algorithm=config.security.jwt_algorithm,
        jwt_expiration_hours=config.security.jwt_expiration_hours,
    )

    session = db.get_session()
    try:
        seed(session)
    except Exception as e:
        session.rollback()
        print(f"Error en seed: {e}")
        raise
    finally:
        session.close()


if __name__ == "__main__":
    main()
