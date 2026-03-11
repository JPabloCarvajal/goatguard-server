"""
Database repository for GOATGuard server.

Encapsulates all database operations behind simple methods.
Other modules never write SQL directly — they call repository
methods. This isolates the database logic and makes it easy
to change queries without touching the rest of the system.
"""

import logging
from datetime import datetime
from sqlalchemy.orm import Session

from src.database.models import (
    Agent,
    Device,
    DeviceCurrentMetrics,
    Network,
    NetworkCurrentMetrics,
    TopTalkerCurrent,
)

from src.database.models import (
    Agent,
    Device,
    DeviceCurrentMetrics,
    Network,
)

logger = logging.getLogger(__name__)

class Repository:
    """Handles all database read/write operations.

    Args:
        db_session_factory: A callable that returns a new SQLAlchemy Session.
    """

    def __init__(self, db_session_factory) -> None:
        self._get_session = db_session_factory
    
    def get_or_create_agent(self, agent_id: str, sender_ip: str,
                            network_id: int = 1) -> int:
        """Find an existing agent or register a new one.

        Parses the agent_id (HOSTNAME__MAC) to extract device info.
        Creates Device and Agent records if they don't exist.

        Args:
            agent_id: The unique agent identifier (HOSTNAME__MAC).
            sender_ip: The IP address the agent is sending from.
            network_id: The network this agent belongs to.

        Returns:
            The device_id associated with this agent.
        """
        session = self._get_session()
        try:
            # Check if agent already exists
            agent = session.query(Agent).filter_by(uid=agent_id).first()

            if agent:
                # Update last seen
                agent.last_heartbeat = datetime.utcnow()
                agent.device.last_seen = datetime.utcnow()
                agent.device.ip = sender_ip
                session.commit()
                return agent.device_id

            # Parse agent_id: "MALEDUCADA__CC:28:AA:09:16:04"
            parts = agent_id.split("__")
            hostname = parts[0] if len(parts) >= 1 else "unknown"
            mac = parts[1] if len(parts) >= 2 else "00:00:00:00:00:00"

            # Create new device
            device = Device(
                network_id=network_id,
                ip=sender_ip,
                mac=mac,
                hostname=hostname,
                has_agent=True,
                status="active",
            )
            session.add(device)
            session.flush()  # Get the auto-generated device.id

            # Create new agent
            agent = Agent(
                device_id=device.id,
                uid=agent_id,
                status="active",
            )
            session.add(agent)
            session.commit()

            logger.info(f"New agent registered: {agent_id} (device_id={device.id})")
            return device.id

        except Exception as e:
            session.rollback()
            logger.error(f"Failed to register agent {agent_id}: {e}")
            raise
        finally:
            session.close()

    
    def save_device_metrics(self, device_id: int, metrics: dict) -> None:
        """Save or update current metrics for a device.

        Uses UPSERT logic: if a row exists for this device_id,
        updates it. If not, creates a new one. This keeps exactly
        one row per device in device_current_metrics.

        Args:
            device_id: The device to update.
            metrics: Dictionary with metric values from the agent.
        """
        session = self._get_session()
        try:
            current = session.query(DeviceCurrentMetrics).filter_by(
                device_id=device_id
            ).first()

            now = datetime.utcnow()

            if current:
                current.timestamp = now
                current.cpu_pct = metrics.get("cpu_percent")
                current.ram_pct = metrics.get("ram_percent")
                current.disk_usage_pct = metrics.get("disk_usage_percent")
                current.link_speed = metrics.get("link_speed_mbps")
                current.cpu_count = metrics.get("cpu_count")
                current.ram_total_bytes = metrics.get("ram_total_bytes")
                current.ram_available_bytes = metrics.get("ram_available_bytes")
                current.uptime_seconds = metrics.get("uptime_seconds")
            else:
                current = DeviceCurrentMetrics(
                    device_id=device_id,
                    timestamp=now,
                    cpu_pct=metrics.get("cpu_percent"),
                    ram_pct=metrics.get("ram_percent"),
                    disk_usage_pct=metrics.get("disk_usage_percent"),
                    link_speed=metrics.get("link_speed_mbps"),
                    cpu_count=metrics.get("cpu_count"),
                    ram_total_bytes=metrics.get("ram_total_bytes"),
                    ram_available_bytes=metrics.get("ram_available_bytes"),
                    uptime_seconds=metrics.get("uptime_seconds"),
                )
                session.add(current)

            session.commit()
            logger.debug(f"Metrics saved for device {device_id}")

        except Exception as e:
            session.rollback()
            logger.error(f"Failed to save metrics for device {device_id}: {e}")
        finally:
            session.close()
    
    def update_heartbeat(self, agent_id: str) -> None:
        """Update the last heartbeat timestamp for an agent.

        Args:
            agent_id: The unique agent identifier.
        """
        session = self._get_session()
        try:
            agent = session.query(Agent).filter_by(uid=agent_id).first()
            if agent:
                agent.last_heartbeat = datetime.utcnow()
                agent.status = "active"
                session.commit()
                logger.debug(f"Heartbeat updated for {agent_id}")
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to update heartbeat for {agent_id}: {e}")
        finally:
            session.close()
    
    def ensure_default_network(self) -> int:
        """Create the default network if it doesn't exist.

        Returns:
            The network_id of the default network.
        """
        session = self._get_session()
        try:
            network = session.query(Network).first()
            if network:
                return network.id

            network = Network(
                name="Default LAN",
                subnet="192.168.1.0/24",
                gateway="192.168.1.1",
            )
            session.add(network)
            session.commit()
            logger.info(f"Default network created: {network.name}")
            return network.id

        except Exception as e:
            session.rollback()
            logger.error(f"Failed to create default network: {e}")
            raise
        finally:
            session.close()

        
    def update_device_traffic_metrics(self, ip: str, bandwidth_in: float,
                                       bandwidth_out: float,
                                       tcp_retransmissions: int,
                                       failed_connections: int,
                                       unique_destinations: int,
                                       bytes_ratio: float,
                                       dns_response_time: float) -> None:
        """Update traffic-derived metrics for a device identified by IP.

        Only updates devices that exist in the database.
        These metrics come from Zeek analysis, not from the agent directly.
        """
        session = self._get_session()
        try:
            device = session.query(Device).filter_by(ip=ip).first()
            if not device:
                return

            current = session.query(DeviceCurrentMetrics).filter_by(
                device_id=device.id
            ).first()

            if current:
                current.bandwidth_in = bandwidth_in
                current.bandwidth_out = bandwidth_out
                current.tcp_retransmissions = tcp_retransmissions
                current.failed_connections = failed_connections
                current.unique_destinations = unique_destinations
                current.bytes_ratio = bytes_ratio
                current.dns_response_time = dns_response_time
                session.commit()
                logger.debug(f"Traffic metrics updated for {ip}")

        except Exception as e:
            session.rollback()
            logger.error(f"Failed to update traffic metrics for {ip}: {e}")
        finally:
            session.close()

    def update_network_metrics(self, network_id: int,
                                active_connections: int,
                                new_connections_per_min: int,
                                failed_connections_global: int,
                                internal_traffic_bytes: int,
                                external_traffic_bytes: int) -> None:
        """Update network-wide metrics via UPSERT."""
        session = self._get_session()
        try:
            current = session.query(NetworkCurrentMetrics).filter_by(
                network_id=network_id
            ).first()

            now = datetime.utcnow()

            if current:
                current.timestamp = now
                current.active_connections = active_connections
                current.new_connections_per_min = new_connections_per_min
                current.failed_connections_global = failed_connections_global
                current.internal_traffic_bytes = internal_traffic_bytes
                current.external_traffic_bytes = external_traffic_bytes
            else:
                current = NetworkCurrentMetrics(
                    network_id=network_id,
                    timestamp=now,
                    active_connections=active_connections,
                    new_connections_per_min=new_connections_per_min,
                    failed_connections_global=failed_connections_global,
                    internal_traffic_bytes=internal_traffic_bytes,
                    external_traffic_bytes=external_traffic_bytes,
                )
                session.add(current)

            session.commit()
            logger.debug("Network metrics updated")

        except Exception as e:
            session.rollback()
            logger.error(f"Failed to update network metrics: {e}")
        finally:
            session.close()

    def update_top_talkers(self, network_id: int,
                            top_talkers: list[dict]) -> None:
        """Replace current top talkers with new rankings.

        Deletes all existing entries and inserts the new ranking.
        Done in a single transaction for consistency.
        """
        session = self._get_session()
        try:
            session.query(TopTalkerCurrent).filter_by(
                network_id=network_id
            ).delete()

            for talker in top_talkers:
                device = session.query(Device).filter_by(
                    ip=talker["ip"]
                ).first()

                if device:
                    entry = TopTalkerCurrent(
                        network_id=network_id,
                        device_id=device.id,
                        total_consumption=talker["total_consumption"],
                        rank=talker["rank"],
                        is_hog=talker["is_hog"],
                    )
                    session.add(entry)

            session.commit()
            logger.debug(f"Top talkers updated: {len(top_talkers)} entries")

        except Exception as e:
            session.rollback()
            logger.error(f"Failed to update top talkers: {e}")
        finally:
            session.close()