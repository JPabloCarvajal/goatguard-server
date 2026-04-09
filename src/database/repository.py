"""
Database repository for GOATGuard server.

Encapsulates all database operations behind simple methods.
Other modules never write SQL directly — they call repository
methods. This isolates the database logic and makes it easy
to change queries without touching the rest of the system.
"""

import logging
from datetime import datetime, timezone
from src.discovery.enrichment import enrich_device_vendor

from src.database.models import (
    Agent,
    Device,
    DeviceCurrentMetrics,
    Network,
    NetworkCurrentMetrics,
    PushToken,
    TopTalkerCurrent,
)

from src.database.models import (
    EndpointSnapshot,
    NetworkSnapshot,
    TopTalker,
    RecentConnection
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
        If an agent with this UID exists, updates its timestamps.
        If not, checks if ARP already discovered a device with the
        same MAC and reuses it instead of creating a duplicate.

        Args:
            agent_id: The unique agent identifier (HOSTNAME__MAC).
            sender_ip: The IP address the agent is sending from.
            network_id: The network this agent belongs to.

        Returns:
            The device_id associated with this agent.
        """
        session = self._get_session()
        try:
            # Check if agent already exists by UID
            agent = session.query(Agent).filter_by(uid=agent_id).first()

            if agent:
                agent.last_heartbeat = datetime.now(timezone.utc)
                agent.device.last_seen = datetime.now(timezone.utc)
                agent.device.ip = sender_ip
                session.commit()
                return agent.device_id

            # Parse agent_id: "HOSTNAME__MAC"
            parts = agent_id.split("__")
            hostname = parts[0] if len(parts) >= 1 else "unknown"
            mac = parts[1] if len(parts) >= 2 else "00:00:00:00:00:00"
            mac = mac.upper()

            # Check if ARP already discovered this device by MAC
            device = session.query(Device).filter_by(mac=mac).first()

            if device:
                # ARP found it first — upgrade to has_agent=true
                device.ip = sender_ip
                device.hostname = hostname
                device.has_agent = True
                device.status = "active"
                device.last_seen = datetime.now(timezone.utc)
            else:
                # Completely new device
                device = Device(
                    network_id=network_id,
                    ip=sender_ip,
                    mac=mac,
                    hostname=hostname,
                    has_agent=True,
                    status="active",
                )
                session.add(device)

            session.flush()

            # Create the agent record
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

            now = datetime.now(timezone.utc)

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
                                external_traffic_bytes: int,
                                dns_response_time_avg: float = None) -> None:
        """Update network-wide metrics via UPSERT."""
        session = self._get_session()
        try:
            current = session.query(NetworkCurrentMetrics).filter_by(
                network_id=network_id
            ).first()

            now = datetime.now(timezone.utc)

            if current:
                current.timestamp = now
                current.active_connections = active_connections
                current.new_connections_per_min = new_connections_per_min
                current.failed_connections_global = failed_connections_global
                current.internal_traffic_bytes = internal_traffic_bytes
                current.external_traffic_bytes = external_traffic_bytes
                if dns_response_time_avg is not None:
                    current.dns_response_time_avg = dns_response_time_avg
            else:
                current = NetworkCurrentMetrics(
                    network_id=network_id,
                    timestamp=now,
                    active_connections=active_connections,
                    new_connections_per_min=new_connections_per_min,
                    failed_connections_global=failed_connections_global,
                    internal_traffic_bytes=internal_traffic_bytes,
                    external_traffic_bytes=external_traffic_bytes,
                    dns_response_time_avg=dns_response_time_avg,
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


    def mark_inactive_agents(self, cutoff: datetime) -> int:
        """Mark agents with last_heartbeat before cutoff as inactive.

        Also updates the associated device status to "disconnected".

        Args:
            cutoff: Datetime threshold. Agents with last_heartbeat
                    before this time are marked inactive.

        Returns:
            Number of agents marked as inactive.
        """
        session = self._get_session()
        try:
            stale_agents = session.query(Agent).filter(
                Agent.status == "active",
                Agent.last_heartbeat < cutoff,
            ).all()

            for agent in stale_agents:
                agent.status = "inactive"
                if agent.device:
                    agent.device.status = "disconnected"
                logger.info(
                    f"Agent marked inactive: {agent.uid} "
                    f"(last heartbeat: {agent.last_heartbeat})"
                )

            session.commit()
            return len(stale_agents)

        except Exception as e:
            session.rollback()
            logger.error(f"Failed to mark inactive agents: {e}")
            return 0
        finally:
            session.close()

    def update_heartbeat(self, agent_id: str) -> None:
        """Update the last heartbeat timestamp for an agent."""
        session = self._get_session()
        try:
            agent = session.query(Agent).filter_by(uid=agent_id).first()
            if agent:
                agent.last_heartbeat = datetime.now(timezone.utc)
                agent.status = "active"
                if agent.device:
                    agent.device.status = "active"
                    agent.device.last_seen = datetime.now(timezone.utc)
                session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to update heartbeat for {agent_id}: {e}")
        finally:
            session.close()

    def update_isp_metrics(self, network_id: int, latency_avg: float,
                            packet_loss_pct: float, jitter: float) -> None:
        """Update ISP health metrics in network_current_metrics.

        Args:
            network_id: The network to update.
            latency_avg: Average ping RTT in milliseconds.
            packet_loss_pct: Percentage of lost pings.
            jitter: Standard deviation of RTTs in milliseconds.
        """
        session = self._get_session()
        try:
            current = session.query(NetworkCurrentMetrics).filter_by(
                network_id=network_id
            ).first()

            now = datetime.now(timezone.utc)

            if current:
                current.timestamp = now
                current.isp_latency_avg = latency_avg
                current.packet_loss_pct = packet_loss_pct
                current.jitter = jitter
            else:
                current = NetworkCurrentMetrics(
                    network_id=network_id,
                    timestamp=now,
                    isp_latency_avg=latency_avg,
                    packet_loss_pct=packet_loss_pct,
                    jitter=jitter,
                )
                session.add(current)

            session.commit()
            logger.debug("ISP metrics updated")

        except Exception as e:
            session.rollback()
            logger.error(f"Failed to update ISP metrics: {e}")
        finally:
            session.close()

    def register_discovered_device(self, network_id: int,
                                    ip: str, mac: str) -> None:
        """Register a device found via ARP scan.

        If the device already exists (matched by MAC), updates its
        IP and last_seen. If it's new, creates it with has_agent=false.

        Matching by MAC instead of IP because IPs can change via DHCP
        but MACs are tied to hardware (Layer 2 identifier).

        Args:
            network_id: The network where the device was found.
            ip: IPv4 address of the discovered device.
            mac: MAC address (normalized uppercase, colon-separated).
        """
        session = self._get_session()
        try:
            # Normalize MAC format
            mac_normalized = mac.replace("-", ":").upper()

            # Search by MAC (stable hardware identifier)
            device = session.query(Device).filter_by(mac=mac_normalized).first()

            if device:
                device.ip = ip
                device.last_seen = datetime.now(timezone.utc)
                if not device.has_agent:
                    device.status = "active"
                if not device.detected_type:
                    device.detected_type = enrich_device_vendor(mac_normalized)
                session.commit()
                return

            # New device — register without agent
            vendor = enrich_device_vendor(mac_normalized)

            device = Device(
                network_id=network_id,
                ip=ip,
                mac=mac_normalized,
                has_agent=False,
                status="active",
                detected_type=vendor,
            )

            session.add(device)
            session.commit()

            logger.info(
                f"New device discovered via ARP: {ip} ({mac_normalized})"
            )

        except Exception as e:
            session.rollback()
            logger.error(f"Failed to register discovered device {ip}: {e}")
        finally:
            session.close()

    def mark_unseen_devices_inactive(self, network_id: int,
                                      seen_macs: list[str]) -> int:
        """Mark devices without agent that were NOT found by ARP as inactive.

        Args:
            network_id: The network that was scanned.
            seen_macs: List of MAC addresses found in the latest scan.

        Returns:
            Number of devices marked inactive.
        """
        session = self._get_session()
        try:
            stale = session.query(Device).filter(
                Device.network_id == network_id,
                Device.has_agent.is_(False),
                Device.status == "active",
                ~Device.mac.in_(seen_macs),
            ).all()

            for device in stale:
                device.status = "inactive"
                logger.info(f"Device no longer on network: {device.ip} ({device.mac})")

            session.commit()
            return len(stale)

        except Exception as e:
            session.rollback()
            logger.error(f"Failed to mark unseen devices: {e}")
            return 0
        finally:
            session.close()

    def save_endpoint_snapshot(self, device_id: int, network_snapshot_id: int,
                                metrics: dict) -> None:
        """Save a historical snapshot of endpoint metrics.

        Merges traffic metrics from Zeek analysis with system
        metrics from UDP (CPU, RAM, disk) stored in
        device_current_metrics.
        """
        session = self._get_session()
        try:
            # Read current system metrics from UDP data
            current = session.query(DeviceCurrentMetrics).filter_by(
                device_id=device_id
            ).first()

            snapshot = EndpointSnapshot(
                device_id=device_id,
                network_snapshot_id=network_snapshot_id,
                timestamp=datetime.now(timezone.utc),
                # System metrics from UDP (device_current_metrics)
                cpu_pct=current.cpu_pct if current else None,
                ram_pct=current.ram_pct if current else None,
                disk_usage_pct=current.disk_usage_pct if current else None,
                link_speed=current.link_speed if current else None,
                cpu_count=current.cpu_count if current else None,
                ram_total_bytes=current.ram_total_bytes if current else None,
                ram_available_bytes=current.ram_available_bytes if current else None,
                uptime_seconds=current.uptime_seconds if current else None,
                # Traffic metrics from Zeek analysis
                bandwidth_in=metrics.get("bandwidth_in"),
                bandwidth_out=metrics.get("bandwidth_out"),
                tcp_retransmissions=metrics.get("tcp_retransmissions", 0),
                failed_connections=metrics.get("failed_connections", 0),
                unique_destinations=metrics.get("unique_destinations"),
                bytes_ratio=metrics.get("bytes_ratio"),
                dns_response_time=metrics.get("dns_response_time"),
            )
            session.add(snapshot)
            session.commit()
            logger.debug(f"Endpoint snapshot saved for device {device_id}")

        except Exception as e:
            session.rollback()
            logger.error(f"Failed to save endpoint snapshot: {e}")
        finally:
            session.close()
    
    def save_network_snapshot(self, network_id: int, metrics: dict) -> int:
        """Save a historical snapshot of network-wide metrics.

        Merges traffic metrics from Zeek analysis with ISP
        metrics from the ISP Probe stored in
        network_current_metrics.

        Returns the snapshot ID for endpoint snapshot references.
        """
        session = self._get_session()
        try:
            # Read current ISP metrics from probe data
            current = session.query(NetworkCurrentMetrics).filter_by(
                network_id=network_id
            ).first()

            snapshot = NetworkSnapshot(
                network_id=network_id,
                timestamp=datetime.now(timezone.utc),
                # ISP metrics from probe (network_current_metrics)
                isp_latency_avg=current.isp_latency_avg if current else None,
                packet_loss_pct=current.packet_loss_pct if current else None,
                jitter=current.jitter if current else None,
                dns_response_time_avg=current.dns_response_time_avg if current else None,
                # Traffic metrics from Zeek analysis
                failed_connections_global=metrics.get("failed_connections_global", 0),
                active_connections=metrics.get("active_connections"),
                new_connections_per_min=metrics.get("new_connections_per_min"),
                internal_traffic_bytes=metrics.get("internal_traffic_bytes"),
                external_traffic_bytes=metrics.get("external_traffic_bytes"),
            )
            session.add(snapshot)
            session.commit()
            session.refresh(snapshot)

            logger.debug(f"Network snapshot saved: id={snapshot.id}")
            return snapshot.id

        except Exception as e:
            session.rollback()
            logger.error(f"Failed to save network snapshot: {e}")
            return -1
        finally:
            session.close()


    def save_top_talker_snapshot(self, network_snapshot_id: int,
                                  top_talkers: list[dict]) -> None:
        """Save historical top talker ranking.

        Args:
            network_snapshot_id: The parent network snapshot.
            top_talkers: List of talker dicts with ip, total, rank, is_hog.
        """
        session = self._get_session()
        try:
            for talker in top_talkers:
                device = session.query(Device).filter_by(
                    ip=talker["ip"]
                ).first()

                if device:
                    entry = TopTalker(
                        network_snapshot_id=network_snapshot_id,
                        device_id=device.id,
                        total_consumption=talker["total_consumption"],
                        rank=talker["rank"],
                        is_hog=talker["is_hog"],
                    )
                    session.add(entry)

            session.commit()
            logger.debug(f"Top talker snapshot saved: {len(top_talkers)} entries")

        except Exception as e:
            session.rollback()
            logger.error(f"Failed to save top talker snapshot: {e}")
        finally:
            session.close()

    def save_recent_connections(self, connections: list[dict]) -> None:
        """Save resolved external connections per device.

        Replaces all existing entries each cycle. Groups connections
        by (device_ip, dst_ip, dst_port, proto) and aggregates
        bytes and connection count.

        Args:
            connections: Enriched connection dicts from the pipeline.
        """
        session = self._get_session()
        try:
            # Clear previous cycle
            session.query(RecentConnection).delete()

            # Group by device → destination
            from collections import defaultdict
            grouped = defaultdict(lambda: {
                "total_bytes": 0,
                "count": 0,
                "dst_hostname": None,
                "proto": "tcp",
            })

            for conn in connections:
                src_ip = conn.get("src_ip")
                dst_ip = conn.get("dst_ip")
                dst_port = conn.get("dst_port", 0)
                proto = conn.get("proto", "tcp")
                dst_hostname = conn.get("dst_hostname")

                if not src_ip or not dst_ip:
                    continue

                # Skip internal-only traffic
                if self._is_local(src_ip) and self._is_local(dst_ip):
                    continue

                # Only track outbound from local devices
                if not self._is_local(src_ip):
                    continue

                key = (src_ip, dst_ip, dst_port, proto)
                grouped[key]["total_bytes"] += conn.get("orig_bytes", 0) + conn.get("resp_bytes", 0)
                grouped[key]["count"] += 1
                grouped[key]["proto"] = proto
                if dst_hostname:
                    grouped[key]["dst_hostname"] = dst_hostname

            # Save grouped connections
            for (src_ip, dst_ip, dst_port, proto), data in grouped.items():
                device = session.query(Device).filter_by(ip=src_ip).first()
                if not device:
                    continue

                entry = RecentConnection(
                    device_id=device.id,
                    dst_ip=dst_ip,
                    dst_hostname=data["dst_hostname"],
                    dst_port=dst_port,
                    proto=data["proto"],
                    total_bytes=data["total_bytes"],
                    connection_count=data["count"],
                    last_seen=datetime.now(timezone.utc),
                )
                session.add(entry)

            session.commit()
            logger.debug(f"Recent connections saved: {len(grouped)} entries")

        except Exception as e:
            session.rollback()
            logger.error(f"Failed to save recent connections: {e}")
        finally:
            session.close()

    # ── Push token operations ──────────────────────────────────

    def upsert_push_token(self, user_id: int, token: str,
                          platform: str = "android") -> None:
        """Register or update an FCM push token for a user.

        If the token already exists for this user, updates the
        timestamp. If it belongs to another user (device changed
        accounts), reassigns it. Otherwise creates a new record.
        """
        session = self._get_session()
        try:
            existing = session.query(PushToken).filter_by(token=token).first()

            if existing:
                existing.user_id = user_id
                existing.platform = platform
                existing.created_at = datetime.now(timezone.utc)
            else:
                entry = PushToken(
                    user_id=user_id,
                    token=token,
                    platform=platform,
                )
                session.add(entry)

            session.commit()
            logger.info(f"Push token registered for user {user_id} ({platform})")

        except Exception as e:
            session.rollback()
            logger.error(f"Failed to upsert push token: {e}")
        finally:
            session.close()

    def delete_push_token(self, token: str) -> None:
        """Remove an FCM token (used on logout or when token is invalid)."""
        session = self._get_session()
        try:
            session.query(PushToken).filter_by(token=token).delete()
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to delete push token: {e}")
        finally:
            session.close()

    def get_all_push_tokens(self) -> list[str]:
        """Return all registered FCM tokens for broadcast."""
        session = self._get_session()
        try:
            tokens = session.query(PushToken.token).all()
            return [t[0] for t in tokens]
        except Exception as e:
            logger.error(f"Failed to fetch push tokens: {e}")
            return []
        finally:
            session.close()

    def delete_push_tokens_batch(self, tokens: list[str]) -> None:
        """Remove multiple invalid FCM tokens in one transaction."""
        if not tokens:
            return
        session = self._get_session()
        try:
            session.query(PushToken).filter(
                PushToken.token.in_(tokens)
            ).delete(synchronize_session="fetch")
            session.commit()
            logger.info(f"Removed {len(tokens)} invalid push tokens")
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to batch-delete push tokens: {e}")
        finally:
            session.close()

    @staticmethod
    def _is_local(ip: str) -> bool:
        """Check if IP is private (RFC 1918)."""
        return (
            ip.startswith("192.168.") or
            ip.startswith("10.") or
            ip.startswith("172.16.") or
            ip.startswith("172.17.") or
            ip.startswith("172.18.") or
            ip.startswith("172.19.") or
            ip.startswith("172.2") or
            ip.startswith("172.30.") or
            ip.startswith("172.31.") or
            ip.startswith("fe80:")
        )