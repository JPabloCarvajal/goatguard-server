"""
Analysis pipeline for GOATGuard server.

Orchestrates the full processing chain when a PCAP file
is rotated: runs Zeek, parses the logs, calculates metrics,
and persists results to PostgreSQL.

This module connects the analysis components without containing
analysis logic itself (Mediator pattern, same as main.py in
the agent).
"""
import logging
from pathlib import Path

from src.analysis.zeek_runner import ZeekRunner
from src.analysis.log_parser import parse_conn_log, parse_dns_log
from src.discovery.enrichment import enrich_connections
from src.analysis.metrics_calculator import (
    calculate_device_metrics,
    calculate_network_metrics,
    calculate_top_talkers,
)

logger = logging.getLogger(__name__)
    
class AnalysisPipeline:
    """Processes rotated PCAP files through the full analysis chain.

    Each call to process() runs the complete pipeline:
    1. Zeek analyzes the PCAP file
    2. Log parser extracts structured data
    3. Metrics calculator computes per-device and network metrics
    4. Results are passed to the repository for persistence

    Args:
        zeek_runner: ZeekRunner instance for PCAP processing.
        repository: Database repository for persisting results.
        network_id: ID of the monitored network in the database.
        rotation_seconds: PCAP rotation interval (for rate calculations).
    """

    def __init__(self, zeek_runner: ZeekRunner, repository,
                 network_id: int, rotation_seconds: int = 30) -> None:
        self.zeek = zeek_runner
        self.repo = repository
        self.network_id = network_id
        self.rotation_seconds = rotation_seconds
    
    def process(self, pcap_path: str) -> None:
        """Run the full analysis pipeline on a PCAP file.

        Args:
            pcap_path: Path to the rotated PCAP file.
        """
        try:
            # Step 1: Run Zeek
            log_dir = self.zeek.process_pcap(pcap_path)

            # Step 2: Parse logs
            connections = parse_conn_log(log_dir)
            dns_queries = parse_dns_log(log_dir)
            # Step 2.5: Enrich external IPs with hostnames
            connections = enrich_connections(connections)

            if not connections:
                logger.info(f"No connections in {pcap_path}, skipping")
                return

            # Step 3: Calculate metrics
            device_metrics = calculate_device_metrics(
                connections, self.rotation_seconds
            )
            network_metrics = calculate_network_metrics(
                connections, self.rotation_seconds
            )
            top_talkers = calculate_top_talkers(device_metrics)

            # Step 4: Calculate DNS response times per device
            dns_metrics = self._calculate_dns_metrics(dns_queries)

            # Step 5: Persist to database
            self._save_device_metrics(device_metrics, dns_metrics)
            self._save_network_metrics(network_metrics, dns_metrics)
            self._save_top_talkers(top_talkers)

            # Step 6: Save historical snapshots
            self._save_snapshots(
                device_metrics, dns_metrics,
                network_metrics, top_talkers,
            )

            # Step 7: Save recent connections with resolved hostnames
            self.repo.save_recent_connections(connections)

            logger.info(
                f"Pipeline complete for {Path(pcap_path).name}: "
                f"{len(connections)} connections, "
                f"{len(device_metrics)} devices, "
                f"{len(dns_queries)} DNS queries"
            )

        except Exception as e:
            logger.error(f"Pipeline failed for {pcap_path}: {e}")
    
    def _save_snapshots(self, device_metrics: dict, dns_metrics: dict,
                         network_metrics: dict, top_talkers: list[dict]) -> None:
        """Save historical snapshots for trend graphs.

        Creates a network snapshot first (to get its ID), then
        creates endpoint snapshots referencing it, and finally
        saves the top talker ranking for this cycle.
        """
        # Network snapshot (returns its ID)
        snapshot_id = self.repo.save_network_snapshot(
            network_id=self.network_id,
            metrics=network_metrics,
        )

        if snapshot_id == -1:
            return

        # Endpoint snapshots for each device with metrics
        for ip, metrics in device_metrics.items():
            if not ip.startswith("192.168.") and not ip.startswith("10."):
                continue

            dns_rt = dns_metrics.get(ip, 0.0)
            metrics["dns_response_time"] = dns_rt

            # Find device_id by IP
            session = self.repo._get_session()
            try:
                from src.database.models import Device
                device = session.query(Device).filter_by(ip=ip).first()
                if device:
                    self.repo.save_endpoint_snapshot(
                        device_id=device.id,
                        network_snapshot_id=snapshot_id,
                        metrics=metrics,
                    )
            finally:
                session.close()

        # Top talker snapshot
        self.repo.save_top_talker_snapshot(
            network_snapshot_id=snapshot_id,
            top_talkers=top_talkers,
        )
    
    def _calculate_dns_metrics(self, dns_queries: list[dict]) -> dict:
        """Calculate average DNS response time per device.

        Args:
            dns_queries: Parsed DNS query records.

        Returns:
            Dict mapping device IP to average RTT in milliseconds.
        """
        from collections import defaultdict

        rtt_sums = defaultdict(lambda: {"total": 0.0, "count": 0})

        for query in dns_queries:
            src_ip = query.get("src_ip")
            rtt = query.get("rtt", 0.0)

            if src_ip and rtt > 0:
                rtt_sums[src_ip]["total"] += rtt
                rtt_sums[src_ip]["count"] += 1

        result = {}
        for ip, data in rtt_sums.items():
            if data["count"] > 0:
                avg_ms = (data["total"] / data["count"]) * 1000
                result[ip] = avg_ms

        return result
    
    def _save_device_metrics(self, device_metrics: dict,
                              dns_metrics: dict) -> None:
        """Save per-device metrics to the database.

        Only saves metrics for devices that are registered in the
        database (have an agent). Skips unknown IPs.
        """
        for ip, metrics in device_metrics.items():
            # Skip non-local IPs
            if not ip.startswith("192.168.") and not ip.startswith("10."):
                continue

            dns_rt = dns_metrics.get(ip, 0.0)

            self.repo.update_device_traffic_metrics(
                ip=ip,
                bandwidth_in=metrics["bandwidth_in"],
                bandwidth_out=metrics["bandwidth_out"],
                tcp_retransmissions=metrics["tcp_retransmissions"],
                failed_connections=metrics["failed_connections"],
                unique_destinations=metrics["unique_destinations"],
                bytes_ratio=metrics["bytes_ratio"],
                dns_response_time=dns_rt,
            )

    def _save_network_metrics(self, network_metrics: dict,
                               dns_metrics: dict) -> None:
        """Save network-wide metrics to the database."""
        # Calculate network-wide DNS response time average
        if dns_metrics:
            dns_values = [v for v in dns_metrics.values() if v > 0]
            dns_avg = sum(dns_values) / len(dns_values) if dns_values else None
        else:
            dns_avg = None

        self.repo.update_network_metrics(
            network_id=self.network_id,
            active_connections=network_metrics["active_connections"],
            new_connections_per_min=network_metrics["new_connections_per_min"],
            failed_connections_global=network_metrics["failed_connections_global"],
            internal_traffic_bytes=network_metrics["internal_traffic_bytes"],
            external_traffic_bytes=network_metrics["external_traffic_bytes"],
            dns_response_time_avg=dns_avg,
        )

    def _save_top_talkers(self, top_talkers: list[dict]) -> None:
        """Save top talker rankings to the database."""
        self.repo.update_top_talkers(
            network_id=self.network_id,
            top_talkers=top_talkers,
        )
