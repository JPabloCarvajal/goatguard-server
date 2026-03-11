"""Entry point for GOATGuard server."""

import sys
import logging
import time

sys.path.insert(0, ".")

from src.config import load_config, ConfigError
from src.database.connection import Database
from src.database.models import Base
from src.database.repository import Repository
from src.receivers.tcp_receiver import TcpReceiver
from src.receivers.udp_receiver import UdpReceiver
from src.ingestion.pcap_assembler import PcapAssembler
from src.analysis.zeek_runner import ZeekRunner
from src.analysis.pipeline import AnalysisPipeline
from src.monitoring.health_checker import HealthChecker

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

def main():
    try:
        config = load_config()
    except ConfigError as e:
        print(f"[CONFIG ERROR] {e}")
        sys.exit(1)

    # Database
    db = Database(
        host=config.database.host,
        port=config.database.port,
        name=config.database.name,
        user=config.database.user,
        password=config.database.password,
    )
    db.create_tables(Base)
    repo = Repository(db.get_session)

    health_checker = HealthChecker(
        repository=repo,
        check_interval=30,
        timeout_seconds=90,
    )
    health_checker.start()

    network_id = repo.ensure_default_network()

    # Analysis pipeline
    zeek = ZeekRunner(output_base_dir="zeek_output")
    pipeline = AnalysisPipeline(
        zeek_runner=zeek,
        repository=repo,
        network_id=network_id,
        rotation_seconds=config.pcap.rotation_seconds,
    )

    # PCAP assembly with pipeline callback
    assembler = PcapAssembler(
        output_dir=config.pcap.output_dir,
        rotation_seconds=config.pcap.rotation_seconds,
        on_rotation=pipeline.process,
    )

    # TCP: captured packets
    tcp_receiver = TcpReceiver(
        host=config.server.host,
        port=config.server.tcp_port,
        on_packet=assembler.write_packet,
    )

    # UDP: metrics and heartbeats
    def on_metrics(data):
        agent_id = data.get("agent_id", "")
        sender_ip = data.get("_sender_ip", "0.0.0.0")
        device_id = repo.get_or_create_agent(agent_id, sender_ip, network_id)
        repo.save_device_metrics(device_id, data)

    def on_heartbeat(data):
        agent_id = data.get("agent_id", "")
        repo.update_heartbeat(agent_id)

    udp_receiver = UdpReceiver(
        host=config.server.host,
        port=config.server.udp_port,
        on_metrics=on_metrics,
        on_heartbeat=on_heartbeat,
    )

    # Start everything
    tcp_receiver.start()
    udp_receiver.start()

    print("\n  GOATGuard Server running. Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        tcp_receiver.stop()
        udp_receiver.stop()
        health_checker.stop()
        assembler.close()


if __name__ == "__main__":
    main()