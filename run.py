"""Entry point for GOATGuard server."""

import sys
import logging
import time

sys.path.insert(0, ".")

from src.config import load_config, ConfigError
from src.receivers.tcp_receiver import TcpReceiver
from src.ingestion.pcap_assembler import PcapAssembler

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

def main():
    try:
        config = load_config()
    except ConfigError as e:
        print(f"[CONFIG ERROR] {e}")
        sys.exit(1)

    def on_pcap_ready(path):
        print(f"\n  >>> PCAP READY: {path}\n")

    assembler = PcapAssembler(
        output_dir=config.pcap.output_dir,
        rotation_seconds=config.pcap.rotation_seconds,
        on_rotation=on_pcap_ready,
    )

    receiver = TcpReceiver(
        host=config.server.host,
        port=config.server.tcp_port,
        on_packet=assembler.write_packet,
    )
    receiver.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        receiver.stop()
        assembler.close()


if __name__ == "__main__":
    main()