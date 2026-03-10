"""
PCAP file assembler for GOATGuard server.

Receives parsed packets from TCP Receiver threads and writes
them into standard PCAP files. Rotates files based on time
interval (default 30 seconds) so Zeek can process completed
files while new packets keep arriving in a fresh file.

PCAP format (libpcap):
    [Global Header 24 bytes] once at file start
    [Packet Header 16 bytes][Packet Data] repeated per packet

Requirements: RF-006 (PCAP ingestion and rotation)
"""

import logging
import struct
import threading
import time
from pathlib import Path

logger = logging.getLogger(__name__)

# PCAP Global Header format and constants
PCAP_GLOBAL_FORMAT = '! I H H i I I I'
PCAP_MAGIC = 0xA1B2C3D4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_SNAPLEN = 65535
PCAP_NETWORK_ETHERNET = 1

# PCAP Per-Packet Header format
PCAP_PACKET_FORMAT = '! I I I I'

class PcapAssembler:
    """Assembles received packets into rotating PCAP files.

    Thread-safe: multiple TCP Receiver threads can call
    write_packet() simultaneously. A lock protects the
    file handle from concurrent writes.

    Args:
        output_dir: Directory where PCAP files are created.
        rotation_seconds: How often to rotate to a new file.
        on_rotation: Optional callback when a file is completed.
                     Receives the path of the finished file.
    """

    def __init__(self, output_dir: str, rotation_seconds: int,
                 on_rotation=None) -> None:
        self.output_dir = Path(output_dir)
        self.rotation_seconds = rotation_seconds
        self.on_rotation = on_rotation
        self._lock = threading.Lock()
        self._current_file = None
        self._current_path = None
        self._file_start_time = 0.0
        self._packet_count = 0

        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _open_new_file(self) -> None:
        """Create a new PCAP file with global header.

        Filename format: capture_YYYYMMDD_HHMMSS.pcap
        """
        timestamp_str = time.strftime("%Y%m%d_%H%M%S")
        self._current_path = self.output_dir / f"capture_{timestamp_str}.pcap"

        self._current_file = open(self._current_path, "wb")

        global_header = struct.pack(
            PCAP_GLOBAL_FORMAT,
            PCAP_MAGIC,
            PCAP_VERSION_MAJOR,
            PCAP_VERSION_MINOR,
            0,
            0,
            PCAP_SNAPLEN,
            PCAP_NETWORK_ETHERNET,
        )
        self._current_file.write(global_header)

        self._file_start_time = time.time()
        self._packet_count = 0

        logger.info(f"New PCAP file: {self._current_path}")

    def write_packet(self, packet) -> None:
        """Write a received packet to the current PCAP file.

        Thread-safe. Automatically rotates the file when the
        rotation interval has elapsed.

        Args:
            packet: ReceivedPacket from the TCP Receiver.
        """
        with self._lock:
            if self._current_file is None:
                self._open_new_file()

            if self._should_rotate():
                self._rotate()

            ts_sec = int(packet.timestamp)
            ts_usec = int((packet.timestamp - ts_sec) * 1_000_000)

            packet_header = struct.pack(
                PCAP_PACKET_FORMAT,
                ts_sec,
                ts_usec,
                len(packet.data),
                packet.orig_len,
            )

            self._current_file.write(packet_header)
            self._current_file.write(packet.data)
            self._packet_count += 1
    
    def _should_rotate(self) -> bool:
        """Check if the current file should be rotated."""
        elapsed = time.time() - self._file_start_time
        return elapsed >= self.rotation_seconds

    def _rotate(self) -> None:
        """Close current file and open a new one.

        If on_rotation callback is set, calls it with the
        path of the completed file.
        """
        completed_path = self._current_path
        completed_count = self._packet_count

        self._current_file.close()
        logger.info(
            f"PCAP rotated: {completed_path.name} "
            f"({completed_count} packets)"
        )

        self._open_new_file()

        if self.on_rotation:
            self.on_rotation(str(completed_path))
    
    def close(self) -> None:
        """Close the current PCAP file."""
        with self._lock:
            if self._current_file:
                self._current_file.close()
                logger.info(f"PCAP assembler closed: {self._current_path}")

