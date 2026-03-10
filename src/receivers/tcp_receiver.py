"""
TCP receiver for sanitized packet data from GOATGuard agents.

Listens on a TCP port and spawns a dedicated thread for each
agent that connects (Thread-per-Client pattern). Each thread
reads packets using the binary length-prefix protocol defined
in the agent's TcpSender.

Wire protocol (per packet, all big-endian):
    [4 bytes: orig_len   ] uint32
    [4 bytes: dst_port   ] uint32
    [8 bytes: timestamp  ] float64
    [4 bytes: data_len   ] uint32
    [N bytes: packet data] raw bytes

Requirements: RF-005 (receive traffic from agents via TCP)
"""

import logging
import socket
import struct
import threading
from typing import Callable, Optional

logger = logging.getLogger(__name__)

HEADER_FORMAT = '! I I d I'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

class ReceivedPacket:
    """A packet received from an agent, parsed from the wire protocol.

    Attributes:
        orig_len: Original packet size before sanitization.
        dst_port: Destination port from the TCP/UDP header.
        timestamp: Capture time as Unix epoch float.
        data: The truncated packet bytes.
        agent_addr: Tuple (ip, port) identifying which agent sent this.
    """

    __slots__ = ['orig_len', 'dst_port', 'timestamp', 'data', 'agent_addr']

    def __init__(self, orig_len: int, dst_port: int, timestamp: float,
                 data: bytes, agent_addr: tuple) -> None:
        self.orig_len = orig_len
        self.dst_port = dst_port
        self.timestamp = timestamp
        self.data = data
        self.agent_addr = agent_addr

def _recv_exact(sock: socket.socket, num_bytes: int) -> Optional[bytes]:
    """Read exactly num_bytes from a socket.

    socket.recv() may return fewer bytes than requested if the
    kernel buffer has less available. This function loops until
    all requested bytes are received or the connection drops.

    Args:
        sock: Connected TCP socket.
        num_bytes: Exact number of bytes to read.

    Returns:
        The complete bytes read, or None if the connection closed.
    """
    chunks = []
    received = 0
    while received < num_bytes:
        chunk = sock.recv(num_bytes - received)
        if not chunk:
            return None
        chunks.append(chunk)
        received += len(chunk)
    return b''.join(chunks)

class TcpReceiver:
    """Multi-client TCP server that receives sanitized packets.

    Spawns a new thread for each agent connection (Thread-per-Client).
    Each thread reads the binary length-prefix protocol and forwards
    parsed packets to a callback function.

    Args:
        host: Bind address ("0.0.0.0" for all interfaces).
        port: TCP port to listen on.
        on_packet: Callback invoked for each received packet.
    """

    def __init__(self, host: str, port: int, on_packet: Callable) -> None:
        self.host = host
        self.port = port
        self.on_packet = on_packet
        self._server_sock: Optional[socket.socket] = None
        self._running = False

    def start(self) -> None:

        """Start the TCP server in a background thread."""
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen(20)
        self._server_sock.settimeout(1.0)
        self._running = True

        accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        accept_thread.start()

        logger.info(f"TCP Receiver listening on {self.host}:{self.port}")
    
    def _accept_loop(self) -> None:
        """Accept incoming agent connections in a loop.

        For each new connection, spawns a dedicated thread that
        handles that specific agent (Thread-per-Client pattern).
        The 1-second timeout allows periodic checking of _running
        for clean shutdown.
        """
        while self._running:
            try:
                client_sock, addr = self._server_sock.accept()
                logger.info(f"Agent connected: {addr[0]}:{addr[1]}")

                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, addr),
                    daemon=True,
                )
                client_thread.start()

            except socket.timeout:
                continue
            except OSError as e:
                if self._running:
                    logger.error(f"Accept error: {e}")
    
    def _handle_client(self, client_sock: socket.socket, addr: tuple) -> None:
        """Handle a single agent connection.

        Reads packets continuously using the binary length-prefix
        protocol until the agent disconnects or an error occurs.
        Each parsed packet is forwarded to self.on_packet callback.

        Args:
            client_sock: The connected socket for this agent.
            addr: Tuple (ip, port) of the agent.
        """
        packet_count = 0
        try:
            while self._running:
                # Step 1: Read the 20-byte header
                header_data = _recv_exact(client_sock, HEADER_SIZE)
                if header_data is None:
                    break

                # Step 2: Unpack the four fields
                orig_len, dst_port, timestamp, data_len = struct.unpack(
                    HEADER_FORMAT, header_data
                )

                # Step 3: Read exactly data_len bytes of packet data
                packet_data = _recv_exact(client_sock, data_len)
                if packet_data is None:
                    break

                # Step 4: Build the ReceivedPacket and forward it
                packet = ReceivedPacket(
                    orig_len=orig_len,
                    dst_port=dst_port,
                    timestamp=timestamp,
                    data=packet_data,
                    agent_addr=addr,
                )
                self.on_packet(packet)
                packet_count += 1

        except OSError as e:
            logger.error(f"Error reading from {addr[0]}:{addr[1]}: {e}")

        finally:
            client_sock.close()
            logger.info(
                f"Agent disconnected: {addr[0]}:{addr[1]} "
                f"({packet_count} packets received)"
            )
            
    def stop(self) -> None:
        """Shut down the TCP server."""
        self._running = False
        if self._server_sock:
            self._server_sock.close()
        logger.info("TCP Receiver stopped")