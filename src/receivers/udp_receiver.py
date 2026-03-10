"""
UDP receiver for system metrics and heartbeat signals from agents.

Listens on a UDP port and deserializes incoming JSON datagrams.
Distinguishes between metric payloads and heartbeat signals using
the presence of a "type" field in the JSON.

UDP is connectionless: unlike the TCP Receiver, no per-client
threads are needed. A single loop receives datagrams from all
agents on the same socket.

Requirements: RF-006 (receive metrics via UDP)
"""

import json
import logging
import socket
import threading
from typing import Callable, Optional

logger = logging.getLogger(__name__)

class UdpReceiver:
    """Receives JSON datagrams from agents via UDP.

    Runs a single listener thread that handles all agents.
    Incoming data is parsed as JSON and routed to the appropriate
    callback based on message type.

    Args:
        host: Bind address.
        port: UDP port to listen on.
        on_metrics: Callback for metric payloads. Receives a dict.
        on_heartbeat: Callback for heartbeat signals. Receives a dict.
    """

    def __init__(self, host: str, port: int,
                 on_metrics: Callable,
                 on_heartbeat: Optional[Callable] = None) -> None:
        self.host = host
        self.port = port
        self.on_metrics = on_metrics
        self.on_heartbeat = on_heartbeat
        self._sock: Optional[socket.socket] = None
        self._running = False

    
    def start(self) -> None:
        """Start the UDP listener in a background thread."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((self.host, self.port))
        self._sock.settimeout(1.0)
        self._running = True

        listener_thread = threading.Thread(target=self._listen_loop, daemon=True)
        listener_thread.start()

        logger.info(f"UDP Receiver listening on {self.host}:{self.port}")
    
    def _listen_loop(self) -> None:
        """Receive and route UDP datagrams in a loop."""
        while self._running:
            try:
                data, addr = self._sock.recvfrom(4096)
                self._process_datagram(data, addr)

            except socket.timeout:
                continue
            except OSError as e:
                if self._running:
                    logger.error(f"UDP receive error: {e}")

    def _process_datagram(self, data: bytes, addr: tuple) -> None:
        """Parse JSON and route to the appropriate callback.

        Args:
            data: Raw bytes of the UDP datagram.
            addr: Tuple (ip, port) of the sender.
        """
        try:
            message = json.loads(data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.warning(f"Invalid datagram from {addr[0]}: {e}")
            return

        if not isinstance(message, dict):
            logger.warning(f"Non-dict datagram from {addr[0]}")
            return

        message["_sender_ip"] = addr[0]

        if message.get("type") == "heartbeat":
            if self.on_heartbeat:
                self.on_heartbeat(message)
                logger.debug(f"Heartbeat from {message.get('agent_id', 'unknown')}")
        else:
            self.on_metrics(message)
            logger.debug(
                f"Metrics from {message.get('agent_id', 'unknown')}: "
                f"CPU={message.get('cpu_percent')}%, "
                f"RAM={message.get('ram_percent')}%"
            )
    
    def stop(self) -> None:
        """Shut down the UDP listener."""
        self._running = False
        if self._sock:
            self._sock.close()
        logger.info("UDP Receiver stopped")