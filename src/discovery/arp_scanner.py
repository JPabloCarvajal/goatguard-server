"""
ARP-based network device discovery for GOATGuard server.

Periodically scans the local network segment by sending ARP
requests to all addresses in the subnet. Devices that respond
are registered in the inventory with has_agent=false if they
don't already have an agent registered.

ARP (Address Resolution Protocol, RFC 826) operates at OSI
Layer 2 (Data Link). An ARP Request is a broadcast frame
(destination MAC FF:FF:FF:FF:FF:FF) that asks "who has IP
X.X.X.X? Tell me your MAC address." Each device with that
IP responds with its MAC. This only works within the same
broadcast domain (LAN segment) — ARP does not cross routers.

Requirements: Dynamic device inventory (RF-011)
OSI layers:   L2 (Ethernet broadcast, MAC addresses)
"""

import logging
import threading
import time

from scapy.all import arping

logger = logging.getLogger(__name__)

class ArpScanner:
    """Discovers devices on the LAN via periodic ARP scans.

    Sends ARP requests to all IPs in the configured subnet and
    registers discovered devices in the database. Devices already
    registered (by IP or MAC) are updated with last_seen timestamp.
    New devices are created with has_agent=false.

    Args:
        repository: Database repository for device registration.
        network_id: ID of the monitored network.
        subnet: Network range to scan in CIDR notation (e.g. "192.168.1.0/24").
        interval: Seconds between scans.
        timeout: Seconds to wait for ARP replies.
    """

    def __init__(self, repository, network_id: int,
                 subnet: str = "192.168.1.0/24",
                 interval: int = 60, timeout: int = 3) -> None:
        self.repo = repository
        self.network_id = network_id
        self.subnet = subnet
        self.interval = interval
        self.timeout = timeout
        self._running = False

    def start(self) -> None:
        """Start the ARP scanner in a background thread."""
        self._running = True
        thread = threading.Thread(target=self._scan_loop, daemon=True)
        thread.start()
        logger.info(
            f"ARP Scanner started: subnet={self.subnet}, "
            f"interval={self.interval}s"
        )

    def _scan_loop(self) -> None:
        """Periodically scan the network."""
        while self._running:
            try:
                self._run_scan()
            except Exception as e:
                logger.error(f"ARP scan error: {e}")

            time.sleep(self.interval)

    def _run_scan(self) -> None:
        """Execute a single ARP scan and register discovered devices."""
        logger.info(f"Scanning {self.subnet}...")

        ans, _ = arping(self.subnet, timeout=self.timeout, verbose=False)

        discovered = []
        seen_macs = []

        for sent, received in ans:
            mac = received.hwsrc.upper()
            device_info = {
                "ip": received.psrc,
                "mac": mac,
            }
            discovered.append(device_info)
            seen_macs.append(mac)

        logger.info(f"ARP scan found {len(discovered)} devices")

        for device_info in discovered:
            self.repo.register_discovered_device(
                network_id=self.network_id,
                ip=device_info["ip"],
                mac=device_info["mac"],
            )

        # Mark devices not found in this scan as inactive
        if seen_macs:
            inactive_count = self.repo.mark_unseen_devices_inactive(
                network_id=self.network_id,
                seen_macs=seen_macs,
            )
            if inactive_count > 0:
                logger.warning(f"Marked {inactive_count} devices as inactive (not found by ARP)")

    def stop(self) -> None:
        """Stop the ARP scanner."""
        self._running = False
        logger.info("ARP Scanner stopped")