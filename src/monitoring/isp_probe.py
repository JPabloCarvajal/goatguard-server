"""
ISP health probe for GOATGuard server.

Periodically measures the quality of the internet connection
by sending ICMP echo requests (ping) to a public DNS server
(8.8.8.8 by default). From the responses, calculates three
key indicators of ISP health:

    - Latency (avg round-trip time in milliseconds)
    - Packet Loss (percentage of lost pings)
    - Jitter (variation in latency, measured as standard deviation)

These metrics fill the isp_latency_avg, packet_loss_pct, and
jitter fields in network_current_metrics.

ICMP operates at OSI Layer 3 (Network), defined in RFC 792.
Unlike TCP/UDP, it does not use ports. Ping sends an Echo
Request (type 8) and expects an Echo Reply (type 0).

Requirements: ISP health monitoring for the network dashboard
"""

import logging
import math
import threading
import time

from pythonping import ping

logger = logging.getLogger(__name__)

def _measure_isp_health(target: str = "8.8.8.8",
                         count: int = 10,
                         timeout: int = 2) -> dict:
    """Send pings and calculate latency, packet loss, and jitter.

    Sends 'count' ICMP echo requests and analyzes the responses.
    Jitter is calculated as the standard deviation of the round-trip
    times, which measures how much the latency varies between pings.
    High jitter indicates an unstable connection even if average
    latency is acceptable.

    Args:
        target: IP address to ping.
        count: Number of pings to send.
        timeout: Seconds to wait for each reply.

    Returns:
        Dictionary with latency_avg, packet_loss_pct, and jitter.
        All values in milliseconds except packet_loss which is percentage.
    """
    try:
        response = ping(target, count=count, timeout=timeout)

        rtts = []
        lost = 0

        for reply in response:
            if reply.success:
                rtts.append(reply.time_elapsed_ms)
            else:
                lost += 1

        packet_loss_pct = (lost / count) * 100

        if not rtts:
            # All pings failed — total connectivity loss
            return {
                "latency_avg": 0.0,
                "packet_loss_pct": 100.0,
                "jitter": 0.0,
            }

        latency_avg = sum(rtts) / len(rtts)

        # Jitter = standard deviation of RTTs
        # Formula: sqrt( sum((xi - mean)^2) / n )
        if len(rtts) > 1:
            variance = sum((rtt - latency_avg) ** 2 for rtt in rtts) / len(rtts)
            jitter = math.sqrt(variance)
        else:
            jitter = 0.0

        return {
            "latency_avg": round(latency_avg, 2),
            "packet_loss_pct": round(packet_loss_pct, 2),
            "jitter": round(jitter, 2),
        }

    except Exception as e:
        logger.error(f"ISP probe failed: {e}")
        return {
            "latency_avg": 0.0,
            "packet_loss_pct": 100.0,
            "jitter": 0.0,
        }

class IspProbe:
    """Periodically measures ISP health and persists results.

    Runs in a background thread, sending pings at regular intervals
    and updating network_current_metrics in PostgreSQL.

    Args:
        repository: Database repository for persisting results.
        network_id: ID of the monitored network.
        target: IP address to ping (default: 8.8.8.8).
        interval: Seconds between measurements.
        ping_count: Number of pings per measurement.
    """

    def __init__(self, repository, network_id: int,
                 target: str = "8.8.8.8", interval: int = 30,
                 ping_count: int = 10) -> None:
        self.repo = repository
        self.network_id = network_id
        self.target = target
        self.interval = interval
        self.ping_count = ping_count
        self._running = False

    def start(self) -> None:
        """Start the ISP probe in a background thread."""
        self._running = True
        thread = threading.Thread(target=self._probe_loop, daemon=True)
        thread.start()
        logger.info(
            f"ISP Probe started: target={self.target}, "
            f"interval={self.interval}s, count={self.ping_count}"
        )

    def _probe_loop(self) -> None:
        """Periodically measure and persist ISP health."""
        while self._running:
            metrics = _measure_isp_health(
                target=self.target,
                count=self.ping_count,
            )

            logger.info(
                f"ISP Health: latency={metrics['latency_avg']}ms, "
                f"loss={metrics['packet_loss_pct']}%, "
                f"jitter={metrics['jitter']}ms"
            )

            self.repo.update_isp_metrics(
                network_id=self.network_id,
                latency_avg=metrics["latency_avg"],
                packet_loss_pct=metrics["packet_loss_pct"],
                jitter=metrics["jitter"],
            )

            time.sleep(self.interval)

    def stop(self) -> None:
        """Stop the ISP probe."""
        self._running = False
        logger.info("ISP Probe stopped")