"""
Anomaly detection engine for GOATGuard.

Orchestrates all detection components (Mediator pattern):
- Maintains a registry of per-device detectors
- Reads current metrics from the database each cycle
- Passes metrics through detectors (Strategy pattern)
- Forwards results to AlertManager for persistence
- Runs as a background thread synchronized with the pipeline

The engine doesn't perform detection itself — it coordinates
the detectors, insight generator, and alert manager.
"""

import logging
import threading
import time

from src.detection.anomaly_detector import DeviceDetector, NetworkDetector
from src.detection.alert_manager import AlertManager
from src.database.models import (
    Device, DeviceCurrentMetrics, NetworkCurrentMetrics, Network,
)

logger = logging.getLogger(__name__)

class DetectionEngine:
    """Main anomaly detection engine.

    Args:
        repository: Database repository for reading metrics.
        network_id: ID of the monitored network.
        alpha: EWMA smoothing factor for all baselines.
        min_samples: Warm-up period in cycles.
        check_interval: Seconds between detection cycles.
    """

    def __init__(self, repository, network_id: int,
                 alpha: float = 0.10, min_samples: int = 30,
                 check_interval: int = 30,
                 on_alert=None) -> None:
        self.repo = repository
        self.network_id = network_id
        self.alpha = alpha
        self.min_samples = min_samples
        self.check_interval = check_interval
        self._running = False
        self._on_alert = on_alert  # callback for real-time push

        self._device_detectors: dict[int, DeviceDetector] = {}

        self._network_detector = NetworkDetector(
            alpha=alpha, min_samples=min_samples,
        )

        self.alert_manager = AlertManager(
            repository=repository,
            network_id=network_id,
        )
    
    def _get_or_create_detector(self, device_id: int,
                                 device_name: str) -> DeviceDetector:
        """Get existing detector or create one for a new device.

        New devices get a fresh detector that starts in warm-up.
        Existing devices reuse their detector with accumulated baseline.

        Args:
            device_id: Database ID of the device.
            device_name: Display name for insights.

        Returns:
            The DeviceDetector for this device.
        """
        if device_id not in self._device_detectors:
            self._device_detectors[device_id] = DeviceDetector(
                device_id=device_id,
                device_name=device_name,
                alpha=self.alpha,
                min_samples=self.min_samples,
            )
            logger.info(f"New detector created for {device_name} (id={device_id})")

        return self._device_detectors[device_id]
    
    def _run_cycle(self) -> None:
        """Execute one detection cycle.

        Reads all current metrics from the database, evaluates
        each device and the network, and processes any anomalies.
        """
        session = self.repo._get_session()
        try:
            # Get all devices with agents (they have metrics)
            devices = session.query(Device).filter_by(
                has_agent=True, status="active"
            ).all()

            for device in devices:
                # Read current metrics for this device
                current = session.query(DeviceCurrentMetrics).filter_by(
                    device_id=device.id
                ).first()

                if not current:
                    continue

                # Build metrics dict from DB row
                metrics = {
                    "cpu_pct": float(current.cpu_pct) if current.cpu_pct is not None else None,
                    "ram_pct": float(current.ram_pct) if current.ram_pct is not None else None,
                    "bandwidth_in": float(current.bandwidth_in) if current.bandwidth_in is not None else None,
                    "bandwidth_out": float(current.bandwidth_out) if current.bandwidth_out is not None else None,
                    "tcp_retransmissions": current.tcp_retransmissions,
                    "failed_connections": current.failed_connections,
                    "unique_destinations": current.unique_destinations,
                    "bytes_ratio": float(current.bytes_ratio) if current.bytes_ratio is not None else None,
                    "dns_response_time": float(current.dns_response_time) if current.dns_response_time is not None else None,
                }

                # Get or create detector for this device
                name = device.hostname or device.alias or device.detected_type or device.ip
                detector = self._get_or_create_detector(device.id, name)

                # Evaluate all metrics → list of AnomalyResult
                results = detector.evaluate(metrics)

                # Process results → create alerts if needed
                created = self.alert_manager.process_device_results(
                    device_id=device.id,
                    device_name=name,
                    results=results,
                )

                # Push new alerts to WebSocket immediately
                if created and self._on_alert:
                    for alert_data in created:
                        self._on_alert(alert_data)

            # Evaluate network-wide metrics
            self._evaluate_network(session)

        except Exception as e:
            logger.error(f"Detection cycle error: {e}")
        finally:
            session.close()

    def _evaluate_network(self, session) -> None:
        """Evaluate network-wide metrics (ISP health)."""
        network = session.query(Network).filter_by(id=self.network_id).first()
        if not network:
            return

        current = session.query(NetworkCurrentMetrics).filter_by(
            network_id=self.network_id
        ).first()

        if not current:
            return

        metrics = {
            "isp_latency_avg": float(current.isp_latency_avg) if current.isp_latency_avg is not None else None,
            "packet_loss_pct": float(current.packet_loss_pct) if current.packet_loss_pct is not None else None,
            "jitter": float(current.jitter) if current.jitter is not None else None,
        }

        results = self._network_detector.evaluate(metrics)

        created = self.alert_manager.process_network_results(results)

        if created and self._on_alert:
            for alert_data in created:
                self._on_alert(alert_data)

    def start(self) -> None:
        """Start the detection engine in a background thread."""
        self._running = True
        thread = threading.Thread(target=self._detection_loop, daemon=True)
        thread.start()
        logger.info(
            f"Detection engine started: interval={self.check_interval}s, "
            f"alpha={self.alpha}, warm-up={self.min_samples} cycles"
        )

    def _detection_loop(self) -> None:
        """Run detection cycles periodically."""
        while self._running:
            self._run_cycle()
            time.sleep(self.check_interval)

    def stop(self) -> None:
        """Stop the detection engine."""
        self._running = False
        logger.info(
            f"Detection engine stopped. "
            f"Tracking {len(self._device_detectors)} devices."
        )        