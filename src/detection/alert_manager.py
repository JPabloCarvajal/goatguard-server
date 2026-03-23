"""
Alert manager for GOATGuard anomaly detection.

Receives anomaly results from detectors, generates insight
text, and persists alerts to PostgreSQL. Tracks active
anomaly events to avoid duplicate alerts.

Without deduplication, an anomaly lasting 10 cycles (5 min)
would generate 10 identical alerts. The manager generates
ONE alert when the event starts, and doesn't generate another
until the metric returns to normal and crosses again.

Lifecycle of an anomaly event:
    1. Metric crosses threshold (2 consecutive cycles) → CREATE alert
    2. Metric stays above threshold → ACTIVE (no new alert)
    3. Metric returns to normal → CLEAR event
    4. Metric crosses again → CREATE new alert
"""

import logging
from typing import Optional

from src.detection.anomaly_detector import AnomalyResult
from src.detection.insight_generator import (
    generate_device_insight,
    generate_network_insight,
    generate_event_insight,
)
from src.database.models import Alert

logger = logging.getLogger(__name__)

class AlertManager:
    """Manages alert creation, deduplication, and persistence.

    Args:
        repository: Database repository for saving alerts.
        network_id: ID of the monitored network.
    """

    def __init__(self, repository, network_id: int) -> None:
        self.repo = repository
        self.network_id = network_id
        # Active events: {(device_id, metric_name): True}
        # If a key exists, we already alerted for this ongoing anomaly
        self._active_events: dict[tuple, bool] = {}

    def process_device_results(self, device_id: int, device_name: str,
                                results: list[AnomalyResult]) -> list[dict]:
        """Process anomaly results and create alerts if needed.

        For each result:
        - If warning/critical AND persistent AND not already active → CREATE
        - If warning/critical AND already active → SKIP (deduplicate)
        - If normal AND was active → CLEAR the event

        Args:
            device_id: Database ID of the device.
            device_name: Display name for the insight text.
            results: List of AnomalyResult from the detector.

        Returns:
            List of alert dicts that were created (for WebSocket push).
        """
        created_alerts = []

        for result in results:
            key = (device_id, result.metric)

            if result.severity in ("warning", "critical") and result.persistent:
                # Already alerted for this ongoing anomaly?
                if key in self._active_events:
                    continue

                # Generate human-readable insight
                insight_text = generate_device_insight(device_name, result)

                # Classify the anomaly type
                anomaly_type = self._classify_anomaly(result)

                # Save to database
                alert_data = self._save_alert(
                    device_id=device_id,
                    anomaly_type=anomaly_type,
                    description=insight_text,
                    severity=result.severity,
                )

                if alert_data:
                    created_alerts.append(alert_data)

                # Mark event as active (no more alerts until cleared)
                self._active_events[key] = True

                logger.info(
                    f"Alert [{result.severity}] {device_name}: "
                    f"{result.metric} Z={result.z_score}"
                )

            else:
                # Metric returned to normal — clear the event
                if key in self._active_events:
                    del self._active_events[key]

        return created_alerts
    
    def process_network_results(self, results: list[AnomalyResult]) -> list[dict]:
        """Process network-level anomaly results.

        Uses device_id=0 convention for network-level events.
        """
        created_alerts = []

        for result in results:
            key = (0, result.metric)

            if result.severity in ("warning", "critical") and result.persistent:
                if key in self._active_events:
                    continue

                insight_text = generate_network_insight(result)
                anomaly_type = f"network_{result.metric}"

                alert_data = self._save_alert(
                    device_id=None,
                    anomaly_type=anomaly_type,
                    description=insight_text,
                    severity=result.severity,
                )

                if alert_data:
                    created_alerts.append(alert_data)

                self._active_events[key] = True

                logger.info(
                    f"Network alert [{result.severity}]: "
                    f"{result.metric} Z={result.z_score}"
                )
            else:
                if key in self._active_events:
                    del self._active_events[key]

        return created_alerts
    
    def create_event_alert(self, event_type: str, device_id: int = None,
                            severity: str = "info", **kwargs) -> Optional[dict]:
        """Create an alert for an operational event.

        These are not Z-score based. They're lifecycle events
        like new device detected, agent disconnected, etc.

        Args:
            event_type: Type of event (new_device, agent_inactive, etc.)
            device_id: Device involved (None for network events).
            severity: Alert severity level.
            **kwargs: Parameters for the insight template.

        Returns:
            Alert dict if created, None on failure.
        """
        insight_text = generate_event_insight(event_type, **kwargs)

        return self._save_alert(
            device_id=device_id,
            anomaly_type=event_type,
            description=insight_text,
            severity=severity,
        )
    
    def _classify_anomaly(self, result: AnomalyResult) -> str:
        """Map metric names to meaningful anomaly type labels."""
        classification = {
            "cpu_pct": "high_cpu",
            "ram_pct": "high_ram",
            "bandwidth_in": "bandwidth_spike_in",
            "bandwidth_out": "bandwidth_spike_out",
            "tcp_retransmissions": "retransmission_spike",
            "failed_connections": "connection_failures",
            "unique_destinations": "unusual_destinations",
            "bytes_ratio": "traffic_ratio_anomaly",
            "dns_response_time": "dns_latency",
        }
        return classification.get(result.metric, f"anomaly_{result.metric}")
    
    def _save_alert(self, device_id: int, anomaly_type: str,
                     description: str, severity: str) -> Optional[dict]:
        """Persist an alert to the database.

        Returns alert data as dict for WebSocket broadcasting.
        """
        session = self.repo._get_session()
        try:
            alert = Alert(
                device_id=device_id or 1,
                network_id=self.network_id,
                anomaly_type=anomaly_type,
                description=description,
                severity=severity,
                seen=False,
            )
            session.add(alert)
            session.commit()
            session.refresh(alert)

            alert_data = {
                "id": alert.id,
                "device_id": device_id,
                "anomaly_type": anomaly_type,
                "description": description,
                "severity": severity,
                "timestamp": str(alert.timestamp),
            }

            logger.debug(f"Alert saved: {anomaly_type} [{severity}]")
            return alert_data

        except Exception as e:
            session.rollback()
            logger.error(f"Failed to save alert: {e}")
            return None
        finally:
            session.close()