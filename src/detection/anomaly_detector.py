"""
Per-device anomaly detector for GOATGuard.

Manages a MetricBaseline per monitored metric per device.
Evaluates Z-scores, applies the persistence filter (2/2
consecutive cycles), and classifies alert severity.

The persistence filter reduces false positives by 95.4%:
    P(single spike |Z|>2) = 4.56%
    P(2 consecutive |Z|>2) = 0.0456² = 0.21%

Pattern: Strategy — each MetricBaseline is an interchangeable
detection strategy. The detector doesn't know what algorithm
runs inside each baseline, only asks for a Z-score.
"""

import logging
from typing import Optional
from src.detection.baseline import MetricBaseline

logger = logging.getLogger(__name__)

# Each metric's display name, unit, and minimum variance floor
METRIC_CONFIG = {
    "cpu_pct": {"name": "uso de CPU", "unit": "%", "min_var": 1.0},
    "ram_pct": {"name": "uso de RAM", "unit": "%", "min_var": 1.0},
    "bandwidth_in": {"name": "ancho de banda de entrada", "unit": "B/s", "min_var": 100.0},
    "bandwidth_out": {"name": "ancho de banda de salida", "unit": "B/s", "min_var": 100.0},
    "tcp_retransmissions": {"name": "retransmisiones TCP", "unit": "", "min_var": 0.5},
    "failed_connections": {"name": "conexiones fallidas", "unit": "", "min_var": 0.5},
    "unique_destinations": {"name": "destinos únicos", "unit": "", "min_var": 1.0},
    "bytes_ratio": {"name": "ratio enviado/recibido", "unit": "", "min_var": 0.01},
    "dns_response_time": {"name": "tiempo respuesta DNS", "unit": "ms", "min_var": 1.0},
}

NETWORK_METRIC_CONFIG = {
    "isp_latency_avg": {"name": "latencia ISP", "unit": "ms", "min_var": 1.0},
    "packet_loss_pct": {"name": "pérdida de paquetes", "unit": "%", "min_var": 0.1},
    "jitter": {"name": "jitter", "unit": "ms", "min_var": 0.1},
}

# Z-score thresholds (derived from normal distribution)
Z_WARNING = 2.0     # P = 4.56% — inusual
Z_CRITICAL = 3.0    # P = 0.27% — muy inusual
Z_INFO = 1.5        # P = 13.36% — variación moderada

class AnomalyResult:
    """Result of evaluating one metric in one cycle.

    Contains everything needed to generate an alert and an insight:
    what happened, how bad it is, and the statistical context.
    """

    __slots__ = [
        "metric", "value", "z_score", "baseline",
        "std_dev", "severity", "persistent", "is_warm",
    ]

    def __init__(self, metric: str, value: float, z_score: float,
                 baseline: float, std_dev: float, severity: str,
                 persistent: bool, is_warm: bool) -> None:
        self.metric = metric
        self.value = value
        self.z_score = z_score
        self.baseline = baseline
        self.std_dev = std_dev
        self.severity = severity      # normal, info, warning, critical
        self.persistent = persistent  # passed 2/2 filter?
        self.is_warm = is_warm        # baseline calibrated?

class DeviceDetector:
    """Anomaly detector for a single device.

    Creates a MetricBaseline (Strategy) for each metric.
    Each cycle, evaluates all metrics, applies persistence
    filter, and returns classified results.

    Args:
        device_id: Database ID of the device.
        device_name: Display name for insights.
        alpha: EWMA smoothing factor.
        min_samples: Warm-up period in cycles.
    """

    def __init__(self, device_id: int, device_name: str,
                 alpha: float = 0.10, min_samples: int = 30) -> None:
        self.device_id = device_id
        self.device_name = device_name

        # Strategy pattern: one baseline per metric
        self.baselines: dict[str, MetricBaseline] = {}
        for metric, config in METRIC_CONFIG.items():
            self.baselines[metric] = MetricBaseline(
                alpha=alpha,
                min_variance=config["min_var"],
                min_samples=min_samples,
            )
    
    def evaluate(self, metrics: dict) -> list[AnomalyResult]:
        """Evaluate all metrics for this device in this cycle.

        For each metric:
        1. Get Z-score from baseline (Strategy)
        2. Classify severity by Z magnitude
        3. Apply persistence filter (2/2 consecutive cycles)
        4. Return classified result

        Args:
            metrics: Dict with metric names and float values.

        Returns:
            List of AnomalyResult, one per evaluated metric.
        """
        results = []

        for metric_name, baseline in self.baselines.items():
            value = metrics.get(metric_name)
            if value is None:
                continue

            value = float(value)
            prev_z = baseline.prev_z

            # Step 1: Get Z-score from the strategy
            z_score = baseline.update(value)

            # Still warming up
            if z_score is None:
                results.append(AnomalyResult(
                    metric=metric_name, value=value, z_score=0.0,
                    baseline=baseline.baseline, std_dev=baseline.std_dev,
                    severity="normal", persistent=False, is_warm=False,
                ))
                continue

            # Step 2: Classify severity
            abs_z = abs(z_score)
            if abs_z > Z_CRITICAL:
                severity = "critical"
            elif abs_z > Z_WARNING:
                severity = "warning"
            elif abs_z > Z_INFO:
                severity = "info"
            else:
                severity = "normal"

            # Step 3: Persistence filter for warning and critical
            persistent = False
            if severity in ("warning", "critical"):
                # Both current AND previous must exceed WARNING
                if abs(prev_z) > Z_WARNING and abs_z > Z_WARNING:
                    persistent = True
                else:
                    severity = "normal"  # spike: downgrade
            elif severity == "info":
                persistent = True  # info doesn't need persistence

            results.append(AnomalyResult(
                metric=metric_name, value=value,
                z_score=round(z_score, 2),
                baseline=round(baseline.baseline, 2),
                std_dev=round(baseline.std_dev, 2),
                severity=severity if persistent or severity == "normal" else "normal",
                persistent=persistent, is_warm=True,
            ))

        return results

    @property
    def is_warm(self) -> bool:
        """Whether all baselines completed warm-up."""
        return all(b.is_warm for b in self.baselines.values())
    
class NetworkDetector:
    """Anomaly detector for network-wide metrics (ISP health).

    Same logic as DeviceDetector but uses NETWORK_METRIC_CONFIG
    instead of METRIC_CONFIG.
    """

    def __init__(self, alpha: float = 0.10, min_samples: int = 30) -> None:
        self.baselines: dict[str, MetricBaseline] = {}
        for metric, config in NETWORK_METRIC_CONFIG.items():
            self.baselines[metric] = MetricBaseline(
                alpha=alpha,
                min_variance=config["min_var"],
                min_samples=min_samples,
            )

    def evaluate(self, metrics: dict) -> list[AnomalyResult]:
        """Evaluate network metrics for this cycle."""
        results = []

        for metric_name, baseline in self.baselines.items():
            value = metrics.get(metric_name)
            if value is None:
                continue

            value = float(value)
            prev_z = baseline.prev_z
            z_score = baseline.update(value)

            if z_score is None:
                results.append(AnomalyResult(
                    metric=metric_name, value=value, z_score=0.0,
                    baseline=baseline.baseline, std_dev=baseline.std_dev,
                    severity="normal", persistent=False, is_warm=False,
                ))
                continue

            abs_z = abs(z_score)
            if abs_z > Z_CRITICAL:
                severity = "critical"
            elif abs_z > Z_WARNING:
                severity = "warning"
            elif abs_z > Z_INFO:
                severity = "info"
            else:
                severity = "normal"

            persistent = False
            if severity in ("warning", "critical"):
                if abs(prev_z) > Z_WARNING and abs_z > Z_WARNING:
                    persistent = True
                else:
                    severity = "normal"
            elif severity == "info":
                persistent = True

            results.append(AnomalyResult(
                metric=metric_name, value=value,
                z_score=round(z_score, 2),
                baseline=round(baseline.baseline, 2),
                std_dev=round(baseline.std_dev, 2),
                severity=severity if persistent or severity == "normal" else "normal",
                persistent=persistent, is_warm=True,
            ))

        return results