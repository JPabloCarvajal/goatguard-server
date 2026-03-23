"""
Natural language insight generator for GOATGuard alerts.

Transforms statistical results (Z-scores, baselines, severity)
into human-readable text for the mobile app notifications.

Each insight answers four questions:
1. WHAT device is affected?
2. WHICH metric deviated?
3. HOW MUCH did it deviate?
4. HOW RARE is this statistically?

The probability calculation uses the complementary error function
(erfc) to convert Z-scores into occurrence probabilities under
the normal distribution.
"""

import math
import logging

from src.detection.anomaly_detector import (
    AnomalyResult, METRIC_CONFIG, NETWORK_METRIC_CONFIG,
)

logger = logging.getLogger(__name__)

def _z_to_probability(z: float) -> float:
    """Convert Z-score to probability of normal occurrence.

    Uses the complementary error function (erfc) which gives
    the probability that a value from a standard normal
    distribution exceeds Z standard deviations.

    Examples:
        Z=2.0 → 4.56%  (1 in every 22 observations)
        Z=3.0 → 0.27%  (1 in every 370 observations)
        Z=4.0 → 0.006% (1 in every 15,787 observations)

    Args:
        z: Absolute Z-score value.

    Returns:
        Probability as percentage (0-100).
    """
    return math.erfc(abs(z) / math.sqrt(2)) * 100

def _format_value(value: float, unit: str) -> str:
    """Format a metric value with appropriate scale.

    Converts raw bytes/second to KB/s or MB/s for readability.
    Rounds percentages to one decimal. Counts show as integers.
    """
    if unit == "B/s":
        if value >= 1_048_576:
            return f"{value / 1_048_576:.1f} MB/s"
        elif value >= 1024:
            return f"{value / 1024:.1f} KB/s"
        else:
            return f"{value:.0f} B/s"
    elif unit == "%":
        return f"{value:.1f}%"
    elif unit == "ms":
        return f"{value:.1f} ms"
    elif unit == "":
        if value == int(value):
            return str(int(value))
        return f"{value:.2f}"
    return f"{value:.2f} {unit}"

def generate_device_insight(device_name: str, result: AnomalyResult) -> str:
    """Generate human-readable text for a device metric anomaly.

    Args:
        device_name: Display name of the device.
        result: The anomaly detection result with Z-score and baseline.

    Returns:
        Complete sentence describing the anomaly with context.
    """
    config = METRIC_CONFIG.get(result.metric, {})
    display_name = config.get("name", result.metric)
    unit = config.get("unit", "")

    current = _format_value(result.value, unit)
    baseline = _format_value(result.baseline, unit)
    probability = _z_to_probability(result.z_score)

    direction = "por encima" if result.z_score > 0 else "por debajo"

    return (
        f"{device_name} presenta un {display_name} de {current}, "
        f"{abs(result.z_score):.1f} desviaciones estándar {direction} "
        f"de su promedio habitual (baseline: {baseline}). "
        f"Probabilidad de ocurrencia normal: {probability:.3f}%."
    )

def generate_network_insight(result: AnomalyResult) -> str:
    """Generate human-readable text for a network metric anomaly."""
    config = NETWORK_METRIC_CONFIG.get(result.metric, {})
    display_name = config.get("name", result.metric)
    unit = config.get("unit", "")

    current = _format_value(result.value, unit)
    baseline = _format_value(result.baseline, unit)
    probability = _z_to_probability(result.z_score)

    direction = "por encima" if result.z_score > 0 else "por debajo"

    return (
        f"La red presenta una {display_name} de {current}, "
        f"{abs(result.z_score):.1f} desviaciones estándar {direction} "
        f"del promedio habitual (baseline: {baseline}). "
        f"Probabilidad de ocurrencia normal: {probability:.3f}%."
    )

def generate_event_insight(event_type: str, **kwargs) -> str:
    """Generate text for operational events (not Z-score based).

    Args:
        event_type: Type of event.
        **kwargs: Event-specific parameters for the template.

    Returns:
        Human-readable event description.
    """
    templates = {
        "new_device": (
            "Nuevo dispositivo detectado en la red: "
            "IP {ip}, MAC {mac}"
            + (", fabricante: {vendor}" if kwargs.get("vendor") else "")
        ),
        "agent_inactive": (
            "El agente en {device_name} no reporta "
            "desde hace {minutes:.0f} minutos"
        ),
        "agent_reconnected": (
            "{device_name} se reconectó después de "
            "{minutes:.0f} minutos offline"
        ),
        "warmup_complete": (
            "{device_name}: baseline calibrado después de "
            "{samples} observaciones ({minutes:.0f} min)"
        ),
    }

    template = templates.get(event_type, f"Evento: {event_type}")

    try:
        return template.format(**kwargs)
    except KeyError as e:
        logger.error(f"Missing parameter for {event_type}: {e}")
        return f"Evento {event_type}"