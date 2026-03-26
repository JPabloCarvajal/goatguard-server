"""Unit tests for the insight generator — Z-scores to human text."""
import sys
sys.path.insert(0, ".")

from src.detection.anomaly_detector import AnomalyResult
from src.detection.insight_generator import (
    generate_device_insight,
    generate_network_insight,
    generate_event_insight,
    _z_to_probability,
    _format_value,
)


class TestZToProbability:
    """Tests for Z-score to probability conversion."""

    def test_known_probability_values(self):
        """Verify against known normal distribution values."""
        # Z=2.0 → ~4.55%
        p2 = _z_to_probability(2.0)
        assert 4.0 < p2 < 5.0, f"Z=2.0 should be ~4.55%, got {p2}"

        # Z=3.0 → ~0.27%
        p3 = _z_to_probability(3.0)
        assert 0.2 < p3 < 0.4, f"Z=3.0 should be ~0.27%, got {p3}"

    def test_z_zero_is_100_percent(self):
        """Z=0 means no deviation — 100% probability of occurrence."""
        p = _z_to_probability(0.0)
        assert p > 99.0

    def test_high_z_approaches_zero(self):
        """Very high Z should give near-zero probability."""
        p = _z_to_probability(5.0)
        assert p < 0.01

    def test_negative_z_same_as_positive(self):
        """Probability is based on |Z|, direction doesn't matter."""
        p_pos = _z_to_probability(2.5)
        p_neg = _z_to_probability(-2.5)
        assert abs(p_pos - p_neg) < 0.001


class TestFormatValue:
    """Tests for value formatting with units."""

    def test_bytes_to_kb(self):
        assert "KB/s" in _format_value(5000, "B/s")

    def test_bytes_to_mb(self):
        assert "MB/s" in _format_value(2_000_000, "B/s")

    def test_small_bytes_stay_bytes(self):
        assert "B/s" in _format_value(500, "B/s")

    def test_percentage_format(self):
        result = _format_value(42.567, "%")
        assert "42.6%" == result

    def test_milliseconds_format(self):
        result = _format_value(11.83, "ms")
        assert "11.8 ms" == result

    def test_integer_count(self):
        result = _format_value(5.0, "")
        assert result == "5"


class TestDeviceInsight:
    """Tests for device insight text generation."""

    def test_contains_device_name(self):
        result = AnomalyResult(
            metric="cpu_pct", value=85.0, z_score=3.1,
            baseline=22.5, std_dev=8.3, severity="critical",
            persistent=True, is_warm=True,
        )
        text = generate_device_insight("MALEDUCADA", result)
        assert "MALEDUCADA" in text

    def test_contains_metric_display_name(self):
        result = AnomalyResult(
            metric="bandwidth_in", value=1509800, z_score=4.2,
            baseline=150000, std_dev=35000, severity="critical",
            persistent=True, is_warm=True,
        )
        text = generate_device_insight("TEST-PC", result)
        assert "ancho de banda de entrada" in text

    def test_contains_probability(self):
        result = AnomalyResult(
            metric="cpu_pct", value=85.0, z_score=3.0,
            baseline=22.5, std_dev=8.3, severity="critical",
            persistent=True, is_warm=True,
        )
        text = generate_device_insight("TEST", result)
        assert "Probabilidad" in text
        assert "%" in text

    def test_direction_above(self):
        result = AnomalyResult(
            metric="cpu_pct", value=85.0, z_score=3.0,
            baseline=22.5, std_dev=8.3, severity="critical",
            persistent=True, is_warm=True,
        )
        text = generate_device_insight("TEST", result)
        assert "por encima" in text

    def test_direction_below(self):
        result = AnomalyResult(
            metric="cpu_pct", value=5.0, z_score=-2.5,
            baseline=22.5, std_dev=7.0, severity="warning",
            persistent=True, is_warm=True,
        )
        text = generate_device_insight("TEST", result)
        assert "por debajo" in text


class TestNetworkInsight:
    """Tests for network insight text generation."""

    def test_contains_network_prefix(self):
        result = AnomalyResult(
            metric="isp_latency_avg", value=95.0, z_score=2.8,
            baseline=11.5, std_dev=3.2, severity="warning",
            persistent=True, is_warm=True,
        )
        text = generate_network_insight(result)
        assert "La red" in text

    def test_contains_metric_name(self):
        result = AnomalyResult(
            metric="isp_latency_avg", value=95.0, z_score=2.8,
            baseline=11.5, std_dev=3.2, severity="warning",
            persistent=True, is_warm=True,
        )
        text = generate_network_insight(result)
        assert "latencia ISP" in text


class TestEventInsight:
    """Tests for operational event text generation."""

    def test_new_device_event(self):
        text = generate_event_insight(
            "new_device", ip="192.168.1.9",
            mac="AA:BB:CC:DD:EE:FF", vendor="Samsung",
        )
        assert "192.168.1.9" in text
        assert "AA:BB:CC:DD:EE:FF" in text
        assert "Samsung" in text

    def test_agent_inactive_event(self):
        text = generate_event_insight(
            "agent_inactive", device_name="MALEDUCADA", minutes=5.0,
        )
        assert "MALEDUCADA" in text
        assert "5" in text

    def test_unknown_event_type_doesnt_crash(self):
        text = generate_event_insight("unknown_event_type")
        assert "unknown_event_type" in text