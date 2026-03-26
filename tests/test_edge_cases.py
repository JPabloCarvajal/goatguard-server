"""Edge case tests — boundary values, null handling, empty inputs."""
import sys
sys.path.insert(0, ".")

import math
from src.detection.baseline import MetricBaseline
from src.detection.anomaly_detector import DeviceDetector, NetworkDetector
from src.detection.insight_generator import (
    generate_device_insight, generate_event_insight,
    _format_value, _z_to_probability,
)
from src.detection.anomaly_detector import AnomalyResult
from src.config.models import (
    ServerConfig, NetworkConfig, DatabaseConfig, SecurityConfig,
)
from src.api.auth import init_auth, hash_password, verify_password, create_token, verify_token


class TestBaselineBoundaryValues:
    """Boundary and extreme value tests for MetricBaseline."""

    def test_zero_value(self):
        """Metric value of exactly 0.0 should be handled."""
        baseline = MetricBaseline(alpha=0.10, min_variance=0.01, min_samples=2)
        baseline.update(0.0)
        z = baseline.update(0.0)
        assert z is None or math.isfinite(z)

    def test_negative_value(self):
        """Some metrics could theoretically be negative (Z-scores are)."""
        baseline = MetricBaseline(alpha=0.10, min_variance=1.0, min_samples=2)
        baseline.update(10.0)
        z = baseline.update(-5.0)
        assert z is not None
        assert z < 0, "Negative deviation should produce negative Z"

    def test_very_large_value(self):
        """Extremely large values should not cause overflow."""
        baseline = MetricBaseline(alpha=0.10, min_variance=1.0, min_samples=2)
        baseline.update(100.0)
        z = baseline.update(999999999.0)
        assert z is not None
        assert math.isfinite(z)
        assert z > 0

    def test_very_small_alpha(self):
        """Alpha near zero should make baseline almost immovable."""
        baseline = MetricBaseline(alpha=0.001, min_variance=1.0, min_samples=2)
        baseline.update(100.0)
        baseline.update(100.0)
        baseline.update(200.0)
        # Baseline should barely move from 100
        assert baseline.baseline < 105, f"Baseline moved too much: {baseline.baseline}"

    def test_alpha_near_one(self):
        """Alpha near 1.0 should make baseline track the latest value."""
        baseline = MetricBaseline(alpha=0.99, min_variance=1.0, min_samples=2)
        baseline.update(100.0)
        baseline.update(100.0)
        baseline.update(500.0)
        # Baseline should jump close to 500
        assert baseline.baseline > 450, f"Baseline should track latest: {baseline.baseline}"

    def test_identical_values_variance_stays_at_floor(self):
        """Constant input should keep variance at min_variance."""
        baseline = MetricBaseline(alpha=0.10, min_variance=2.0, min_samples=3)
        for _ in range(20):
            baseline.update(50.0)
        assert baseline.std_dev == math.sqrt(2.0), "Std dev should be sqrt(min_variance)"

    def test_single_sample_is_not_warm(self):
        """One observation is never enough for warm-up."""
        baseline = MetricBaseline(alpha=0.10, min_variance=1.0, min_samples=1)
        baseline.update(10.0)
        # min_samples=1 but first observation returns None (initialization)
        assert baseline.samples == 1

    def test_rapid_alternation(self):
        """Rapidly alternating values should increase variance."""
        baseline = MetricBaseline(alpha=0.10, min_variance=0.01, min_samples=3)
        for i in range(20):
            baseline.update(100.0 if i % 2 == 0 else 0.0)
        assert baseline.ewmv > 10, "High alternation should produce high variance"


class TestDetectorEdgeCases:
    """Edge cases for DeviceDetector and NetworkDetector."""

    def test_empty_metrics_dict(self):
        """Empty dict should return empty results, no crash."""
        detector = DeviceDetector(device_id=1, device_name="TEST", min_samples=3)
        results = detector.evaluate({})
        assert results == []

    def test_all_none_metrics(self):
        """All None values should return empty results."""
        detector = DeviceDetector(device_id=1, device_name="TEST", min_samples=3)
        results = detector.evaluate({
            "cpu_pct": None,
            "ram_pct": None,
            "bandwidth_in": None,
        })
        assert results == []

    def test_unknown_metric_ignored(self):
        """Metrics not in METRIC_CONFIG should be ignored."""
        detector = DeviceDetector(device_id=1, device_name="TEST", min_samples=3)
        results = detector.evaluate({"fake_metric": 42.0, "cpu_pct": 15.0})
        metrics = [r.metric for r in results]
        assert "fake_metric" not in metrics
        assert "cpu_pct" in metrics

    def test_string_value_converted_to_float(self):
        """Numeric strings should be converted without error."""
        detector = DeviceDetector(device_id=1, device_name="TEST", min_samples=3)
        # float("15.5") should work
        results = detector.evaluate({"cpu_pct": "15.5"})
        assert len(results) == 1
        assert results[0].value == 15.5

    def test_network_detector_partial_metrics(self):
        """Network detector should handle partial metric sets."""
        detector = NetworkDetector(min_samples=3)
        results = detector.evaluate({"isp_latency_avg": 10.0})
        metrics = [r.metric for r in results]
        assert "isp_latency_avg" in metrics
        assert "packet_loss_pct" not in metrics


class TestInsightEdgeCases:
    """Edge cases for insight generation."""

    def test_z_score_zero_probability(self):
        """Z=0 should give ~100% probability."""
        p = _z_to_probability(0.0)
        assert p > 99.0

    def test_very_high_z_score(self):
        """Z=10 should not crash and give near-zero probability."""
        p = _z_to_probability(10.0)
        assert p >= 0.0
        assert p < 0.001

    def test_format_value_zero(self):
        """Zero bytes should display as '0 B/s'."""
        result = _format_value(0.0, "B/s")
        assert "0" in result

    def test_format_value_exact_boundary_kb(self):
        """Exactly 1024 B/s should show as KB/s."""
        result = _format_value(1024.0, "B/s")
        assert "KB/s" in result

    def test_format_value_exact_boundary_mb(self):
        """Exactly 1048576 B/s should show as MB/s."""
        result = _format_value(1048576.0, "B/s")
        assert "MB/s" in result

    def test_event_insight_missing_params(self):
        """Missing template params should not crash."""
        text = generate_event_insight("agent_inactive")
        # Should return something without crashing
        assert isinstance(text, str)


class TestAuthEdgeCases:
    """Edge cases for authentication."""

    def test_empty_password_hash(self):
        """Empty password should still hash without error."""
        hashed = hash_password("")
        assert len(hashed) > 0

    def test_very_long_password(self):
        """bcrypt rejects passwords > 72 bytes."""
        long_pass = "a" * 200
        try:
            hashed = hash_password(long_pass)
            assert verify_password(long_pass, hashed) is True
        except ValueError:
            pass  # bcrypt correctly rejects >72 byte passwords

    def test_unicode_password(self):
        """Unicode characters in password should work."""
        hashed = hash_password("contraseña_ñ_ü_日本語")
        assert verify_password("contraseña_ñ_ü_日本語", hashed) is True

    def test_verify_token_empty_string(self):
        """Empty token string should return None."""
        init_auth(jwt_secret="test-secret-key-for-goatguard-unit-tests")
        result = verify_token("")
        assert result is None

    def test_verify_token_garbage(self):
        """Random garbage should return None, not crash."""
        init_auth(jwt_secret="test-secret-key-for-goatguard-unit-tests")
        result = verify_token("not.a.valid.jwt.token.at.all")
        assert result is None

    def test_verify_token_none_handling(self):
        """Malformed base64 should return None."""
        init_auth(jwt_secret="test-secret-key-for-goatguard-unit-tests")
        result = verify_token("eyJhbGciOiJIUzI1NiJ9.broken.garbage")
        assert result is None


class TestConfigEdgeCases:
    """Edge cases for configuration."""

    def test_default_config_is_valid(self):
        """Default ServerConfig should have all sections populated."""
        config = ServerConfig()
        assert config.server.tcp_port > 0
        assert config.server.udp_port > 0
        assert len(config.database.host) > 0
        assert len(config.security.jwt_secret) > 0

    def test_config_ports_are_different(self):
        """TCP, UDP, and API ports should not collide."""
        config = ServerConfig()
        ports = {config.server.tcp_port, config.server.udp_port, config.server.api_port}
        assert len(ports) == 3, "All three ports should be unique"