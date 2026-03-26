"""Unit tests for DeviceDetector and NetworkDetector."""
import sys
sys.path.insert(0, ".")

from src.detection.anomaly_detector import (
    DeviceDetector, NetworkDetector, METRIC_CONFIG, NETWORK_METRIC_CONFIG,
)


class TestDeviceDetectorWarmup:
    """Tests for warm-up phase."""

    def test_warmup_all_results_not_warm(self):
        """During warm-up, all results should have is_warm=False."""
        detector = DeviceDetector(device_id=1, device_name="TEST", min_samples=5)

        results = detector.evaluate({"cpu_pct": 15.0, "ram_pct": 40.0})

        for r in results:
            assert r.is_warm is False
            assert r.severity == "normal"

    def test_detector_creates_baseline_per_metric(self):
        """Should have one baseline for each metric in METRIC_CONFIG."""
        detector = DeviceDetector(device_id=1, device_name="TEST")

        assert len(detector.baselines) == len(METRIC_CONFIG)
        for metric_name in METRIC_CONFIG:
            assert metric_name in detector.baselines

    def test_is_warm_false_until_all_baselines_warm(self):
        """is_warm is True only when ALL baselines completed warm-up."""
        detector = DeviceDetector(device_id=1, device_name="TEST", min_samples=3)

        # Feed only cpu_pct for 3 cycles
        for _ in range(3):
            detector.evaluate({"cpu_pct": 15.0})

        # Not all baselines are warm (ram_pct etc never received data)
        # But is_warm checks all baselines, and unfed ones have 0 samples
        assert detector.is_warm is False


class TestDeviceDetectorFiltering:
    """Tests for the persistence filter and severity classification."""

    def test_single_spike_filtered(self):
        """A spike lasting 1 cycle should be filtered (persistent=False).
        This is the core anti-false-positive mechanism."""
        detector = DeviceDetector(device_id=1, device_name="TEST", min_samples=5)

        # Warm up
        for _ in range(6):
            detector.evaluate({"cpu_pct": 15.0})

        # Single spike
        results = detector.evaluate({"cpu_pct": 80.0})

        cpu_result = [r for r in results if r.metric == "cpu_pct"][0]
        assert cpu_result.persistent is False, "Single spike should be filtered"

    def test_sustained_anomaly_triggers_alert(self):
        """2 consecutive cycles above threshold should trigger alert."""
        detector = DeviceDetector(device_id=1, device_name="TEST", min_samples=5)

        # Warm up with stable values
        for _ in range(6):
            detector.evaluate({"cpu_pct": 15.0})

        # First anomalous cycle — filtered (no precedent)
        results1 = detector.evaluate({"cpu_pct": 80.0})
        cpu1 = [r for r in results1 if r.metric == "cpu_pct"][0]
        assert cpu1.persistent is False

        # Second anomalous cycle — should trigger
        results2 = detector.evaluate({"cpu_pct": 80.0})
        cpu2 = [r for r in results2 if r.metric == "cpu_pct"][0]
        assert cpu2.persistent is True
        assert cpu2.severity in ("warning", "critical")

    def test_none_metrics_skipped_gracefully(self):
        """Metrics with None values should be skipped without error."""
        detector = DeviceDetector(device_id=1, device_name="TEST", min_samples=3)

        results = detector.evaluate({
            "cpu_pct": 15.0,
            "ram_pct": None,
            "bandwidth_in": None,
        })

        # Should only have result for cpu_pct
        metrics_evaluated = [r.metric for r in results]
        assert "cpu_pct" in metrics_evaluated
        assert "ram_pct" not in metrics_evaluated
        assert "bandwidth_in" not in metrics_evaluated

    def test_severity_classification(self):
        """WARNING for Z>2, CRITICAL for Z>3 (with persistence)."""
        detector = DeviceDetector(device_id=1, device_name="TEST", min_samples=3)

        # Warm up
        for _ in range(4):
            detector.evaluate({"cpu_pct": 10.0})

        # Two cycles of extreme anomaly for persistence
        detector.evaluate({"cpu_pct": 90.0})
        results = detector.evaluate({"cpu_pct": 90.0})

        cpu = [r for r in results if r.metric == "cpu_pct"][0]
        assert cpu.severity in ("warning", "critical"), f"Should be warning or critical, got {cpu.severity}"

    def test_return_to_normal_clears_persistence(self):
        """After anomaly, returning to normal should reset."""
        detector = DeviceDetector(device_id=1, device_name="TEST", min_samples=3)

        for _ in range(4):
            detector.evaluate({"cpu_pct": 15.0})

        # Trigger anomaly (2 cycles)
        detector.evaluate({"cpu_pct": 80.0})
        detector.evaluate({"cpu_pct": 80.0})

        # Return to normal
        results = detector.evaluate({"cpu_pct": 15.0})

        cpu = [r for r in results if r.metric == "cpu_pct"][0]
        assert cpu.severity == "normal"


class TestNetworkDetector:
    """Tests for network-level detection."""

    def test_evaluates_isp_metrics(self):
        """Should evaluate all 3 ISP metrics."""
        detector = NetworkDetector(min_samples=3)

        results = detector.evaluate({
            "isp_latency_avg": 11.5,
            "packet_loss_pct": 0.0,
            "jitter": 0.2,
        })

        metrics = [r.metric for r in results]
        assert "isp_latency_avg" in metrics
        assert "packet_loss_pct" in metrics
        assert "jitter" in metrics

    def test_persistence_filter_works_same_as_device(self):
        """Network detector should also filter single spikes."""
        detector = NetworkDetector(min_samples=3)

        # Warm up
        for _ in range(4):
            detector.evaluate({"isp_latency_avg": 11.0})

        # Single spike
        results = detector.evaluate({"isp_latency_avg": 200.0})

        lat = [r for r in results if r.metric == "isp_latency_avg"][0]
        assert lat.persistent is False, "Single spike should be filtered"