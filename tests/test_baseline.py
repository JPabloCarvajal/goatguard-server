"""Unit tests for MetricBaseline — the EWMA + Z-Score engine."""
import sys
sys.path.insert(0, ".")

import math
from src.detection.baseline import MetricBaseline


class TestMetricBaselineWarmup:
    """Tests for the warm-up phase behavior."""

    def test_first_observation_returns_none(self):
        """First value has nothing to compare against.
        Expected: returns None, baseline equals the first value."""
        baseline = MetricBaseline(alpha=0.10, min_variance=1.0, min_samples=5)

        result = baseline.update(15.0)

        assert result is None
        assert baseline.ewma == 15.0
        assert baseline.samples == 1

    def test_warmup_returns_none_until_min_samples(self):
        """During warm-up, update() returns None for every cycle.
        The baseline is learning, not yet ready to judge."""
        baseline = MetricBaseline(alpha=0.10, min_variance=1.0, min_samples=5)

        for i in range(4):
            result = baseline.update(15.0 + i)
            assert result is None, f"Cycle {i+1} should return None during warm-up"

        assert baseline.is_warm is False

    def test_first_z_score_after_warmup(self):
        """After min_samples cycles, update() starts returning Z-scores."""
        baseline = MetricBaseline(alpha=0.10, min_variance=1.0, min_samples=5)

        for i in range(4):
            baseline.update(15.0)

        # 5th observation — should return a Z-score
        result = baseline.update(15.0)

        assert result is not None
        assert isinstance(result, float)
        assert baseline.is_warm is True

class TestMetricBaselineDetection:
    """Tests for anomaly detection after warm-up."""

    def test_spike_produces_high_z_score(self):
        """A sudden spike should produce a Z-score >> 2.0.
        Simulates normal CPU ~15% then sudden jump to 45%."""
        baseline = MetricBaseline(alpha=0.10, min_variance=1.0, min_samples=5)

        # Warm up with stable values
        for _ in range(5):
            baseline.update(15.0)

        # Inject spike
        z = baseline.update(45.0)

        assert z is not None
        assert z > 5.0, f"Spike should produce high Z, got {z}"

    def test_stable_values_produce_low_z_scores(self):
        """Consistent values should produce Z-scores near zero."""
        baseline = MetricBaseline(alpha=0.10, min_variance=1.0, min_samples=5)

        for _ in range(5):
            baseline.update(20.0)

        # Same value as baseline — Z should be ~0
        z = baseline.update(20.0)

        assert z is not None
        assert abs(z) < 1.0, f"Stable value should have low Z, got {z}"

    def test_min_variance_prevents_division_by_zero(self):
        """When all values are identical, variance is zero.
        min_variance prevents Z = infinity."""
        baseline = MetricBaseline(alpha=0.10, min_variance=1.0, min_samples=3)

        # All identical — variance converges to 0
        for _ in range(5):
            baseline.update(10.0)

        # Slightly different value — without min_variance this would be Z=inf
        z = baseline.update(11.0)

        assert z is not None
        assert math.isfinite(z), "Z-score must be finite, not infinity"
        assert abs(z) == 1.0, f"With min_var=1.0, deviation of 1.0 should give Z=1.0, got {z}"

    def test_baseline_adapts_to_sustained_change(self):
        """If values permanently shift, baseline should follow.
        Simulates a legitimate change from ~15 to ~40."""
        baseline = MetricBaseline(alpha=0.10, min_variance=1.0, min_samples=5)

        # Establish baseline at ~15
        for _ in range(10):
            baseline.update(15.0)

        old_baseline = baseline.baseline

        # Sustained shift to 40
        for _ in range(50):
            baseline.update(40.0)

        new_baseline = baseline.baseline

        # Baseline should have moved significantly toward 40
        assert new_baseline > 35.0, f"Baseline should adapt toward 40, got {new_baseline}"
        assert new_baseline > old_baseline, "Baseline should have increased"

    def test_z_calculated_before_baseline_update(self):
        """Z-score must use the PREVIOUS baseline, not the updated one.
        This is critical: if we update first, anomalies dampen themselves."""
        baseline = MetricBaseline(alpha=0.10, min_variance=1.0, min_samples=3)

        for _ in range(3):
            baseline.update(10.0)

        baseline_before = baseline.baseline  # should be ~10.0

        z = baseline.update(50.0)

        # Z should be calculated against baseline ~10, not updated baseline ~14
        # (50 - 10) / 1.0 = 40.0 approximately
        assert z > 20.0, f"Z should use old baseline, got {z} (too low means it updated first)"

    def test_prev_z_stored_for_persistence_filter(self):
        """prev_z must be updated each cycle for the persistence filter."""
        baseline = MetricBaseline(alpha=0.10, min_variance=1.0, min_samples=3)

        for _ in range(3):
            baseline.update(10.0)

        assert baseline.prev_z == 0.0  # During warm-up, prev_z stays 0

        z1 = baseline.update(15.0)
        assert baseline.prev_z == z1, "prev_z should store the last Z-score"

        z2 = baseline.update(12.0)
        assert baseline.prev_z == z2, "prev_z should update each cycle"