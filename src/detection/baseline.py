"""
EWMA-based adaptive baseline for metric anomaly detection.

Instead of comparing a value against a fixed threshold
("is CPU > 90%?"), we compare it against what THIS SPECIFIC
device normally does ("is CPU significantly higher than what
this device usually shows?").

Two running statistics per metric:
    EWMA (μ)  — the adaptive mean: what we EXPECT the value to be
    EWMV (σ²) — the adaptive variance: how much variation is NORMAL

Both update with O(1) computation: only 2 floats of state,
regardless of how many cycles have passed.

References:
    Hunter, J.S. (1986). The Exponentially Weighted Moving Average.
        Journal of Quality Technology, 18(4), 203-210.
    Roberts, S.W. (1959). Control Chart Tests Based on Geometric
        Moving Averages. Technometrics, 1(3), 239-250.
"""

import math
import logging
from typing import Optional

logger = logging.getLogger(__name__)

class MetricBaseline:
    """Adaptive baseline for a single metric using EWMA + Z-Score.

    Think of it as a student learning what's "normal" for one
    metric of one device. At first it knows nothing (warm-up).
    Over time it builds a model of what to expect. When something
    deviates significantly, it flags it.

    Args:
        alpha: How fast the baseline adapts (0.10 = remembers ~22 min).
        min_variance: Floor to prevent division by zero in Z-score.
        min_samples: How many observations before generating alerts.
    """

    def __init__(self, alpha: float = 0.10, min_variance: float = 0.01,
                 min_samples: int = 30) -> None:
        self.alpha = alpha
        self.min_variance = min_variance
        self.min_samples = min_samples

        # State: only 2 floats needed regardless of history length
        self.ewma: float = 0.0      # μ — what we expect
        self.ewmv: float = 0.0      # σ² — how much variation is normal
        self.samples: int = 0        # how many observations we've seen
        self.prev_z: float = 0.0     # Z from last cycle (for persistence filter)
        self._initialized: bool = False
    
    def update(self, value: float) -> Optional[float]:
        """Process a new observation and return its Z-score.

        Order of operations (critical):
        1. Calculate Z against PREVIOUS baseline
        2. THEN update baseline with new value

        If we updated first, anomalies would partially absorb
        themselves into the baseline before being scored.

        Args:
            value: The metric value for this cycle.

        Returns:
            Z-score if past warm-up, None if still warming up.
        """
        self.samples += 1

        # First observation: nothing to compare against
        if not self._initialized:
            self.ewma = value
            self.ewmv = 0.0
            self._initialized = True
            self.prev_z = 0.0
            return None

        # Step 1: Score BEFORE updating
        z_score = self._calculate_z(value)

        # Step 2: Update EWMA — μ_t = α · x_t + (1 − α) · μ_{t-1}
        prev_ewma = self.ewma
        self.ewma = self.alpha * value + (1 - self.alpha) * self.ewma

        # Step 3: Update EWMV — σ²_t = (1-α) · [σ²_{t-1} + α · (x_t - μ_{t-1})²]
        diff = value - prev_ewma
        self.ewmv = (1 - self.alpha) * (self.ewmv + self.alpha * diff * diff)

        # Save Z for persistence filter (next cycle checks this)
        self.prev_z = z_score if z_score is not None else 0.0

        # During warm-up, don't generate alerts
        if self.samples < self.min_samples:
            return None

        return z_score
    
    def _calculate_z(self, value: float) -> Optional[float]:
        """Calculate Z-score against the current baseline.

        Z = (value - μ) / σ

        Uses variance floor if variance is too low to prevent
        division by zero and artificially inflated Z-scores.
        """
        if not self._initialized:
            return None

        variance = max(self.ewmv, self.min_variance)
        std_dev = math.sqrt(variance)

        return (value - self.ewma) / std_dev
    
    @property
    def is_warm(self) -> bool:
        """Whether enough samples have been collected."""
        return self.samples >= self.min_samples

    @property
    def baseline(self) -> float:
        """Current expected value (EWMA)."""
        return self.ewma

    @property
    def std_dev(self) -> float:
        """Current expected standard deviation."""
        return math.sqrt(max(self.ewmv, self.min_variance))