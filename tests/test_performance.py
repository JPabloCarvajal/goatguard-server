"""Performance tests — verify operations complete within time limits."""
import sys
sys.path.insert(0, ".")

import time
from src.detection.baseline import MetricBaseline
from src.detection.anomaly_detector import DeviceDetector, NetworkDetector
from src.detection.insight_generator import generate_device_insight
from src.detection.anomaly_detector import AnomalyResult
from src.api.auth import init_auth, hash_password, create_token, verify_token


class TestBaselinePerformance:
    """MetricBaseline must be fast — it runs 12x per device per cycle."""

    def test_single_update_under_1ms(self):
        """A single update() call should take less than 1ms."""
        baseline = MetricBaseline(alpha=0.10, min_variance=1.0, min_samples=5)
        for _ in range(5):
            baseline.update(15.0)

        start = time.perf_counter()
        for _ in range(1000):
            baseline.update(15.0 + (_ % 10))
        duration = (time.perf_counter() - start) / 1000

        assert duration < 0.001, f"Single update took {duration*1000:.3f}ms, limit is 1ms"

    def test_1000_updates_under_50ms(self):
        """1000 consecutive updates should complete under 50ms."""
        baseline = MetricBaseline(alpha=0.10, min_variance=1.0, min_samples=5)

        start = time.perf_counter()
        for i in range(1000):
            baseline.update(float(i % 100))
        duration = time.perf_counter() - start

        assert duration < 0.05, f"1000 updates took {duration*1000:.1f}ms, limit is 50ms"


class TestDetectorPerformance:
    """DeviceDetector evaluates 9 metrics per cycle — must be fast."""

    def test_full_evaluation_under_5ms(self):
        """One full evaluate() with all 9 metrics should be under 5ms."""
        detector = DeviceDetector(device_id=1, device_name="PERF-TEST", min_samples=5)

        metrics = {
            "cpu_pct": 15.0, "ram_pct": 40.0,
            "bandwidth_in": 5000.0, "bandwidth_out": 1000.0,
            "tcp_retransmissions": 2, "failed_connections": 5,
            "unique_destinations": 10, "bytes_ratio": 0.5,
            "dns_response_time": 8.0,
        }

        # Warm up
        for _ in range(6):
            detector.evaluate(metrics)

        start = time.perf_counter()
        for _ in range(100):
            detector.evaluate(metrics)
        duration = (time.perf_counter() - start) / 100

        assert duration < 0.005, f"Evaluation took {duration*1000:.2f}ms, limit is 5ms"

    def test_100_devices_under_500ms(self):
        """Simulating 100 devices evaluated in one cycle."""
        detectors = [
            DeviceDetector(device_id=i, device_name=f"DEV-{i}", min_samples=5)
            for i in range(100)
        ]

        metrics = {
            "cpu_pct": 15.0, "ram_pct": 40.0,
            "bandwidth_in": 5000.0, "bandwidth_out": 1000.0,
            "tcp_retransmissions": 2, "failed_connections": 5,
            "unique_destinations": 10, "bytes_ratio": 0.5,
            "dns_response_time": 8.0,
        }

        # Warm up all
        for _ in range(6):
            for d in detectors:
                d.evaluate(metrics)

        start = time.perf_counter()
        for d in detectors:
            d.evaluate(metrics)
        duration = time.perf_counter() - start

        assert duration < 0.5, f"100 devices took {duration*1000:.1f}ms, limit is 500ms"


class TestInsightPerformance:
    """Insight generation should be near-instant."""

    def test_insight_generation_under_1ms(self):
        """Single insight generation should be under 1ms."""
        result = AnomalyResult(
            metric="cpu_pct", value=85.0, z_score=3.1,
            baseline=22.5, std_dev=8.3, severity="critical",
            persistent=True, is_warm=True,
        )

        start = time.perf_counter()
        for _ in range(1000):
            generate_device_insight("TEST-DEVICE", result)
        duration = (time.perf_counter() - start) / 1000

        assert duration < 0.001, f"Insight took {duration*1000:.3f}ms, limit is 1ms"


class TestAuthPerformance:
    """Auth operations have different expected speeds."""

    def test_jwt_creation_under_5ms(self):
        """JWT creation should be fast (no crypto heavy lifting)."""
        init_auth(jwt_secret="test-secret-key-for-goatguard-unit-tests")

        start = time.perf_counter()
        for _ in range(100):
            create_token(user_id=1, username="admin")
        duration = (time.perf_counter() - start) / 100

        assert duration < 0.005, f"Token creation took {duration*1000:.2f}ms, limit is 5ms"

    def test_jwt_verification_under_5ms(self):
        """JWT verification should be fast."""
        init_auth(jwt_secret="test-secret-key-for-goatguard-unit-tests")
        token = create_token(user_id=1, username="admin")

        start = time.perf_counter()
        for _ in range(100):
            verify_token(token)
        duration = (time.perf_counter() - start) / 100

        assert duration < 0.005, f"Token verification took {duration*1000:.2f}ms, limit is 5ms"

    def test_bcrypt_intentionally_slow(self):
        """bcrypt SHOULD be slow (>50ms) — that's the security feature."""
        start = time.perf_counter()
        hash_password("testpassword")
        duration = time.perf_counter() - start

        assert duration > 0.05, f"bcrypt too fast ({duration*1000:.1f}ms), may not be secure"
        assert duration < 2.0, f"bcrypt too slow ({duration*1000:.1f}ms), usability issue"