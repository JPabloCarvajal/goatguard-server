"""
Tests de comportamiento para ``DetectionEngine._run_cycle``.

Estos tests aíslan el ciclo de detección de la BD usando mocks
para verificar invariantes de orquestación: cuántas veces se
invoca el ``AlertManager``, cómo se encadenan devices y red, etc.
"""
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, ".")

import pytest

from src.detection.engine import DetectionEngine


class _FakeQuery:
    """Query encadenable que emula ``session.query(X).filter_by(...).all/first``."""

    def __init__(self, result):
        self._result = result

    def filter_by(self, **_kwargs):
        return self

    def all(self):
        return self._result

    def first(self):
        return self._result


class _FakeSession:
    """Session fake que despacha queries según la clase consultada."""

    def __init__(self, devices, current_metrics_by_device):
        self._devices = devices
        self._current_metrics_by_device = current_metrics_by_device
        self._last_device_id = None
        self.closed = False

    def query(self, model):
        model_name = model.__name__
        if model_name == "Device":
            return _FakeQuery(self._devices)
        if model_name == "DeviceCurrentMetrics":
            # El engine llama filter_by(device_id=X).first() device-por-device.
            # Devolvemos un proxy que memoriza el device_id y devuelve el
            # metric correspondiente. Simplificamos: devolvemos siempre el
            # primero disponible (el test usa 1 metric por device).
            return _FakeCurrentMetricsQuery(self._current_metrics_by_device)
        if model_name == "Network":
            return _FakeQuery(None)  # desactiva _evaluate_network
        if model_name == "NetworkCurrentMetrics":
            return _FakeQuery(None)
        return _FakeQuery(None)

    def close(self):
        self.closed = True


class _FakeCurrentMetricsQuery:
    """Emula ``query(DeviceCurrentMetrics).filter_by(device_id=X).first()``."""

    def __init__(self, metrics_by_device: dict):
        self._metrics_by_device = metrics_by_device
        self._device_id = None

    def filter_by(self, device_id=None, **_kwargs):
        self._device_id = device_id
        return self

    def first(self):
        return self._metrics_by_device.get(self._device_id)


def _make_device(device_id: int, hostname: str):
    return SimpleNamespace(
        id=device_id,
        hostname=hostname,
        alias=None,
        detected_type=None,
        ip=f"192.168.0.{device_id}",
    )


def _make_current_metrics():
    """DeviceCurrentMetrics con todos los campos None → detector no emite nada."""
    return SimpleNamespace(
        cpu_pct=None,
        ram_pct=None,
        bandwidth_in=None,
        bandwidth_out=None,
        tcp_retransmissions=None,
        failed_connections=None,
        unique_destinations=None,
        bytes_ratio=None,
        dns_response_time=None,
    )


@pytest.fixture()
def engine_with_mocks():
    """Crea un DetectionEngine con repo mockeado y 2 devices fake."""
    devices = [
        _make_device(1, "alpha"),
        _make_device(2, "beta"),
    ]
    metrics_by_device = {
        1: _make_current_metrics(),
        2: _make_current_metrics(),
    }
    fake_session = _FakeSession(devices, metrics_by_device)

    fake_repo = MagicMock()
    fake_repo._get_session.return_value = fake_session

    engine = DetectionEngine(
        repository=fake_repo,
        network_id=1,
        alpha=0.10,
        min_samples=30,
        check_interval=30,
    )
    # Reemplazar alert_manager por un MagicMock para contar llamadas.
    engine.alert_manager = MagicMock()
    engine.alert_manager.process_device_results.return_value = []
    engine.alert_manager.process_network_results.return_value = []

    return engine, fake_session


class TestRunCycleOrchestration:
    """Invariantes del ciclo de detección: cuántas veces se llama al AlertManager."""

    def test_process_device_results_called_once_per_device(self, engine_with_mocks):
        """Con 2 devices, ``process_device_results`` debe llamarse exactamente 2 veces.

        Bug histórico: ``_run_cycle`` invocaba ``process_device_results`` dos
        veces por device (una ignorando el return, otra capturando ``created``).
        Esto persistía cada alerta dos veces en la BD y causaba ruido en el
        push por WebSocket. Debe invocarse **una sola vez por device**.
        """
        engine, _session = engine_with_mocks

        engine._run_cycle()

        call_count = engine.alert_manager.process_device_results.call_count
        assert call_count == 2, (
            f"Se esperaban 2 llamadas a process_device_results (1 por device), "
            f"pero hubo {call_count}. Bug conocido: doble invocación en _run_cycle."
        )

    def test_run_cycle_closes_session(self, engine_with_mocks):
        """El ciclo siempre debe cerrar la session, incluso si todo es happy path."""
        engine, session = engine_with_mocks

        engine._run_cycle()

        assert session.closed is True
