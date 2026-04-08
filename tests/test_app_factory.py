"""
Tests para el factory ``create_app``.

Verifican las invariantes de construcción de la aplicación FastAPI
que no dependen de requests HTTP: registro de routers, configuración
de middleware y ciclo de vida.
"""
import sys

sys.path.insert(0, ".")

from src.api.app import create_app
from src.config.models import ServerConfig


class _FakeDatabase:
    """Stub mínimo: create_app solo usa get_session y create_tables."""

    def get_session(self):
        return None

    def create_tables(self, base):
        pass


def _build_app():
    """Instancia la app con un fake DB y la config de test."""
    config = ServerConfig()
    # Mismo secreto que usa conftest.py para que init_auth no reviente.
    config.security.jwt_secret = "goatguard-test-secret-key-for-pytest-suite"
    return create_app(_FakeDatabase(), config)


def _collect_endpoints(app) -> list[tuple[str, str]]:
    """Devuelve (method, path) por cada ruta HTTP registrada.

    Ignora mounts y websockets (tienen estructura distinta) para
    que la comparación sea por endpoint HTTP real.
    """
    endpoints: list[tuple[str, str]] = []
    for route in app.router.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        if not path or not methods:
            continue
        for method in methods:
            endpoints.append((method, path))
    return endpoints


class TestRouterRegistration:
    """Invariantes sobre el registro de routers en ``create_app``."""

    def test_no_duplicate_http_endpoints(self):
        """Ningún (método, path) debe registrarse dos veces.

        Bug histórico: ``auth_routes.router`` se incluía dos veces
        en ``create_app``, duplicando todas las rutas /api/auth/*.
        Esto contamina ``app.routes`` y puede producir comportamiento
        imprevisto con middleware y generación de OpenAPI.
        """
        app = _build_app()
        endpoints = _collect_endpoints(app)

        # Un duplicado es cualquier endpoint que aparece >1 vez.
        seen: dict[tuple[str, str], int] = {}
        for endpoint in endpoints:
            seen[endpoint] = seen.get(endpoint, 0) + 1
        duplicates = {ep: count for ep, count in seen.items() if count > 1}

        assert duplicates == {}, (
            f"Se detectaron endpoints duplicados en create_app: "
            f"{duplicates}. Revisar llamadas a app.include_router."
        )
