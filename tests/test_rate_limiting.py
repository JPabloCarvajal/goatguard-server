"""
Tests del wiring de slowapi y registro de endpoints 2FA [RF-13].

Verifican que ``create_app``:
- Expone el limiter en ``app.state.limiter``.
- Registra ``SlowAPIMiddleware`` y el handler de ``RateLimitExceeded``.
- Inyecta el ``SecurityConfig`` para que los endpoints TOTP puedan
  acceder a ``fernet_key``.
- Registra todos los endpoints del flujo 2FA (register, login, totp/*,
  recovery/*, regenerate-backup-codes).

La verificación funcional del rate limit ocurre contra ``/auth/login``
hammereando el endpoint hasta superar el límite declarativo.
"""

import sys

sys.path.insert(0, ".")

import pytest
from slowapi.errors import RateLimitExceeded

from src.api.app import create_app
from src.config.models import ServerConfig


class _FakeDatabase:
    """Stub mínimo — create_app solo usa get_session/create_tables."""

    def get_session(self):
        return None

    def create_tables(self, base):
        pass


def _build_app():
    config = ServerConfig()
    config.security.jwt_secret = "goatguard-test-secret-key-for-pytest-suite"
    # Fernet key válida para que los tests no choquen con set_security_config
    from cryptography.fernet import Fernet
    config.security.fernet_key = Fernet.generate_key().decode()
    return create_app(_FakeDatabase(), config)


@pytest.fixture(autouse=True)
def _reset_limiter_state():
    """Resetea el storage del limiter para aislar contadores entre tests."""
    from src.api.rate_limit import limiter

    limiter.reset()
    yield
    limiter.reset()


class TestSlowAPIWiring:
    def test_app_has_limiter_in_state(self):
        app = _build_app()
        assert hasattr(app.state, "limiter")
        assert app.state.limiter is not None

    def test_slowapi_middleware_registered(self):
        app = _build_app()
        middleware_names = [m.cls.__name__ for m in app.user_middleware]
        assert "SlowAPIMiddleware" in middleware_names, (
            f"SlowAPIMiddleware no está en el stack: {middleware_names}"
        )

    def test_rate_limit_exceeded_handler_registered(self):
        app = _build_app()
        assert RateLimitExceeded in app.exception_handlers, (
            "create_app no registró el handler de RateLimitExceeded"
        )


class TestAuth2FAEndpointsRegistered:
    """Todos los endpoints del flujo 2FA deben existir tras create_app."""

    _EXPECTED_PATHS = [
        "/auth/register",
        "/auth/login",
        "/auth/totp/enroll/verify",
        "/auth/totp/verify",
        "/auth/totp/verify-backup",
        "/auth/recovery/verify-code",
        "/auth/recovery/reset-password",
        "/auth/totp/regenerate-backup-codes",
    ]

    def test_all_auth_2fa_endpoints_registered(self):
        app = _build_app()
        paths = {
            getattr(route, "path", None) for route in app.router.routes
        }
        for expected in self._EXPECTED_PATHS:
            assert expected in paths, f"endpoint {expected} no registrado"


class TestSecurityConfigInjectedByCreateApp:
    def test_security_config_accessible_after_create_app(self):
        from src.api.dependencies import get_security_config

        _build_app()
        cfg = get_security_config()
        assert cfg is not None
        assert cfg.fernet_key != ""


class TestLoginRateLimit:
    """El endpoint /auth/login debe bloquear tras exceder su límite."""

    def test_login_returns_429_after_exceeding_limit(self, client):
        """Con límite declarativo de ``10/minute`` en /auth/login, el
        intento número 11 debe recibir 429 en lugar del 401 habitual.

        Este test usa el fixture ``client`` de ``conftest.py`` que
        crea una app completa con la BD in-memory. El reset del
        limiter en el fixture autouse garantiza que no hay contadores
        contaminados de tests previos.
        """
        last_response = None
        for i in range(12):
            last_response = client.post(
                "/auth/login",
                json={"username": f"nope{i}", "password": "wrong"},
            )

        assert last_response is not None
        assert last_response.status_code == 429, (
            f"Esperaba 429 tras 12 intentos, obtuve "
            f"{last_response.status_code}: {last_response.text}"
        )
