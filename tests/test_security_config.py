"""
Tests de invariantes sobre ``SecurityConfig`` [RF-13].

Confirman que los campos necesarios para el flujo 2FA existen con
defaults razonables, sin perder las garantías agregadas en Fase 1
(``cors_origins``).
"""

import sys

sys.path.insert(0, ".")

from src.config.models import SecurityConfig, ServerConfig


class TestSecurityConfigFields:
    def test_fernet_key_default_empty_string(self):
        """``fernet_key`` debe existir con default ``""``.

        Un default vacío obliga al operador a setear una clave real
        en ``server_config.yaml`` o env var para que TOTP funcione,
        sin impedir el import/carga de la config en entornos sin 2FA.
        """
        cfg = SecurityConfig()
        assert hasattr(cfg, "fernet_key")
        assert cfg.fernet_key == ""

    def test_hibp_check_enabled_default_true(self):
        """HIBP debe estar habilitado por defecto — fail-open si la red cae.

        El fail-open se implementa en ``check_password_hibp`` (con warning
        logueado, no silencioso). Este flag permite apagarlo completamente
        en despliegues donde la política interna lo exija.
        """
        cfg = SecurityConfig()
        assert hasattr(cfg, "hibp_check_enabled")
        assert cfg.hibp_check_enabled is True

    def test_cors_origins_preserved_from_phase1(self):
        """Regresión: el fix de CORS de Fase 1 no debe perderse al integrar 2FA.

        ``cors_origins`` debe seguir existiendo con defaults de localhost
        — no ``["*"]``, porque la API acepta credenciales.
        """
        cfg = SecurityConfig()
        assert hasattr(cfg, "cors_origins")
        assert isinstance(cfg.cors_origins, list)
        assert cfg.cors_origins  # no vacía
        assert "*" not in cfg.cors_origins

    def test_server_config_includes_security(self):
        cfg = ServerConfig()
        assert hasattr(cfg.security, "fernet_key")
        assert hasattr(cfg.security, "hibp_check_enabled")
        assert hasattr(cfg.security, "cors_origins")
