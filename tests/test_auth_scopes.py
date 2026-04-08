"""
Tests de JWT con scopes explícitos [RF-13].

El flujo 2FA requiere emitir tokens de distintos privilegios:
- ``full_access`` — token normal tras password + TOTP
- ``pending_totp`` — solo habilita endpoints del segundo factor
- ``password_reset`` — solo habilita reset de contraseña tras recovery code

``create_token`` debe aceptar ``scope`` y ``expiration_minutes`` como
parámetros opcionales (default ``full_access`` + ``jwt_expiration_hours``
en minutos) para preservar compatibilidad con los call sites existentes.
``verify_token_scope`` debe rechazar tokens cuyo scope no coincida.
"""

import sys

sys.path.insert(0, ".")

import jwt
import pytest

from src.api.auth import (
    create_token,
    init_auth,
    verify_token,
    verify_token_scope,
)

TEST_SECRET = "goatguard-test-secret-key-for-pytest-suite"


@pytest.fixture(autouse=True)
def _init_auth_for_scope_tests():
    """Re-inicializa auth con un secret conocido por si algún test anterior lo cambió."""
    init_auth(
        jwt_secret=TEST_SECRET,
        jwt_algorithm="HS256",
        jwt_expiration_hours=1,
    )


class TestCreateTokenScope:
    def test_default_scope_is_full_access(self):
        """Un token sin scope explícito debe ser ``full_access``.

        Esto preserva la compatibilidad con los callers antiguos que
        invocan ``create_token(user_id, username)`` sin argumentos extras.
        """
        token = create_token(user_id=1, username="alice")
        payload = jwt.decode(token, TEST_SECRET, algorithms=["HS256"])
        assert payload["scope"] == "full_access"

    def test_explicit_pending_totp_scope(self):
        token = create_token(
            user_id=1, username="alice", scope="pending_totp",
        )
        payload = jwt.decode(token, TEST_SECRET, algorithms=["HS256"])
        assert payload["scope"] == "pending_totp"

    def test_explicit_password_reset_scope(self):
        token = create_token(
            user_id=1, username="alice", scope="password_reset",
        )
        payload = jwt.decode(token, TEST_SECRET, algorithms=["HS256"])
        assert payload["scope"] == "password_reset"

    def test_custom_expiration_minutes_shortens_token(self):
        """Un token con ``expiration_minutes=5`` debe expirar antes que uno
        con la ventana por defecto (1 hora en tests)."""
        short = create_token(
            user_id=1, username="alice", expiration_minutes=5,
        )
        normal = create_token(user_id=1, username="alice")
        short_payload = jwt.decode(short, TEST_SECRET, algorithms=["HS256"])
        normal_payload = jwt.decode(normal, TEST_SECRET, algorithms=["HS256"])
        assert short_payload["exp"] < normal_payload["exp"]


class TestVerifyTokenScope:
    def test_matching_scope_returns_payload(self):
        token = create_token(
            user_id=1, username="alice", scope="pending_totp",
        )
        payload = verify_token_scope(token, required_scope="pending_totp")
        assert payload is not None
        assert payload["sub"] == "1"
        assert payload["scope"] == "pending_totp"

    def test_mismatched_scope_returns_none(self):
        """Un token ``pending_totp`` no debe pasar chequeo de ``full_access``."""
        token = create_token(
            user_id=1, username="alice", scope="pending_totp",
        )
        assert verify_token_scope(token, required_scope="full_access") is None

    def test_invalid_token_returns_none(self):
        assert verify_token_scope("not-a-real-jwt", "full_access") is None

    def test_verify_token_still_accepts_scoped_tokens(self):
        """``verify_token`` (sin check de scope) debe seguir aceptando
        cualquier token válido — su contrato no cambia con este cambio."""
        token = create_token(
            user_id=1, username="alice", scope="pending_totp",
        )
        payload = verify_token(token)
        assert payload is not None
        assert payload["scope"] == "pending_totp"
