"""
Tests E2E del flujo de recuperación de password [RF-13].

Cubre:
- /recovery/verify-code: recovery code correcto → reset_token scope=password_reset
- /recovery/verify-code: código incorrecto → 400 + recovery_code_attempts incrementado
- /recovery/verify-code: recovery_code_used=True → 400
- /recovery/verify-code: 5 intentos acumulados → 429 Too Many Requests
- /recovery/verify-code: username inexistente → 400 (timing-safe)
- /recovery/verify-code: código correcto tras intentos fallidos (< 5) → 200
- /recovery/reset-password: reset_token + new_password → 200 + password_hash cambiado
- /recovery/reset-password: actualiza password_changed_at → JWT previos invalidados
- /recovery/reset-password: token scope=pending_totp → 401
- /recovery/reset-password: token scope=full_access → 401
- /recovery/reset-password: new_password < 15 chars → 422

Ejecutar con: pytest tests/test_auth_recovery.py -v
"""
import sys
sys.path.insert(0, ".")

import jwt
import time
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker
from cryptography.fernet import Fernet

from tests.db_test_utils import make_test_engine

from src.api.auth import init_auth, create_token, hash_password
from src.api.dependencies import get_db
from src.config.models import ServerConfig
from src.database.models import Base, User
from src.api.registration_utils import (
    generate_recovery_code,
    hash_recovery_code,
)
from src.api.totp_utils import encrypt_secret, generate_totp_secret

# ── Constantes de test ────────────────────────────────────────────────────────

TEST_JWT_SECRET = "goatguard-test-secret-key-for-pytest-suite"
TEST_JWT_ALGORITHM = "HS256"
TEST_FERNET_KEY = Fernet.generate_key().decode()

_VALID_PASSWORD = "goatguard-pass-nist-ok"
_NEW_PASSWORD = "new-password-nist-compliant-15"


# ── Fixtures de infraestructura ───────────────────────────────────────────────

@pytest.fixture(scope="module", autouse=True)
def _init_auth():
    init_auth(
        jwt_secret=TEST_JWT_SECRET,
        jwt_algorithm=TEST_JWT_ALGORITHM,
        jwt_expiration_hours=1,
    )


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Resetea el storage del limiter entre tests para aislar contadores.

    /recovery/verify-code tiene límite 5/minute. Sin reset, los tests de
    intentos fallidos agotan el rate limit antes de que el test de 429
    pueda verificar el contador de BD.
    """
    from src.api.rate_limit import limiter
    limiter.reset()
    yield
    limiter.reset()


@pytest.fixture()
def db_session():
    engine = make_test_engine()
    Base.metadata.create_all(engine)
    TestingSession = sessionmaker(bind=engine)
    session = TestingSession()
    yield session
    session.close()
    Base.metadata.drop_all(engine)


@pytest.fixture()
def client_2fa(db_session):
    """TestClient con fernet_key inyectado y HIBP desactivado."""
    from src.api.app import create_app

    config = ServerConfig()
    config.security.jwt_secret = TEST_JWT_SECRET
    config.security.fernet_key = TEST_FERNET_KEY
    config.security.hibp_check_enabled = False

    class _FakeDatabase:
        def get_session(self):
            return db_session

        def create_tables(self, base):
            pass

    app = create_app(_FakeDatabase(), config)

    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db

    with TestClient(app, raise_server_exceptions=True) as test_client:
        yield test_client


# ── Fixtures de dominio ───────────────────────────────────────────────────────

@pytest.fixture()
def user_with_recovery(db_session):
    """User con totp_enabled=True y recovery_code_hash set.

    Devuelve (user, plain_recovery_code).
    """
    plain_recovery = generate_recovery_code()
    totp_secret = generate_totp_secret()
    user = User(
        username="recovery_user",
        password_hash=hash_password(_VALID_PASSWORD),
        totp_secret_enc=encrypt_secret(totp_secret, TEST_FERNET_KEY),
        totp_enabled=True,
        totp_enrolled_at=datetime.now(timezone.utc),
        recovery_code_hash=hash_recovery_code(plain_recovery),
        recovery_code_attempts=0,
        recovery_code_used=False,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user, plain_recovery


@pytest.fixture()
def reset_token(user_with_recovery):
    """JWT scope=password_reset para user_with_recovery."""
    user, _ = user_with_recovery
    return create_token(
        user_id=user.id,
        username=user.username,
        scope="password_reset",
        expiration_minutes=15,
    )


# ── Helper ────────────────────────────────────────────────────────────────────

def _post_recovery_verify(client, username: str, recovery_code: str):
    return client.post(
        "/auth/recovery/verify-code",
        json={"username": username, "recovery_code": recovery_code},
    )


# ── Tests: /recovery/verify-code ─────────────────────────────────────────────

class TestRecoveryVerifyCode:
    def test_recovery_verify_valid_code_returns_reset_token(
        self, client_2fa, user_with_recovery
    ):
        """Recovery code correcto → reset_token con scope=password_reset."""
        user, plain_code = user_with_recovery
        response = _post_recovery_verify(client_2fa, user.username, plain_code)
        assert response.status_code == 200
        body = response.json()
        assert "reset_token" in body
        payload = jwt.decode(
            body["reset_token"], TEST_JWT_SECRET, algorithms=[TEST_JWT_ALGORITHM]
        )
        assert payload["scope"] == "password_reset"
        assert payload["sub"] == str(user.id)

    def test_recovery_verify_wrong_code_increments_attempts(
        self, client_2fa, user_with_recovery, db_session
    ):
        """Código incorrecto → 400 + user.recovery_code_attempts += 1."""
        user, _ = user_with_recovery
        initial_attempts = user.recovery_code_attempts
        wrong_code = "AAAA-BBBB-CCCC-DDDD"

        response = _post_recovery_verify(client_2fa, user.username, wrong_code)
        assert response.status_code == 400
        assert response.json()["detail"] == "Credenciales de recuperación inválidas"

        db_session.refresh(user)
        assert user.recovery_code_attempts == initial_attempts + 1

    def test_recovery_verify_used_code_returns_400(
        self, client_2fa, user_with_recovery, db_session
    ):
        """recovery_code_used=True → 400 sin revelar estado interno."""
        user, plain_code = user_with_recovery
        user.recovery_code_used = True
        db_session.commit()

        response = _post_recovery_verify(client_2fa, user.username, plain_code)
        assert response.status_code == 400
        assert response.json()["detail"] == "Credenciales de recuperación inválidas"

    def test_recovery_verify_max_attempts_returns_429(
        self, client_2fa, user_with_recovery, db_session
    ):
        """5 intentos fallidos acumulados en BD → 429 Too Many Requests."""
        user, _ = user_with_recovery
        user.recovery_code_attempts = 5
        db_session.commit()

        wrong_code = "XXXX-XXXX-XXXX-XXXX"
        response = _post_recovery_verify(client_2fa, user.username, wrong_code)
        assert response.status_code == 429

    def test_recovery_verify_nonexistent_user_returns_400(self, client_2fa):
        """Username inexistente → 400 (timing-safe: no filtra existencia del user)."""
        response = _post_recovery_verify(
            client_2fa, "noexiste", "AAAA-BBBB-CCCC-DDDD"
        )
        assert response.status_code == 400
        assert response.json()["detail"] == "Credenciales de recuperación inválidas"

    def test_recovery_verify_valid_after_failed_attempts(
        self, client_2fa, user_with_recovery, db_session
    ):
        """Edge case: 3 intentos fallidos + código correcto → 200.

        El bloqueo solo ocurre al llegar a 5 intentos acumulados. Antes de
        ese límite, el código correcto debe seguir siendo aceptado.
        """
        user, plain_code = user_with_recovery
        user.recovery_code_attempts = 3
        db_session.commit()

        response = _post_recovery_verify(client_2fa, user.username, plain_code)
        assert response.status_code == 200
        assert "reset_token" in response.json()


# ── Tests: /recovery/reset-password ──────────────────────────────────────────

class TestRecoveryResetPassword:
    def test_recovery_reset_password_changes_hash(
        self, client_2fa, user_with_recovery, reset_token, db_session
    ):
        """reset_token + new_password válido → 200 + password_hash cambiado en BD."""
        user, _ = user_with_recovery
        original_hash = user.password_hash

        response = client_2fa.post(
            "/auth/recovery/reset-password",
            json={"new_password": _NEW_PASSWORD},
            headers={"Authorization": f"Bearer {reset_token}"},
        )
        assert response.status_code == 200
        assert "access_token" in response.json()

        db_session.refresh(user)
        assert user.password_hash != original_hash
        assert user.recovery_code_used is True
        assert user.recovery_code_hash is None

    def test_recovery_reset_password_invalidates_old_tokens(
        self, client_2fa, user_with_recovery, reset_token, db_session
    ):
        """password_changed_at se actualiza → JWT emitido antes rechazado con 401.

        El endpoint /devices requiere get_current_user que chequea
        password_changed_at vs iat del token.
        """
        user, _ = user_with_recovery

        # Token emitido ANTES del reset — simula una sesión activa robada.
        # time.sleep(1) garantiza que iat del token sea al menos 1s anterior a
        # password_changed_at, eliminando la condición de carrera donde ambos
        # timestamps caen en el mismo segundo de Unix.
        old_token = create_token(
            user_id=user.id,
            username=user.username,
            scope="full_access",
        )
        time.sleep(1)

        client_2fa.post(
            "/auth/recovery/reset-password",
            json={"new_password": _NEW_PASSWORD},
            headers={"Authorization": f"Bearer {reset_token}"},
        )
        db_session.refresh(user)
        assert user.password_changed_at is not None

        # El old_token debe ser rechazado en endpoints protegidos
        response = client_2fa.get(
            "/devices",
            headers={"Authorization": f"Bearer {old_token}"},
        )
        assert response.status_code == 401

    def test_recovery_reset_password_with_pending_totp_scope_fails(
        self, client_2fa, user_with_recovery
    ):
        """Token con scope=pending_totp (no password_reset) → 401."""
        user, _ = user_with_recovery
        wrong_token = create_token(
            user_id=user.id,
            username=user.username,
            scope="pending_totp",
            expiration_minutes=15,
        )
        response = client_2fa.post(
            "/auth/recovery/reset-password",
            json={"new_password": _NEW_PASSWORD},
            headers={"Authorization": f"Bearer {wrong_token}"},
        )
        assert response.status_code == 401

    def test_recovery_reset_password_with_full_access_scope_fails(
        self, client_2fa, user_with_recovery
    ):
        """Token scope=full_access no puede llamar reset-password → 401."""
        user, _ = user_with_recovery
        full_token = create_token(
            user_id=user.id,
            username=user.username,
            scope="full_access",
        )
        response = client_2fa.post(
            "/auth/recovery/reset-password",
            json={"new_password": _NEW_PASSWORD},
            headers={"Authorization": f"Bearer {full_token}"},
        )
        assert response.status_code == 401

    def test_recovery_reset_password_short_password_rejected(
        self, client_2fa, reset_token
    ):
        """new_password < 15 chars → 422 (Pydantic schema min_length=15)."""
        response = client_2fa.post(
            "/auth/recovery/reset-password",
            json={"new_password": "corta"},
            headers={"Authorization": f"Bearer {reset_token}"},
        )
        assert response.status_code == 422

    def test_recovery_reset_password_resets_attempts_counter(
        self, client_2fa, user_with_recovery, reset_token, db_session
    ):
        """Edge case: recovery_code_attempts se resetea a 0 tras reset exitoso."""
        user, _ = user_with_recovery
        user.recovery_code_attempts = 3
        db_session.commit()

        client_2fa.post(
            "/auth/recovery/reset-password",
            json={"new_password": _NEW_PASSWORD},
            headers={"Authorization": f"Bearer {reset_token}"},
        )
        db_session.refresh(user)
        assert user.recovery_code_attempts == 0
