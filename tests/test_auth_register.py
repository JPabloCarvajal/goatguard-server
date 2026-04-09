"""
Tests E2E del endpoint POST /auth/register [RF-13].

Cubre:
- Happy path: invitation válida + password NIST → 201 con datos TOTP completos
- Invitation token inválida, ya usada, y expirada → 400 _REGISTER_FAIL
- Username duplicado → 400 (respuesta genérica por seguridad)
- Password que no cumple NIST → 422 (Pydantic schema)
- El JWT devuelto tiene scope=pending_totp
- La BD refleja correctamente el estado post-registro (totp_secret_enc, invitation.used)

Edge case: usar la misma invitation token dos veces — la segunda falla con 400.

Cada test es autocontenido: usa fixtures locales.
Ejecutar con: pytest tests/test_auth_register.py -v
"""
import sys
sys.path.insert(0, ".")

import base64
import jwt
import pytest
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker
from cryptography.fernet import Fernet

from tests.db_test_utils import make_test_engine

from src.api.auth import init_auth, hash_password
from src.api.dependencies import get_db
from src.config.models import ServerConfig
from src.database.models import Base, InvitationToken, User
from src.api.registration_utils import (
    generate_invitation_token,
    hash_invitation_token,
)

# ── Constantes de test ────────────────────────────────────────────────────────

TEST_JWT_SECRET = "goatguard-test-secret-key-for-pytest-suite"
TEST_JWT_ALGORITHM = "HS256"
TEST_FERNET_KEY = Fernet.generate_key().decode()

# Password que cumple NIST SP 800-63B (≥15 chars, ≤128)
_VALID_PASSWORD = "goatguard-pass-nist-ok"


# ── Fixtures de infraestructura ───────────────────────────────────────────────

@pytest.fixture(scope="module", autouse=True)
def _init_auth():
    """Inicializa el módulo auth con el secret de test para toda la suite."""
    init_auth(
        jwt_secret=TEST_JWT_SECRET,
        jwt_algorithm=TEST_JWT_ALGORITHM,
        jwt_expiration_hours=1,
    )


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Resetea el storage del limiter entre tests para aislar contadores.

    slowapi usa un singleton de módulo con estado en memoria. Sin reset,
    los tests que llaman /auth/register múltiples veces agotan el límite
    (5/minute) y los tests siguientes reciben 429 en lugar del código real.
    """
    from src.api.rate_limit import limiter
    limiter.reset()
    yield
    limiter.reset()


@pytest.fixture()
def db_session():
    """Engine SQLite in-memory aislado por función de test."""
    engine = make_test_engine()
    Base.metadata.create_all(engine)
    TestingSession = sessionmaker(bind=engine)
    session = TestingSession()
    yield session
    session.close()
    Base.metadata.drop_all(engine)


@pytest.fixture()
def client_2fa(db_session):
    """TestClient con SecurityConfig inyectado (fernet_key + hibp_check_enabled=False).

    Extiende el patrón de conftest.py con las dos líneas extra necesarias
    para que los endpoints TOTP puedan cifrar secretos.
    """
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


@pytest.fixture()
def invitation_token_factory(db_session):
    """Fábrica que inserta una InvitationToken en BD y devuelve el plain token.

    Parámetros:
        used: si la invitation ya fue marcada como usada
        expires_in_hours: offset en horas desde ahora (negativo = expirada)
    """
    def _make(used: bool = False, expires_in_hours: int = 24) -> str:
        plain = generate_invitation_token()
        token_hash = hash_invitation_token(plain)
        now = datetime.now(timezone.utc)
        invitation = InvitationToken(
            token_hash=token_hash,
            expires_at=now + timedelta(hours=expires_in_hours),
            used=used,
        )
        db_session.add(invitation)
        db_session.commit()
        return plain

    return _make


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestRegisterSuccess:
    def test_register_success_returns_201_with_totp_data(
        self, client_2fa, invitation_token_factory
    ):
        """Happy path: invitation válida + password NIST → 201 con todos los campos."""
        plain_token = invitation_token_factory()
        response = client_2fa.post(
            "/auth/register",
            json={
                "username": "newadmin",
                "password": _VALID_PASSWORD,
                "invitation_token": plain_token,
            },
        )
        assert response.status_code == 201
        body = response.json()
        assert "access_token" in body
        assert "recovery_code" in body
        assert "totp_uri" in body
        assert "qr_png_base64" in body
        # El QR debe ser base64 válido y decodificar a un PNG
        decoded = base64.b64decode(body["qr_png_base64"])
        assert decoded[:4] == b"\x89PNG"

    def test_register_token_scope_is_pending_totp(
        self, client_2fa, invitation_token_factory
    ):
        """El JWT devuelto tras registro tiene scope=pending_totp [RF-13]."""
        plain_token = invitation_token_factory()
        response = client_2fa.post(
            "/auth/register",
            json={
                "username": "scopecheck",
                "password": _VALID_PASSWORD,
                "invitation_token": plain_token,
            },
        )
        assert response.status_code == 201
        token = response.json()["access_token"]
        payload = jwt.decode(token, TEST_JWT_SECRET, algorithms=[TEST_JWT_ALGORITHM])
        assert payload["scope"] == "pending_totp"
        assert payload["username"] == "scopecheck"

    def test_register_creates_user_with_encrypted_totp_secret(
        self, client_2fa, invitation_token_factory, db_session
    ):
        """Tras registro, el user en BD tiene totp_secret_enc no vacío y totp_enabled=False."""
        plain_token = invitation_token_factory()
        response = client_2fa.post(
            "/auth/register",
            json={
                "username": "totpcheck",
                "password": _VALID_PASSWORD,
                "invitation_token": plain_token,
            },
        )
        assert response.status_code == 201
        user = db_session.query(User).filter_by(username="totpcheck").first()
        assert user is not None
        assert user.totp_secret_enc is not None
        assert len(user.totp_secret_enc) > 0
        assert user.totp_enabled is False

    def test_register_marks_invitation_as_used(
        self, client_2fa, invitation_token_factory, db_session
    ):
        """Tras registro exitoso, invitation.used=True y invitation.used_at no es None."""
        plain_token = invitation_token_factory()
        token_hash = hash_invitation_token(plain_token)
        client_2fa.post(
            "/auth/register",
            json={
                "username": "usedtoken",
                "password": _VALID_PASSWORD,
                "invitation_token": plain_token,
            },
        )
        invitation = db_session.query(InvitationToken).filter_by(
            token_hash=token_hash
        ).first()
        assert invitation.used is True
        assert invitation.used_at is not None


class TestRegisterFailures:
    def test_register_invalid_invitation_returns_400(self, client_2fa):
        """Token inexistente en BD → 400 con mensaje genérico _REGISTER_FAIL."""
        response = client_2fa.post(
            "/auth/register",
            json={
                "username": "hacker",
                "password": _VALID_PASSWORD,
                "invitation_token": "token-que-no-existe-en-la-bd",
            },
        )
        assert response.status_code == 400
        assert response.json()["detail"] == "No se pudo completar el registro"

    def test_register_used_invitation_returns_400(
        self, client_2fa, invitation_token_factory
    ):
        """Invitation marcada used=True → 400, no revela estado interno."""
        plain_token = invitation_token_factory(used=True)
        response = client_2fa.post(
            "/auth/register",
            json={
                "username": "replay",
                "password": _VALID_PASSWORD,
                "invitation_token": plain_token,
            },
        )
        assert response.status_code == 400
        assert response.json()["detail"] == "No se pudo completar el registro"

    def test_register_expired_invitation_returns_400(
        self, client_2fa, invitation_token_factory
    ):
        """Invitation con expires_at en el pasado → 400."""
        plain_token = invitation_token_factory(expires_in_hours=-1)
        response = client_2fa.post(
            "/auth/register",
            json={
                "username": "expired",
                "password": _VALID_PASSWORD,
                "invitation_token": plain_token,
            },
        )
        assert response.status_code == 400
        assert response.json()["detail"] == "No se pudo completar el registro"

    def test_register_duplicate_username_returns_400(
        self, client_2fa, invitation_token_factory, db_session
    ):
        """Username ya existente → 400 (NO 409: respuesta genérica por seguridad)."""
        existing = User(
            username="existingadmin",
            password_hash=hash_password(_VALID_PASSWORD),
        )
        db_session.add(existing)
        db_session.commit()

        plain_token = invitation_token_factory()
        response = client_2fa.post(
            "/auth/register",
            json={
                "username": "existingadmin",
                "password": _VALID_PASSWORD,
                "invitation_token": plain_token,
            },
        )
        assert response.status_code == 400
        assert response.json()["detail"] == "No se pudo completar el registro"

    def test_register_short_password_rejected_by_schema(
        self, client_2fa, invitation_token_factory
    ):
        """Password < 15 chars viola min_length del schema Pydantic → 422."""
        plain_token = invitation_token_factory()
        response = client_2fa.post(
            "/auth/register",
            json={
                "username": "shortpwd",
                "password": "corta",
                "invitation_token": plain_token,
            },
        )
        assert response.status_code == 422

    def test_register_password_exactly_14_chars_rejected(
        self, client_2fa, invitation_token_factory
    ):
        """Edge case: 14 chars (límite NIST - 1) → 422 por Pydantic min_length=15."""
        plain_token = invitation_token_factory()
        response = client_2fa.post(
            "/auth/register",
            json={
                "username": "boundary",
                "password": "A" * 14,
                "invitation_token": plain_token,
            },
        )
        assert response.status_code == 422

    def test_register_same_invitation_twice_second_fails(
        self, client_2fa, invitation_token_factory
    ):
        """Edge case: misma invitation en dos requests → segunda falla con 400.

        Verifica que el marcado used=True es atómico y persistente.
        """
        plain_token = invitation_token_factory()
        client_2fa.post(
            "/auth/register",
            json={
                "username": "first_user",
                "password": _VALID_PASSWORD,
                "invitation_token": plain_token,
            },
        )
        response2 = client_2fa.post(
            "/auth/register",
            json={
                "username": "second_user",
                "password": _VALID_PASSWORD,
                "invitation_token": plain_token,
            },
        )
        assert response2.status_code == 400
        assert response2.json()["detail"] == "No se pudo completar el registro"
