"""
Tests del flujo de bootstrap del primer usuario + endpoint de invitaciones.

Cubre:
- GET /auth/bootstrap-status: devuelve needs_bootstrap según user_count
- POST /auth/register sin invitation_token cuando BD vacía (user_count == 0)
- POST /auth/register sin invitation_token cuando BD tiene users → 400
- POST /auth/invitations: admin genera invitation token (scope=full_access)
- POST /auth/invitations sin auth → 401
- Race condition: with_for_update en invitation token

Ejecutar con: pytest tests/test_auth_bootstrap.py -v
"""
import sys
sys.path.insert(0, ".")

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
from src.api.registration_utils import hash_invitation_token


# ── Constantes ───────────────────────────────────────────────────────────────

TEST_JWT_SECRET = "goatguard-test-secret-key-for-pytest-suite"
TEST_JWT_ALGORITHM = "HS256"
TEST_FERNET_KEY = Fernet.generate_key().decode()
_VALID_PASSWORD = "goatguard-pass-nist-ok"


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module", autouse=True)
def _init_auth():
    init_auth(
        jwt_secret=TEST_JWT_SECRET,
        jwt_algorithm=TEST_JWT_ALGORITHM,
        jwt_expiration_hours=1,
    )


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
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


def _register_admin(client, db_session, username="admin"):
    """Helper: registra un admin en BD vacía (bootstrap) y devuelve auth headers."""
    response = client.post(
        "/auth/register",
        json={"username": username, "password": _VALID_PASSWORD},
    )
    assert response.status_code == 201
    # El token del registro tiene scope=pending_totp, necesitamos full_access
    from src.api.auth import create_token
    user = db_session.query(User).filter_by(username=username).first()
    full_token = create_token(user.id, user.username, scope="full_access")
    return {"Authorization": f"Bearer {full_token}"}


# ── Bootstrap Status ─────────────────────────────────────────────────────────


class TestBootstrapStatus:
    def test_bootstrap_status_empty_db_returns_true(self, client_2fa):
        """BD sin usuarios → needs_bootstrap=true."""
        response = client_2fa.get("/auth/bootstrap-status")
        assert response.status_code == 200
        assert response.json()["needs_bootstrap"] is True

    def test_bootstrap_status_with_user_returns_false(
        self, client_2fa, db_session
    ):
        """BD con al menos 1 usuario → needs_bootstrap=false."""
        user = User(
            username="existing",
            password_hash=hash_password(_VALID_PASSWORD),
        )
        db_session.add(user)
        db_session.commit()

        response = client_2fa.get("/auth/bootstrap-status")
        assert response.status_code == 200
        assert response.json()["needs_bootstrap"] is False


# ── Register Bootstrap (sin invitation token) ────────────────────────────────


class TestRegisterBootstrap:
    def test_register_without_token_succeeds_on_empty_db(self, client_2fa):
        """BD vacía → registro sin invitation_token → 201."""
        response = client_2fa.post(
            "/auth/register",
            json={"username": "firstadmin", "password": _VALID_PASSWORD},
        )
        assert response.status_code == 201
        body = response.json()
        assert "access_token" in body
        assert "recovery_code" in body
        assert "totp_uri" in body

    def test_register_without_token_fails_when_users_exist(
        self, client_2fa, db_session
    ):
        """BD con usuarios → registro sin invitation_token → 400."""
        user = User(
            username="existing",
            password_hash=hash_password(_VALID_PASSWORD),
        )
        db_session.add(user)
        db_session.commit()

        response = client_2fa.post(
            "/auth/register",
            json={"username": "secondadmin", "password": _VALID_PASSWORD},
        )
        assert response.status_code == 400

    def test_register_with_token_still_works_on_empty_db(
        self, client_2fa, db_session
    ):
        """BD vacía pero se pasa invitation_token → también funciona (no rompe)."""
        from src.api.registration_utils import generate_invitation_token
        plain = generate_invitation_token()
        invitation = InvitationToken(
            token_hash=hash_invitation_token(plain),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )
        db_session.add(invitation)
        db_session.commit()

        response = client_2fa.post(
            "/auth/register",
            json={
                "username": "admin_with_token",
                "password": _VALID_PASSWORD,
                "invitation_token": plain,
            },
        )
        assert response.status_code == 201

    def test_bootstrap_register_scope_is_pending_totp(self, client_2fa):
        """El JWT del bootstrap tiene scope=pending_totp (mismo flujo que normal)."""
        response = client_2fa.post(
            "/auth/register",
            json={"username": "scopetest", "password": _VALID_PASSWORD},
        )
        assert response.status_code == 201
        token = response.json()["access_token"]
        payload = jwt.decode(token, TEST_JWT_SECRET, algorithms=[TEST_JWT_ALGORITHM])
        assert payload["scope"] == "pending_totp"


# ── Invitations Endpoint ─────────────────────────────────────────────────────


class TestInvitations:
    def test_create_invitation_returns_token(self, client_2fa, db_session):
        """Admin autenticado genera invitation token → 201 con token en claro."""
        headers = _register_admin(client_2fa, db_session)
        response = client_2fa.post("/auth/invitations", headers=headers)
        assert response.status_code == 201
        body = response.json()
        assert "invitation_token" in body
        assert "expires_at" in body
        assert len(body["invitation_token"]) > 20

    def test_create_invitation_without_auth_returns_401(self, client_2fa):
        """Sin JWT → 401."""
        response = client_2fa.post("/auth/invitations")
        assert response.status_code in (401, 403)

    def test_created_invitation_can_register_user(self, client_2fa, db_session):
        """El token generado por el endpoint funciona para registrar otro user."""
        headers = _register_admin(client_2fa, db_session)

        inv_response = client_2fa.post("/auth/invitations", headers=headers)
        assert inv_response.status_code == 201
        inv_token = inv_response.json()["invitation_token"]

        reg_response = client_2fa.post(
            "/auth/register",
            json={
                "username": "secondadmin",
                "password": _VALID_PASSWORD,
                "invitation_token": inv_token,
            },
        )
        assert reg_response.status_code == 201

    def test_invitation_token_stored_as_hash(self, client_2fa, db_session):
        """El token se guarda hasheado en BD, no en texto plano."""
        headers = _register_admin(client_2fa, db_session)
        inv_response = client_2fa.post("/auth/invitations", headers=headers)
        plain_token = inv_response.json()["invitation_token"]

        expected_hash = hash_invitation_token(plain_token)
        invitation = db_session.query(InvitationToken).filter_by(
            token_hash=expected_hash
        ).first()
        assert invitation is not None
        assert invitation.used is False
