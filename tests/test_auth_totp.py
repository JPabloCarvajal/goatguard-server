"""
Tests E2E del flujo TOTP [RF-13]: login paso 1 y verificación de segundo factor.

Cubre:
- Login devuelve pending_totp para usuario con totp_enabled=True
- Login rechaza password incorrecto y usuario inexistente (timing-safe)
- Login con user en pre-enrollment devuelve needs_enrollment=True
- /totp/verify acepta código válido y devuelve full_access
- /totp/verify rechaza código inválido → 401
- /totp/verify rechaza JWT full_access con 403 (scope enforcement)
- /totp/verify sin header → 401 (HTTPBearer)
- /totp/verify-backup acepta backup code válido → full_access
- /totp/verify-backup rechaza backup code ya marcado used → 401
- /totp/verify-backup rechaza JWT full_access con 403
- /totp/enroll/verify activa TOTP (totp_enabled=True) y devuelve 10 backup_codes
- /totp/enroll/verify rechaza usuario ya enrollado → 400

Ejecutar con: pytest tests/test_auth_totp.py -v
"""
import sys
sys.path.insert(0, ".")

import jwt
import pyotp
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker
from cryptography.fernet import Fernet

from tests.db_test_utils import make_test_engine

from src.api.auth import init_auth, create_token, hash_password
from src.api.dependencies import get_db
from src.config.models import ServerConfig
from src.database.models import Base, User, TotpBackupCode
from src.api.totp_utils import (
    encrypt_secret,
    generate_totp_secret,
    generate_backup_codes,
    hash_backup_code,
)

# ── Constantes de test ────────────────────────────────────────────────────────

TEST_JWT_SECRET = "goatguard-test-secret-key-for-pytest-suite"
TEST_JWT_ALGORITHM = "HS256"
TEST_FERNET_KEY = Fernet.generate_key().decode()

_VALID_PASSWORD = "goatguard-pass-nist-ok"


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

    Sin este reset, los tests que disparan errores de autenticacion agotan
    los limites de /auth/login (10/min) y /auth/totp/* (5-10/min), haciendo
    que tests posteriores reciban 429 en lugar del codigo real esperado.
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
def enrolled_user(db_session):
    """User con TOTP enrollado (totp_enabled=True) en BD.

    Adjunta _plain_totp_secret para que los tests generen codigos con pyotp.
    """
    totp_secret = generate_totp_secret()
    encrypted = encrypt_secret(totp_secret, TEST_FERNET_KEY)
    user = User(
        username="totp_user",
        password_hash=hash_password(_VALID_PASSWORD),
        totp_secret_enc=encrypted,
        totp_enabled=True,
        totp_enrolled_at=datetime.now(timezone.utc),
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    user._plain_totp_secret = totp_secret
    return user


@pytest.fixture()
def pre_enrollment_user(db_session):
    """User con totp_secret_enc pero sin enrollment (totp_enrolled_at=None).

    Estado post-registro, antes de completar el primer TOTP.
    """
    totp_secret = generate_totp_secret()
    encrypted = encrypt_secret(totp_secret, TEST_FERNET_KEY)
    user = User(
        username="pre_enroll_user",
        password_hash=hash_password(_VALID_PASSWORD),
        totp_secret_enc=encrypted,
        totp_enabled=False,
        totp_enrolled_at=None,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    user._plain_totp_secret = totp_secret
    return user


@pytest.fixture()
def pending_totp_token(enrolled_user):
    """JWT scope=pending_totp para el enrolled_user."""
    return create_token(
        user_id=enrolled_user.id,
        username=enrolled_user.username,
        scope="pending_totp",
        expiration_minutes=10,
    )


@pytest.fixture()
def full_access_token(enrolled_user):
    """JWT scope=full_access para el enrolled_user."""
    return create_token(
        user_id=enrolled_user.id,
        username=enrolled_user.username,
        scope="full_access",
    )


@pytest.fixture()
def backup_code_for_user(db_session, enrolled_user):
    """Inserta un backup code en BD para enrolled_user y devuelve el plain code."""
    plain_codes = generate_backup_codes(1)
    plain_code = plain_codes[0]
    db_session.add(
        TotpBackupCode(
            user_id=enrolled_user.id,
            code_hash=hash_backup_code(plain_code),
        )
    )
    db_session.commit()
    return plain_code


# ── Tests: Login paso 1 ───────────────────────────────────────────────────────

class TestLogin:
    def test_login_returns_pending_totp_for_enrolled_user(
        self, client_2fa, enrolled_user
    ):
        """Login con user totp_enabled=True devuelve pending_totp + totp_required=True."""
        response = client_2fa.post(
            "/auth/login",
            json={"username": "totp_user", "password": _VALID_PASSWORD},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["totp_required"] is True
        payload = jwt.decode(
            body["access_token"], TEST_JWT_SECRET, algorithms=[TEST_JWT_ALGORITHM]
        )
        assert payload["scope"] == "pending_totp"

    def test_login_wrong_password_returns_401(self, client_2fa, enrolled_user):
        """Password incorrecto devuelve 401 con mensaje generico."""
        response = client_2fa.post(
            "/auth/login",
            json={"username": "totp_user", "password": "wrong-password-here"},
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "Credenciales inválidas"

    def test_login_nonexistent_user_returns_401(self, client_2fa):
        """Username inexistente devuelve 401 (timing-safe: ejecuta bcrypt dummy)."""
        response = client_2fa.post(
            "/auth/login",
            json={"username": "noexiste", "password": "any-password-for-test"},
        )
        assert response.status_code == 401

    def test_login_pre_enrollment_returns_needs_enrollment_true(
        self, client_2fa, pre_enrollment_user
    ):
        """User con secret pero sin enrollment completo devuelve needs_enrollment=True."""
        response = client_2fa.post(
            "/auth/login",
            json={"username": "pre_enroll_user", "password": _VALID_PASSWORD},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["totp_required"] is True
        assert body["needs_enrollment"] is True


# ── Tests: /totp/verify ───────────────────────────────────────────────────────

class TestTotpVerify:
    def test_totp_verify_valid_code_returns_full_access(
        self, client_2fa, enrolled_user, pending_totp_token
    ):
        """Codigo TOTP correcto + pending_totp token devuelve full_access token."""
        valid_code = pyotp.TOTP(enrolled_user._plain_totp_secret).now()
        response = client_2fa.post(
            "/auth/totp/verify",
            json={"code": valid_code},
            headers={"Authorization": f"Bearer {pending_totp_token}"},
        )
        assert response.status_code == 200
        payload = jwt.decode(
            response.json()["access_token"],
            TEST_JWT_SECRET,
            algorithms=[TEST_JWT_ALGORITHM],
        )
        assert payload["scope"] == "full_access"

    def test_totp_verify_invalid_code_returns_401(
        self, client_2fa, enrolled_user, pending_totp_token
    ):
        """Codigo TOTP incorrecto devuelve 401."""
        response = client_2fa.post(
            "/auth/totp/verify",
            json={"code": "000000"},
            headers={"Authorization": f"Bearer {pending_totp_token}"},
        )
        assert response.status_code == 401

    def test_totp_verify_rejects_full_access_token_with_403(
        self, client_2fa, enrolled_user, full_access_token
    ):
        """JWT full_access enviado a /totp/verify devuelve 403 (scope enforcement) [RF-13]."""
        valid_code = pyotp.TOTP(enrolled_user._plain_totp_secret).now()
        response = client_2fa.post(
            "/auth/totp/verify",
            json={"code": valid_code},
            headers={"Authorization": f"Bearer {full_access_token}"},
        )
        assert response.status_code == 403

    def test_totp_verify_without_auth_header_returns_401(self, client_2fa):
        """Sin Authorization header, HTTPBearer devuelve 401 antes del endpoint."""
        response = client_2fa.post(
            "/auth/totp/verify",
            json={"code": "123456"},
        )
        assert response.status_code == 401


# ── Tests: /totp/verify-backup ────────────────────────────────────────────────

class TestTotpVerifyBackup:
    def test_totp_verify_backup_valid_code_returns_full_access(
        self, client_2fa, enrolled_user, pending_totp_token, backup_code_for_user
    ):
        """Backup code valido + pending_totp devuelve full_access token."""
        response = client_2fa.post(
            "/auth/totp/verify-backup",
            json={"backup_code": backup_code_for_user},
            headers={"Authorization": f"Bearer {pending_totp_token}"},
        )
        assert response.status_code == 200
        payload = jwt.decode(
            response.json()["access_token"],
            TEST_JWT_SECRET,
            algorithms=[TEST_JWT_ALGORITHM],
        )
        assert payload["scope"] == "full_access"

    def test_totp_verify_backup_used_code_returns_401(
        self,
        client_2fa,
        enrolled_user,
        pending_totp_token,
        backup_code_for_user,
        db_session,
    ):
        """Backup code ya marcado used=True devuelve 401."""
        db_backup = (
            db_session.query(TotpBackupCode)
            .filter_by(user_id=enrolled_user.id, used=False)
            .first()
        )
        db_backup.used = True
        db_backup.used_at = datetime.now(timezone.utc)
        db_session.commit()

        response = client_2fa.post(
            "/auth/totp/verify-backup",
            json={"backup_code": backup_code_for_user},
            headers={"Authorization": f"Bearer {pending_totp_token}"},
        )
        assert response.status_code == 401

    def test_totp_verify_backup_rejects_full_access_token_with_403(
        self, client_2fa, enrolled_user, full_access_token, backup_code_for_user
    ):
        """JWT full_access enviado a /totp/verify-backup devuelve 403 (scope enforcement)."""
        response = client_2fa.post(
            "/auth/totp/verify-backup",
            json={"backup_code": backup_code_for_user},
            headers={"Authorization": f"Bearer {full_access_token}"},
        )
        assert response.status_code == 403

    def test_totp_verify_backup_invalid_format_rejected(
        self, client_2fa, pending_totp_token
    ):
        """Edge case: backup code demasiado largo devuelve 422 por schema max_length=14."""
        response = client_2fa.post(
            "/auth/totp/verify-backup",
            json={"backup_code": "TOOLONG-CODE-HERE-EXTRA"},
            headers={"Authorization": f"Bearer {pending_totp_token}"},
        )
        assert response.status_code == 422


# ── Tests: /totp/enroll/verify ────────────────────────────────────────────────

class TestTotpEnrollVerify:
    def test_totp_enroll_verify_activates_totp_and_returns_backup_codes(
        self, client_2fa, pre_enrollment_user, db_session
    ):
        """Primer TOTP verificado activa totp_enabled=True y devuelve 10 backup_codes."""
        token = create_token(
            user_id=pre_enrollment_user.id,
            username=pre_enrollment_user.username,
            scope="pending_totp",
            expiration_minutes=60,
        )
        valid_code = pyotp.TOTP(pre_enrollment_user._plain_totp_secret).now()
        response = client_2fa.post(
            "/auth/totp/enroll/verify",
            json={"code": valid_code},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        codes = response.json()["backup_codes"]
        assert len(codes) == 10
        # Verificar formato XXXX-XXXX-XXXX (14 chars, 3 segmentos de 4)
        for code in codes:
            assert len(code) == 14
            parts = code.split("-")
            assert len(parts) == 3
            assert all(len(p) == 4 for p in parts)

        db_session.refresh(pre_enrollment_user)
        assert pre_enrollment_user.totp_enabled is True
        assert pre_enrollment_user.totp_enrolled_at is not None

    def test_totp_enroll_verify_rejects_already_enrolled_user(
        self, client_2fa, enrolled_user, pending_totp_token
    ):
        """Llamar enroll/verify con user ya enrollado (totp_enrolled_at set) devuelve 400."""
        valid_code = pyotp.TOTP(enrolled_user._plain_totp_secret).now()
        response = client_2fa.post(
            "/auth/totp/enroll/verify",
            json={"code": valid_code},
            headers={"Authorization": f"Bearer {pending_totp_token}"},
        )
        assert response.status_code == 400
