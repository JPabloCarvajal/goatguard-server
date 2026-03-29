"""
Tests de registro con Invitation Token y login [RF-13].

Cubre:
- TC-R1 a TC-R11: flujo de registro (POST /auth/register)
- TC-L1 a TC-L3:  flujo de login (POST /auth/login)
"""
import sys
sys.path.insert(0, ".")

import base64
from datetime import datetime, timedelta, timezone

import jwt

from src.api.registration_utils import (
    generate_invitation_token, hash_invitation_token,
)
from src.database.models import InvitationToken, User
from tests.conftest import TEST_JWT_SECRET, TEST_JWT_ALGORITHM, TEST_FERNET_KEY


# ── Helpers ───────────────────────────────────────────────────────────────────

VALID_PASSWORD = "SecurePassword2025!"   # 21 chars, cumple NIST min=15
VALID_USERNAME = "newadmin"


def _make_register_payload(
    invitation_token: str,
    username: str = VALID_USERNAME,
    password: str = VALID_PASSWORD,
) -> dict:
    return {
        "username": username,
        "password": password,
        "invitation_token": invitation_token,
    }


# ── TC-R1: Bootstrap genera invitation_token cuando no hay admins ─────────────

class TestBootstrapInvitationToken:

    def test_bootstrap_creates_token_when_no_admins(self, db_session):
        """TC-R1: BD vacía → bootstrap genera un InvitationToken."""
        from run_api import _bootstrap_first_admin

        assert db_session.query(User).count() == 0
        _bootstrap_first_admin(db_session)

        tokens = db_session.query(InvitationToken).all()
        assert len(tokens) == 1
        assert tokens[0].used is False
        # SQLite almacena naive — comparar como naive
        assert tokens[0].expires_at > datetime.utcnow()

    def test_bootstrap_skips_when_admin_exists(self, db_session):
        """TC-R1 variante: Si ya hay admin, no crea token."""
        from run_api import _bootstrap_first_admin
        from src.api.auth import hash_password

        db_session.add(User(
            username="existing_admin",
            password_hash=hash_password("password123"),
        ))
        db_session.commit()

        _bootstrap_first_admin(db_session)
        assert db_session.query(InvitationToken).count() == 0


# ── TC-R2 a TC-R7: Validación de inputs ──────────────────────────────────────

class TestRegisterValidation:

    def test_missing_invitation_token_returns_422(self, client):
        """TC-R2: Body sin invitation_token → 422."""
        response = client.post("/auth/register", json={
            "username": VALID_USERNAME,
            "password": VALID_PASSWORD,
        })
        assert response.status_code == 422

    def test_password_below_minimum_returns_422(self, client, invitation_token):
        """TC-R6: Contraseña < 15 chars → 422."""
        response = client.post("/auth/register", json=_make_register_payload(
            invitation_token=invitation_token,
            password="Short1!",
        ))
        assert response.status_code == 422

    def test_password_above_maximum_returns_422(self, client, invitation_token):
        """TC-R7: Contraseña > 128 chars → 422."""
        response = client.post("/auth/register", json=_make_register_payload(
            invitation_token=invitation_token,
            password="A" * 129,
        ))
        assert response.status_code == 422


# ── TC-R3: Token inválido → 400 ──────────────────────────────────────────────

class TestRegisterInvalidToken:

    def test_invalid_invitation_token_returns_400(self, client):
        """TC-R3: Token inexistente → 400."""
        response = client.post("/auth/register", json=_make_register_payload(
            invitation_token="totally-invalid-token",
        ))
        assert response.status_code == 400


# ── TC-R4: Token expirado → 400 ──────────────────────────────────────────────

class TestRegisterExpiredToken:

    def test_expired_invitation_token_returns_400(self, client, db_session):
        """TC-R4: Token expirado → 400."""
        plain_token = generate_invitation_token()
        inv = InvitationToken(
            token_hash=hash_invitation_token(plain_token),
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        db_session.add(inv)
        db_session.commit()

        response = client.post("/auth/register", json=_make_register_payload(
            invitation_token=plain_token,
        ))
        assert response.status_code == 400


# ── TC-R5: Token ya usado → 400 ──────────────────────────────────────────────

class TestRegisterUsedToken:

    def test_already_used_token_returns_400(self, client, db_session):
        """TC-R5: Token con used=True → 400."""
        plain_token = generate_invitation_token()
        inv = InvitationToken(
            token_hash=hash_invitation_token(plain_token),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
            used=True,
            used_at=datetime.now(timezone.utc),
        )
        db_session.add(inv)
        db_session.commit()

        response = client.post("/auth/register", json=_make_register_payload(
            invitation_token=plain_token,
        ))
        assert response.status_code == 400


# ── TC-R8: Registro exitoso → 201 ────────────────────────────────────────────

class TestRegisterSuccess:

    def test_successful_register_returns_201_with_all_fields(
        self, client, invitation_token,
    ):
        """TC-R8: Registro OK → 201 con todos los campos de RegisterResponse."""
        response = client.post("/auth/register", json=_make_register_payload(
            invitation_token=invitation_token,
        ))

        assert response.status_code == 201
        body = response.json()
        assert "access_token" in body
        assert "recovery_code" in body
        assert "totp_uri" in body
        assert "qr_png_base64" in body
        assert body["username"] == VALID_USERNAME
        assert body["token_type"] == "bearer"

    def test_jwt_has_pending_totp_scope(self, client, invitation_token):
        """TC-R8: JWT retornado tiene scope=pending_totp."""
        response = client.post("/auth/register", json=_make_register_payload(
            invitation_token=invitation_token,
        ))
        token = response.json()["access_token"]
        payload = jwt.decode(token, TEST_JWT_SECRET, algorithms=[TEST_JWT_ALGORITHM])
        assert payload["scope"] == "pending_totp"

    def test_totp_uri_format(self, client, invitation_token):
        """TC-R8: totp_uri tiene formato otpauth://totp/ con issuer GOATGuard."""
        response = client.post("/auth/register", json=_make_register_payload(
            invitation_token=invitation_token,
        ))
        totp_uri = response.json()["totp_uri"]
        assert totp_uri.startswith("otpauth://totp/")
        assert "GOATGuard" in totp_uri

    def test_qr_is_valid_png_base64(self, client, invitation_token):
        """TC-R8: qr_png_base64 decodifica a PNG válido."""
        response = client.post("/auth/register", json=_make_register_payload(
            invitation_token=invitation_token,
        ))
        raw = base64.b64decode(response.json()["qr_png_base64"])
        assert raw[:4] == b"\x89PNG"

    def test_invitation_marked_as_used(self, client, invitation_token, db_session):
        """TC-R8: InvitationToken queda used=True en BD."""
        client.post("/auth/register", json=_make_register_payload(
            invitation_token=invitation_token,
        ))
        token_hash = hash_invitation_token(invitation_token)
        inv = db_session.query(InvitationToken).filter_by(token_hash=token_hash).first()
        assert inv.used is True
        assert inv.used_at is not None


# ── TC-R9: Username duplicado → 409 ──────────────────────────────────────────

class TestRegisterDuplicateUsername:

    def test_duplicate_username_returns_409(self, client, db_session, invitation_token):
        """TC-R9: Username existente → 409."""
        from src.api.auth import hash_password

        db_session.add(User(
            username=VALID_USERNAME,
            password_hash=hash_password("OtherPassword2025!"),
        ))
        db_session.commit()

        response = client.post("/auth/register", json=_make_register_payload(
            invitation_token=invitation_token,
        ))
        assert response.status_code == 409


# ── TC-R10: Recovery code en response, hash en BD ────────────────────────────

class TestRegisterRecoveryCode:

    def test_recovery_code_in_response_and_hashed_in_db(
        self, client, invitation_token, db_session,
    ):
        """TC-R10: recovery_code en texto plano en response, bcrypt hash en BD."""
        response = client.post("/auth/register", json=_make_register_payload(
            invitation_token=invitation_token,
        ))
        assert response.status_code == 201
        plain_code = response.json()["recovery_code"]

        # Formato XXXX-XXXX-XXXX-XXXX
        parts = plain_code.split("-")
        assert len(parts) == 4
        assert all(len(p) == 4 for p in parts)

        # Hash en BD, no texto plano
        user = db_session.query(User).filter_by(username=VALID_USERNAME).first()
        assert user.recovery_code_hash is not None
        assert plain_code not in user.recovery_code_hash

        from src.api.registration_utils import verify_recovery_code
        assert verify_recovery_code(plain_code, user.recovery_code_hash) is True


# ── TC-R11: HIBP comprometida (mock) → 400 ───────────────────────────────────

class TestRegisterHibpCheck:

    def test_compromised_password_returns_400(
        self, db_session, invitation_token, monkeypatch,
    ):
        """TC-R11: Password en HIBP (mockeado) → 400."""
        from src.api.app import create_app
        from src.api.dependencies import get_db
        from src.config.models import ServerConfig

        config = ServerConfig()
        config.security.jwt_secret = TEST_JWT_SECRET
        config.security.fernet_key = TEST_FERNET_KEY
        config.security.hibp_check_enabled = True

        class _FakeDatabase:
            def get_session(self):
                return db_session
            def create_tables(self, base):
                pass

        app = create_app(_FakeDatabase(), config)
        app.dependency_overrides[get_db] = lambda: (yield db_session).__next__() or db_session

        def _override():
            yield db_session
        app.dependency_overrides[get_db] = _override

        def _mock_hibp(password: str) -> bool:
            return True

        monkeypatch.setattr("src.api.routes.auth.check_password_hibp", _mock_hibp)

        from fastapi.testclient import TestClient
        with TestClient(app, raise_server_exceptions=True) as hibp_client:
            response = hibp_client.post(
                "/auth/register",
                json=_make_register_payload(invitation_token=invitation_token),
            )
        assert response.status_code == 400
        assert "comprometida" in response.json()["detail"].lower()


# ── TC-L1: Login sin TOTP → full_access ──────────────────────────────────────

class TestLoginNoTotp:

    def test_legacy_user_gets_full_access(self, client, seed_data):
        """TC-L1: User sin TOTP → TokenResponse scope=full_access."""
        response = client.post("/auth/login", json={
            "username": "admin",
            "password": "password123",
        })
        assert response.status_code == 200
        body = response.json()
        assert "access_token" in body
        assert "totp_required" not in body

        payload = jwt.decode(body["access_token"], TEST_JWT_SECRET, algorithms=[TEST_JWT_ALGORITHM])
        assert payload["scope"] == "full_access"


# ── TC-L2: Credenciales incorrectas → 401 ────────────────────────────────────

class TestLoginWrongCredentials:

    def test_wrong_password_returns_401(self, client, seed_data):
        """TC-L2: Password incorrecto → 401."""
        response = client.post("/auth/login", json={
            "username": "admin",
            "password": "wrongpassword",
        })
        assert response.status_code == 401

    def test_nonexistent_user_returns_401(self, client, seed_data):
        """TC-L2: Usuario inexistente → 401 mismo mensaje."""
        response = client.post("/auth/login", json={
            "username": "ghost_user",
            "password": "password123",
        })
        assert response.status_code == 401

    def test_error_messages_are_identical(self, client, seed_data):
        """Seguridad: misma respuesta para user inexistente y password malo."""
        r1 = client.post("/auth/login", json={"username": "ghost", "password": "x"})
        r2 = client.post("/auth/login", json={"username": "admin", "password": "x"})
        assert r1.json()["detail"] == r2.json()["detail"]


# ── TC-L3: Login con TOTP → pending_totp ─────────────────────────────────────

class TestLoginWithTotp:

    def test_totp_enabled_user_gets_pending_totp(self, client, db_session):
        """TC-L3: User con totp_enabled=True → LoginStep1Response."""
        from src.api.auth import hash_password

        db_session.add(User(
            username="totp_admin",
            password_hash=hash_password("SecurePassword2025!"),
            totp_enabled=True,
            totp_secret_enc="encrypted_placeholder",
            totp_enrolled_at=datetime.utcnow(),
        ))
        db_session.commit()

        response = client.post("/auth/login", json={
            "username": "totp_admin",
            "password": "SecurePassword2025!",
        })
        assert response.status_code == 200
        body = response.json()
        assert body["totp_required"] is True
        assert body["needs_enrollment"] is False

        payload = jwt.decode(body["access_token"], TEST_JWT_SECRET, algorithms=[TEST_JWT_ALGORITHM])
        assert payload["scope"] == "pending_totp"

    def test_unenrolled_user_gets_needs_enrollment(self, client, db_session):
        """Login con TOTP secret pero sin enrollment → needs_enrollment=True."""
        from src.api.auth import hash_password

        db_session.add(User(
            username="pending_user",
            password_hash=hash_password("SecurePassword2025!"),
            totp_enabled=False,
            totp_secret_enc="some_encrypted_secret",
            totp_enrolled_at=None,
        ))
        db_session.commit()

        response = client.post("/auth/login", json={
            "username": "pending_user",
            "password": "SecurePassword2025!",
        })
        assert response.status_code == 200
        body = response.json()
        assert body["totp_required"] is True
        assert body["needs_enrollment"] is True
