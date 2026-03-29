"""
Tests de recuperación de contraseña [RF-13].

TC-P1 a TC-P8.
"""
import sys
sys.path.insert(0, ".")

from datetime import datetime

import jwt

from src.api.auth import hash_password, create_token
from src.api.registration_utils import (
    generate_recovery_code, hash_recovery_code,
)
from src.database.models import User
from tests.conftest import TEST_JWT_SECRET, TEST_JWT_ALGORITHM


# ── Helpers ───────────────────────────────────────────────────────────────────

VALID_PASSWORD = "NewSecurePassword2025!"


def _create_user_with_recovery(db_session) -> tuple[User, str]:
    """Crea user con recovery code. Retorna (user, plain_code)."""
    plain_code = generate_recovery_code()
    user = User(
        username="recovery_user",
        password_hash=hash_password("OldPassword2025xxxx!"),
        recovery_code_hash=hash_recovery_code(plain_code),
        recovery_code_attempts=0,
        recovery_code_used=False,
        totp_enabled=True,
        totp_secret_enc="encrypted_placeholder",
        totp_enrolled_at=datetime.utcnow(),
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user, plain_code


# ── TC-P1: Username inexistente → 400 (timing-safe) ──────────────────────────

class TestRecoveryNonexistentUser:

    def test_nonexistent_user_returns_400(self, client):
        """TC-P1: Username que no existe → 400 con mensaje genérico."""
        response = client.post("/auth/recovery/verify-code", json={
            "username": "ghost_user",
            "recovery_code": "AAAA-BBBB-CCCC-DDDD",
        })
        assert response.status_code == 400
        assert "inválidas" in response.json()["detail"].lower()


# ── TC-P2: Código correcto → reset_token ──────────────────────────────────────

class TestRecoveryCorrectCode:

    def test_correct_code_returns_reset_token(self, client, db_session):
        """TC-P2: Recovery code válido → reset_token con scope=password_reset."""
        user, plain_code = _create_user_with_recovery(db_session)

        response = client.post("/auth/recovery/verify-code", json={
            "username": user.username,
            "recovery_code": plain_code,
        })
        assert response.status_code == 200

        reset_token = response.json()["reset_token"]
        payload = jwt.decode(reset_token, TEST_JWT_SECRET,
                             algorithms=[TEST_JWT_ALGORITHM])
        assert payload["scope"] == "password_reset"
        assert int(payload["sub"]) == user.id


# ── TC-P3: Código incorrecto → 400, contador incrementa ──────────────────────

class TestRecoveryWrongCode:

    def test_wrong_code_increments_attempts(self, client, db_session):
        """TC-P3: Código incorrecto → 400, recovery_code_attempts +1."""
        user, _ = _create_user_with_recovery(db_session)

        response = client.post("/auth/recovery/verify-code", json={
            "username": user.username,
            "recovery_code": "ZZZZ-YYYY-XXXX-WWWW",
        })
        assert response.status_code == 400
        assert "inválidas" in response.json()["detail"].lower()

        db_session.refresh(user)
        assert user.recovery_code_attempts == 1


# ── TC-P4: 5 intentos fallidos → 429 ─────────────────────────────────────────

class TestRecoveryLockout:

    def test_five_failed_attempts_returns_429(self, client, db_session):
        """TC-P4: 5 intentos fallidos → 429, código bloqueado."""
        user, _ = _create_user_with_recovery(db_session)
        user.recovery_code_attempts = 5
        db_session.commit()

        response = client.post("/auth/recovery/verify-code", json={
            "username": user.username,
            "recovery_code": "AAAA-BBBB-CCCC-DDDD",
        })
        assert response.status_code == 429
        assert "bloqueado" in response.json()["detail"].lower()


# ── TC-P5: Reset con token inválido → 401 ────────────────────────────────────

class TestResetInvalidToken:

    def test_invalid_reset_token_returns_401(self, client):
        """TC-P5: Token de reset inválido → 401."""
        response = client.post(
            "/auth/recovery/reset-password",
            json={"new_password": VALID_PASSWORD},
            headers={"Authorization": "Bearer invalid-token-xxx"},
        )
        assert response.status_code == 401


# ── TC-P6: Nueva contraseña < 15 chars → 400 ─────────────────────────────────

class TestResetWeakPassword:

    def test_short_password_returns_422(self, client, db_session):
        """TC-P6: Contraseña nueva < 15 chars → 422 (Pydantic min_length)."""
        user, plain_code = _create_user_with_recovery(db_session)
        reset_token = create_token(user.id, user.username,
                                   scope="password_reset", expiration_minutes=15)

        response = client.post(
            "/auth/recovery/reset-password",
            json={"new_password": "short"},
            headers={"Authorization": f"Bearer {reset_token}"},
        )
        assert response.status_code == 422


# ── TC-P7: Reset OK → nuevo JWT, recovery_code_hash NULL ─────────────────────

class TestResetSuccess:

    def test_successful_reset_returns_jwt_and_clears_recovery(
        self, client, db_session,
    ):
        """TC-P7: Reset OK → JWT, recovery_code_hash NULL, attempts=0."""
        user, _ = _create_user_with_recovery(db_session)
        reset_token = create_token(user.id, user.username,
                                   scope="password_reset", expiration_minutes=15)

        response = client.post(
            "/auth/recovery/reset-password",
            json={"new_password": VALID_PASSWORD},
            headers={"Authorization": f"Bearer {reset_token}"},
        )
        assert response.status_code == 200

        body = response.json()
        assert "access_token" in body

        # BD limpia
        db_session.refresh(user)
        assert user.recovery_code_hash is None
        assert user.recovery_code_used is True
        assert user.recovery_code_attempts == 0

        # Verificar que la nueva contraseña funciona
        from src.api.auth import verify_password
        assert verify_password(VALID_PASSWORD, user.password_hash) is True


# ── TC-P8: Reset con token expirado → 401 ────────────────────────────────────

class TestResetExpiredToken:

    def test_expired_reset_token_returns_401(self, client, db_session):
        """TC-P8: Token password_reset expirado → 401."""
        user, _ = _create_user_with_recovery(db_session)

        # Token que expiró hace 1 minuto
        reset_token = create_token(user.id, user.username,
                                   scope="password_reset", expiration_minutes=-1)

        response = client.post(
            "/auth/recovery/reset-password",
            json={"new_password": VALID_PASSWORD},
            headers={"Authorization": f"Bearer {reset_token}"},
        )
        assert response.status_code == 401
