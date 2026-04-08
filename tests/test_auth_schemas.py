"""
Tests de los schemas Pydantic del flujo de autenticación 2FA [RF-13].

Validan las constraints declarativas de longitud/formato en los modelos
``RegisterRequest``, ``TotpCodeRequest``, ``BackupCodeVerifyRequest`` y
``RecoveryVerifyRequest``. Así garantizamos que cualquier request mal
formado se rechaza en la capa de serialización, antes de llegar a la
lógica del endpoint.
"""

import sys

import pytest
from pydantic import ValidationError

sys.path.insert(0, ".")

from src.api.schemas.auth_schemas import (
    BackupCodeVerifyRequest,
    LoginRequest,
    RecoveryVerifyRequest,
    RegisterRequest,
    ResetPasswordRequest,
    TotpCodeRequest,
)


class TestRegisterRequest:
    def test_valid_request(self):
        req = RegisterRequest(
            username="alice",
            password="a" * 20,
            invitation_token="token-xyz",
        )
        assert req.username == "alice"

    def test_password_min_15(self):
        with pytest.raises(ValidationError):
            RegisterRequest(
                username="alice",
                password="a" * 14,
                invitation_token="t",
            )

    def test_password_max_128(self):
        with pytest.raises(ValidationError):
            RegisterRequest(
                username="alice",
                password="a" * 129,
                invitation_token="t",
            )

    def test_username_min_3(self):
        with pytest.raises(ValidationError):
            RegisterRequest(
                username="ab",
                password="a" * 20,
                invitation_token="t",
            )


class TestTotpCodeRequest:
    def test_valid_six_digit_code(self):
        req = TotpCodeRequest(code="123456")
        assert req.code == "123456"

    def test_rejects_alphanumeric(self):
        with pytest.raises(ValidationError):
            TotpCodeRequest(code="12345a")

    def test_rejects_wrong_length(self):
        with pytest.raises(ValidationError):
            TotpCodeRequest(code="12345")
        with pytest.raises(ValidationError):
            TotpCodeRequest(code="1234567")


class TestBackupCodeVerifyRequest:
    def test_valid_14_char_code(self):
        # XXXX-XXXX-XXXX = 14 chars incluyendo dashes
        req = BackupCodeVerifyRequest(backup_code="ABCD-EFGH-JKMN")
        assert req.backup_code == "ABCD-EFGH-JKMN"

    def test_rejects_wrong_length(self):
        with pytest.raises(ValidationError):
            BackupCodeVerifyRequest(backup_code="ABCD-EFGH")


class TestRecoveryVerifyRequest:
    def test_valid_19_char_code(self):
        # XXXX-XXXX-XXXX-XXXX = 19 chars incluyendo dashes
        req = RecoveryVerifyRequest(
            username="alice", recovery_code="ABCD-EFGH-JKMN-PQRS"
        )
        assert req.recovery_code == "ABCD-EFGH-JKMN-PQRS"

    def test_rejects_wrong_length(self):
        with pytest.raises(ValidationError):
            RecoveryVerifyRequest(
                username="alice", recovery_code="ABCD-EFGH-JKMN"
            )


class TestResetPasswordRequest:
    def test_accepts_15_char_password(self):
        req = ResetPasswordRequest(new_password="a" * 15)
        assert len(req.new_password) == 15

    def test_rejects_14_char_password(self):
        with pytest.raises(ValidationError):
            ResetPasswordRequest(new_password="a" * 14)


class TestLoginRequest:
    def test_accepts_arbitrary_password(self):
        """Login NO valida longitud de password — acepta el input tal cual
        para que la validación ocurra contra el hash bcrypt. Si cambiamos
        las reglas NIST, usuarios antiguos con passwords cortos siguen
        pudiendo loguear."""
        req = LoginRequest(username="alice", password="x")
        assert req.password == "x"
