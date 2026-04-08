"""
Tests del modelo ``User`` extendido para 2FA y recuperación [RF-13].

Estos tests son un **guardrail de esquema**: verifican que todas las
columnas y tablas auxiliares que el flujo TOTP necesita están declaradas
en ``Base.metadata``. Si alguien elimina una columna por error, los
tests explotan antes de que el bug llegue a producción.

Usan ``sqlalchemy.inspect`` en lugar de crear instancias para detectar
columnas faltantes sin depender del motor de BD concreto.
"""

import sys

sys.path.insert(0, ".")

from sqlalchemy import inspect

from src.database.models import Base, InvitationToken, TotpBackupCode, User


class TestUserTotpColumns:
    """Columnas 2FA + recovery en la tabla ``user``."""

    REQUIRED_COLUMNS = {
        "totp_secret_enc",        # Cifrado Fernet — no puede hashearse
        "totp_enabled",
        "totp_enrolled_at",
        "totp_last_used_at",      # Anti-replay para códigos TOTP
        "password_changed_at",    # Invalida tokens emitidos antes
        "recovery_code_hash",
        "recovery_code_attempts",
        "recovery_code_used",
    }

    def test_user_has_all_2fa_columns(self):
        mapper = inspect(User)
        column_names = {c.key for c in mapper.columns}

        missing = self.REQUIRED_COLUMNS - column_names
        assert missing == set(), (
            f"Faltan columnas 2FA en User: {missing}. "
            f"Columnas actuales: {sorted(column_names)}"
        )

    def test_user_totp_enabled_defaults_to_false(self):
        """``totp_enabled`` debe ser ``False`` por defecto — usuarios
        legacy no tienen 2FA activo hasta completar enrollment."""
        mapper = inspect(User)
        totp_enabled = mapper.columns["totp_enabled"]
        assert totp_enabled.nullable is False
        assert totp_enabled.default is not None
        assert totp_enabled.default.arg is False

    def test_user_recovery_code_attempts_defaults_to_zero(self):
        """``recovery_code_attempts`` debe iniciar en 0 para que el
        rate limiting por intentos funcione desde el primer request."""
        mapper = inspect(User)
        attempts = mapper.columns["recovery_code_attempts"]
        assert attempts.nullable is False
        assert attempts.default is not None
        assert attempts.default.arg == 0


class TestInvitationTokenTable:
    """Tabla ``invitation_token`` para registro de admins [RF-13]."""

    def test_invitation_token_table_exists(self):
        assert InvitationToken.__tablename__ == "invitation_token"
        assert "invitation_token" in Base.metadata.tables

    def test_invitation_token_has_required_columns(self):
        mapper = inspect(InvitationToken)
        column_names = {c.key for c in mapper.columns}
        required = {
            "id",
            "token_hash",      # SHA-256 del token plano
            "expires_at",      # Ventana de uso
            "used",
            "used_at",
            "created_at",
        }
        missing = required - column_names
        assert missing == set(), f"Faltan columnas: {missing}"

    def test_invitation_token_hash_is_unique(self):
        """El hash debe ser único para que el lookup sea O(1) y no
        permita dos invitaciones con el mismo token."""
        mapper = inspect(InvitationToken)
        token_hash = mapper.columns["token_hash"]
        assert token_hash.unique is True


class TestTotpBackupCodeTable:
    """Tabla ``totp_backup_code`` para acceso de emergencia [RF-13]."""

    def test_totp_backup_code_table_exists(self):
        assert TotpBackupCode.__tablename__ == "totp_backup_code"
        assert "totp_backup_code" in Base.metadata.tables

    def test_totp_backup_code_has_required_columns(self):
        mapper = inspect(TotpBackupCode)
        column_names = {c.key for c in mapper.columns}
        required = {
            "id",
            "user_id",
            "code_hash",       # bcrypt, no texto plano
            "used",            # Un backup code solo sirve una vez
            "used_at",
            "created_at",
        }
        missing = required - column_names
        assert missing == set(), f"Faltan columnas: {missing}"

    def test_totp_backup_code_foreign_key_to_user(self):
        """Los backup codes deben estar atados a un usuario concreto."""
        mapper = inspect(TotpBackupCode)
        fks = list(mapper.columns["user_id"].foreign_keys)
        assert len(fks) == 1
        assert fks[0].column.table.name == "user"

    def test_user_backup_codes_relationship_cascades_delete(self):
        """Borrar un usuario debe borrar sus backup codes (no dejar
        huérfanos en la BD)."""
        rel = inspect(User).relationships["totp_backup_codes"]
        assert "delete" in (rel.cascade or "")
