"""Add 2FA TOTP + recovery columns and tables [RF-13].

Agrega los componentes de seguridad 2FA al schema:

- 8 columnas en ``user``: enrollment TOTP cifrado, anti-replay,
  invalidación de tokens por cambio de password y recovery code.
- ``invitation_token``: tokens de un solo uso para registro de
  administradores. Se almacena solo el SHA-256.
- ``totp_backup_code``: códigos de respaldo single-use con hash
  bcrypt y FK ON DELETE CASCADE para que la eliminación de un
  usuario se lleve sus códigos sin orfandad.

batch_alter_table es obligatorio en SQLite porque ALTER TABLE ADD
COLUMN nativo de SQLite no soporta todas las opciones que usamos
(server_default con tipo Boolean, por ejemplo). En Postgres es
no-op: alembic emite ALTER TABLE estándar.

Revision ID: 001_add_auth_security_features
Revises: 000_initial_schema
Create Date: 2026-04-09
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "001_add_auth_security_features"
down_revision: Union[str, None] = "000_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Agrega columnas 2FA al user y crea las tablas auxiliares 2FA."""
    # ── ALTER user con 8 columnas 2FA ────────────────────────────────────
    # batch_alter_table genera un workflow CREATE/COPY/DROP/RENAME en
    # SQLite y un ALTER nativo en Postgres. Todas las columnas con
    # NOT NULL traen server_default para que filas existentes pasen.
    with op.batch_alter_table("user") as batch_op:
        # TOTP enrollment cifrado con Fernet (AES-128-CBC + HMAC-SHA256).
        # Nullable porque hasta enrollment el usuario no tiene secret.
        batch_op.add_column(
            sa.Column("totp_secret_enc", sa.String(length=500), nullable=True)
        )
        batch_op.add_column(
            sa.Column(
                "totp_enabled",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("0"),
            )
        )
        batch_op.add_column(
            sa.Column("totp_enrolled_at", sa.DateTime(timezone=True), nullable=True)
        )
        # Anti-replay: rechaza códigos del mismo time-step que el último.
        batch_op.add_column(
            sa.Column("totp_last_used_at", sa.DateTime(timezone=True), nullable=True)
        )
        # Invalida cualquier JWT emitido antes de este timestamp.
        batch_op.add_column(
            sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=True)
        )
        # Recovery code: hash bcrypt del código entregado fuera de banda.
        batch_op.add_column(
            sa.Column("recovery_code_hash", sa.String(length=255), nullable=True)
        )
        batch_op.add_column(
            sa.Column(
                "recovery_code_attempts",
                sa.Integer(),
                nullable=False,
                server_default="0",
            )
        )
        batch_op.add_column(
            sa.Column(
                "recovery_code_used",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("0"),
            )
        )

    # ── invitation_token: registro por invitación ────────────────────────
    # token_hash es UNIQUE para que un mismo token no cree dos cuentas
    # aunque alguien lo comparta por error. Se almacena SHA-256 del token
    # plano para que filtraciones de BD no expongan tokens reutilizables.
    op.create_table(
        "invitation_token",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("token_hash", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "used", sa.Boolean(), nullable=False, server_default=sa.text("0")
        ),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("token_hash"),
    )

    # ── totp_backup_code: códigos de respaldo single-use ─────────────────
    # ondelete=CASCADE: si se elimina el user, sus backup codes se borran
    # automáticamente. El ORM declara cascade del lado Python pero esta
    # constraint defensiva garantiza la integridad incluso si alguien
    # hace DELETE FROM user con SQL crudo (ej. desde psql).
    op.create_table(
        "totp_backup_code",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("code_hash", sa.String(length=255), nullable=False),
        sa.Column(
            "used", sa.Boolean(), nullable=False, server_default=sa.text("0")
        ),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"], ondelete="CASCADE"),
    )


def downgrade() -> None:
    """Revierte 001: drop tablas 2FA y luego columnas 2FA del user.

    Orden importante: primero drop de las tablas que dependen del user
    (totp_backup_code), luego invitation_token (independiente), y al
    final el ALTER user para eliminar las 8 columnas. SQLite requiere
    batch_alter_table también para drop_column.
    """
    op.drop_table("totp_backup_code")
    op.drop_table("invitation_token")

    with op.batch_alter_table("user") as batch_op:
        batch_op.drop_column("recovery_code_used")
        batch_op.drop_column("recovery_code_attempts")
        batch_op.drop_column("recovery_code_hash")
        batch_op.drop_column("password_changed_at")
        batch_op.drop_column("totp_last_used_at")
        batch_op.drop_column("totp_enrolled_at")
        batch_op.drop_column("totp_enabled")
        batch_op.drop_column("totp_secret_enc")
