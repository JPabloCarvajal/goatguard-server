"""Agregar columnas de seguridad a user + tablas invitation_token y totp_backup_code [RF-13]

Revision ID: 001
Revises: (primera migración)
"""

from alembic import op
import sqlalchemy as sa

revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- Columnas nuevas en tabla user ---
    op.add_column("user", sa.Column(
        "totp_secret_enc", sa.String(500), nullable=True,
    ))
    op.add_column("user", sa.Column(
        "totp_enabled", sa.Boolean, nullable=False, server_default="false",
    ))
    op.add_column("user", sa.Column(
        "totp_enrolled_at", sa.DateTime(timezone=True), nullable=True,
    ))
    op.add_column("user", sa.Column(
        "totp_last_used_at", sa.DateTime(timezone=True), nullable=True,
    ))
    op.add_column("user", sa.Column(
        "password_changed_at", sa.DateTime(timezone=True), nullable=True,
    ))
    op.add_column("user", sa.Column(
        "recovery_code_hash", sa.String(255), nullable=True,
    ))
    op.add_column("user", sa.Column(
        "recovery_code_attempts", sa.Integer, nullable=False, server_default="0",
    ))
    op.add_column("user", sa.Column(
        "recovery_code_used", sa.Boolean, nullable=False, server_default="false",
    ))

    # --- Tabla invitation_token ---
    op.create_table(
        "invitation_token",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("token_hash", sa.String(255), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
    )

    # --- Tabla totp_backup_code ---
    op.create_table(
        "totp_backup_code",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("user.id"), nullable=False),
        sa.Column("code_hash", sa.String(255), nullable=False),
        sa.Column("used", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )


def downgrade() -> None:
    # Orden inverso: tablas primero, columnas después
    op.drop_table("totp_backup_code")
    op.drop_table("invitation_token")

    op.drop_column("user", "recovery_code_used")
    op.drop_column("user", "recovery_code_attempts")
    op.drop_column("user", "recovery_code_hash")
    op.drop_column("user", "password_changed_at")
    op.drop_column("user", "totp_last_used_at")
    op.drop_column("user", "totp_enrolled_at")
    op.drop_column("user", "totp_enabled")
    op.drop_column("user", "totp_secret_enc")
