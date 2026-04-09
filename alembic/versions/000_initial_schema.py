"""Initial schema baseline (pre-2FA) [RF-05].

Crea las 16 tablas del schema base de GOATGuard tal como existían
antes de los cambios 2FA del RF-13. La tabla ``user`` se crea solo
con sus 4 columnas originales (id, username, password_hash,
created_at). Las columnas y tablas 2FA viven en 001.

Esta separación permite que un downgrade selectivo de 2FA
(``alembic downgrade -1``) deje la BD en un estado consistente con
el código pre-RF-13 sin tener que recrear todo el schema.

Revision ID: 000_initial_schema
Revises:
Create Date: 2026-04-09
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "000_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Crea las 16 tablas base en orden topológico de FKs.

    Orden: padres antes que hijos. Network y User no tienen FKs
    salientes, por eso van primero en sus respectivas cadenas.
    """
    # ── 1. Network: raíz del grafo de red ────────────────────────────────
    op.create_table(
        "network",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("subnet", sa.String(length=45), nullable=False),
        sa.Column("gateway", sa.String(length=45), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )

    # ── 2. Device: depende de network ────────────────────────────────────
    op.create_table(
        "device",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("network_id", sa.Integer(), nullable=False),
        sa.Column("ip", sa.String(length=45), nullable=False),
        sa.Column("mac", sa.String(length=17), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("alias", sa.String(length=64), nullable=True),
        sa.Column("detected_type", sa.String(length=50), nullable=True),
        sa.Column("device_type", sa.String(length=50), nullable=True),
        sa.Column("has_agent", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="active"),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["network_id"], ["network.id"]),
    )

    # ── 3. Agent: depende de device ──────────────────────────────────────
    op.create_table(
        "agent",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("device_id", sa.Integer(), nullable=False),
        sa.Column("uid", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="active"),
        sa.Column("last_heartbeat", sa.DateTime(), nullable=False),
        sa.Column("registered_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["device_id"], ["device.id"]),
        sa.UniqueConstraint("uid"),
    )

    # ── 4. RecentConnection: depende de device ───────────────────────────
    op.create_table(
        "recent_connection",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("device_id", sa.Integer(), nullable=False),
        sa.Column("dst_ip", sa.String(length=45), nullable=False),
        sa.Column("dst_hostname", sa.String(length=255), nullable=True),
        sa.Column("dst_port", sa.Integer(), nullable=False),
        sa.Column("proto", sa.String(length=50), nullable=False),
        sa.Column("total_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("connection_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["device_id"], ["device.id"]),
    )

    # ── 5. NetworkSnapshot: depende de network ───────────────────────────
    op.create_table(
        "network_snapshot",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("network_id", sa.Integer(), nullable=False),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("isp_latency_avg", sa.Numeric(10, 2), nullable=True),
        sa.Column("packet_loss_pct", sa.Numeric(5, 2), nullable=True),
        sa.Column("jitter", sa.Numeric(10, 2), nullable=True),
        sa.Column("dns_response_time_avg", sa.Numeric(10, 2), nullable=True),
        sa.Column("failed_connections_global", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("active_connections", sa.Integer(), nullable=True),
        sa.Column("new_connections_per_min", sa.Integer(), nullable=True),
        sa.Column("internal_traffic_bytes", sa.BigInteger(), nullable=True),
        sa.Column("external_traffic_bytes", sa.BigInteger(), nullable=True),
        sa.ForeignKeyConstraint(["network_id"], ["network.id"]),
    )

    # ── 6. EndpointSnapshot: depende de device + network_snapshot ────────
    op.create_table(
        "endpoint_snapshot",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("device_id", sa.Integer(), nullable=False),
        sa.Column("network_snapshot_id", sa.Integer(), nullable=False),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("bandwidth_in", sa.Numeric(15, 2), nullable=True),
        sa.Column("bandwidth_out", sa.Numeric(15, 2), nullable=True),
        sa.Column("tcp_retransmissions", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failed_connections", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("dns_response_time", sa.Numeric(10, 2), nullable=True),
        sa.Column("jitter", sa.Numeric(10, 2), nullable=True),
        sa.Column("cpu_pct", sa.Numeric(5, 2), nullable=True),
        sa.Column("ram_pct", sa.Numeric(5, 2), nullable=True),
        sa.Column("link_speed", sa.Numeric(10, 2), nullable=True),
        sa.Column("cpu_count", sa.Integer(), nullable=True),
        sa.Column("ram_total_bytes", sa.BigInteger(), nullable=True),
        sa.Column("ram_available_bytes", sa.BigInteger(), nullable=True),
        sa.Column("disk_usage_pct", sa.Numeric(5, 2), nullable=True),
        sa.Column("uptime_seconds", sa.Numeric(15, 2), nullable=True),
        sa.Column("unique_destinations", sa.Integer(), nullable=True),
        sa.Column("bytes_ratio", sa.Numeric(10, 4), nullable=True),
        sa.ForeignKeyConstraint(["device_id"], ["device.id"]),
        sa.ForeignKeyConstraint(["network_snapshot_id"], ["network_snapshot.id"]),
    )

    # ── 7. TopTalker: depende de network_snapshot + device ───────────────
    op.create_table(
        "top_talker",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("network_snapshot_id", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=False),
        sa.Column("total_consumption", sa.Numeric(15, 2), nullable=False),
        sa.Column("rank", sa.Integer(), nullable=False),
        sa.Column("is_hog", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.ForeignKeyConstraint(["network_snapshot_id"], ["network_snapshot.id"]),
        sa.ForeignKeyConstraint(["device_id"], ["device.id"]),
    )

    # ── 8. Alert: depende de device + network ────────────────────────────
    op.create_table(
        "alert",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("device_id", sa.Integer(), nullable=False),
        sa.Column("network_id", sa.Integer(), nullable=False),
        sa.Column("anomaly_type", sa.String(length=50), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("seen", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["device_id"], ["device.id"]),
        sa.ForeignKeyConstraint(["network_id"], ["network.id"]),
    )

    # ── 9. User: solo columnas pre-2FA. 001 agrega las columnas 2FA ──────
    op.create_table(
        "user",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("username", sa.String(length=50), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("username"),
    )

    # ── 10. Session: depende de user ─────────────────────────────────────
    op.create_table(
        "session",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("jwt_token", sa.Text(), nullable=False),
        sa.Column("mobile_device", sa.String(length=100), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
    )

    # ── 11. PushToken: depende de user ───────────────────────────────────
    op.create_table(
        "push_token",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("token", sa.String(length=255), nullable=False),
        sa.Column("platform", sa.String(length=20), nullable=False, server_default="android"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
    )

    # ── 12. NetworkCurrentMetrics: PK = network_id (UPSERT) ──────────────
    op.create_table(
        "network_current_metrics",
        sa.Column("network_id", sa.Integer(), primary_key=True),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("isp_latency_avg", sa.Numeric(10, 2), nullable=True),
        sa.Column("packet_loss_pct", sa.Numeric(5, 2), nullable=True),
        sa.Column("jitter", sa.Numeric(10, 2), nullable=True),
        sa.Column("dns_response_time_avg", sa.Numeric(10, 2), nullable=True),
        sa.Column("failed_connections_global", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("active_connections", sa.Integer(), nullable=True),
        sa.Column("new_connections_per_min", sa.Integer(), nullable=True),
        sa.Column("internal_traffic_bytes", sa.BigInteger(), nullable=True),
        sa.Column("external_traffic_bytes", sa.BigInteger(), nullable=True),
        sa.ForeignKeyConstraint(["network_id"], ["network.id"]),
    )

    # ── 13. DeviceCurrentMetrics: PK = device_id (UPSERT) ────────────────
    op.create_table(
        "device_current_metrics",
        sa.Column("device_id", sa.Integer(), primary_key=True),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("bandwidth_in", sa.Numeric(15, 2), nullable=True),
        sa.Column("bandwidth_out", sa.Numeric(15, 2), nullable=True),
        sa.Column("tcp_retransmissions", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failed_connections", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("dns_response_time", sa.Numeric(10, 2), nullable=True),
        sa.Column("jitter", sa.Numeric(10, 2), nullable=True),
        sa.Column("cpu_pct", sa.Numeric(5, 2), nullable=True),
        sa.Column("ram_pct", sa.Numeric(5, 2), nullable=True),
        sa.Column("link_speed", sa.Numeric(10, 2), nullable=True),
        sa.Column("cpu_count", sa.Integer(), nullable=True),
        sa.Column("ram_total_bytes", sa.BigInteger(), nullable=True),
        sa.Column("ram_available_bytes", sa.BigInteger(), nullable=True),
        sa.Column("disk_usage_pct", sa.Numeric(5, 2), nullable=True),
        sa.Column("uptime_seconds", sa.Numeric(15, 2), nullable=True),
        sa.Column("unique_destinations", sa.Integer(), nullable=True),
        sa.Column("bytes_ratio", sa.Numeric(10, 4), nullable=True),
        sa.ForeignKeyConstraint(["device_id"], ["device.id"]),
    )

    # ── 14. TopTalkerCurrent ─────────────────────────────────────────────
    op.create_table(
        "top_talker_current",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("network_id", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=False),
        sa.Column("total_consumption", sa.Numeric(15, 2), nullable=False),
        sa.Column("rank", sa.Integer(), nullable=False),
        sa.Column("is_hog", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.ForeignKeyConstraint(["network_id"], ["network.id"]),
        sa.ForeignKeyConstraint(["device_id"], ["device.id"]),
    )

    # ── 15. MLPrediction ─────────────────────────────────────────────────
    op.create_table(
        "ml_prediction",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("network_id", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=False),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("src_ip", sa.String(length=45), nullable=False),
        sa.Column("dst_ip", sa.String(length=45), nullable=False),
        sa.Column("src_port", sa.Integer(), nullable=False),
        sa.Column("dst_port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(length=10), nullable=False),
        sa.Column("predicted_label", sa.String(length=50), nullable=False),
        sa.Column("confidence", sa.Numeric(5, 4), nullable=False),
        sa.Column("feature_snapshot", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["network_id"], ["network.id"]),
        sa.ForeignKeyConstraint(["device_id"], ["device.id"]),
    )

    # ── 16. Insight ──────────────────────────────────────────────────────
    op.create_table(
        "insight",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("network_id", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=True),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("category", sa.String(length=30), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("metric_name", sa.String(length=50), nullable=False),
        sa.Column("metric_value", sa.Numeric(15, 4), nullable=False),
        sa.Column("metric_baseline", sa.Numeric(15, 4), nullable=False),
        sa.ForeignKeyConstraint(["network_id"], ["network.id"]),
        sa.ForeignKeyConstraint(["device_id"], ["device.id"]),
    )


def downgrade() -> None:
    """Elimina las 16 tablas en orden inverso al de creación.

    Orden inverso es necesario para respetar las FKs: las hijas
    deben caer antes que las padres.
    """
    op.drop_table("insight")
    op.drop_table("ml_prediction")
    op.drop_table("top_talker_current")
    op.drop_table("device_current_metrics")
    op.drop_table("network_current_metrics")
    op.drop_table("push_token")
    op.drop_table("session")
    op.drop_table("user")
    op.drop_table("alert")
    op.drop_table("top_talker")
    op.drop_table("endpoint_snapshot")
    op.drop_table("network_snapshot")
    op.drop_table("recent_connection")
    op.drop_table("agent")
    op.drop_table("device")
    op.drop_table("network")
