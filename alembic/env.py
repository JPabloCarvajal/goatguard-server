"""
Entorno de runtime de Alembic para GOATGuard [RF-13].

Resuelve la URL de la BD con precedencia explícita para que las
migraciones funcionen en tres contextos sin acoplarse a ninguno:

1. Tests: ``cfg.set_main_option("sqlalchemy.url", "sqlite:///...")``
   sobreescribe la URL antes de invocar ``command.upgrade``.
2. CI/Producción: variable de entorno ``DATABASE_URL`` (estándar
   para 12-factor apps).
3. Fallback local: construir desde ``ServerConfig().database`` para
   que ``alembic upgrade head`` funcione en una sesión interactiva
   sin variables de entorno.

``render_as_batch`` se activa automáticamente cuando la URL es
SQLite porque SQLite no soporta ALTER TABLE nativo (DROP COLUMN,
ALTER COLUMN). Postgres no necesita batch mode.
"""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from src.database.models import Base

# Config object provisto por Alembic. Da acceso a alembic.ini.
config = context.config

# Cargar logging desde alembic.ini si existe la sección. Usamos
# disable_existing_loggers=False para no destruir handlers configurados
# por otros frameworks (pytest's caplog, FastAPI logging, etc.). Sin
# esto, cualquier test que invoque las migraciones pierde captura de
# logs en módulos importados previamente.
if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

# Metadata del ORM contra el cual Alembic compara para autogenerate
# y para que ``op.create_table`` herede el dialecto correcto.
target_metadata = Base.metadata


def _resolve_url() -> str:
    """Resuelve la URL de conexión con la precedencia documentada arriba."""
    url = config.get_main_option("sqlalchemy.url")
    if url:
        return url

    env_url = os.environ.get("DATABASE_URL")
    if env_url:
        return env_url

    # Fallback: importamos perezosamente para no acoplar el módulo
    # a ServerConfig en los tests (que sobreescriben sqlalchemy.url).
    from src.config.models import ServerConfig

    db = ServerConfig().database
    return f"postgresql://{db.user}:{db.password}@{db.host}:{db.port}/{db.name}"


def run_migrations_offline() -> None:
    """Modo offline: emite SQL sin conectarse a la BD.

    Útil para generar scripts de migración revisables antes de
    aplicarlos en producción. No se usa en tests.
    """
    url = _resolve_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=url.startswith("sqlite"),
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Modo online: abre conexión real a la BD y aplica las migraciones."""
    url = _resolve_url()
    connectable = engine_from_config(
        {"sqlalchemy.url": url},
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=url.startswith("sqlite"),
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
