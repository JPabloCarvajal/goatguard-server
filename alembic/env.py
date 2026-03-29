"""
Alembic environment — lee la URL de BD desde la misma config YAML del servidor.
"""

import sys
from logging.config import fileConfig
from pathlib import Path

from sqlalchemy import engine_from_config, pool
from alembic import context

# Agregar raíz del proyecto al path para importar src.*
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.database.models import Base
from src.config import load_config

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Construir URL de BD desde la config YAML del servidor
server_config = load_config()
db = server_config.database
db_url = f"postgresql://{db.user}:{db.password}@{db.host}:{db.port}/{db.name}"
config.set_main_option("sqlalchemy.url", db_url)

# Metadata de los modelos ORM para autogenerate
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Migraciones offline — genera SQL sin conectar."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Migraciones online — conecta a PostgreSQL y ejecuta."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
