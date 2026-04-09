"""
Helper para crear el engine de test según el entorno [RF-13].

Si DATABASE_URL está definido (ej. Postgres en docker-compose),
usa ese engine. Si no, cae a SQLite in-memory.

StaticPool en ambos casos: fuerza una única conexión compartida
entre el hilo de pytest y el thread del TestClient de FastAPI.
Sin StaticPool + SQLite in-memory, cada hilo recibiría una BD
vacía; con Postgres, evita race conditions entre hilos.
"""

import os

from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool


def make_test_engine():
    """Crea engine de test según DATABASE_URL o fallback a SQLite."""
    db_url = os.environ.get("DATABASE_URL")
    if db_url:
        return create_engine(db_url, poolclass=StaticPool)
    return create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
