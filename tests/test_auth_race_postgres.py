"""
Test de race condition para SELECT FOR UPDATE en TOTP verify [RF-13].

Valida que dos sesiones concurrentes con el MISMO código TOTP válido
no pasen ambas. SELECT FOR UPDATE bloquea la fila del user hasta el
commit, forzando serialización a nivel de BD.

Este test opera directamente sobre sesiones SQLAlchemy (no HTTP) para
garantizar concurrencia real. TestClient serializa requests, por lo
que no puede demostrar el locking.

SOLO corre cuando DATABASE_URL apunta a Postgres real — SQLite no
soporta SELECT FOR UPDATE (es un no-op).

Requiere: docker compose up -d postgres
Ejecutar:
    DATABASE_URL="postgresql://goatguard:goatguard@localhost:5432/goatguard_test" \
        pytest tests/test_auth_race_postgres.py -v
"""
import sys
sys.path.insert(0, ".")

import os
import threading
from datetime import datetime, timezone

import pyotp
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.api.auth import init_auth, hash_password
from src.database.models import Base, User
from src.api.totp_utils import (
    encrypt_secret,
    generate_totp_secret,
    verify_totp_code,
)
from cryptography.fernet import Fernet

# ── Constantes ───────────────────────────────────────────────────────────────

TEST_JWT_SECRET = "goatguard-test-secret-key-for-pytest-suite"
TEST_FERNET_KEY = Fernet.generate_key().decode()
_VALID_PASSWORD = "goatguard-pass-nist-ok"

_DB_URL = os.environ.get("DATABASE_URL")

pytestmark = pytest.mark.skipif(
    not _DB_URL or "postgresql" not in (_DB_URL or ""),
    reason="Requiere DATABASE_URL con Postgres (docker compose up -d postgres)",
)


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module", autouse=True)
def _init_auth():
    init_auth(jwt_secret=TEST_JWT_SECRET, jwt_expiration_hours=1)


@pytest.fixture()
def pg_engine():
    """Engine Postgres con pool real (múltiples conexiones concurrentes)."""
    engine = create_engine(_DB_URL, pool_size=5, max_overflow=5)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture()
def enrolled_user_id(pg_engine):
    """Crea un user enrollado en TOTP y devuelve (user_id, plain_secret)."""
    Session = sessionmaker(bind=pg_engine)
    session = Session()
    totp_secret = generate_totp_secret()
    encrypted = encrypt_secret(totp_secret, TEST_FERNET_KEY)
    user = User(
        username="race_user",
        password_hash=hash_password(_VALID_PASSWORD),
        totp_secret_enc=encrypted,
        totp_enabled=True,
        totp_enrolled_at=datetime.now(timezone.utc),
    )
    session.add(user)
    session.commit()
    user_id = user.id
    session.close()
    return user_id, totp_secret


# ── Tests ────────────────────────────────────────────────────────────────────

class TestSelectForUpdateLocking:
    def test_concurrent_sessions_serialized_by_for_update(
        self, pg_engine, enrolled_user_id
    ):
        """Dos sesiones concurrentes leen el mismo user con FOR UPDATE.

        Reproduce la lógica de /auth/totp/verify a nivel de BD:
        1. Ambas sesiones obtienen un código TOTP válido idéntico.
        2. Ambas hacen SELECT ... FOR UPDATE simultáneamente.
        3. La primera adquiere el lock, verifica, actualiza, commit.
        4. La segunda espera el lock, luego lee totp_last_used_at
           actualizado y rechaza como replay (mismo time-step).

        Sin FOR UPDATE, ambas leerían totp_last_used_at=None y
        verificarían correctamente → ambas aceptarían (200, 200).
        """
        user_id, totp_secret = enrolled_user_id
        valid_code = pyotp.TOTP(totp_secret).now()

        Session = sessionmaker(bind=pg_engine)
        barrier = threading.Barrier(2, timeout=10)
        results = []

        def _simulate_totp_verify(thread_name: str):
            """Simula la lógica de /totp/verify con locking real."""
            session = Session()
            try:
                barrier.wait()

                # SELECT FOR UPDATE — bloquea la fila hasta commit
                user = (
                    session.query(User)
                    .filter_by(id=user_id)
                    .with_for_update()
                    .first()
                )

                is_valid = verify_totp_code(
                    user.totp_secret_enc,
                    TEST_FERNET_KEY,
                    valid_code,
                    last_used_at=user.totp_last_used_at,
                )

                if is_valid:
                    user.totp_last_used_at = datetime.now(timezone.utc)
                    session.commit()
                    results.append("accepted")
                else:
                    session.rollback()
                    results.append("rejected")
            finally:
                session.close()

        t1 = threading.Thread(target=_simulate_totp_verify, args=("A",))
        t2 = threading.Thread(target=_simulate_totp_verify, args=("B",))
        t1.start()
        t2.start()
        t1.join(timeout=15)
        t2.join(timeout=15)

        results.sort()
        assert results == ["accepted", "rejected"], (
            f"Se esperaba ['accepted', 'rejected'] pero se obtuvo {results}. "
            "SELECT FOR UPDATE debería serializar ambos accesos y rechazar "
            "el replay del mismo time-step."
        )

    # Nota: no se incluye un test negativo "sin FOR UPDATE ambas aceptan"
    # porque Postgres READ COMMITTED no garantiza lecturas simultáneas —
    # si un thread commitea antes de que el otro haga SELECT, el segundo
    # ve el estado actualizado. Ese test sería inherentemente flaky.
    # El test positivo (arriba) ya demuestra que FOR UPDATE serializa
    # correctamente y previene replay del mismo time-step TOTP.
