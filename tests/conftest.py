"""
Fixtures compartidos para los tests de la API GOATGuard.

Usa SQLite in-memory en lugar de PostgreSQL para aislar
los tests del entorno real. El override de get_db redirige
todas las sesiones al engine de prueba.
"""
import sys
sys.path.insert(0, ".")

import pytest
from datetime import datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.api.auth import init_auth, create_token
from src.api.dependencies import get_db
from src.config.models import ServerConfig
from src.database.models import Base, User, Network, Device, Agent
from src.api.auth import hash_password

# ── Configuración de auth para tests ─────────────────────────────────────────

# Secret de 40 caracteres para cumplir el mínimo de 32 bytes de SHA-256
# recomendado por RFC 7518 y exigido por PyJWT >= 2.9.
TEST_JWT_SECRET = "goatguard-test-secret-key-for-pytest-suite"
TEST_JWT_ALGORITHM = "HS256"
TEST_JWT_EXPIRATION_HOURS = 1


# ── Engine SQLite in-memory ───────────────────────────────────────────────────

@pytest.fixture(scope="session", autouse=True)
def _init_auth_module():
    """Inicializa el módulo auth una sola vez por sesión de tests."""
    init_auth(
        jwt_secret=TEST_JWT_SECRET,
        jwt_algorithm=TEST_JWT_ALGORITHM,
        jwt_expiration_hours=TEST_JWT_EXPIRATION_HOURS,
    )


@pytest.fixture()
def db_session():
    """
    Crea un engine SQLite in-memory y una sesión limpia para cada test.

    check_same_thread=False es necesario porque pytest y FastAPI
    pueden usar el mismo engine desde hilos distintos.
    """
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    TestingSession = sessionmaker(bind=engine)
    session = TestingSession()
    yield session
    session.close()
    Base.metadata.drop_all(engine)


@pytest.fixture()
def client(db_session):
    """
    TestClient de FastAPI con get_db sobreescrito para usar SQLite.

    Crea la app importando create_app directamente y aplica el
    dependency override ANTES de que el TestClient haga su primer
    request.
    """
    # Importación tardía para evitar que create_app intente conectar
    # a PostgreSQL en el momento de la importación del módulo.
    from src.api.app import create_app

    config = ServerConfig()
    # Sobreescribimos el secret para que create_app inicialice auth
    # con el mismo secret que usamos en los fixtures de token.
    config.security.jwt_secret = TEST_JWT_SECRET

    # Database falso: create_app llama set_database(database) y
    # broadcast_loop(database.get_session). Pasamos un stub mínimo.
    class _FakeDatabase:
        def get_session(self):
            return db_session

        def create_tables(self, base):
            pass

    app = create_app(_FakeDatabase(), config)

    # Override de get_db: cada request obtiene la sesión de test.
    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db

    with TestClient(app, raise_server_exceptions=True) as test_client:
        yield test_client


# ── Datos de prueba ───────────────────────────────────────────────────────────

@pytest.fixture()
def seed_data(db_session):
    """
    Inserta en la BD de test:
      - 1 network
      - 3 devices (d1, d2, d3)
      - 3 agents: agent1 (active, device d1), agent2 (active, d2),
                  agent3 (inactive, d3)
      - 1 user admin para generar tokens válidos

    Devuelve un dict con los objetos creados para que los tests
    puedan inspeccionarlos sin re-consultar.
    """
    now = datetime.utcnow()

    # Network
    network = Network(
        name="LAN-Test",
        subnet="192.168.99.0/24",
        gateway="192.168.99.1",
    )
    db_session.add(network)
    db_session.flush()

    # Devices
    d1 = Device(
        network_id=network.id,
        ip="192.168.99.10",
        mac="AA:BB:CC:DD:EE:01",
        hostname="endpoint-alpha",
        has_agent=True,
        status="active",
    )
    d2 = Device(
        network_id=network.id,
        ip="192.168.99.20",
        mac="AA:BB:CC:DD:EE:02",
        hostname="endpoint-beta",
        has_agent=True,
        status="active",
    )
    d3 = Device(
        network_id=network.id,
        ip="192.168.99.30",
        mac="AA:BB:CC:DD:EE:03",
        hostname="endpoint-gamma",
        has_agent=True,
        status="active",
    )
    db_session.add_all([d1, d2, d3])
    db_session.flush()

    # Agents
    agent1 = Agent(
        device_id=d1.id,
        uid="agent-uid-alpha",
        status="active",
        last_heartbeat=now - timedelta(minutes=1),
        registered_at=now - timedelta(days=2),
    )
    agent2 = Agent(
        device_id=d2.id,
        uid="agent-uid-beta",
        status="active",
        last_heartbeat=now - timedelta(minutes=5),
        registered_at=now - timedelta(days=1),
    )
    agent3 = Agent(
        device_id=d3.id,
        uid="agent-uid-gamma",
        status="inactive",
        last_heartbeat=now - timedelta(hours=2),
        registered_at=now - timedelta(days=5),
    )
    db_session.add_all([agent1, agent2, agent3])

    # User admin
    user = User(
        username="admin",
        password_hash=hash_password("password123"),
    )
    db_session.add(user)
    db_session.commit()

    # Refresca para obtener los IDs asignados por SQLite
    db_session.refresh(user)
    db_session.refresh(agent1)
    db_session.refresh(agent2)
    db_session.refresh(agent3)
    db_session.refresh(d1)
    db_session.refresh(d2)
    db_session.refresh(d3)

    return {
        "network": network,
        "devices": [d1, d2, d3],
        "agents": [agent1, agent2, agent3],
        "user": user,
    }


@pytest.fixture()
def auth_headers(seed_data):
    """
    Genera el header Authorization con un JWT válido para el user
    creado en seed_data.
    """
    user = seed_data["user"]
    token = create_token(user_id=user.id, username=user.username)
    return {"Authorization": f"Bearer {token}"}
