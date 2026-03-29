"""Entry point for GOATGuard API server.

Runs separately from the pipeline (run.py). Both processes
share the same PostgreSQL database: the pipeline writes
metrics, the API reads and serves them to the mobile app.

Usage:
    Terminal 1: python run.py      (pipeline: receivers + analysis)
    Terminal 2: python run_api.py  (API: REST + WebSocket)
"""

import sys
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, ".")

import uvicorn
from cryptography.fernet import Fernet

from src.config import load_config, ConfigError
from src.database.connection import Database
from src.database.models import Base, User, InvitationToken
from src.api.app import create_app
from src.api.registration_utils import generate_invitation_token, hash_invitation_token

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


logger = logging.getLogger(__name__)


def _ensure_fernet_key(config) -> None:
    """Si fernet_key está vacía, lee de archivo local o genera y persiste."""
    if config.security.fernet_key:
        return

    key_file = Path(".fernet_key")
    if key_file.exists():
        config.security.fernet_key = key_file.read_text().strip()
        logger.info("Fernet key cargada desde %s", key_file)
        return

    # Generar nueva key y persistirla para sobrevivir reinicios
    config.security.fernet_key = Fernet.generate_key().decode()
    key_file.write_text(config.security.fernet_key)
    key_file.chmod(0o600)
    logger.warning(
        "FERNET_KEY generada y guardada en %s (permisos 0600). "
        "En producción, configure GOATGUARD_FERNET_KEY.", key_file,
    )


def _bootstrap_first_admin(db_session) -> None:
    """Si no existe ningún admin, genera un invitation token y lo loguea."""
    count = db_session.query(User).count()
    if count > 0:
        return

    token = generate_invitation_token()
    token_hash = hash_invitation_token(token)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=24)

    inv = InvitationToken(token_hash=token_hash, expires_at=expires_at)
    db_session.add(inv)
    db_session.commit()

    # Solo stdout, NUNCA al file logger — el token no debe persistir en logs
    print("\n" + "=" * 60)
    print("  BOOTSTRAP: token de registro de administrador:")
    print(f"  TOKEN: {token}")
    print("  Válido por 24 horas. Guárdalo en un lugar seguro.")
    print("=" * 60 + "\n")
    logger.info("Invitation token de bootstrap generado (visible solo en stdout)")


def main():
    try:
        config = load_config()
    except ConfigError as e:
        print(f"[CONFIG ERROR] {e}")
        sys.exit(1)

    _ensure_fernet_key(config)

    # Connect to the same database as the pipeline
    db = Database(
        host=config.database.host,
        port=config.database.port,
        name=config.database.name,
        user=config.database.user,
        password=config.database.password,
    )
    db.create_tables(Base)

    # Bootstrap: genera invitation token si no hay admins
    session = db.get_session()
    try:
        _bootstrap_first_admin(session)
    finally:
        session.close()

    # Create FastAPI app
    app = create_app(database=db, config=config)

    print(f"\n  GOATGuard API running on http://0.0.0.0:{config.server.api_port}")
    print(f"  Swagger docs: http://localhost:{config.server.api_port}/docs\n")

    # uvicorn is the ASGI server that runs FastAPI.
    # It handles HTTP connections, keep-alive, and concurrency.
    uvicorn.run(app, host="0.0.0.0", port=config.server.api_port)


if __name__ == "__main__":
    main()