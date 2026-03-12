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

sys.path.insert(0, ".")

import uvicorn

from src.config import load_config, ConfigError
from src.database.connection import Database
from src.database.models import Base
from src.api.app import create_app

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def main():
    try:
        config = load_config()
    except ConfigError as e:
        print(f"[CONFIG ERROR] {e}")
        sys.exit(1)

    # Connect to the same database as the pipeline
    db = Database(
        host=config.database.host,
        port=config.database.port,
        name=config.database.name,
        user=config.database.user,
        password=config.database.password,
    )
    db.create_tables(Base)

    # Create FastAPI app
    app = create_app(database=db, config=config)

    print(f"\n  GOATGuard API running on http://0.0.0.0:{config.server.api_port}")
    print(f"  Swagger docs: http://localhost:{config.server.api_port}/docs\n")

    # uvicorn is the ASGI server that runs FastAPI.
    # It handles HTTP connections, keep-alive, and concurrency.
    uvicorn.run(app, host="0.0.0.0", port=config.server.api_port)


if __name__ == "__main__":
    main()