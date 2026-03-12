"""
FastAPI application factory for GOATGuard API.

Creates and configures the FastAPI instance, registers route
modules, and initializes shared dependencies (database, auth).

Uses the factory pattern: create_app() receives configuration
and returns a ready-to-run application. This makes testing
easier (you can create multiple app instances with different
configs) and keeps the configuration explicit.
"""

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.api.auth import init_auth
from src.api.dependencies import set_database
from src.api.routes import auth as auth_routes
from src.database.connection import Database
from src.api.routes import auth as auth_routes
from src.api.routes import devices as device_routes
from src.api.routes import network as network_routes
from src.api.routes import alerts as alert_routes

logger = logging.getLogger(__name__)


def create_app(database: Database, config) -> FastAPI:
    """Create and configure the FastAPI application.

    Initializes all shared modules (database, auth) and
    registers route modules. The app is ready to serve
    requests after this function returns.

    Args:
        database: Database instance for session creation.
        config: ServerConfig with security settings.

    Returns:
        Configured FastAPI application.
    """
    app = FastAPI(
        title="GOATGuard API",
        description="Network monitoring and security management API",
        version="1.0.0",
    )

    # Initialize shared modules
    set_database(database)
    init_auth(
        jwt_secret=config.security.jwt_secret,
        jwt_algorithm=config.security.jwt_algorithm,
        jwt_expiration_hours=config.security.jwt_expiration_hours,
    )

    # CORS: allow mobile app to connect from any origin.
    # The app may connect from localhost (emulator), LAN IP
    # (same network), or a Cloudflare Tunnel domain (remote).
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register route modules
    app.include_router(auth_routes.router)

    app.include_router(auth_routes.router)
    app.include_router(device_routes.router)
    app.include_router(network_routes.router)
    app.include_router(alert_routes.router)

    logger.info("FastAPI application created")

    return app