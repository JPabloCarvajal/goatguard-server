"""
FastAPI application factory for GOATGuard API.

Creates and configures the FastAPI instance, registers route
modules, and initializes shared dependencies (database, auth).

Uses the factory pattern: create_app() receives configuration
and returns a ready-to-run application. This makes testing
easier (you can create multiple app instances with different
configs) and keeps the configuration explicit.
"""

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from src.api.auth import init_auth
from src.api.dependencies import set_database, set_security_config
from src.api.rate_limit import limiter
from src.api.routes import agents as agent_routes
from src.api.routes import alerts as alert_routes
from src.api.routes import auth as auth_routes
from src.api.routes import dashboard as dashboard_routes
from src.api.routes import devices as device_routes
from src.api.routes import network as network_routes
from src.api.routes import notifications as notification_routes
from src.api.websocket import broadcast_loop
from src.api.websocket import router as ws_router
from src.database.connection import Database

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
    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        """Ciclo de vida de la app: arranca el broadcast loop al inicio
        y lo cancela limpiamente al apagado. Reemplaza el decorador
        ``@app.on_event("startup")`` deprecado desde FastAPI 0.93.
        """
        broadcast_task = asyncio.create_task(
            broadcast_loop(database.get_session)
        )
        logger.info("Broadcast loop iniciado via lifespan")
        try:
            yield
        finally:
            broadcast_task.cancel()
            try:
                await broadcast_task
            except asyncio.CancelledError:
                pass
            logger.info("Broadcast loop cancelado en shutdown")

    app = FastAPI(
        title="GOATGuard API",
        description="Network monitoring and security management API",
        version="1.0.0",
        lifespan=lifespan,
    )

    # Initialize shared modules
    set_database(database)
    set_security_config(config.security)
    init_auth(
        jwt_secret=config.security.jwt_secret,
        jwt_algorithm=config.security.jwt_algorithm,
        jwt_expiration_hours=config.security.jwt_expiration_hours,
    )

    # Rate limiting con slowapi [RF-13]. El limiter es un singleton
    # a nivel de módulo para que los routers puedan decorar endpoints
    # sin inyección — lo enganchamos a ``app.state`` que es lo que
    # espera ``SlowAPIMiddleware`` y el exception handler.
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)

    # CORS: orígenes explícitos desde config.security.cors_origins.
    # Nunca usar ``["*"]`` porque la API acepta credenciales (JWT) y la
    # CORS spec (W3C Fetch §3.2.2) obliga a los navegadores a rechazar
    # la combinación wildcard + credentials.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.security.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register route modules
    app.include_router(auth_routes.router)
    app.include_router(device_routes.router)
    app.include_router(network_routes.router)
    app.include_router(alert_routes.router)
    app.include_router(notification_routes.router)

    app.include_router(dashboard_routes.router)
    app.include_router(agent_routes.router)

    app.include_router(ws_router)

    logger.info("FastAPI application created")

    return app