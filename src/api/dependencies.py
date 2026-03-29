"""
Shared dependencies for FastAPI endpoints.

Dependencies are functions that FastAPI calls automatically
before each request. They handle cross-cutting concerns:
- Database session creation and cleanup
- Authentication verification (JWT token extraction and validation)

Using dependencies avoids duplicating session/auth logic in
every endpoint (DRY principle).

FastAPI's Depends() works like the callback pattern from the
agent: you define a function, and the framework calls it for you.
"""

import logging
from typing import Generator

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from datetime import datetime, timezone

from src.api.auth import verify_token
from src.database.models import User

logger = logging.getLogger(__name__)

# Will be set during app startup via set_database() / set_security_config()
_database = None
_security_config = None

# Tells FastAPI to expect "Authorization: Bearer <token>" header
security_scheme = HTTPBearer()


def set_database(database) -> None:
    """Set the database instance for dependency injection."""
    global _database
    _database = database


def set_security_config(security_config) -> None:
    """Set security config para acceso a fernet_key desde endpoints."""
    global _security_config
    _security_config = security_config


def get_security_config():
    """Retorna SecurityConfig inyectado en startup."""
    return _security_config

def get_db() -> Generator[Session, None, None]:
    """Provide a database session for a single request.

    Creates a new session, yields it to the endpoint function,
    and closes it after the response is sent — even if the
    endpoint raises an exception.

    The 'yield' keyword makes this a generator. FastAPI uses it
    as a context manager:
        session = get_db()   → creates session
        endpoint runs        → uses session
        session.close()      → cleanup (always runs)

    This is the same pattern as 'with open(file) as f:' but
    for database sessions.
    """
    session = _database.get_session()
    try:
        yield session
    finally:
        session.close()

def _resolve_user_from_token(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Verifica JWT y retorna User. Uso interno — NO usar en endpoints directamente."""
    payload = verify_token(credentials.credentials)

    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    user_id = int(payload.get("sub"))
    user = db.query(User).filter_by(id=user_id).first()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    # Invalidar tokens emitidos antes de un cambio de contraseña [Security Fix #5]
    if user.password_changed_at and payload.get("iat"):
        token_iat = datetime.fromtimestamp(payload["iat"], tz=timezone.utc)
        if token_iat < user.password_changed_at.replace(tzinfo=timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token invalidado por cambio de contraseña",
            )

    # Adjuntar scope como atributo transitorio para evitar doble decode JWT
    user._token_scope = payload.get("scope", "full_access")

    return user


# Alias público para backward-compat en conftest.py y endpoints TOTP
get_current_user = _resolve_user_from_token


def get_current_user_totp_verified(
    user: User = Depends(_resolve_user_from_token),
) -> User:
    """Dependencia para endpoints protegidos — requiere scope=full_access [RF-13].

    Rechaza tokens scope=pending_totp con HTTP 403.
    Usar esta dependencia en TODOS los endpoints de datos.
    """
    if getattr(user, "_token_scope", "full_access") != "full_access":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Se requiere verificación de segundo factor (TOTP)",
        )
    return user