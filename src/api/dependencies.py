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
from datetime import datetime, timezone
from typing import Generator, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from src.api.auth import verify_token
from src.config.models import SecurityConfig
from src.database.models import User

logger = logging.getLogger(__name__)

# Will be set during app startup via set_database() / set_security_config()
_database = None
_security_config: Optional[SecurityConfig] = None

# Tells FastAPI to expect "Authorization: Bearer <token>" header
security_scheme = HTTPBearer()


def set_database(database) -> None:
    """Set the database instance for dependency injection.

    Called once during API startup. Dependencies use this
    instance to create sessions for each request.

    Args:
        database: Database instance from connection.py
    """
    global _database
    _database = database


def set_security_config(security_config: SecurityConfig) -> None:
    """Inyecta el ``SecurityConfig`` para acceso desde endpoints [RF-13].

    Los endpoints de TOTP necesitan ``fernet_key`` para cifrar/descifrar
    los secretos. Pasar la config en startup evita que cada endpoint
    dependa de un módulo singleton de configuración.
    """
    global _security_config
    _security_config = security_config


def get_security_config() -> Optional[SecurityConfig]:
    """Retorna el ``SecurityConfig`` inyectado en startup, o ``None``.

    Los endpoints TOTP hacen ``Depends(get_security_config)`` y acceden
    a ``.fernet_key`` desde el resultado.
    """
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

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Verify JWT token and return the authenticated user.

    This dependency chains two others:
    1. security_scheme extracts the Bearer token from the header
    2. get_db provides a database session

    If the token is missing, expired, or invalid, raises 401.
    If the user ID in the token doesn't exist in the DB, raises 401.

    Usage in an endpoint:
        @router.get("/devices")
        def list_devices(user: User = Depends(get_current_user)):
            # 'user' is guaranteed to be authenticated here

    Args:
        credentials: Bearer token extracted by HTTPBearer.
        db: Database session from get_db.

    Returns:
        The authenticated User object from the database.

    Raises:
        HTTPException 401 if authentication fails.
    """
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

    # Invalidación retroactiva tras cambio de contraseña [RF-13].
    # Sin esto, un JWT robado sobrevive a un password reset.
    if user.password_changed_at and payload.get("iat") is not None:
        token_iat = datetime.fromtimestamp(payload["iat"], tz=timezone.utc)
        pwd_changed = user.password_changed_at
        if pwd_changed.tzinfo is None:
            pwd_changed = pwd_changed.replace(tzinfo=timezone.utc)
        if token_iat < pwd_changed:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token invalidado por cambio de contraseña",
            )

    # Adjuntamos el scope como atributo transitorio para que
    # ``get_current_user_totp_verified`` no tenga que decodificar el
    # JWT otra vez. Default ``full_access`` mantiene compat con tokens
    # antiguos sin campo scope.
    user._token_scope = payload.get("scope", "full_access")

    return user


def get_current_user_pending_totp(
    user: User = Depends(get_current_user),
) -> User:
    """Dependencia para endpoints del segundo factor — exige scope ``pending_totp`` [RF-13].

    Solo permite tokens emitidos tras login paso 1 o registro.
    Rechaza ``full_access`` y ``password_reset`` con 403 para que un
    token de sesión completa no pueda reingresar al flujo TOTP.
    """
    token_scope = getattr(user, "_token_scope", "full_access")
    if token_scope != "pending_totp":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Se requiere un token pending_totp para este endpoint",
        )
    return user


def get_current_user_totp_verified(
    user: User = Depends(get_current_user),
) -> User:
    """Dependencia para endpoints de negocio — exige scope ``full_access`` [RF-13].

    Rechaza tokens con scope ``pending_totp`` o ``password_reset`` con
    HTTP 403. Devolver 401 sería ambiguo (sugeriría credenciales inválidas);
    403 comunica que el usuario está autenticado pero le falta completar
    el segundo factor.
    """
    token_scope = getattr(user, "_token_scope", "full_access")
    if token_scope != "full_access":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Se requiere verificación de segundo factor (TOTP)",
        )
    return user