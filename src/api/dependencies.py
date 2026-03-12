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

from src.api.auth import verify_token
from src.database.models import User

logger = logging.getLogger(__name__)

# Will be set during app startup via set_database()
_database = None

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

    return user