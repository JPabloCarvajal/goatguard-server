"""
Authentication endpoints for GOATGuard API.

POST /auth/register  — Create a new admin account
POST /auth/login     — Authenticate and receive JWT token

These are the only UNPROTECTED endpoints. All other endpoints
require a valid JWT token in the Authorization header.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from src.api.auth import hash_password, verify_password, create_token
from src.api.dependencies import get_db
from src.database.models import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])

class RegisterRequest(BaseModel):
    """Request body for user registration."""
    username: str
    password: str


class LoginRequest(BaseModel):
    """Request body for login."""
    username: str
    password: str


class TokenResponse(BaseModel):
    """Response with JWT token after successful auth."""
    access_token: str
    token_type: str = "bearer"
    username: str

@router.post("/register", response_model=TokenResponse,
             status_code=status.HTTP_201_CREATED)
def register(request: RegisterRequest, db: Session = Depends(get_db)):
    """Create a new administrator account.

    Hashes the password with bcrypt before storing.
    Returns a JWT token so the user is immediately logged in.
    """
    # Check if username already exists
    existing = db.query(User).filter_by(username=request.username).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists",
        )

    # Create user with hashed password
    user = User(
        username=request.username,
        password_hash=hash_password(request.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # Generate token so user is immediately authenticated
    token = create_token(user.id, user.username)

    logger.info(f"New user registered: {user.username}")

    return TokenResponse(
        access_token=token,
        username=user.username,
    )


@router.post("/login", response_model=TokenResponse)
def login(request: LoginRequest, db: Session = Depends(get_db)):
    """Authenticate and receive a JWT token.

    Validates credentials against the database. On success,
    returns a signed JWT token valid for the configured period.
    """
    user = db.query(User).filter_by(username=request.username).first()

    if not user or not verify_password(request.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    token = create_token(user.id, user.username)

    logger.info(f"User logged in: {user.username}")

    return TokenResponse(
        access_token=token,
        username=user.username,
    )