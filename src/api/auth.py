"""
Authentication utilities for GOATGuard API.

Two responsibilities:
1. Password hashing with bcrypt (for storage in PostgreSQL)
2. JWT token creation and verification (for session management)

bcrypt is intentionally slow — each hash takes ~100ms. This makes
brute-force attacks impractical: trying 1 billion passwords would
take ~3 years instead of seconds.

JWT (JSON Web Token, RFC 7519) is a self-contained token. The server
can verify it WITHOUT querying the database because the token carries
its own proof of authenticity (a cryptographic signature).
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
import jwt

logger = logging.getLogger(__name__)

# Module-level config — set during API startup via init_auth().
# Never hardcoded with real secrets. Development defaults come
# from server_config.yaml, production values from env variables.
_jwt_secret: str = ""
_jwt_algorithm: str = "HS256"
_jwt_expiration_hours: int = 24


def init_auth(jwt_secret: str, jwt_algorithm: str = "HS256",
              jwt_expiration_hours: int = 24) -> None:
    """Initialize auth module with configuration values.

    Called once during API startup with values from ServerConfig.
    Avoids hardcoding secrets in source code.

    Args:
        jwt_secret: Secret key for signing JWT tokens.
        jwt_algorithm: Signing algorithm (default HS256).
        jwt_expiration_hours: Token validity period.
    """
    global _jwt_secret, _jwt_algorithm, _jwt_expiration_hours
    _jwt_secret = jwt_secret
    _jwt_algorithm = jwt_algorithm
    _jwt_expiration_hours = jwt_expiration_hours
    logger.info("Auth module initialized")


def hash_password(plain_password: str) -> str:
    """Hash a password using bcrypt.

    bcrypt generates a random salt automatically and embeds it
    in the output hash. Two identical passwords produce DIFFERENT
    hashes because each gets a unique salt. This prevents rainbow
    table attacks (precomputed hash dictionaries).

    Args:
        plain_password: The password in plain text.

    Returns:
        The bcrypt hash string (ready for database storage).
    """
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(plain_password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its bcrypt hash.

    bcrypt extracts the embedded salt from the stored hash,
    re-hashes the input with that same salt, and compares.
    The comparison is constant-time to prevent timing attacks.

    Args:
        plain_password: The password attempt from login.
        hashed_password: The stored hash from the database.

    Returns:
        True if the password matches.
    """
    return bcrypt.checkpw(
        plain_password.encode("utf-8"),
        hashed_password.encode("utf-8"),
    )


def create_token(
    user_id: int,
    username: str,
    scope: str = "full_access",
    expiration_minutes: Optional[int] = None,
) -> str:
    """Crea JWT con scope explícito [RF-13].

    Scopes válidos: "full_access", "pending_totp", "password_reset"
    """
    now = datetime.now(timezone.utc)
    exp_minutes = expiration_minutes or (_jwt_expiration_hours * 60)
    payload = {
        "sub": str(user_id),
        "username": username,
        "scope": scope,
        "iat": now,
        "exp": now + timedelta(minutes=exp_minutes),
    }
    return jwt.encode(payload, _jwt_secret, algorithm=_jwt_algorithm)


def verify_token(token: str) -> Optional[dict]:
    """Verify and decode a JWT token.

    Checks two things:
    1. Signature — was this token signed with OUR secret key?
    2. Expiration — has the token expired?

    If either check fails, returns None (unauthenticated).

    Args:
        token: The JWT string from the Authorization header.

    Returns:
        The decoded payload dict if valid, None otherwise.
    """
    try:
        payload = jwt.decode(token, _jwt_secret, algorithms=[_jwt_algorithm])
        return payload
    except jwt.ExpiredSignatureError:
        logger.debug("Token expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.debug(f"Invalid token: {e}")
        return None


def verify_token_scope(token: str, required_scope: str) -> Optional[dict]:
    """
    Verifica token JWT y que tenga el scope requerido.
    Retorna payload si válido, None si inválido o scope incorrecto.
    """
    payload = verify_token(token)
    if not payload:
        return None
    if payload.get("scope") != required_scope:
        return None
    return payload