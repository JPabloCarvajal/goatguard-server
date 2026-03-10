"""
Database connection management for GOATGuard server.

Uses SQLAlchemy to establish and manage the connection pool
to PostgreSQL. A connection pool keeps several connections
open and reuses them instead of creating a new one per query.
This is important because opening a TCP connection to PostgreSQL
(with its own three-way handshake) on every query would be slow.
"""

import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

logger = logging.getLogger(__name__)

class Database:
    """Manages PostgreSQL connection and session creation.

    Args:
        host: Database server address.
        port: Database server port.
        name: Database name.
        user: Database user.
        password: Database password.
    """

    def __init__(self, host: str, port: int, name: str,
                 user: str, password: str) -> None:
        self.url = f"postgresql://{user}:{password}@{host}:{port}/{name}"
        self.engine = create_engine(self.url, echo=False)
        self.SessionLocal = sessionmaker(bind=self.engine)

        logger.info(f"Database connection configured: {host}:{port}/{name}")

    def get_session(self) -> Session:
        """Create a new database session for a unit of work."""
        return self.SessionLocal()

    def create_tables(self, base) -> None:
        """Create all tables defined in the ORM models."""
        base.metadata.create_all(self.engine)
        logger.info("Database tables created")