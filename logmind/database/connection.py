"""Database connection management."""

from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from logmind.config.settings import get_settings


class DatabaseConnection:
    """
    Database connection manager with session handling.

    Provides thread-safe session management with automatic
    transaction handling.
    """

    _instance: "DatabaseConnection | None" = None

    def __new__(cls) -> "DatabaseConnection":
        """Ensure single instance per process."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        """Initialize database engine and session factory."""
        if self._initialized:
            return

        settings = get_settings()
        self._engine = create_engine(
            settings.postgres_dsn,
            pool_size=5,
            max_overflow=10,
            pool_pre_ping=True,
            echo=settings.debug,
        )
        self._session_factory = sessionmaker(
            bind=self._engine,
            autocommit=False,
            autoflush=False,
        )
        self._initialized = True

    @property
    def engine(self):
        """Get SQLAlchemy engine."""
        return self._engine

    @contextmanager
    def session(self) -> Generator[Session, None, None]:
        """
        Context manager for database sessions.

        Automatically commits on success, rolls back on error.
        """
        session = self._session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def create_tables(self) -> None:
        """Create all database tables."""
        from logmind.database.models import Base
        Base.metadata.create_all(self._engine)

    def drop_tables(self) -> None:
        """Drop all database tables."""
        from logmind.database.models import Base
        Base.metadata.drop_all(self._engine)

    def close(self) -> None:
        """Close all connections."""
        self._engine.dispose()
        DatabaseConnection._instance = None


def get_db() -> DatabaseConnection:
    """Get database connection instance."""
    return DatabaseConnection()
