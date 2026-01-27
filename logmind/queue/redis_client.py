"""Redis connection wrapper with connection pooling."""

from contextlib import contextmanager
from typing import Generator

import redis
from redis import Redis

from logmind.config.settings import get_settings


class RedisClient:
    """
    Redis client wrapper with connection pooling.

    Provides singleton-like behavior for connection reuse.
    """

    _instance: "RedisClient | None" = None
    _pool: redis.ConnectionPool | None = None

    def __new__(cls) -> "RedisClient":
        """Ensure single instance per process."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        """Initialize connection pool if not already created."""
        if self._pool is None:
            settings = get_settings()
            password = None
            if settings.redis_password:
                password = settings.redis_password.get_secret_value()

            self._pool = redis.ConnectionPool(
                host=settings.redis_host,
                port=settings.redis_port,
                db=settings.redis_db,
                password=password,
                decode_responses=True,
                max_connections=10,
            )

    @property
    def connection(self) -> Redis:
        """Get a Redis connection from the pool."""
        return Redis(connection_pool=self._pool)

    @contextmanager
    def get_connection(self) -> Generator[Redis, None, None]:
        """Context manager for Redis connections."""
        conn = self.connection
        try:
            yield conn
        finally:
            pass

    def ping(self) -> bool:
        """Test Redis connectivity."""
        try:
            return self.connection.ping()
        except redis.ConnectionError:
            return False

    def close(self) -> None:
        """Close all connections in the pool."""
        if self._pool:
            self._pool.disconnect()
            self._pool = None
            RedisClient._instance = None

    def ensure_stream(self, stream_name: str) -> None:
        """Ensure a Redis stream exists."""
        with self.get_connection() as conn:
            try:
                conn.xinfo_stream(stream_name)
            except redis.ResponseError:
                conn.xadd(stream_name, {"_init": "1"})
                conn.xdel(stream_name, conn.xinfo_stream(stream_name)["first-entry"][0])

    def create_consumer_group(
        self,
        stream_name: str,
        group_name: str,
        start_id: str = "0",
    ) -> bool:
        """
        Create a consumer group for a stream.

        Args:
            stream_name: Redis stream name
            group_name: Consumer group name
            start_id: Starting message ID ("0" for all, "$" for new only)

        Returns:
            True if created, False if already exists
        """
        with self.get_connection() as conn:
            try:
                conn.xgroup_create(
                    stream_name,
                    group_name,
                    id=start_id,
                    mkstream=True,
                )
                return True
            except redis.ResponseError as e:
                if "BUSYGROUP" in str(e):
                    return False
                raise

    def get_stream_info(self, stream_name: str) -> dict | None:
        """Get information about a stream."""
        try:
            with self.get_connection() as conn:
                return conn.xinfo_stream(stream_name)
        except redis.ResponseError:
            return None

    def get_consumer_group_info(self, stream_name: str) -> list[dict]:
        """Get information about consumer groups for a stream."""
        try:
            with self.get_connection() as conn:
                return conn.xinfo_groups(stream_name)
        except redis.ResponseError:
            return []
