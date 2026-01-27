"""Async Redis stream consumer with consumer groups."""

import asyncio
import json
from datetime import datetime
from typing import AsyncIterator, Callable

import redis.asyncio as aioredis

from logmind.config.settings import get_settings
from logmind.ingestion.base import LogSeverity, NormalizedLog


class LogConsumer:
    """
    Async consumer for Redis stream with consumer group support.

    Provides exactly-once processing semantics through acknowledgments.
    """

    def __init__(
        self,
        stream_name: str | None = None,
        group_name: str | None = None,
        consumer_name: str | None = None,
        batch_size: int = 100,
        block_ms: int = 5000,
    ) -> None:
        """
        Initialize the consumer.

        Args:
            stream_name: Redis stream name
            group_name: Consumer group name
            consumer_name: Unique consumer identifier
            batch_size: Number of messages per read
            block_ms: Block timeout in milliseconds
        """
        settings = get_settings()
        self.stream_name = stream_name or settings.redis_stream_name
        self.group_name = group_name or settings.redis_consumer_group
        self.consumer_name = consumer_name or f"worker-{id(self)}"
        self.batch_size = batch_size
        self.block_ms = block_ms
        self._running = False
        self._redis: aioredis.Redis | None = None

    async def _get_connection(self) -> aioredis.Redis:
        """Get or create async Redis connection."""
        if self._redis is None:
            settings = get_settings()
            password = None
            if settings.redis_password:
                password = settings.redis_password.get_secret_value()

            self._redis = aioredis.Redis(
                host=settings.redis_host,
                port=settings.redis_port,
                db=settings.redis_db,
                password=password,
                decode_responses=True,
            )
        return self._redis

    async def ensure_group(self) -> None:
        """Ensure consumer group exists."""
        redis = await self._get_connection()
        try:
            await redis.xgroup_create(
                self.stream_name,
                self.group_name,
                id="0",
                mkstream=True,
            )
        except aioredis.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise

    def _deserialize_log(self, data: dict) -> NormalizedLog | None:
        """Deserialize a log from Redis message data."""
        try:
            payload = json.loads(data.get("payload", "{}"))
            payload["timestamp"] = datetime.fromisoformat(payload["timestamp"])
            payload["ingested_at"] = datetime.fromisoformat(payload["ingested_at"])
            payload["severity"] = LogSeverity(payload.get("severity", "unknown"))
            return NormalizedLog(**payload)
        except (json.JSONDecodeError, KeyError, ValueError):
            return None

    async def consume(
        self,
        handler: Callable[[NormalizedLog], bool] | None = None,
    ) -> AsyncIterator[tuple[str, NormalizedLog]]:
        """
        Consume messages from the stream.

        Args:
            handler: Optional callback for each message.
                     If returns True, message is acknowledged.

        Yields:
            Tuple of (message_id, NormalizedLog)
        """
        redis = await self._get_connection()
        await self.ensure_group()
        self._running = True

        while self._running:
            try:
                messages = await redis.xreadgroup(
                    groupname=self.group_name,
                    consumername=self.consumer_name,
                    streams={self.stream_name: ">"},
                    count=self.batch_size,
                    block=self.block_ms,
                )

                if not messages:
                    continue

                for stream_name, stream_messages in messages:
                    for message_id, data in stream_messages:
                        log = self._deserialize_log(data)
                        if log is None:
                            await redis.xack(self.stream_name, self.group_name, message_id)
                            continue

                        if handler:
                            try:
                                if handler(log):
                                    await redis.xack(self.stream_name, self.group_name, message_id)
                            except Exception:
                                pass
                        else:
                            yield (message_id, log)

            except aioredis.ConnectionError:
                await asyncio.sleep(1)
                self._redis = None
            except Exception:
                await asyncio.sleep(0.1)

    async def acknowledge(self, message_ids: str | list[str]) -> int:
        """
        Acknowledge processed messages.

        Args:
            message_ids: Single ID or list of message IDs

        Returns:
            Number of acknowledged messages
        """
        if isinstance(message_ids, str):
            message_ids = [message_ids]

        redis = await self._get_connection()
        return await redis.xack(self.stream_name, self.group_name, *message_ids)

    async def claim_pending(
        self,
        min_idle_ms: int = 60000,
        count: int = 100,
    ) -> list[tuple[str, NormalizedLog]]:
        """
        Claim pending messages from dead consumers.

        Args:
            min_idle_ms: Minimum idle time before claiming
            count: Maximum messages to claim

        Returns:
            List of (message_id, NormalizedLog) tuples
        """
        redis = await self._get_connection()
        results = []

        try:
            pending = await redis.xpending_range(
                self.stream_name,
                self.group_name,
                min="-",
                max="+",
                count=count,
            )

            for entry in pending:
                if entry.get("time_since_delivered", 0) >= min_idle_ms:
                    message_id = entry["message_id"]
                    claimed = await redis.xclaim(
                        self.stream_name,
                        self.group_name,
                        self.consumer_name,
                        min_idle_time=min_idle_ms,
                        message_ids=[message_id],
                    )
                    for mid, data in claimed:
                        log = self._deserialize_log(data)
                        if log:
                            results.append((mid, log))

        except Exception:
            pass

        return results

    def stop(self) -> None:
        """Stop consuming messages."""
        self._running = False

    async def close(self) -> None:
        """Close the Redis connection."""
        self.stop()
        if self._redis:
            await self._redis.close()
            self._redis = None
