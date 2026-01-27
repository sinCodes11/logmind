"""Redis stream producer for log ingestion."""

import json
from typing import Sequence

from logmind.config.settings import get_settings
from logmind.ingestion.base import NormalizedLog
from logmind.queue.redis_client import RedisClient


class LogProducer:
    """
    Produces normalized logs to a Redis stream.

    Logs are serialized to JSON and added to the stream with
    automatic ID generation.
    """

    def __init__(
        self,
        stream_name: str | None = None,
        max_len: int = 100000,
    ) -> None:
        """
        Initialize the producer.

        Args:
            stream_name: Redis stream name (defaults to config)
            max_len: Maximum stream length (MAXLEN approximate)
        """
        settings = get_settings()
        self.stream_name = stream_name or settings.redis_stream_name
        self.max_len = max_len
        self._client = RedisClient()

    def publish(self, log: NormalizedLog) -> str:
        """
        Publish a single log to the stream.

        Args:
            log: NormalizedLog to publish

        Returns:
            Message ID assigned by Redis
        """
        with self._client.get_connection() as conn:
            data = {
                "payload": json.dumps(log.model_dump_json_safe()),
                "source_type": log.source_type,
                "severity": log.severity.value,
            }
            message_id = conn.xadd(
                self.stream_name,
                data,
                maxlen=self.max_len,
                approximate=True,
            )
            return message_id

    def publish_batch(self, logs: Sequence[NormalizedLog]) -> list[str]:
        """
        Publish multiple logs to the stream.

        Uses pipelining for efficiency.

        Args:
            logs: Sequence of NormalizedLog entries

        Returns:
            List of message IDs
        """
        if not logs:
            return []

        with self._client.get_connection() as conn:
            pipe = conn.pipeline()
            for log in logs:
                data = {
                    "payload": json.dumps(log.model_dump_json_safe()),
                    "source_type": log.source_type,
                    "severity": log.severity.value,
                }
                pipe.xadd(
                    self.stream_name,
                    data,
                    maxlen=self.max_len,
                    approximate=True,
                )
            results = pipe.execute()
            return [str(r) for r in results]

    def get_stream_length(self) -> int:
        """Get current stream length."""
        with self._client.get_connection() as conn:
            return conn.xlen(self.stream_name)

    def get_pending_count(self, group_name: str) -> int:
        """Get count of pending messages for a consumer group."""
        with self._client.get_connection() as conn:
            try:
                info = conn.xpending(self.stream_name, group_name)
                return info.get("pending", 0) if info else 0
            except Exception:
                return 0
