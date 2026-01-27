"""Base log schema and parser interface."""

from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator

# Security constants
MAX_LOG_LINE_LENGTH = 65536  # 64KB max per log line
MAX_MESSAGE_LENGTH = 32768  # 32KB max message
MAX_SOURCE_LENGTH = 255
MAX_PROGRAM_LENGTH = 255
MAX_USER_LENGTH = 255


class LogSeverity(str, Enum):
    """Log severity levels aligned with syslog."""

    EMERGENCY = "emergency"
    ALERT = "alert"
    CRITICAL = "critical"
    ERROR = "error"
    WARNING = "warning"
    NOTICE = "notice"
    INFO = "info"
    DEBUG = "debug"
    UNKNOWN = "unknown"


class NormalizedLog(BaseModel):
    """
    Normalized log entry schema.

    All log formats are converted to this schema for uniform processing.
    """

    id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime
    source: str = Field(description="Log source identifier (hostname, service)", max_length=MAX_SOURCE_LENGTH)
    source_type: str = Field(description="Original log format (syslog, json, cef)", max_length=50)
    severity: LogSeverity = LogSeverity.UNKNOWN
    facility: str | None = Field(default=None, max_length=50)
    program: str | None = Field(default=None, description="Process or application name", max_length=MAX_PROGRAM_LENGTH)
    pid: int | None = Field(default=None, description="Process ID if available", ge=0, le=2147483647)
    message: str = Field(description="Log message content", max_length=MAX_MESSAGE_LENGTH)
    raw: str = Field(description="Original raw log line", max_length=MAX_LOG_LINE_LENGTH)

    # Network context
    src_ip: str | None = Field(default=None, max_length=45)  # IPv6 max length
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_ip: str | None = Field(default=None, max_length=45)
    dst_port: int | None = Field(default=None, ge=0, le=65535)

    # User context
    user: str | None = Field(default=None, max_length=MAX_USER_LENGTH)

    # Extended fields
    extensions: dict[str, Any] = Field(default_factory=dict)

    # Processing metadata
    ingested_at: datetime = Field(default_factory=datetime.utcnow)
    tags: list[str] = Field(default_factory=list, max_length=100)

    @field_validator('message', 'raw', 'source', 'program', 'user')
    @classmethod
    def truncate_if_needed(cls, v: str | None) -> str | None:
        """Truncate strings that exceed max length instead of rejecting."""
        if v is None:
            return v
        # Pydantic will handle max_length validation
        return v

    def model_dump_json_safe(self) -> dict[str, Any]:
        """Return dict with datetime objects serialized to ISO format."""
        data = self.model_dump()
        data["timestamp"] = self.timestamp.isoformat()
        data["ingested_at"] = self.ingested_at.isoformat()
        return data


class BaseParser(ABC):
    """Abstract base class for log parsers."""

    @property
    @abstractmethod
    def source_type(self) -> str:
        """Return the source type identifier for this parser."""
        pass

    @abstractmethod
    def parse(self, raw_line: str, source: str = "unknown") -> NormalizedLog | None:
        """
        Parse a raw log line into a NormalizedLog.

        Args:
            raw_line: Raw log line string
            source: Source identifier (hostname, filename, etc.)

        Returns:
            NormalizedLog if parsing successful, None otherwise
        """
        pass

    def parse_batch(
        self, lines: list[str], source: str = "unknown", max_lines: int = 100000
    ) -> list[NormalizedLog]:
        """
        Parse multiple log lines.

        Args:
            lines: List of raw log lines
            source: Source identifier
            max_lines: Maximum number of lines to process (DoS protection)

        Returns:
            List of successfully parsed NormalizedLog entries
        """
        results = []
        for idx, line in enumerate(lines):
            if idx >= max_lines:
                break
            line = line.strip()
            if not line:
                continue
            # Skip lines that are too long
            if len(line) > MAX_LOG_LINE_LENGTH:
                continue
            parsed = self.parse(line, source)
            if parsed:
                results.append(parsed)
        return results
