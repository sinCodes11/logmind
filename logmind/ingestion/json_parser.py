"""JSON log parser for structured log formats."""

import json
from datetime import datetime
from typing import Any, ClassVar

from logmind.ingestion.base import BaseParser, LogSeverity, NormalizedLog


class JSONLogParser(BaseParser):
    """
    Parser for JSON-formatted logs.

    Supports common JSON log formats:
    - Nginx JSON access logs
    - Application logs (Python structlog, Node.js winston)
    - Generic JSON with flexible field mapping
    """

    # Common timestamp field names
    TIMESTAMP_FIELDS: ClassVar[list[str]] = [
        "timestamp",
        "@timestamp",
        "time",
        "datetime",
        "date",
        "ts",
        "created",
        "event_time",
    ]

    # Common message field names
    MESSAGE_FIELDS: ClassVar[list[str]] = [
        "message",
        "msg",
        "log",
        "text",
        "event",
        "description",
    ]

    # Common severity/level field names
    SEVERITY_FIELDS: ClassVar[list[str]] = [
        "level",
        "severity",
        "log_level",
        "loglevel",
        "priority",
    ]

    # Severity string mapping
    SEVERITY_MAP: ClassVar[dict[str, LogSeverity]] = {
        "emergency": LogSeverity.EMERGENCY,
        "emerg": LogSeverity.EMERGENCY,
        "alert": LogSeverity.ALERT,
        "critical": LogSeverity.CRITICAL,
        "crit": LogSeverity.CRITICAL,
        "fatal": LogSeverity.CRITICAL,
        "error": LogSeverity.ERROR,
        "err": LogSeverity.ERROR,
        "warning": LogSeverity.WARNING,
        "warn": LogSeverity.WARNING,
        "notice": LogSeverity.NOTICE,
        "info": LogSeverity.INFO,
        "information": LogSeverity.INFO,
        "debug": LogSeverity.DEBUG,
        "trace": LogSeverity.DEBUG,
    }

    # Nginx JSON log field mapping
    NGINX_FIELDS: ClassVar[dict[str, str]] = {
        "remote_addr": "src_ip",
        "remote_user": "user",
        "request": "message",
        "status": "http_status",
        "body_bytes_sent": "bytes_sent",
        "http_referer": "referer",
        "http_user_agent": "user_agent",
    }

    @property
    def source_type(self) -> str:
        return "json"

    def _find_field(self, data: dict[str, Any], field_names: list[str]) -> Any | None:
        """Find a field value by trying multiple possible names."""
        for name in field_names:
            if name in data:
                return data[name]
            # Try case-insensitive lookup
            for key in data:
                if key.lower() == name.lower():
                    return data[key]
        return None

    def _parse_timestamp(self, value: Any) -> datetime:
        """Parse timestamp from various formats."""
        if value is None:
            return datetime.utcnow()

        if isinstance(value, datetime):
            return value

        if isinstance(value, (int, float)):
            if value > 1e12:
                return datetime.fromtimestamp(value / 1000)
            return datetime.fromtimestamp(value)

        if isinstance(value, str):
            formats = [
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S.%f%z",
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%d %H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S",
                "%d/%b/%Y:%H:%M:%S %z",
            ]
            for fmt in formats:
                try:
                    return datetime.strptime(value, fmt)
                except ValueError:
                    continue

            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                pass

        return datetime.utcnow()

    def _parse_severity(self, value: Any) -> LogSeverity:
        """Parse severity from string or number."""
        if value is None:
            return LogSeverity.UNKNOWN

        if isinstance(value, int):
            if 0 <= value <= 7:
                severity_map = {
                    0: LogSeverity.EMERGENCY,
                    1: LogSeverity.ALERT,
                    2: LogSeverity.CRITICAL,
                    3: LogSeverity.ERROR,
                    4: LogSeverity.WARNING,
                    5: LogSeverity.NOTICE,
                    6: LogSeverity.INFO,
                    7: LogSeverity.DEBUG,
                }
                return severity_map.get(value, LogSeverity.UNKNOWN)
            return LogSeverity.UNKNOWN

        if isinstance(value, str):
            return self.SEVERITY_MAP.get(value.lower(), LogSeverity.UNKNOWN)

        return LogSeverity.UNKNOWN

    def _extract_nginx_fields(
        self, data: dict[str, Any]
    ) -> tuple[str | None, str | None, dict[str, Any]]:
        """Extract nginx-specific fields."""
        src_ip = data.get("remote_addr")
        user = data.get("remote_user")
        if user == "-":
            user = None

        extensions = {}
        for nginx_field, ext_field in self.NGINX_FIELDS.items():
            if nginx_field in data and nginx_field not in ("remote_addr", "remote_user"):
                extensions[ext_field] = data[nginx_field]

        return src_ip, user, extensions

    def parse(self, raw_line: str, source: str = "unknown") -> NormalizedLog | None:
        """Parse a JSON log line into NormalizedLog."""
        raw_line = raw_line.strip()
        if not raw_line:
            return None

        try:
            data = json.loads(raw_line)
        except json.JSONDecodeError:
            return None

        if not isinstance(data, dict):
            return None

        # Extract timestamp
        ts_value = self._find_field(data, self.TIMESTAMP_FIELDS)
        timestamp = self._parse_timestamp(ts_value)

        # Extract message
        message = self._find_field(data, self.MESSAGE_FIELDS)
        if message is None:
            message = raw_line

        # Extract severity
        severity_value = self._find_field(data, self.SEVERITY_FIELDS)
        severity = self._parse_severity(severity_value)

        # Extract source/hostname
        log_source = data.get("host") or data.get("hostname") or data.get("server") or source

        # Extract program/service
        program = data.get("service") or data.get("app") or data.get("application") or data.get("logger")

        # Extract PID
        pid = data.get("pid") or data.get("process_id")
        if isinstance(pid, str) and pid.isdigit():
            pid = int(pid)
        elif not isinstance(pid, int):
            pid = None

        # Extract network context
        src_ip = data.get("client_ip") or data.get("src_ip") or data.get("remote_addr")
        dst_ip = data.get("server_ip") or data.get("dst_ip")
        src_port = data.get("client_port") or data.get("src_port")
        dst_port = data.get("server_port") or data.get("dst_port")
        user = data.get("user") or data.get("username") or data.get("remote_user")

        # Check for nginx format
        if "remote_addr" in data and "request" in data:
            nginx_ip, nginx_user, nginx_ext = self._extract_nginx_fields(data)
            src_ip = nginx_ip or src_ip
            user = nginx_user or user
            extensions = nginx_ext
        else:
            extensions = {k: v for k, v in data.items() if k not in self.TIMESTAMP_FIELDS + self.MESSAGE_FIELDS + self.SEVERITY_FIELDS}

        if user == "-":
            user = None

        return NormalizedLog(
            timestamp=timestamp,
            source=log_source,
            source_type=self.source_type,
            severity=severity,
            program=program,
            pid=pid,
            message=str(message),
            raw=raw_line,
            src_ip=src_ip,
            src_port=int(src_port) if src_port else None,
            dst_ip=dst_ip,
            dst_port=int(dst_port) if dst_port else None,
            user=user,
            extensions=extensions,
        )
