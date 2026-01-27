"""Syslog parser supporting RFC 3164 (BSD) and RFC 5424 formats."""

import re
from datetime import datetime
from typing import ClassVar

from logmind.ingestion.base import BaseParser, LogSeverity, NormalizedLog


class SyslogParser(BaseParser):
    """
    Parser for syslog messages.

    Supports:
    - RFC 3164 (BSD syslog): <priority>timestamp hostname program[pid]: message
    - RFC 5424 (IETF syslog): <priority>version timestamp hostname app-name procid msgid structured-data msg
    """

    # Syslog facilities
    FACILITIES: ClassVar[dict[int, str]] = {
        0: "kern",
        1: "user",
        2: "mail",
        3: "daemon",
        4: "auth",
        5: "syslog",
        6: "lpr",
        7: "news",
        8: "uucp",
        9: "cron",
        10: "authpriv",
        11: "ftp",
        16: "local0",
        17: "local1",
        18: "local2",
        19: "local3",
        20: "local4",
        21: "local5",
        22: "local6",
        23: "local7",
    }

    # Severity mapping
    SEVERITY_MAP: ClassVar[dict[int, LogSeverity]] = {
        0: LogSeverity.EMERGENCY,
        1: LogSeverity.ALERT,
        2: LogSeverity.CRITICAL,
        3: LogSeverity.ERROR,
        4: LogSeverity.WARNING,
        5: LogSeverity.NOTICE,
        6: LogSeverity.INFO,
        7: LogSeverity.DEBUG,
    }

    # RFC 3164 pattern: <PRI>Mmm dd HH:MM:SS hostname program[pid]: message
    RFC3164_PATTERN: ClassVar[re.Pattern] = re.compile(
        r"^(?:<(\d{1,3})>)?"
        r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(\S+)\s+"
        r"(?:(\S+?)(?:\[(\d+)\])?:\s*)?"
        r"(.*)$"
    )

    # RFC 5424 pattern
    RFC5424_PATTERN: ClassVar[re.Pattern] = re.compile(
        r"^<(\d{1,3})>(\d+)\s+"
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+"
        r"(\S+)\s+"
        r"(\S+)\s+"
        r"(\S+)\s+"
        r"(\S+)\s+"
        r"(?:\[(.*?)\])?\s*"
        r"(.*)$"
    )

    # Auth log specific patterns for extracting IPs and users
    AUTH_IP_PATTERN: ClassVar[re.Pattern] = re.compile(
        r"(?:from|for)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    )
    AUTH_USER_PATTERN: ClassVar[re.Pattern] = re.compile(
        r"(?:user[=:\s]+|for\s+(?:invalid\s+user\s+)?|Failed\s+password\s+for\s+(?:invalid\s+user\s+)?)(\w+)"
    )
    AUTH_PORT_PATTERN: ClassVar[re.Pattern] = re.compile(r"port\s+(\d+)")

    @property
    def source_type(self) -> str:
        return "syslog"

    def _decode_priority(self, priority: int) -> tuple[str | None, LogSeverity]:
        """Decode syslog priority into facility and severity."""
        facility_num = priority >> 3
        severity_num = priority & 0x07

        facility = self.FACILITIES.get(facility_num)
        severity = self.SEVERITY_MAP.get(severity_num, LogSeverity.UNKNOWN)

        return facility, severity

    def _parse_rfc3164_timestamp(self, ts_str: str) -> datetime:
        """Parse RFC 3164 timestamp (Mmm dd HH:MM:SS)."""
        current_year = datetime.now().year
        try:
            dt = datetime.strptime(f"{current_year} {ts_str}", "%Y %b %d %H:%M:%S")
            if dt > datetime.now():
                dt = dt.replace(year=current_year - 1)
            return dt
        except ValueError:
            return datetime.now()

    def _parse_rfc5424_timestamp(self, ts_str: str) -> datetime:
        """Parse RFC 5424 ISO 8601 timestamp."""
        ts_str = ts_str.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(ts_str)
        except ValueError:
            return datetime.now()

    def _extract_auth_context(
        self, message: str
    ) -> tuple[str | None, str | None, int | None]:
        """Extract IP, user, and port from auth log messages."""
        src_ip = None
        user = None
        src_port = None

        ip_match = self.AUTH_IP_PATTERN.search(message)
        if ip_match:
            src_ip = ip_match.group(1)

        user_match = self.AUTH_USER_PATTERN.search(message)
        if user_match:
            user = user_match.group(1)

        port_match = self.AUTH_PORT_PATTERN.search(message)
        if port_match:
            src_port = int(port_match.group(1))

        return src_ip, user, src_port

    def parse(self, raw_line: str, source: str = "unknown") -> NormalizedLog | None:
        """Parse a syslog line into NormalizedLog."""
        raw_line = raw_line.strip()
        if not raw_line:
            return None

        # Try RFC 5424 first
        match = self.RFC5424_PATTERN.match(raw_line)
        if match:
            priority = int(match.group(1))
            facility, severity = self._decode_priority(priority)
            timestamp = self._parse_rfc5424_timestamp(match.group(3))
            hostname = match.group(4)
            program = match.group(5) if match.group(5) != "-" else None
            pid_str = match.group(6)
            pid = int(pid_str) if pid_str and pid_str != "-" else None
            message = match.group(9) or ""

            src_ip, user, src_port = self._extract_auth_context(message)

            return NormalizedLog(
                timestamp=timestamp,
                source=hostname if hostname != "-" else source,
                source_type=self.source_type,
                severity=severity,
                facility=facility,
                program=program,
                pid=pid,
                message=message,
                raw=raw_line,
                src_ip=src_ip,
                src_port=src_port,
                user=user,
            )

        # Try RFC 3164
        match = self.RFC3164_PATTERN.match(raw_line)
        if match:
            priority_str = match.group(1)
            facility = None
            severity = LogSeverity.UNKNOWN

            if priority_str:
                priority = int(priority_str)
                facility, severity = self._decode_priority(priority)

            timestamp = self._parse_rfc3164_timestamp(match.group(2))
            hostname = match.group(3)
            program = match.group(4)
            pid_str = match.group(5)
            pid = int(pid_str) if pid_str else None
            message = match.group(6) or ""

            src_ip, user, src_port = self._extract_auth_context(message)

            return NormalizedLog(
                timestamp=timestamp,
                source=hostname,
                source_type=self.source_type,
                severity=severity,
                facility=facility,
                program=program,
                pid=pid,
                message=message,
                raw=raw_line,
                src_ip=src_ip,
                src_port=src_port,
                user=user,
            )

        return None
