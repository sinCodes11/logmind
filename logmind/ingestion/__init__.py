"""Log ingestion module."""

from logmind.ingestion.base import BaseParser, NormalizedLog, LogSeverity
from logmind.ingestion.syslog_parser import SyslogParser
from logmind.ingestion.json_parser import JSONLogParser
from logmind.ingestion.cef_parser import CEFParser

__all__ = [
    "BaseParser",
    "NormalizedLog",
    "LogSeverity",
    "SyslogParser",
    "JSONLogParser",
    "CEFParser",
]
