"""Common Event Format (CEF) parser."""

import re
from datetime import datetime
from typing import ClassVar

from logmind.ingestion.base import BaseParser, LogSeverity, NormalizedLog


class CEFParser(BaseParser):
    """
    Parser for Common Event Format (CEF) logs.

    CEF Format:
    CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension

    Extension format: key=value pairs separated by spaces
    """

    # CEF header pattern
    CEF_PATTERN: ClassVar[re.Pattern] = re.compile(
        r"^(?:.*?\s)?CEF:(\d+)\|"
        r"([^|]*)\|"
        r"([^|]*)\|"
        r"([^|]*)\|"
        r"([^|]*)\|"
        r"([^|]*)\|"
        r"([^|]*)\|"
        r"(.*)$"
    )

    # Severity mapping (CEF uses 0-10 scale)
    SEVERITY_MAP: ClassVar[dict[int, LogSeverity]] = {
        0: LogSeverity.INFO,
        1: LogSeverity.INFO,
        2: LogSeverity.INFO,
        3: LogSeverity.INFO,
        4: LogSeverity.WARNING,
        5: LogSeverity.WARNING,
        6: LogSeverity.WARNING,
        7: LogSeverity.ERROR,
        8: LogSeverity.ERROR,
        9: LogSeverity.CRITICAL,
        10: LogSeverity.CRITICAL,
    }

    # String severity mapping
    SEVERITY_STRING_MAP: ClassVar[dict[str, LogSeverity]] = {
        "low": LogSeverity.INFO,
        "medium": LogSeverity.WARNING,
        "high": LogSeverity.ERROR,
        "very-high": LogSeverity.CRITICAL,
        "unknown": LogSeverity.UNKNOWN,
    }

    # CEF extension key mapping to NormalizedLog fields
    EXTENSION_MAP: ClassVar[dict[str, str]] = {
        "src": "src_ip",
        "spt": "src_port",
        "dst": "dst_ip",
        "dpt": "dst_port",
        "suser": "user",
        "duser": "dst_user",
        "msg": "message",
        "act": "action",
        "proto": "protocol",
        "cs1": "custom_string_1",
        "cs2": "custom_string_2",
        "cs3": "custom_string_3",
        "cs4": "custom_string_4",
        "cs5": "custom_string_5",
        "cs6": "custom_string_6",
        "cn1": "custom_number_1",
        "cn2": "custom_number_2",
        "cn3": "custom_number_3",
        "deviceExternalId": "device_external_id",
        "deviceHostName": "device_hostname",
        "deviceAddress": "device_address",
        "deviceProcessName": "program",
    }

    @property
    def source_type(self) -> str:
        return "cef"

    def _parse_extensions(self, extension_str: str) -> dict[str, str]:
        """
        Parse CEF extension key=value pairs.

        Handles escaped characters and multi-word values.
        """
        extensions = {}
        if not extension_str:
            return extensions

        # Handle escaped characters
        extension_str = extension_str.replace("\\=", "\x00")
        extension_str = extension_str.replace("\\\\", "\x01")
        extension_str = extension_str.replace("\\n", "\n")
        extension_str = extension_str.replace("\\r", "\r")

        # Parse key=value pairs
        pattern = re.compile(r"(\w+)=((?:[^ ]| (?!\w+=))*)")
        for match in pattern.finditer(extension_str):
            key = match.group(1)
            value = match.group(2).strip()
            value = value.replace("\x00", "=")
            value = value.replace("\x01", "\\")
            extensions[key] = value

        return extensions

    def _parse_severity(self, severity_str: str) -> LogSeverity:
        """Parse CEF severity (0-10 or string)."""
        severity_str = severity_str.strip().lower()

        if severity_str in self.SEVERITY_STRING_MAP:
            return self.SEVERITY_STRING_MAP[severity_str]

        try:
            severity_num = int(severity_str)
            return self.SEVERITY_MAP.get(severity_num, LogSeverity.UNKNOWN)
        except ValueError:
            return LogSeverity.UNKNOWN

    def _parse_timestamp(self, extensions: dict[str, str]) -> datetime:
        """Extract timestamp from CEF extensions."""
        timestamp_keys = ["rt", "end", "start", "deviceReceiptTime"]

        for key in timestamp_keys:
            if key in extensions:
                ts_value = extensions[key]

                try:
                    if ts_value.isdigit():
                        ts_int = int(ts_value)
                        if ts_int > 1e12:
                            return datetime.fromtimestamp(ts_int / 1000)
                        return datetime.fromtimestamp(ts_int)
                except (ValueError, OSError):
                    pass

                formats = [
                    "%b %d %Y %H:%M:%S",
                    "%Y-%m-%dT%H:%M:%S.%fZ",
                    "%Y-%m-%dT%H:%M:%SZ",
                    "%Y-%m-%d %H:%M:%S",
                ]
                for fmt in formats:
                    try:
                        return datetime.strptime(ts_value, fmt)
                    except ValueError:
                        continue

        return datetime.utcnow()

    def parse(self, raw_line: str, source: str = "unknown") -> NormalizedLog | None:
        """Parse a CEF log line into NormalizedLog."""
        raw_line = raw_line.strip()
        if not raw_line:
            return None

        match = self.CEF_PATTERN.match(raw_line)
        if not match:
            return None

        cef_version = match.group(1)
        device_vendor = match.group(2)
        device_product = match.group(3)
        device_version = match.group(4)
        signature_id = match.group(5)
        name = match.group(6)
        severity_str = match.group(7)
        extension_str = match.group(8)

        extensions = self._parse_extensions(extension_str)
        timestamp = self._parse_timestamp(extensions)
        severity = self._parse_severity(severity_str)

        # Build message from name and any msg extension
        message = name
        if "msg" in extensions:
            message = f"{name}: {extensions['msg']}"

        # Extract network fields
        src_ip = extensions.get("src")
        src_port = extensions.get("spt")
        dst_ip = extensions.get("dst")
        dst_port = extensions.get("dpt")
        user = extensions.get("suser")

        # Extract source/hostname
        log_source = (
            extensions.get("deviceHostName")
            or extensions.get("dvchost")
            or source
        )

        # Extract program
        program = extensions.get("deviceProcessName") or device_product

        # Build extended fields
        extended = {
            "cef_version": cef_version,
            "device_vendor": device_vendor,
            "device_product": device_product,
            "device_version": device_version,
            "signature_id": signature_id,
        }

        for ext_key, ext_value in extensions.items():
            mapped_key = self.EXTENSION_MAP.get(ext_key, ext_key)
            if mapped_key not in ("src_ip", "src_port", "dst_ip", "dst_port", "user", "message", "program"):
                extended[mapped_key] = ext_value

        return NormalizedLog(
            timestamp=timestamp,
            source=log_source,
            source_type=self.source_type,
            severity=severity,
            program=program,
            message=message,
            raw=raw_line,
            src_ip=src_ip,
            src_port=int(src_port) if src_port and src_port.isdigit() else None,
            dst_ip=dst_ip,
            dst_port=int(dst_port) if dst_port and dst_port.isdigit() else None,
            user=user,
            extensions=extended,
        )
