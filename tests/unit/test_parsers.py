"""Unit tests for log parsers."""

import pytest
from datetime import datetime

from logmind.ingestion import SyslogParser, JSONLogParser, CEFParser, LogSeverity


class TestSyslogParser:
    """Tests for SyslogParser."""

    def setup_method(self):
        self.parser = SyslogParser()

    def test_parse_rfc3164_basic(self):
        """Test parsing basic RFC 3164 syslog."""
        line = "Jan 25 10:15:01 webserver sshd[12345]: Accepted publickey for admin from 10.0.1.50 port 52341"
        result = self.parser.parse(line)

        assert result is not None
        assert result.source == "webserver"
        assert result.program == "sshd"
        assert result.pid == 12345
        assert "Accepted publickey" in result.message
        assert result.src_ip == "10.0.1.50"
        assert result.src_port == 52341
        assert result.user == "admin"

    def test_parse_rfc3164_with_priority(self):
        """Test parsing RFC 3164 with priority."""
        line = "<134>Jan 25 09:00:01 firewall kernel: [UFW BLOCK] SRC=203.0.113.50 DST=10.0.0.1"
        result = self.parser.parse(line)

        assert result is not None
        assert result.source == "firewall"
        assert result.facility == "local0"
        assert result.severity == LogSeverity.INFO
        assert result.src_ip == "203.0.113.50"

    def test_parse_failed_password(self):
        """Test parsing failed password attempts."""
        line = "Jan 25 10:20:15 webserver sshd[12500]: Failed password for invalid user guest from 192.168.1.100 port 45123"
        result = self.parser.parse(line)

        assert result is not None
        assert result.src_ip == "192.168.1.100"
        assert result.user == "guest"
        assert result.src_port == 45123

    def test_parse_empty_line(self):
        """Test parsing empty line returns None."""
        assert self.parser.parse("") is None
        assert self.parser.parse("   ") is None

    def test_parse_invalid_line(self):
        """Test parsing invalid line returns None."""
        assert self.parser.parse("not a syslog line") is None


class TestJSONLogParser:
    """Tests for JSONLogParser."""

    def setup_method(self):
        self.parser = JSONLogParser()

    def test_parse_basic_json(self):
        """Test parsing basic JSON log."""
        line = '{"timestamp":"2026-01-25T08:00:00.000Z","level":"info","message":"Request received"}'
        result = self.parser.parse(line)

        assert result is not None
        assert result.severity == LogSeverity.INFO
        assert result.message == "Request received"

    def test_parse_nginx_json(self):
        """Test parsing nginx JSON access log."""
        line = '{"timestamp":"2026-01-25T08:00:00.000Z","remote_addr":"10.0.1.100","remote_user":"-","request":"GET / HTTP/1.1","status":200}'
        result = self.parser.parse(line)

        assert result is not None
        assert result.src_ip == "10.0.1.100"
        assert result.user is None  # "-" should be converted to None

    def test_parse_invalid_json(self):
        """Test parsing invalid JSON returns None."""
        assert self.parser.parse("not json") is None
        assert self.parser.parse('{"incomplete":') is None

    def test_parse_unix_timestamp(self):
        """Test parsing Unix timestamp."""
        line = '{"timestamp":1737792000,"message":"Test"}'
        result = self.parser.parse(line)

        assert result is not None
        assert isinstance(result.timestamp, datetime)


class TestCEFParser:
    """Tests for CEFParser."""

    def setup_method(self):
        self.parser = CEFParser()

    def test_parse_basic_cef(self):
        """Test parsing basic CEF log."""
        line = "CEF:0|Acme|Firewall|1.0|100|Connection Blocked|7|src=203.0.113.100 dst=10.0.0.1 dpt=22"
        result = self.parser.parse(line)

        assert result is not None
        assert result.src_ip == "203.0.113.100"
        assert result.dst_ip == "10.0.0.1"
        assert result.dst_port == 22
        assert result.severity == LogSeverity.ERROR  # CEF 7 maps to error

    def test_parse_cef_with_prefix(self):
        """Test parsing CEF with syslog prefix."""
        line = "Jan 25 08:00:00 firewall CEF:0|Acme|Firewall|1.0|100|Test|5|src=10.0.0.1"
        result = self.parser.parse(line)

        assert result is not None
        assert result.src_ip == "10.0.0.1"

    def test_parse_cef_extensions(self):
        """Test parsing CEF with multiple extensions."""
        line = "CEF:0|Vendor|Product|1.0|1|Test|3|src=1.2.3.4 spt=1234 suser=admin msg=Test message"
        result = self.parser.parse(line)

        assert result is not None
        assert result.src_ip == "1.2.3.4"
        assert result.src_port == 1234
        assert result.user == "admin"

    def test_parse_invalid_cef(self):
        """Test parsing invalid CEF returns None."""
        assert self.parser.parse("not CEF") is None
        assert self.parser.parse("CEF:0|incomplete") is None


class TestParserBatch:
    """Tests for batch parsing."""

    def test_syslog_batch(self):
        """Test batch parsing of syslog."""
        parser = SyslogParser()
        lines = [
            "Jan 25 10:00:00 host1 sshd[1]: Message 1",
            "Jan 25 10:00:01 host2 sshd[2]: Message 2",
            "",  # Empty line should be skipped
            "Jan 25 10:00:02 host3 sshd[3]: Message 3",
        ]

        results = parser.parse_batch(lines)
        assert len(results) == 3

    def test_json_batch(self):
        """Test batch parsing of JSON logs."""
        parser = JSONLogParser()
        lines = [
            '{"timestamp":"2026-01-25T08:00:00Z","message":"msg1"}',
            '{"timestamp":"2026-01-25T08:00:01Z","message":"msg2"}',
        ]

        results = parser.parse_batch(lines)
        assert len(results) == 2
