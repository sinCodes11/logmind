"""Unit tests for detection engines."""

import pytest
from datetime import datetime

from logmind.ingestion.base import NormalizedLog, LogSeverity
from logmind.detection.sigma.engine import SigmaEngine
from logmind.detection.anomaly.detector import AnomalyDetector
from logmind.detection.detector import DetectionOrchestrator


def create_test_log(
    message: str,
    program: str | None = None,
    src_ip: str | None = None,
    user: str | None = None,
    severity: LogSeverity = LogSeverity.INFO,
) -> NormalizedLog:
    """Helper to create test logs."""
    return NormalizedLog(
        timestamp=datetime.now(),
        source="test-host",
        source_type="syslog",
        severity=severity,
        program=program,
        message=message,
        raw=message,
        src_ip=src_ip,
        user=user,
    )


class TestSigmaEngine:
    """Tests for SigmaEngine."""

    def setup_method(self):
        self.engine = SigmaEngine("rules")
        self.engine.load_rules()

    def test_load_rules(self):
        """Test loading Sigma rules."""
        assert self.engine.rule_count > 0

    def test_detect_ssh_brute_force(self):
        """Test detecting SSH brute force pattern."""
        log = create_test_log(
            message="Failed password for invalid user admin from 192.168.1.100 port 45123",
            program="sshd",
            src_ip="192.168.1.100",
            user="admin",
        )

        matches = self.engine.evaluate(log)
        assert len(matches) > 0
        assert any("brute" in m.rule_name.lower() or "ssh" in m.rule_name.lower() for m in matches)

    def test_detect_sudo_escalation(self):
        """Test detecting sudo privilege escalation."""
        log = create_test_log(
            message="attacker : user NOT in sudoers ; TTY=pts/1 ; PWD=/tmp ; USER=root",
            program="sudo",
            user="attacker",
        )

        matches = self.engine.evaluate(log)
        assert len(matches) > 0

    def test_detect_sql_injection(self):
        """Test detecting SQL injection patterns."""
        log = create_test_log(
            message="GET /api/users?id=1' OR '1'='1 HTTP/1.1",
            src_ip="192.168.1.50",
        )

        matches = self.engine.evaluate(log)
        assert len(matches) > 0
        assert any("sql" in m.rule_name.lower() for m in matches)

    def test_no_detection_normal_log(self):
        """Test no detection on normal log."""
        log = create_test_log(
            message="User admin logged in successfully",
            program="login",
            user="admin",
        )

        matches = self.engine.evaluate(log)
        # May have some low-confidence matches, but no high-severity
        high_sev = [m for m in matches if m.level in ("critical", "high")]
        assert len(high_sev) == 0


class TestAnomalyDetector:
    """Tests for AnomalyDetector."""

    def setup_method(self):
        self.detector = AnomalyDetector(
            auth_failure_threshold=3,
            auth_failure_window=60,
        )

    def test_detect_brute_force(self):
        """Test detecting brute force pattern."""
        ip = "192.168.1.100"

        # Generate multiple failed auth attempts
        for i in range(5):
            log = create_test_log(
                message=f"Failed password for user admin from {ip} port {45000 + i}",
                program="sshd",
                src_ip=ip,
            )
            results = self.detector.analyze(log)

        # Should detect brute force after threshold
        assert len(results) > 0
        assert any(r.anomaly_type == "brute_force" for r in results)

    def test_detect_off_hours(self):
        """Test detecting off-hours activity."""
        # Create log with off-hours timestamp
        log = NormalizedLog(
            timestamp=datetime(2026, 1, 25, 3, 0, 0),  # 3 AM
            source="test-host",
            source_type="syslog",
            severity=LogSeverity.INFO,
            program="sudo",
            message="admin : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash",
            raw="sudo admin command",
        )

        results = self.detector.analyze(log)
        assert any(r.anomaly_type == "off_hours_activity" for r in results)

    def test_reset_state(self):
        """Test resetting detector state."""
        ip = "192.168.1.100"

        for i in range(3):
            log = create_test_log(
                message=f"Failed password from {ip}",
                src_ip=ip,
            )
            self.detector.analyze(log)

        self.detector.reset_state()

        # After reset, should not detect brute force
        log = create_test_log(
            message=f"Failed password from {ip}",
            src_ip=ip,
        )
        results = self.detector.analyze(log)
        assert not any(r.anomaly_type == "brute_force" for r in results)


class TestDetectionOrchestrator:
    """Tests for DetectionOrchestrator."""

    def setup_method(self):
        self.orchestrator = DetectionOrchestrator(
            sigma_rules_path="rules",
            enable_sigma=True,
            enable_anomaly=True,
        )

    def test_combined_detection(self):
        """Test combined Sigma and anomaly detection."""
        log = create_test_log(
            message="Failed password for invalid user root from 192.168.1.100 port 45123",
            program="sshd",
            src_ip="192.168.1.100",
            user="root",
        )

        result = self.orchestrator.detect(log)

        assert result.log_id == log.id
        assert result.source == log.source

    def test_batch_detection(self):
        """Test batch detection."""
        logs = [
            create_test_log(
                message="Failed password for user admin",
                program="sshd",
                src_ip="192.168.1.100",
            ),
            create_test_log(
                message="GET /api?id=1' OR '1'='1 HTTP/1.1",
                src_ip="192.168.1.50",
            ),
        ]

        results = self.orchestrator.detect_batch(logs)
        assert len(results) > 0

    def test_get_stats(self):
        """Test getting detection stats."""
        stats = self.orchestrator.get_stats()

        assert "sigma_enabled" in stats
        assert "anomaly_enabled" in stats
        assert "sigma_rules_loaded" in stats
        assert stats["sigma_enabled"] is True
        assert stats["anomaly_enabled"] is True
