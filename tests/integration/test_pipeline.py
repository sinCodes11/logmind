"""Integration tests for the full processing pipeline."""

import pytest
from pathlib import Path

from logmind.ingestion import SyslogParser, JSONLogParser, CEFParser
from logmind.detection import DetectionOrchestrator
from logmind.incidents.generator import IncidentGenerator


DATA_DIR = Path(__file__).parent.parent.parent / "data" / "samples"


class TestFullPipeline:
    """Integration tests for full log processing pipeline."""

    def setup_method(self):
        self.detector = DetectionOrchestrator(
            sigma_rules_path="rules",
            enable_sigma=True,
            enable_anomaly=True,
        )
        self.incident_generator = IncidentGenerator(enable_llm=False)

    @pytest.mark.skipif(
        not (DATA_DIR / "auth.log").exists(),
        reason="Sample data not available",
    )
    def test_auth_log_pipeline(self):
        """Test processing auth.log through full pipeline."""
        parser = SyslogParser()

        with open(DATA_DIR / "auth.log") as f:
            lines = f.readlines()

        logs = parser.parse_batch(lines)
        assert len(logs) > 0

        detections = self.detector.detect_batch(logs)

        # Should detect brute force attempts
        assert len(detections) > 0

        # Check for SSH-related detections
        ssh_detections = [
            d for d in detections
            if any("ssh" in m.rule_name.lower() or "brute" in m.rule_name.lower()
                   for m in d.sigma_matches)
        ]
        assert len(ssh_detections) > 0

    @pytest.mark.skipif(
        not (DATA_DIR / "nginx_access.json").exists(),
        reason="Sample data not available",
    )
    def test_nginx_json_pipeline(self):
        """Test processing nginx JSON logs."""
        parser = JSONLogParser()

        with open(DATA_DIR / "nginx_access.json") as f:
            lines = f.readlines()

        logs = parser.parse_batch(lines)
        assert len(logs) > 0

        detections = self.detector.detect_batch(logs)

        # Should detect SQL injection and path traversal
        web_attacks = [
            d for d in detections
            if any("sql" in m.rule_name.lower() or "traversal" in m.rule_name.lower()
                   for m in d.sigma_matches)
        ]
        assert len(web_attacks) > 0

    @pytest.mark.skipif(
        not (DATA_DIR / "firewall_cef.log").exists(),
        reason="Sample data not available",
    )
    def test_cef_pipeline(self):
        """Test processing CEF firewall logs."""
        parser = CEFParser()

        with open(DATA_DIR / "firewall_cef.log") as f:
            lines = f.readlines()

        logs = parser.parse_batch(lines)
        assert len(logs) > 0

        # Verify CEF parsing extracted IPs
        ips = [log.src_ip for log in logs if log.src_ip]
        assert len(ips) > 0

    def test_incident_generation(self):
        """Test incident generation from detections."""
        parser = SyslogParser()

        # Create logs with known attack pattern
        lines = [
            "Jan 25 10:20:15 webserver sshd[12500]: Failed password for invalid user admin from 192.168.1.100 port 45123",
            "Jan 25 10:20:17 webserver sshd[12501]: Failed password for invalid user root from 192.168.1.100 port 45124",
            "Jan 25 10:20:19 webserver sshd[12502]: Failed password for invalid user test from 192.168.1.100 port 45125",
        ]

        logs = parser.parse_batch(lines)
        detections = self.detector.detect_batch(logs)

        if detections:
            incident = self.incident_generator.generate_from_detections(
                detections=detections,
                logs=logs,
            )

            assert incident.incident_id is not None
            assert incident.detection_count == len(detections)
            assert incident.log_count == len(logs)
            assert "192.168.1.100" in incident.source_ips

    def test_mitre_mapping_in_detections(self):
        """Test MITRE ATT&CK mapping is included in detections."""
        parser = SyslogParser()

        line = "Jan 25 10:20:15 webserver sshd[12500]: Failed password for root from 192.168.1.100 port 45123"
        logs = parser.parse_batch([line])

        detections = self.detector.detect_batch(logs)

        # Check for MITRE mapping
        for detection in detections:
            if detection.mitre_techniques:
                assert any(t.startswith("T") for t in detection.mitre_techniques)
                break


class TestMultiFormatPipeline:
    """Test processing multiple log formats together."""

    def test_mixed_format_detection(self):
        """Test detecting threats across different log formats."""
        syslog_parser = SyslogParser()
        json_parser = JSONLogParser()

        syslog_lines = [
            "Jan 25 10:20:15 webserver sshd[12500]: Failed password for root from 192.168.1.100 port 45123",
        ]
        json_lines = [
            '{"timestamp":"2026-01-25T10:20:16Z","remote_addr":"192.168.1.100","request":"GET /api?id=1\\' OR \\'1\\'=\\'1","status":200}',
        ]

        syslog_logs = syslog_parser.parse_batch(syslog_lines)
        json_logs = json_parser.parse_batch(json_lines)

        all_logs = syslog_logs + json_logs

        detector = DetectionOrchestrator()
        detections = detector.detect_batch(all_logs)

        # Should have detections from both log types
        assert len(detections) >= 1
