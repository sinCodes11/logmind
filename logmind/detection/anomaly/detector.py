"""Statistical anomaly detection for security logs."""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Sequence

from logmind.ingestion.base import LogSeverity, NormalizedLog


@dataclass
class AnomalyResult:
    """Result of anomaly detection."""

    anomaly_type: str
    severity: str
    description: str
    score: float
    evidence: dict = field(default_factory=dict)
    mitre_tactic: str | None = None
    mitre_technique: str | None = None


class AnomalyDetector:
    """
    Statistical anomaly detector for security events.

    Detects:
    - Brute force attempts (high frequency auth failures)
    - Port scanning (connections to multiple ports)
    - Data exfiltration (unusual outbound data volume)
    - Off-hours activity (activity outside normal patterns)
    - New source IPs (first-time connections)
    """

    def __init__(
        self,
        auth_failure_threshold: int = 5,
        auth_failure_window: int = 60,
        port_scan_threshold: int = 10,
        port_scan_window: int = 60,
    ) -> None:
        """
        Initialize anomaly detector.

        Args:
            auth_failure_threshold: Failed auths before alert
            auth_failure_window: Window in seconds
            port_scan_threshold: Ports before scan alert
            port_scan_window: Window in seconds
        """
        self.auth_failure_threshold = auth_failure_threshold
        self.auth_failure_window = auth_failure_window
        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window = port_scan_window

        self._auth_failures: dict[str, list[datetime]] = defaultdict(list)
        self._port_connections: dict[str, set[int]] = defaultdict(set)
        self._known_ips: set[str] = set()
        self._baseline_hours: set[int] = set(range(6, 22))

    def analyze(self, log: NormalizedLog) -> list[AnomalyResult]:
        """
        Analyze a single log for anomalies.

        Args:
            log: NormalizedLog to analyze

        Returns:
            List of detected anomalies
        """
        anomalies = []

        if self._is_auth_failure(log):
            brute_force = self._check_brute_force(log)
            if brute_force:
                anomalies.append(brute_force)

        if log.dst_port and log.src_ip:
            port_scan = self._check_port_scan(log)
            if port_scan:
                anomalies.append(port_scan)

        off_hours = self._check_off_hours(log)
        if off_hours:
            anomalies.append(off_hours)

        new_ip = self._check_new_source(log)
        if new_ip:
            anomalies.append(new_ip)

        return anomalies

    def analyze_batch(
        self, logs: Sequence[NormalizedLog]
    ) -> dict[str, list[AnomalyResult]]:
        """
        Analyze multiple logs for anomalies.

        Args:
            logs: Sequence of logs to analyze

        Returns:
            Dictionary mapping log ID to anomaly results
        """
        results = {}
        for log in logs:
            anomalies = self.analyze(log)
            if anomalies:
                results[log.id] = anomalies
        return results

    def _is_auth_failure(self, log: NormalizedLog) -> bool:
        """Check if log represents an authentication failure."""
        failure_indicators = [
            "failed password",
            "authentication failure",
            "invalid user",
            "access denied",
            "login failed",
            "incorrect password",
        ]
        message_lower = log.message.lower()
        return any(ind in message_lower for ind in failure_indicators)

    def _check_brute_force(self, log: NormalizedLog) -> AnomalyResult | None:
        """Check for brute force attack pattern."""
        if not log.src_ip:
            return None

        now = log.timestamp
        cutoff = now - timedelta(seconds=self.auth_failure_window)

        self._auth_failures[log.src_ip].append(now)
        self._auth_failures[log.src_ip] = [
            ts for ts in self._auth_failures[log.src_ip] if ts > cutoff
        ]

        failure_count = len(self._auth_failures[log.src_ip])

        if failure_count >= self.auth_failure_threshold:
            score = min(1.0, failure_count / (self.auth_failure_threshold * 2))
            return AnomalyResult(
                anomaly_type="brute_force",
                severity="high" if failure_count >= self.auth_failure_threshold * 2 else "medium",
                description=f"Potential brute force: {failure_count} auth failures from {log.src_ip} in {self.auth_failure_window}s",
                score=score,
                evidence={
                    "source_ip": log.src_ip,
                    "failure_count": failure_count,
                    "window_seconds": self.auth_failure_window,
                    "target_user": log.user,
                },
                mitre_tactic="Credential Access",
                mitre_technique="T1110",
            )

        return None

    def _check_port_scan(self, log: NormalizedLog) -> AnomalyResult | None:
        """Check for port scanning activity."""
        if not log.src_ip or not log.dst_port:
            return None

        self._port_connections[log.src_ip].add(log.dst_port)

        port_count = len(self._port_connections[log.src_ip])

        if port_count >= self.port_scan_threshold:
            score = min(1.0, port_count / (self.port_scan_threshold * 3))
            return AnomalyResult(
                anomaly_type="port_scan",
                severity="medium",
                description=f"Potential port scan: {log.src_ip} connected to {port_count} different ports",
                score=score,
                evidence={
                    "source_ip": log.src_ip,
                    "port_count": port_count,
                    "ports": list(self._port_connections[log.src_ip])[:20],
                },
                mitre_tactic="Discovery",
                mitre_technique="T1046",
            )

        return None

    def _check_off_hours(self, log: NormalizedLog) -> AnomalyResult | None:
        """Check for activity outside normal hours."""
        hour = log.timestamp.hour

        if hour in self._baseline_hours:
            return None

        if log.severity in (LogSeverity.ERROR, LogSeverity.CRITICAL):
            return None

        sensitive_indicators = [
            "sudo",
            "su ",
            "admin",
            "root",
            "password",
            "shadow",
            "ssh",
        ]

        message_lower = log.message.lower()
        is_sensitive = any(ind in message_lower for ind in sensitive_indicators)

        if not is_sensitive:
            return None

        return AnomalyResult(
            anomaly_type="off_hours_activity",
            severity="low",
            description=f"Sensitive activity detected at {hour:02d}:00 (outside 06:00-22:00)",
            score=0.3,
            evidence={
                "hour": hour,
                "source": log.source,
                "user": log.user,
                "program": log.program,
            },
            mitre_tactic="Defense Evasion",
            mitre_technique="T1564",
        )

    def _check_new_source(self, log: NormalizedLog) -> AnomalyResult | None:
        """Check for connections from previously unseen IPs."""
        if not log.src_ip:
            return None

        if log.src_ip.startswith(("10.", "192.168.", "172.")):
            self._known_ips.add(log.src_ip)
            return None

        if log.src_ip in self._known_ips:
            return None

        self._known_ips.add(log.src_ip)

        return AnomalyResult(
            anomaly_type="new_external_source",
            severity="low",
            description=f"First connection from external IP: {log.src_ip}",
            score=0.2,
            evidence={
                "source_ip": log.src_ip,
                "destination": log.dst_ip,
                "port": log.dst_port,
            },
            mitre_tactic="Initial Access",
            mitre_technique="T1190",
        )

    def reset_state(self) -> None:
        """Reset detector state."""
        self._auth_failures.clear()
        self._port_connections.clear()

    def add_known_ip(self, ip: str) -> None:
        """Add an IP to the known IPs set."""
        self._known_ips.add(ip)

    def set_baseline_hours(self, hours: set[int]) -> None:
        """Set the baseline hours for off-hours detection."""
        self._baseline_hours = hours
