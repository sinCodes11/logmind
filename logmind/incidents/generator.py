"""Incident report generator."""

from datetime import datetime
from typing import Sequence

from logmind.detection.detector import DetectionResult
from logmind.incidents.models import IncidentData
from logmind.ingestion.base import NormalizedLog
from logmind.llm.analyzer import LogAnalyzer
from logmind.mitre.mapper import ATTACKMapper


class IncidentGenerator:
    """
    Generates incident reports from detections and logs.

    Aggregates related detections, enriches with MITRE ATT&CK,
    and optionally uses LLM for analysis.
    """

    SEVERITY_PRIORITY = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "informational": 4,
    }

    CATEGORY_MAP = {
        "brute_force": "Credential Attack",
        "port_scan": "Reconnaissance",
        "sql_injection": "Web Application Attack",
        "path_traversal": "Web Application Attack",
        "xss_attack": "Web Application Attack",
        "privilege_escalation": "Privilege Escalation",
        "web_shell": "Persistence",
        "off_hours_activity": "Suspicious Activity",
        "new_external_source": "Reconnaissance",
    }

    def __init__(
        self,
        enable_llm: bool = True,
        mitre_data_path: str | None = None,
    ) -> None:
        """
        Initialize incident generator.

        Args:
            enable_llm: Enable LLM-based analysis
            mitre_data_path: Path to MITRE ATT&CK data
        """
        self._enable_llm = enable_llm
        self._mapper = ATTACKMapper(mitre_data_path)
        self._analyzer: LogAnalyzer | None = None

        if enable_llm:
            try:
                self._analyzer = LogAnalyzer()
                if not self._analyzer.is_available():
                    self._analyzer = None
            except Exception:
                self._analyzer = None

    def generate_from_detections(
        self,
        detections: Sequence[DetectionResult],
        logs: Sequence[NormalizedLog],
        title: str | None = None,
    ) -> IncidentData:
        """
        Generate an incident from detection results.

        Args:
            detections: Detection results to aggregate
            logs: Related log entries
            title: Optional incident title

        Returns:
            IncidentData with populated fields
        """
        incident = IncidentData()

        if not detections:
            incident.title = title or "No Detections"
            incident.summary = "No security detections to report."
            return incident

        incident.detection_count = len(detections)
        incident.log_count = len(logs)

        severity = self._determine_severity(detections)
        incident.severity = severity

        category = self._determine_category(detections)
        incident.category = category

        tactics, techniques = self._aggregate_mitre(detections)
        incident.mitre_tactics = tactics
        incident.mitre_techniques = techniques

        context = self._extract_context(detections, logs)
        incident.source_ips = context["source_ips"]
        incident.target_ips = context["target_ips"]
        incident.affected_users = context["users"]
        incident.affected_systems = context["systems"]
        incident.iocs = context["iocs"]

        timestamps = self._extract_timeline(detections, logs)
        incident.first_seen = timestamps["first"]
        incident.last_seen = timestamps["last"]

        incident.title = title or self._generate_title(incident)

        incident.summary = self._generate_summary(incident, detections)

        incident.recommendations = self._generate_recommendations(incident)

        if self._analyzer:
            try:
                llm_response = self._analyzer.generate_incident_summary(
                    detections=list(detections),
                    logs=list(logs),
                )
                incident.llm_analysis = llm_response.content
            except Exception:
                incident.llm_analysis = ""

        incident.detection_ids = [d.log_id for d in detections]
        incident.log_ids = [log.id for log in logs]

        return incident

    def _determine_severity(self, detections: Sequence[DetectionResult]) -> str:
        """Determine overall severity from detections."""
        severities = [d.max_severity for d in detections]
        if not severities:
            return "medium"

        return min(severities, key=lambda s: self.SEVERITY_PRIORITY.get(s, 99))

    def _determine_category(self, detections: Sequence[DetectionResult]) -> str:
        """Determine incident category from detections."""
        categories = []

        for detection in detections:
            for match in detection.sigma_matches:
                rule_lower = match.rule_name.lower()
                for pattern, cat in self.CATEGORY_MAP.items():
                    if pattern.replace("_", " ") in rule_lower:
                        categories.append(cat)

            for anomaly in detection.anomalies:
                if anomaly.anomaly_type in self.CATEGORY_MAP:
                    categories.append(self.CATEGORY_MAP[anomaly.anomaly_type])

        if categories:
            return max(set(categories), key=categories.count)

        return "Security Incident"

    def _aggregate_mitre(
        self, detections: Sequence[DetectionResult]
    ) -> tuple[list[str], list[str]]:
        """Aggregate MITRE ATT&CK mappings."""
        tactics = set()
        techniques = set()

        for detection in detections:
            tactics.update(detection.mitre_tactics)
            techniques.update(detection.mitre_techniques)

        return list(tactics), list(techniques)

    def _extract_context(
        self,
        detections: Sequence[DetectionResult],
        logs: Sequence[NormalizedLog],
    ) -> dict:
        """Extract contextual information."""
        source_ips = set()
        target_ips = set()
        users = set()
        systems = set()
        iocs = set()

        for log in logs:
            if log.src_ip:
                source_ips.add(log.src_ip)
                if not log.src_ip.startswith(("10.", "192.168.", "172.")):
                    iocs.add(f"IP: {log.src_ip}")
            if log.dst_ip:
                target_ips.add(log.dst_ip)
            if log.user:
                users.add(log.user)
            if log.source:
                systems.add(log.source)

        return {
            "source_ips": list(source_ips),
            "target_ips": list(target_ips),
            "users": list(users),
            "systems": list(systems),
            "iocs": list(iocs),
        }

    def _extract_timeline(
        self,
        detections: Sequence[DetectionResult],
        logs: Sequence[NormalizedLog],
    ) -> dict:
        """Extract timeline information."""
        timestamps = []

        for log in logs:
            timestamps.append(log.timestamp)

        if not timestamps:
            now = datetime.utcnow()
            return {"first": now, "last": now}

        return {
            "first": min(timestamps),
            "last": max(timestamps),
        }

    def _generate_title(self, incident: IncidentData) -> str:
        """Generate incident title."""
        parts = []

        if incident.severity in ("critical", "high"):
            parts.append(f"[{incident.severity.upper()}]")

        parts.append(incident.category)

        if incident.source_ips:
            parts.append(f"from {incident.source_ips[0]}")

        if incident.affected_systems:
            parts.append(f"targeting {incident.affected_systems[0]}")

        return " ".join(parts)

    def _generate_summary(
        self,
        incident: IncidentData,
        detections: Sequence[DetectionResult],
    ) -> str:
        """Generate incident summary."""
        lines = []

        lines.append(
            f"Detected {incident.detection_count} security events "
            f"across {len(incident.affected_systems)} system(s)."
        )

        if incident.source_ips:
            lines.append(
                f"Activity originated from {len(incident.source_ips)} source IP(s): "
                f"{', '.join(incident.source_ips[:3])}"
                + ("..." if len(incident.source_ips) > 3 else "")
            )

        if incident.affected_users:
            lines.append(
                f"Affected users: {', '.join(incident.affected_users[:5])}"
            )

        if incident.mitre_techniques:
            lines.append(
                f"MITRE ATT&CK techniques involved: {', '.join(incident.mitre_techniques[:5])}"
            )

        return " ".join(lines)

    def _generate_recommendations(self, incident: IncidentData) -> list[str]:
        """Generate recommendations based on incident type."""
        recommendations = []

        if incident.severity in ("critical", "high"):
            recommendations.append("Escalate to security team immediately")
            recommendations.append("Consider isolating affected systems")

        if incident.source_ips:
            external_ips = [
                ip for ip in incident.source_ips
                if not ip.startswith(("10.", "192.168.", "172."))
            ]
            if external_ips:
                recommendations.append(
                    f"Block external source IPs at firewall: {', '.join(external_ips[:5])}"
                )

        if "Credential Access" in incident.mitre_tactics:
            recommendations.append("Reset passwords for affected accounts")
            recommendations.append("Enable MFA for compromised accounts")

        if "Persistence" in incident.mitre_tactics:
            recommendations.append("Scan for unauthorized processes and files")
            recommendations.append("Review scheduled tasks and startup items")

        if "Web Application Attack" in incident.category:
            recommendations.append("Review and update WAF rules")
            recommendations.append("Audit application for vulnerabilities")

        recommendations.append("Preserve logs for forensic analysis")
        recommendations.append("Document incident timeline and actions taken")

        return recommendations
