"""Incident data models."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from uuid import uuid4


class IncidentStatus(str, Enum):
    """Incident status values."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


@dataclass
class IncidentData:
    """
    Incident data structure for report generation.

    Contains all information needed for incident reporting.
    """

    incident_id: str = field(default_factory=lambda: str(uuid4()))
    title: str = ""
    severity: str = "medium"
    status: IncidentStatus = IncidentStatus.OPEN
    category: str = ""

    # Classification
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)

    # Context
    source_ips: list[str] = field(default_factory=list)
    target_ips: list[str] = field(default_factory=list)
    affected_users: list[str] = field(default_factory=list)
    affected_systems: list[str] = field(default_factory=list)

    # Analysis
    summary: str = ""
    llm_analysis: str = ""
    recommendations: list[str] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)

    # Timeline
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    resolved_at: datetime | None = None

    # Counts
    log_count: int = 0
    detection_count: int = 0

    # Related data
    detection_ids: list[str] = field(default_factory=list)
    log_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "severity": self.severity,
            "status": self.status.value,
            "category": self.category,
            "mitre_tactics": self.mitre_tactics,
            "mitre_techniques": self.mitre_techniques,
            "source_ips": self.source_ips,
            "target_ips": self.target_ips,
            "affected_users": self.affected_users,
            "affected_systems": self.affected_systems,
            "summary": self.summary,
            "llm_analysis": self.llm_analysis,
            "recommendations": self.recommendations,
            "iocs": self.iocs,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "log_count": self.log_count,
            "detection_count": self.detection_count,
        }

    def to_markdown(self) -> str:
        """Generate markdown report."""
        lines = [
            f"# Security Incident Report",
            f"",
            f"**Incident ID:** {self.incident_id}",
            f"**Status:** {self.status.value.upper()}",
            f"**Severity:** {self.severity.upper()}",
            f"**Category:** {self.category or 'Uncategorized'}",
            f"",
            f"## Timeline",
            f"- **First Seen:** {self.first_seen or 'Unknown'}",
            f"- **Last Seen:** {self.last_seen or 'Unknown'}",
            f"- **Created:** {self.created_at}",
            f"",
            f"## Summary",
            f"{self.summary or 'No summary available.'}",
            f"",
        ]

        if self.mitre_tactics or self.mitre_techniques:
            lines.extend([
                f"## MITRE ATT&CK Mapping",
                f"**Tactics:** {', '.join(self.mitre_tactics) or 'None identified'}",
                f"**Techniques:** {', '.join(self.mitre_techniques) or 'None identified'}",
                f"",
            ])

        if self.affected_systems or self.affected_users:
            lines.extend([
                f"## Impact",
                f"**Affected Systems:** {', '.join(self.affected_systems) or 'None'}",
                f"**Affected Users:** {', '.join(self.affected_users) or 'None'}",
                f"",
            ])

        if self.source_ips:
            lines.extend([
                f"## Indicators of Compromise",
                f"**Source IPs:** {', '.join(self.source_ips)}",
                f"",
            ])

        if self.llm_analysis:
            lines.extend([
                f"## Analysis",
                f"{self.llm_analysis}",
                f"",
            ])

        if self.recommendations:
            lines.extend([
                f"## Recommendations",
            ])
            for rec in self.recommendations:
                lines.append(f"- {rec}")
            lines.append("")

        lines.extend([
            f"---",
            f"*Generated by LogMind Security Analyzer*",
            f"*Detection Count: {self.detection_count} | Log Count: {self.log_count}*",
        ])

        return "\n".join(lines)
