"""Data access layer for LogMind entities."""

from datetime import datetime, timedelta
from typing import Sequence

from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from logmind.database.models import Detection, Incident, LogEntry
from logmind.ingestion.base import NormalizedLog


class LogRepository:
    """Repository for log entry operations."""

    def __init__(self, session: Session) -> None:
        """Initialize with database session."""
        self.session = session

    def save_log(self, log: NormalizedLog) -> LogEntry:
        """
        Save a normalized log to the database.

        Args:
            log: NormalizedLog to persist

        Returns:
            Created LogEntry
        """
        entry = LogEntry(
            log_id=log.id,
            timestamp=log.timestamp,
            source=log.source,
            source_type=log.source_type,
            severity=log.severity,
            facility=log.facility,
            program=log.program,
            pid=log.pid,
            message=log.message,
            raw=log.raw,
            src_ip=log.src_ip,
            src_port=log.src_port,
            dst_ip=log.dst_ip,
            dst_port=log.dst_port,
            user=log.user,
            extensions=log.extensions,
            tags=log.tags,
            ingested_at=log.ingested_at,
        )
        self.session.add(entry)
        self.session.flush()
        return entry

    def save_logs_batch(self, logs: Sequence[NormalizedLog]) -> list[LogEntry]:
        """Save multiple logs efficiently."""
        entries = []
        for log in logs:
            entry = LogEntry(
                log_id=log.id,
                timestamp=log.timestamp,
                source=log.source,
                source_type=log.source_type,
                severity=log.severity,
                facility=log.facility,
                program=log.program,
                pid=log.pid,
                message=log.message,
                raw=log.raw,
                src_ip=log.src_ip,
                src_port=log.src_port,
                dst_ip=log.dst_ip,
                dst_port=log.dst_port,
                user=log.user,
                extensions=log.extensions,
                tags=log.tags,
                ingested_at=log.ingested_at,
            )
            entries.append(entry)
        self.session.add_all(entries)
        self.session.flush()
        return entries

    def get_log_by_id(self, log_id: str) -> LogEntry | None:
        """Get log entry by UUID."""
        stmt = select(LogEntry).where(LogEntry.log_id == log_id)
        return self.session.execute(stmt).scalar_one_or_none()

    def get_logs_by_source(
        self,
        source: str,
        limit: int = 100,
        offset: int = 0,
    ) -> Sequence[LogEntry]:
        """Get logs from a specific source."""
        stmt = (
            select(LogEntry)
            .where(LogEntry.source == source)
            .order_by(LogEntry.timestamp.desc())
            .limit(limit)
            .offset(offset)
        )
        return self.session.execute(stmt).scalars().all()

    def get_logs_by_time_range(
        self,
        start: datetime,
        end: datetime,
        source: str | None = None,
        severity: str | None = None,
    ) -> Sequence[LogEntry]:
        """Get logs within a time range."""
        conditions = [
            LogEntry.timestamp >= start,
            LogEntry.timestamp <= end,
        ]
        if source:
            conditions.append(LogEntry.source == source)
        if severity:
            conditions.append(LogEntry.severity == severity)

        stmt = (
            select(LogEntry)
            .where(and_(*conditions))
            .order_by(LogEntry.timestamp.asc())
        )
        return self.session.execute(stmt).scalars().all()

    def get_recent_logs(self, hours: int = 1, limit: int = 1000) -> Sequence[LogEntry]:
        """Get logs from the last N hours."""
        since = datetime.utcnow() - timedelta(hours=hours)
        stmt = (
            select(LogEntry)
            .where(LogEntry.timestamp >= since)
            .order_by(LogEntry.timestamp.desc())
            .limit(limit)
        )
        return self.session.execute(stmt).scalars().all()

    def get_unprocessed_logs(self, limit: int = 100) -> Sequence[LogEntry]:
        """Get logs that haven't been processed."""
        stmt = (
            select(LogEntry)
            .where(LogEntry.processed == False)
            .order_by(LogEntry.timestamp.asc())
            .limit(limit)
        )
        return self.session.execute(stmt).scalars().all()

    def mark_processed(self, log_ids: list[int]) -> int:
        """Mark logs as processed."""
        stmt = (
            select(LogEntry)
            .where(LogEntry.id.in_(log_ids))
        )
        entries = self.session.execute(stmt).scalars().all()
        for entry in entries:
            entry.processed = True
        return len(entries)

    def get_log_count_by_source(self) -> dict[str, int]:
        """Get log counts grouped by source."""
        stmt = (
            select(LogEntry.source, func.count(LogEntry.id))
            .group_by(LogEntry.source)
        )
        results = self.session.execute(stmt).all()
        return {source: count for source, count in results}

    def get_log_count_by_severity(self) -> dict[str, int]:
        """Get log counts grouped by severity."""
        stmt = (
            select(LogEntry.severity, func.count(LogEntry.id))
            .group_by(LogEntry.severity)
        )
        results = self.session.execute(stmt).all()
        return {str(severity): count for severity, count in results}


class DetectionRepository:
    """Repository for detection operations."""

    def __init__(self, session: Session) -> None:
        """Initialize with database session."""
        self.session = session

    def save_detection(
        self,
        log_entry_id: int,
        detection_type: str,
        severity: str,
        rule_id: str | None = None,
        rule_name: str | None = None,
        confidence: float = 1.0,
        description: str | None = None,
        mitre_tactic: str | None = None,
        mitre_technique: str | None = None,
        mitre_technique_name: str | None = None,
        extra_data: dict | None = None,
    ) -> Detection:
        """Save a detection result."""
        detection = Detection(
            log_entry_id=log_entry_id,
            detection_type=detection_type,
            rule_id=rule_id,
            rule_name=rule_name,
            severity=severity,
            confidence=confidence,
            description=description,
            mitre_tactic=mitre_tactic,
            mitre_technique=mitre_technique,
            mitre_technique_name=mitre_technique_name,
            extra_data=extra_data or {},
        )
        self.session.add(detection)
        self.session.flush()
        return detection

    def get_recent_detections(
        self,
        hours: int = 24,
        severity: str | None = None,
    ) -> Sequence[Detection]:
        """Get recent detections."""
        since = datetime.utcnow() - timedelta(hours=hours)
        conditions = [Detection.detected_at >= since]
        if severity:
            conditions.append(Detection.severity == severity)

        stmt = (
            select(Detection)
            .where(and_(*conditions))
            .order_by(Detection.detected_at.desc())
        )
        return self.session.execute(stmt).scalars().all()

    def get_detections_by_incident(self, incident_id: int) -> Sequence[Detection]:
        """Get all detections for an incident."""
        stmt = (
            select(Detection)
            .where(Detection.incident_id == incident_id)
            .order_by(Detection.detected_at.asc())
        )
        return self.session.execute(stmt).scalars().all()

    def get_unassigned_detections(self, limit: int = 100) -> Sequence[Detection]:
        """Get detections not assigned to any incident."""
        stmt = (
            select(Detection)
            .where(Detection.incident_id == None)
            .order_by(Detection.detected_at.desc())
            .limit(limit)
        )
        return self.session.execute(stmt).scalars().all()


class IncidentRepository:
    """Repository for incident operations."""

    def __init__(self, session: Session) -> None:
        """Initialize with database session."""
        self.session = session

    def create_incident(
        self,
        incident_id: str,
        title: str,
        severity: str,
        first_seen: datetime,
        last_seen: datetime,
        category: str | None = None,
        summary: str | None = None,
    ) -> Incident:
        """Create a new incident."""
        incident = Incident(
            incident_id=incident_id,
            title=title,
            severity=severity,
            category=category,
            first_seen=first_seen,
            last_seen=last_seen,
            summary=summary,
        )
        self.session.add(incident)
        self.session.flush()
        return incident

    def get_incident_by_id(self, incident_id: str) -> Incident | None:
        """Get incident by UUID."""
        stmt = select(Incident).where(Incident.incident_id == incident_id)
        return self.session.execute(stmt).scalar_one_or_none()

    def get_open_incidents(self) -> Sequence[Incident]:
        """Get all open incidents."""
        stmt = (
            select(Incident)
            .where(Incident.status == "open")
            .order_by(Incident.created_at.desc())
        )
        return self.session.execute(stmt).scalars().all()

    def get_all_incidents(self) -> Sequence[Incident]:
        """Get all incidents regardless of status."""
        stmt = select(Incident).order_by(Incident.created_at.desc())
        return self.session.execute(stmt).scalars().all()

    def get_incidents_by_severity(self, severity: str) -> Sequence[Incident]:
        """Get incidents by severity level."""
        stmt = (
            select(Incident)
            .where(Incident.severity == severity)
            .order_by(Incident.created_at.desc())
        )
        return self.session.execute(stmt).scalars().all()

    def update_incident(
        self,
        incident_id: str,
        status: str | None = None,
        summary: str | None = None,
        llm_analysis: str | None = None,
        recommendations: list[str] | None = None,
    ) -> Incident | None:
        """Update an existing incident."""
        incident = self.get_incident_by_id(incident_id)
        if not incident:
            return None

        if status:
            incident.status = status
            if status == "resolved":
                incident.resolved_at = datetime.utcnow()
        if summary:
            incident.summary = summary
        if llm_analysis:
            incident.llm_analysis = llm_analysis
        if recommendations:
            incident.recommendations = recommendations

        incident.updated_at = datetime.utcnow()
        return incident

    def get_incident_stats(self) -> dict:
        """Get incident statistics."""
        total = self.session.execute(
            select(func.count(Incident.id))
        ).scalar()

        open_count = self.session.execute(
            select(func.count(Incident.id)).where(Incident.status == "open")
        ).scalar()

        by_severity = self.session.execute(
            select(Incident.severity, func.count(Incident.id))
            .group_by(Incident.severity)
        ).all()

        return {
            "total": total,
            "open": open_count,
            "resolved": total - open_count,
            "by_severity": {sev: count for sev, count in by_severity},
        }
