"""SQLAlchemy ORM models for LogMind."""

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from logmind.ingestion.base import LogSeverity


class Base(DeclarativeBase):
    """Base class for all models."""

    pass


class LogEntry(Base):
    """Persisted log entry."""

    __tablename__ = "log_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    log_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)
    source: Mapped[str] = mapped_column(String(255), index=True)
    source_type: Mapped[str] = mapped_column(String(50))
    severity: Mapped[str] = mapped_column(
        Enum(LogSeverity, name="log_severity"),
        default=LogSeverity.UNKNOWN,
    )
    facility: Mapped[str | None] = mapped_column(String(50), nullable=True)
    program: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    message: Mapped[str] = mapped_column(Text)
    raw: Mapped[str] = mapped_column(Text)

    # Network context
    src_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # User context
    user: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)

    # Extended fields
    extensions: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)

    # Metadata
    ingested_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    processed: Mapped[bool] = mapped_column(Boolean, default=False)

    # Relationships
    detections: Mapped[list["Detection"]] = relationship(
        "Detection",
        back_populates="log_entry",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_log_entries_timestamp_source", "timestamp", "source"),
        Index("ix_log_entries_severity_timestamp", "severity", "timestamp"),
    )


class Detection(Base):
    """Detection result from Sigma rules or anomaly detection."""

    __tablename__ = "detections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    log_entry_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("log_entries.id", ondelete="CASCADE"),
        index=True,
    )
    detection_type: Mapped[str] = mapped_column(String(50))  # sigma, anomaly, llm
    rule_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    rule_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    severity: Mapped[str] = mapped_column(String(50))
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # MITRE ATT&CK mapping
    mitre_tactic: Mapped[str | None] = mapped_column(String(100), nullable=True)
    mitre_technique: Mapped[str | None] = mapped_column(String(50), nullable=True)
    mitre_technique_name: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Additional context
    extra_data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    detected_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationships
    log_entry: Mapped["LogEntry"] = relationship("LogEntry", back_populates="detections")
    incident_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("incidents.id", ondelete="SET NULL"),
        nullable=True,
    )
    incident: Mapped["Incident | None"] = relationship(
        "Incident",
        back_populates="detections",
    )

    __table_args__ = (
        Index("ix_detections_type_severity", "detection_type", "severity"),
        Index("ix_detections_mitre", "mitre_tactic", "mitre_technique"),
    )


class Incident(Base):
    """Security incident aggregating related detections."""

    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(500))
    severity: Mapped[str] = mapped_column(String(50), index=True)
    status: Mapped[str] = mapped_column(String(50), default="open", index=True)

    # Classification
    category: Mapped[str | None] = mapped_column(String(100), nullable=True)
    mitre_tactics: Mapped[list[str]] = mapped_column(JSON, default=list)
    mitre_techniques: Mapped[list[str]] = mapped_column(JSON, default=list)

    # Source context
    source_ips: Mapped[list[str]] = mapped_column(JSON, default=list)
    target_ips: Mapped[list[str]] = mapped_column(JSON, default=list)
    affected_users: Mapped[list[str]] = mapped_column(JSON, default=list)
    affected_systems: Mapped[list[str]] = mapped_column(JSON, default=list)

    # Analysis
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    llm_analysis: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendations: Mapped[list[str]] = mapped_column(JSON, default=list)

    # Timeline
    first_seen: Mapped[datetime] = mapped_column(DateTime)
    last_seen: Mapped[datetime] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Counts
    log_count: Mapped[int] = mapped_column(Integer, default=0)
    detection_count: Mapped[int] = mapped_column(Integer, default=0)

    # Relationships
    detections: Mapped[list["Detection"]] = relationship(
        "Detection",
        back_populates="incident",
    )

    __table_args__ = (
        Index("ix_incidents_status_severity", "status", "severity"),
        Index("ix_incidents_created_at", "created_at"),
    )
