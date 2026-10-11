from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.domain.enums import (
    AssignmentStatus,
    IncidentStatus,
    ReportStatus,
    ScenarioDifficulty,
    ScenarioStatus,
    ShiftStatus,
    UserRole,
)


def new_id() -> str:
    return str(uuid4())


def utc_now() -> datetime:
    return datetime.now(UTC)


class BaseRecord(Base):
    __abstract__ = True

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )


class User(BaseRecord):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(120))
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default=UserRole.TRAINEE.value)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class Scenario(BaseRecord):
    __tablename__ = "scenarios"
    __table_args__ = (UniqueConstraint("slug", "version", name="uq_scenario_slug_version"),)

    slug: Mapped[str] = mapped_column(String(120), index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    difficulty: Mapped[str] = mapped_column(
        String(20), default=ScenarioDifficulty.BEGINNER.value
    )
    status: Mapped[str] = mapped_column(String(20), default=ScenarioStatus.DRAFT.value)
    schema_version: Mapped[str] = mapped_column(String(20), default="1.0")
    definition: Mapped[dict[str, Any]] = mapped_column(JSON)
    author_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)


class Assignment(BaseRecord):
    __tablename__ = "assignments"

    scenario_id: Mapped[str] = mapped_column(ForeignKey("scenarios.id"), index=True)
    trainee_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    instructor_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    status: Mapped[str] = mapped_column(String(20), default=AssignmentStatus.ASSIGNED.value)
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    time_limit_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)


class Shift(BaseRecord):
    __tablename__ = "shifts"
    __table_args__ = (Index("ix_shifts_trainee_status", "trainee_id", "status"),)

    scenario_id: Mapped[str] = mapped_column(ForeignKey("scenarios.id"), index=True)
    trainee_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    assignment_id: Mapped[str | None] = mapped_column(
        ForeignKey("assignments.id"), nullable=True
    )
    template: Mapped[str] = mapped_column(String(40))
    scenario_version: Mapped[int] = mapped_column(Integer)
    seed: Mapped[int] = mapped_column(Integer)
    duration_minutes: Mapped[int] = mapped_column(Integer, default=30)
    status: Mapped[str] = mapped_column(String(20), default=ShiftStatus.ACTIVE.value)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    elapsed_seconds: Mapped[int] = mapped_column(Integer, default=0)
    clock_paused: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class ShiftTruth(BaseRecord):
    __tablename__ = "shift_truth"

    shift_id: Mapped[str] = mapped_column(ForeignKey("shifts.id"), unique=True, index=True)
    truth_data: Mapped[dict[str, Any]] = mapped_column(JSON)


class Alert(BaseRecord):
    __tablename__ = "alerts"
    __table_args__ = (Index("ix_alerts_shift_time", "shift_id", "occurred_at"),)

    shift_id: Mapped[str] = mapped_column(ForeignKey("shifts.id"), index=True)
    chain_id: Mapped[str | None] = mapped_column(String(100), index=True, nullable=True)
    title: Mapped[str] = mapped_column(String(240))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(20))
    source: Mapped[str] = mapped_column(String(80))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class LogEvent(BaseRecord):
    __tablename__ = "logs"
    __table_args__ = (
        Index("ix_logs_shift_index_time", "shift_id", "index_name", "occurred_at"),
        Index("ix_logs_shift_host", "shift_id", "host"),
    )

    shift_id: Mapped[str] = mapped_column(ForeignKey("shifts.id"), index=True)
    index_name: Mapped[str] = mapped_column(String(80), index=True)
    source_type: Mapped[str] = mapped_column(String(80))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    host: Mapped[str | None] = mapped_column(String(120), nullable=True)
    username: Mapped[str | None] = mapped_column(String(120), nullable=True)
    src_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    event_data: Mapped[dict[str, Any]] = mapped_column(JSON)


class QueryHistory(BaseRecord):
    __tablename__ = "query_history"
    __table_args__ = (Index("ix_query_history_shift_executed", "shift_id", "executed_at"),)

    shift_id: Mapped[str] = mapped_column(ForeignKey("shifts.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    query_text: Mapped[str] = mapped_column(Text)
    result_count: Mapped[int] = mapped_column(Integer, default=0)
    succeeded: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    executed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class Incident(BaseRecord):
    __tablename__ = "incidents"

    shift_id: Mapped[str] = mapped_column(ForeignKey("shifts.id"), index=True)
    created_by_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    title: Mapped[str] = mapped_column(String(240))
    status: Mapped[str] = mapped_column(String(24), default=IncidentStatus.NEW.value)
    severity: Mapped[str | None] = mapped_column(String(20), nullable=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Evidence(BaseRecord):
    __tablename__ = "evidence"

    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    added_by_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    source_type: Mapped[str] = mapped_column(String(40))
    source_id: Mapped[str] = mapped_column(String(100))
    note: Mapped[str] = mapped_column(Text, default="")
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ResponseAction(BaseRecord):
    __tablename__ = "response_actions"

    shift_id: Mapped[str] = mapped_column(ForeignKey("shifts.id"), index=True)
    incident_id: Mapped[str | None] = mapped_column(
        ForeignKey("incidents.id"), nullable=True, index=True
    )
    actor_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    action_type: Mapped[str] = mapped_column(String(40))
    target: Mapped[str] = mapped_column(String(200))
    outcome: Mapped[str] = mapped_column(String(40))
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    performed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class Report(BaseRecord):
    __tablename__ = "reports"
    __table_args__ = (UniqueConstraint("incident_id", name="uq_report_incident"),)

    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    author_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    status: Mapped[str] = mapped_column(String(20), default=ReportStatus.DRAFT.value)
    summary: Mapped[str] = mapped_column(Text, default="")
    timeline: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    iocs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    root_cause: Mapped[str] = mapped_column(Text, default="")
    impact: Mapped[str] = mapped_column(Text, default="")
    recommendations: Mapped[str] = mapped_column(Text, default="")
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Score(BaseRecord):
    __tablename__ = "scores"
    __table_args__ = (UniqueConstraint("shift_id", name="uq_score_shift"),)

    shift_id: Mapped[str] = mapped_column(ForeignKey("shifts.id"), index=True)
    total: Mapped[float] = mapped_column(Float)
    breakdown: Mapped[dict[str, float]] = mapped_column(JSON)
    feedback: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    graded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class SkillProgress(BaseRecord):
    __tablename__ = "skill_progress"
    __table_args__ = (UniqueConstraint("user_id", "skill_key", name="uq_user_skill"),)

    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    skill_key: Mapped[str] = mapped_column(String(100), index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    average_score: Mapped[float] = mapped_column(Float, default=0)
    last_score: Mapped[float | None] = mapped_column(Float, nullable=True)


class AuditEvent(BaseRecord):
    __tablename__ = "audit_events"

    actor_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(100), index=True)
    resource_type: Mapped[str] = mapped_column(String(80))
    resource_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    event_data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
