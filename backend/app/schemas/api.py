from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.domain.enums import ShiftStatus
from app.generators.templates import AttackTemplate
from app.schemas.auth import RequestModel

Severity = Literal["informational", "low", "medium", "high", "critical"]
Verdict = Literal["true_positive", "false_positive"]
ActionType = Literal["isolate_host", "disable_account", "block_ip", "reset_password"]


class CreateShiftRequest(RequestModel):
    template: AttackTemplate
    seed: int | None = Field(default=None, ge=0, le=4_294_967_295)
    duration_minutes: int | None = Field(default=None, ge=5, le=240)
    noise_events_per_minute: int | None = Field(default=None, ge=0, le=100)


class SOCSettingsRead(BaseModel):
    default_shift_duration_minutes: int
    default_noise_events_per_minute: int
    critical_alert_sla_seconds: int
    max_query_rows: int
    log_sources: list[str]
    attack_templates: list[str]


class ShiftSummary(BaseModel):
    id: str
    scenario_id: str
    template: AttackTemplate
    seed: int
    status: ShiftStatus
    started_at: datetime
    ended_at: datetime | None
    duration_minutes: int
    log_count: int
    alert_count: int


class AlertRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    chain_id: str | None
    title: str
    description: str
    severity: Severity
    source: str
    occurred_at: datetime
    details: dict[str, Any]


class LogRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    index_name: str
    source_type: str
    occurred_at: datetime
    host: str | None
    username: str | None
    src_ip: str | None
    dst_ip: str | None
    event_data: dict[str, Any]


class QueryRequest(RequestModel):
    query: str = Field(min_length=1, max_length=10_000)
    result_limit: int = Field(default=500, ge=1, le=1000)


class QueryResponse(BaseModel):
    history_id: str
    result_count: int
    returned_count: int
    truncated: bool
    results: list[dict[str, Any]]


class ResponseActionRequest(RequestModel):
    action_type: ActionType
    target: str = Field(min_length=1, max_length=200)
    evidence_ids: list[str] = Field(default_factory=list, max_length=20)


class ResponseActionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    action_type: ActionType
    target: str
    outcome: str
    evidence_ids: list[str]
    performed_at: datetime


class TimelineEntry(RequestModel):
    at: str = Field(min_length=1, max_length=100)
    description: str = Field(min_length=1, max_length=1000)


class ReportDraft(RequestModel):
    summary: str = Field(default="", max_length=6000)
    timeline: list[TimelineEntry] = Field(default_factory=list, max_length=100)
    iocs: list[str] = Field(default_factory=list, max_length=100)
    root_cause: str = Field(default="", max_length=3000)
    impact: str = Field(default="", max_length=3000)
    recommendations: list[str] = Field(default_factory=list, max_length=50)


class ScoreSubmission(RequestModel):
    triage_verdicts: dict[str, Verdict] = Field(default_factory=dict, max_length=500)
    severity_assessments: dict[str, Severity] = Field(default_factory=dict, max_length=500)
    escalated_alert_ids: list[str] = Field(default_factory=list, max_length=500)
    correlated_alert_groups: list[list[str]] = Field(default_factory=list, max_length=100)
    report: ReportDraft = Field(default_factory=ReportDraft)


class ScoreRead(BaseModel):
    id: str
    shift_id: str
    total: float
    breakdown: dict[str, float]
    feedback: dict[str, Any]
    graded_at: datetime
