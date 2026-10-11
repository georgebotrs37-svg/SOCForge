from datetime import UTC, datetime
from typing import Annotated, Any, cast

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user, require_roles
from app.core.config import get_settings
from app.db.session import get_db
from app.domain.enums import (
    IncidentStatus,
    ReportStatus,
    ShiftStatus,
    UserRole,
)
from app.generators import AttackTemplate
from app.generators.templates import TEMPLATE_DEFINITIONS
from app.models import (
    Alert,
    Incident,
    LogEvent,
    QueryHistory,
    Report,
    ResponseAction,
    Score,
    Shift,
    ShiftTruth,
    SkillProgress,
    User,
)
from app.query_engine import QueryExecutionError, QuerySyntaxError, execute_query
from app.schemas.api import (
    AlertRead,
    CreateShiftRequest,
    LogRead,
    QueryRequest,
    QueryResponse,
    ResponseActionRead,
    ResponseActionRequest,
    ScoreRead,
    ScoreSubmission,
    ShiftSummary,
)
from app.scoring.engine import ActionEvidence, ScoringTruth, grade_submission
from app.services.shifts import create_generated_shift, valid_action_target

router = APIRouter(prefix="/shifts", tags=["shifts"])
_SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
DatabaseSession = Annotated[Session, Depends(get_db)]
CurrentUser = Annotated[User, Depends(get_current_user)]
TraineeUser = Annotated[User, Depends(require_roles(UserRole.TRAINEE))]
InstructorUser = Annotated[
    User,
    Depends(require_roles(UserRole.INSTRUCTOR, UserRole.ADMIN)),
]


def _owned_shift(session: Session, shift_id: str, user_id: str) -> Shift:
    shift = session.get(Shift, shift_id)
    if shift is None or shift.trainee_id != user_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Shift not found")
    return shift


def _require_active(shift: Shift) -> None:
    if shift.status != ShiftStatus.ACTIVE.value or shift.clock_paused:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This shift is not accepting investigation changes",
        )


def _shift_summary(
    session: Session,
    shift: Shift,
    *,
    log_count: int | None = None,
    alert_count: int | None = None,
) -> ShiftSummary:
    if log_count is None:
        log_count = (
            session.scalar(
                select(func.count()).select_from(LogEvent).where(LogEvent.shift_id == shift.id)
            )
            or 0
        )
    if alert_count is None:
        alert_count = (
            session.scalar(
                select(func.count()).select_from(Alert).where(Alert.shift_id == shift.id)
            )
            or 0
        )
    return ShiftSummary(
        id=shift.id,
        scenario_id=shift.scenario_id,
        template=AttackTemplate(shift.template),
        seed=shift.seed,
        status=ShiftStatus(shift.status),
        started_at=shift.started_at,
        ended_at=shift.ended_at,
        duration_minutes=shift.duration_minutes,
        log_count=log_count,
        alert_count=alert_count,
    )


@router.get("/templates")
def list_templates(
    _user: InstructorUser,
) -> list[dict[str, object]]:
    return [
        {
            "id": template.value,
            "title": definition.title,
            "technique_ids": list(definition.technique_ids),
        }
        for template, definition in TEMPLATE_DEFINITIONS.items()
    ]


@router.post("", response_model=ShiftSummary, status_code=status.HTTP_201_CREATED)
def start_shift(
    request: CreateShiftRequest,
    user: TraineeUser,
    session: DatabaseSession,
) -> ShiftSummary:
    try:
        shift, log_count, alert_count = create_generated_shift(
            session,
            trainee_id=user.id,
            template=request.template,
            seed=request.seed,
            duration_minutes=(
                request.duration_minutes
                if request.duration_minutes is not None
                else get_settings().default_shift_duration_minutes
            ),
            noise_events_per_minute=(
                request.noise_events_per_minute
                if request.noise_events_per_minute is not None
                else get_settings().default_noise_events_per_minute
            ),
        )
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    return _shift_summary(
        session,
        shift,
        log_count=log_count,
        alert_count=alert_count,
    )


@router.get("", response_model=list[ShiftSummary])
def list_shifts(
    user: CurrentUser,
    session: DatabaseSession,
) -> list[ShiftSummary]:
    shifts = session.scalars(
        select(Shift).where(Shift.trainee_id == user.id).order_by(Shift.started_at.desc()).limit(50)
    )
    return [_shift_summary(session, shift) for shift in shifts]


@router.get("/{shift_id}", response_model=ShiftSummary)
def read_shift(
    shift_id: str,
    user: CurrentUser,
    session: DatabaseSession,
) -> ShiftSummary:
    return _shift_summary(session, _owned_shift(session, shift_id, user.id))


@router.get("/{shift_id}/alerts", response_model=list[AlertRead])
def list_alerts(
    shift_id: str,
    user: CurrentUser,
    session: DatabaseSession,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> list[Alert]:
    _owned_shift(session, shift_id, user.id)
    return list(
        session.scalars(
            select(Alert)
            .where(Alert.shift_id == shift_id)
            .order_by(Alert.occurred_at, Alert.id)
            .offset(offset)
            .limit(limit)
        )
    )


@router.get("/{shift_id}/logs", response_model=list[LogRead])
def list_logs(
    shift_id: str,
    user: CurrentUser,
    session: DatabaseSession,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> list[LogEvent]:
    _owned_shift(session, shift_id, user.id)
    return list(
        session.scalars(
            select(LogEvent)
            .where(LogEvent.shift_id == shift_id)
            .order_by(LogEvent.occurred_at, LogEvent.id)
            .offset(offset)
            .limit(limit)
        )
    )


@router.post("/{shift_id}/query", response_model=QueryResponse)
def run_shift_query(
    shift_id: str,
    request: QueryRequest,
    user: TraineeUser,
    session: DatabaseSession,
) -> QueryResponse:
    shift = _owned_shift(session, shift_id, user.id)
    _require_active(shift)
    records = session.scalars(
        select(LogEvent)
        .where(LogEvent.shift_id == shift_id)
        .order_by(LogEvent.occurred_at, LogEvent.id)
        .limit(get_settings().max_query_rows + 1)
    ).all()
    try:
        results = execute_query(
            request.query,
            cast(list[Any], records),
            max_input_rows=get_settings().max_query_rows,
        )
    except (QuerySyntaxError, QueryExecutionError) as error:
        session.add(
            QueryHistory(
                shift_id=shift_id,
                user_id=user.id,
                query_text=request.query,
                succeeded=False,
                error_message=str(error)[:1000],
                result_count=0,
            )
        )
        session.commit()
        raise HTTPException(
            status_code=422,
            detail=str(error),
        ) from error

    session.add(
        history := QueryHistory(
            shift_id=shift_id,
            user_id=user.id,
            query_text=request.query,
            succeeded=True,
            result_count=len(results),
        )
    )
    session.flush()
    session.commit()
    returned = results[: request.result_limit]
    return QueryResponse(
        history_id=history.id,
        result_count=len(results),
        returned_count=len(returned),
        truncated=len(results) > len(returned),
        results=returned,
    )


@router.post(
    "/{shift_id}/actions",
    response_model=ResponseActionRead,
    status_code=status.HTTP_201_CREATED,
)
def perform_response_action(
    shift_id: str,
    request: ResponseActionRequest,
    user: TraineeUser,
    session: DatabaseSession,
) -> ResponseActionRead:
    shift = _owned_shift(session, shift_id, user.id)
    _require_active(shift)
    if not valid_action_target(session, shift_id, request.action_type, request.target):
        raise HTTPException(
            status_code=422,
            detail="Action target is not present in this shift",
        )
    if len(request.evidence_ids) != len(set(request.evidence_ids)):
        raise HTTPException(
            status_code=422,
            detail="Evidence IDs must be unique",
        )
    if request.evidence_ids:
        valid_alerts = set(
            session.scalars(
                select(Alert.id).where(
                    Alert.shift_id == shift_id,
                    Alert.id.in_(request.evidence_ids),
                )
            )
        )
        valid_logs = set(
            session.scalars(
                select(LogEvent.id).where(
                    LogEvent.shift_id == shift_id,
                    LogEvent.id.in_(request.evidence_ids),
                )
            )
        )
        if set(request.evidence_ids) - valid_alerts - valid_logs:
            raise HTTPException(
                status_code=422,
                detail="Evidence must reference an alert or log from this shift",
            )
    action = ResponseAction(
        shift_id=shift_id,
        actor_id=user.id,
        action_type=request.action_type,
        target=request.target,
        outcome="executed",
        evidence_ids=request.evidence_ids,
        performed_at=datetime.now(UTC),
    )
    session.add(action)
    session.commit()
    session.refresh(action)
    return ResponseActionRead.model_validate(action)


@router.get("/{shift_id}/actions", response_model=list[ResponseActionRead])
def list_response_actions(
    shift_id: str,
    user: CurrentUser,
    session: DatabaseSession,
) -> list[ResponseActionRead]:
    _owned_shift(session, shift_id, user.id)
    actions = session.scalars(
        select(ResponseAction)
        .where(ResponseAction.shift_id == shift_id)
        .order_by(ResponseAction.performed_at, ResponseAction.id)
    )
    return [ResponseActionRead.model_validate(action) for action in actions]


def _validate_submission_alerts(
    submission: ScoreSubmission,
    known_alert_ids: set[str],
) -> None:
    submitted_ids = (
        set(submission.triage_verdicts)
        | set(submission.severity_assessments)
        | set(submission.escalated_alert_ids)
        | {alert_id for group in submission.correlated_alert_groups for alert_id in group}
    )
    unknown = submitted_ids - known_alert_ids
    if unknown:
        raise HTTPException(
            status_code=422,
            detail="Submission references alerts outside this shift",
        )


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


@router.post("/{shift_id}/submit", response_model=ScoreRead)
def submit_shift(
    shift_id: str,
    submission: ScoreSubmission,
    user: TraineeUser,
    session: DatabaseSession,
) -> ScoreRead:
    shift = _owned_shift(session, shift_id, user.id)
    _require_active(shift)
    truth_record = session.scalar(select(ShiftTruth).where(ShiftTruth.shift_id == shift_id))
    if truth_record is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Shift grading data is unavailable",
        )
    alerts = list(session.scalars(select(Alert).where(Alert.shift_id == shift_id)))
    known_alert_ids = {alert.id for alert in alerts}
    _validate_submission_alerts(submission, known_alert_ids)
    try:
        truth = ScoringTruth.model_validate(truth_record.truth_data)
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Shift grading data is invalid",
        ) from error

    started_at = _aware(shift.started_at)
    actions = [
        ActionEvidence(
            action_type=action.action_type,
            target=action.target,
            elapsed_seconds=max(
                int((_aware(action.performed_at) - started_at).total_seconds()),
                0,
            ),
            has_evidence=bool(action.evidence_ids),
        )
        for action in session.scalars(
            select(ResponseAction).where(
                ResponseAction.shift_id == shift_id,
                ResponseAction.outcome == "executed",
            )
        )
    ]
    successful_queries = list(
        session.scalars(
            select(QueryHistory.query_text).where(
                QueryHistory.shift_id == shift_id,
                QueryHistory.succeeded.is_(True),
            )
        )
    )
    grade = grade_submission(
        truth,
        submission,
        actions=actions,
        successful_queries=successful_queries,
    )

    submitted_severities = list(submission.severity_assessments.values())
    severity: str | None = None
    if submitted_severities:
        severity = max(submitted_severities, key=lambda value: _SEVERITY_RANK[value])
    incident = Incident(
        shift_id=shift_id,
        created_by_id=user.id,
        title=(submission.report.summary.strip() or f"{shift.template} investigation")[:240],
        status=IncidentStatus.NEW.value,
        severity=severity,
        summary=submission.report.summary,
    )
    session.add(incident)
    session.flush()
    report = Report(
        incident_id=incident.id,
        author_id=user.id,
        status=ReportStatus.GRADED.value,
        summary=submission.report.summary,
        timeline=[item.model_dump(mode="json") for item in submission.report.timeline],
        iocs=[{"value": value} for value in submission.report.iocs],
        root_cause=submission.report.root_cause,
        impact=submission.report.impact,
        recommendations="\n".join(submission.report.recommendations),
        submitted_at=datetime.now(UTC),
    )
    score = Score(
        shift_id=shift_id,
        total=grade.total,
        breakdown=grade.breakdown,
        feedback=grade.feedback,
        graded_at=datetime.now(UTC),
    )
    ended_at = datetime.now(UTC)
    shift.status = ShiftStatus.COMPLETED.value
    shift.ended_at = ended_at
    shift.elapsed_seconds = max(int((ended_at - started_at).total_seconds()), 0)
    session.add_all((report, score))

    for skill_key in truth.technique_ids:
        skill = session.scalar(
            select(SkillProgress).where(
                SkillProgress.user_id == user.id,
                SkillProgress.skill_key == skill_key,
            )
        )
        if skill is None:
            session.add(
                SkillProgress(
                    user_id=user.id,
                    skill_key=skill_key,
                    attempts=1,
                    average_score=grade.total,
                    last_score=grade.total,
                )
            )
        else:
            skill.average_score = (skill.average_score * skill.attempts + grade.total) / (
                skill.attempts + 1
            )
            skill.attempts += 1
            skill.last_score = grade.total

    session.commit()
    session.refresh(score)
    return ScoreRead(
        id=score.id,
        shift_id=score.shift_id,
        total=score.total,
        breakdown=score.breakdown,
        feedback=score.feedback,
        graded_at=score.graded_at,
    )
