from app.db.base import Base
from app.models import (
    Alert,
    Assignment,
    AuditEvent,
    Evidence,
    Incident,
    LogEvent,
    QueryHistory,
    Report,
    ResponseAction,
    Scenario,
    Score,
    Shift,
    ShiftTruth,
    SkillProgress,
    User,
)


def test_all_phase_one_models_register_with_metadata() -> None:
    expected = {
        "users",
        "scenarios",
        "assignments",
        "shifts",
        "shift_truth",
        "alerts",
        "logs",
        "query_history",
        "incidents",
        "evidence",
        "response_actions",
        "reports",
        "scores",
        "skill_progress",
        "audit_events",
    }

    assert expected == set(Base.metadata.tables)
    assert all(model.__table__ is not None for model in (
        Alert,
        Assignment,
        AuditEvent,
        Evidence,
        Incident,
        LogEvent,
        QueryHistory,
        Report,
        ResponseAction,
        Scenario,
        Score,
        Shift,
        ShiftTruth,
        SkillProgress,
        User,
    ))
