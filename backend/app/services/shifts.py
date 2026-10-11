import secrets
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.generators import generate_shift
from app.generators.templates import TEMPLATE_DEFINITIONS, AttackTemplate
from app.models import Alert, LogEvent, Scenario, Shift, ShiftTruth
from app.schemas.scenario import ScenarioDefinition

_SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _built_in_definition(template: AttackTemplate) -> ScenarioDefinition:
    definition = TEMPLATE_DEFINITIONS[template]
    chain_id = f"chain-{template.value}"
    primary_alert_key = f"{template.value}-primary"
    scenario_slug = f"builtin-{template.value.replace('_', '-')}"
    payload = {
        "schema_version": "1.0",
        "id": scenario_slug,
        "title": definition.title,
        "description": "Seeded SOCForge built-in training template.",
        "difficulty": "intermediate",
        "estimated_duration_minutes": 30,
        "environment": {
            "hosts": [
                {
                    "hostname": "TRAINING-WS",
                    "role": "workstation",
                    "operating_system": "Windows 11",
                },
                {
                    "hostname": "TRAINING-FS",
                    "role": "file_server",
                    "operating_system": "Windows Server",
                },
            ],
            "users": [
                {
                    "username": "training.user",
                    "display_name": "Training User",
                    "department": "Operations",
                }
            ],
        },
        "attack_chains": [
            {
                "chain_id": chain_id,
                "name": definition.title,
                "stages": [
                    {
                        "stage_key": "primary-detection",
                        "name": definition.title,
                        "technique_ids": list(definition.technique_ids),
                        "offset_seconds": 0,
                        "alert_keys": [primary_alert_key],
                    }
                ],
            }
        ],
        "alerts": [
            {
                "alert_key": primary_alert_key,
                "title": definition.title,
                "severity": "high",
                "source": "edr",
                "offset_seconds": 0,
            }
        ],
        "ground_truth": {
            "expected_verdict": "true_positive",
            "expected_severity": "high",
            "correlated_chain_ids": [chain_id],
            "expected_actions": [
                {
                    "action_type": action.action_type,
                    "target_pattern": action.target,
                }
                for action in definition.expected_actions
            ],
        },
    }
    return ScenarioDefinition.model_validate(payload)


def _get_or_create_scenario(session: Session, template: AttackTemplate) -> Scenario:
    slug = f"builtin-{template.value.replace('_', '-')}"
    statement = select(Scenario).where(Scenario.slug == slug, Scenario.version == 1)
    scenario = session.scalar(statement)
    if scenario is not None:
        return scenario

    definition = _built_in_definition(template)
    scenario = Scenario(
        slug=definition.id,
        version=1,
        title=definition.title,
        description=definition.description,
        difficulty=definition.difficulty.value,
        status="published",
        schema_version=definition.schema_version,
        definition=definition.model_dump(mode="json"),
    )
    session.add(scenario)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        existing = session.scalar(statement)
        if existing is None:
            raise
        scenario = existing
    return scenario


def create_generated_shift(
    session: Session,
    *,
    trainee_id: str,
    template: AttackTemplate,
    seed: int | None,
    duration_minutes: int,
    noise_events_per_minute: int,
) -> tuple[Shift, int, int]:
    resolved_seed = seed if seed is not None else secrets.randbits(32)
    started_at = datetime.now(UTC)
    generated = generate_shift(
        seed=resolved_seed,
        template=template,
        duration_minutes=duration_minutes,
        noise_events_per_minute=noise_events_per_minute,
        start_time=started_at,
    )
    scenario = _get_or_create_scenario(session, template)
    shift = Shift(
        scenario_id=scenario.id,
        trainee_id=trainee_id,
        template=template.value,
        scenario_version=scenario.version,
        seed=resolved_seed,
        duration_minutes=duration_minutes,
        started_at=started_at,
    )
    session.add(shift)
    session.flush()

    log_ids = {log.id: str(uuid4()) for log in generated.logs}
    alert_ids = {alert.id: str(uuid4()) for alert in generated.alerts}
    truth_data: dict[str, object] = {
        "expected_verdicts": {
            alert_ids[alert_id]: verdict
            for alert_id, verdict in generated.ground_truth.expected_verdicts
        },
        "expected_severities": {alert_ids[alert.id]: alert.severity for alert in generated.alerts},
        "correlated_alert_groups": [
            [alert_ids[alert_id] for alert_id in group]
            for group in generated.ground_truth.correlated_alert_groups
        ],
        "expected_actions": [
            {"action_type": action.action_type, "target": action.target}
            for action in generated.ground_truth.expected_actions
        ],
        "key_entities": list(generated.ground_truth.key_entities),
        "indicators_of_compromise": list(generated.ground_truth.indicators_of_compromise),
        "technique_ids": list(generated.ground_truth.technique_ids),
        "sla_seconds": get_settings().critical_alert_sla_seconds,
    }
    session.add(ShiftTruth(shift_id=shift.id, truth_data=truth_data))
    session.add_all(
        [
            Alert(
                id=alert_ids[alert.id],
                shift_id=shift.id,
                chain_id=alert.chain_id,
                title=alert.title,
                description="",
                severity=alert.severity,
                source=alert.source,
                occurred_at=alert.occurred_at,
                details={
                    **alert.details,
                    "event_id": log_ids.get(str(alert.details.get("event_id")), ""),
                },
            )
            for alert in generated.alerts
        ]
    )
    session.add_all(
        [
            LogEvent(
                id=log_ids[log.id],
                shift_id=shift.id,
                index_name=log.index_name,
                source_type=log.source_type,
                occurred_at=log.occurred_at,
                host=log.host,
                username=log.username,
                src_ip=log.src_ip,
                dst_ip=log.dst_ip,
                event_data=log.event_data,
            )
            for log in generated.logs
        ]
    )
    session.commit()
    session.refresh(shift)
    return shift, len(generated.logs), len(generated.alerts)


def valid_action_target(session: Session, shift_id: str, action_type: str, target: str) -> bool:
    if action_type == "block_ip":
        ip_statement = select(LogEvent.src_ip, LogEvent.dst_ip).where(
            LogEvent.shift_id == shift_id
        )
        normalized_target = target.casefold()
        return any(
            candidate is not None and candidate.casefold() == normalized_target
            for source_ip, destination_ip in session.execute(ip_statement)
            for candidate in (source_ip, destination_ip)
        )
    column_by_action = {
        "isolate_host": LogEvent.host,
        "disable_account": LogEvent.username,
        "reset_password": LogEvent.username,
    }
    column = column_by_action.get(action_type)
    if column is None:
        return False
    normalized_target = target.casefold()
    target_statement = select(column).where(
        LogEvent.shift_id == shift_id,
        column.is_not(None),
    )
    return any(
        value is not None and value.casefold() == normalized_target
        for value in session.scalars(target_statement)
    )
