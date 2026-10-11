from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from random import Random
from typing import Literal

from app.generators.templates import (
    TEMPLATE_DEFINITIONS,
    AttackTemplate,
    ResponseExpectation,
    TemplateContext,
)

DEFAULT_SHIFT_START = datetime(2025, 1, 1, 9, 0, tzinfo=UTC)
MAX_BACKGROUND_EVENTS = 50_000


@dataclass(frozen=True, slots=True)
class GeneratedLog:
    id: str
    index_name: str
    source_type: str
    occurred_at: datetime
    host: str
    username: str | None
    src_ip: str | None
    dst_ip: str | None
    event_data: dict[str, object]


@dataclass(frozen=True, slots=True)
class GeneratedAlert:
    id: str
    chain_id: str | None
    title: str
    severity: str
    source: str
    occurred_at: datetime
    details: dict[str, object]


@dataclass(frozen=True, slots=True)
class GroundTruth:
    expected_verdicts: tuple[tuple[str, Literal["true_positive", "false_positive"]], ...]
    correlated_alert_groups: tuple[tuple[str, ...], ...]
    expected_actions: tuple[ResponseExpectation, ...]
    technique_ids: tuple[str, ...]
    key_entities: tuple[str, ...]
    indicators_of_compromise: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GeneratedShift:
    seed: int
    template: AttackTemplate
    started_at: datetime
    duration_minutes: int
    logs: tuple[GeneratedLog, ...]
    alerts: tuple[GeneratedAlert, ...]
    ground_truth: GroundTruth


@dataclass(frozen=True, slots=True)
class _EventDraft:
    offset_seconds: int
    index_name: str
    source_type: str
    event_code: str
    host: str
    username: str | None
    src_ip: str | None
    dst_ip: str | None
    event_data: dict[str, object]
    chain_id: str | None = None
    alert_title: str | None = None
    alert_severity: str | None = None


def _make_background_event(
    rng: Random,
    offset_seconds: int,
    hosts: tuple[str, str],
    users: tuple[str, str],
    client_ip: str,
    remote_ip: str,
) -> _EventDraft:
    host = rng.choice(hosts)
    username = rng.choice(users)
    source_type = rng.choice(
        (
            "windows_security",
            "sysmon",
            "dns",
            "proxy",
            "firewall",
            "edr",
            "email_gateway",
        )
    )
    if source_type == "windows_security":
        event_code = rng.choice(("4624", "4625", "4688", "4672"))
        data: dict[str, object] = {
            "event_id": int(event_code),
            "channel": "Security",
            "status": {
                "4624": "0x0",
                "4625": "0xC000006D",
            }.get(event_code, "audit"),
            "logon_type": rng.choice((2, 3, 10)),
        }
        return _EventDraft(
            offset_seconds,
            "windows",
            source_type,
            event_code,
            host,
            username,
            client_ip,
            None,
            data,
        )
    if source_type == "sysmon":
        event_code = rng.choice(("1", "3", "7", "11", "13"))
        data = {
            "event_id": int(event_code),
            "image": rng.choice(
                (
                    "C:\\Windows\\System32\\svchost.exe",
                    "C:\\Windows\\explorer.exe",
                    "C:\\Program Files\\Contoso\\Updater.exe",
                )
            ),
            "rule_name": "ProcessCreate" if event_code == "1" else "Operational",
        }
        return _EventDraft(
            offset_seconds,
            "sysmon",
            source_type,
            event_code,
            host,
            username,
            client_ip if event_code == "3" else None,
            remote_ip if event_code == "3" else None,
            data,
        )
    if source_type == "dns":
        query = rng.choice(("intranet.corp.test", "updates.vendor.test", "mail.corp.test"))
        return _EventDraft(
            offset_seconds,
            "dns",
            source_type,
            "query",
            host,
            username,
            client_ip,
            None,
            {"query": query, "query_type": "A", "response_code": "NOERROR"},
        )
    if source_type == "proxy":
        site = rng.choice(("intranet.corp.test", "docs.vendor.test", "updates.vendor.test"))
        return _EventDraft(
            offset_seconds,
            "proxy",
            source_type,
            "http_transaction",
            host,
            username,
            client_ip,
            remote_ip,
            {
                "url": f"https://{site}/",
                "method": "GET",
                "status_code": 200,
                "bytes_out": rng.randint(200, 5000),
                "action": "allowed",
            },
        )
    if source_type == "firewall":
        return _EventDraft(
            offset_seconds,
            "firewall",
            source_type,
            "connection",
            host,
            username,
            client_ip,
            remote_ip,
            {
                "destination_port": rng.choice((53, 80, 443, 445)),
                "protocol": rng.choice(("tcp", "udp")),
                "action": rng.choice(("allowed", "denied")),
                "rule": "corp-egress",
            },
        )
    if source_type == "edr":
        return _EventDraft(
            offset_seconds,
            "edr",
            source_type,
            "behavior_assessment",
            host,
            username,
            None,
            None,
            {
                "behavior": rng.choice(("signed_updater", "browser_child", "scheduled_scan")),
                "disposition": "benign",
                "confidence": round(rng.uniform(0.01, 0.2), 2),
            },
        )
    return _EventDraft(
        offset_seconds,
        "email",
        source_type,
        "message_received",
        host,
        username,
        None,
        None,
        {
            "sender": f"notifications@{rng.choice(('vendor.test', 'corp.test'))}",
            "recipient": username,
            "subject": rng.choice(("Weekly digest", "Service notification", "Meeting update")),
            "attachment": None,
            "gateway_action": "delivered",
        },
    )


def _make_lookalike(context: TemplateContext) -> _EventDraft:
    return _EventDraft(
        offset_seconds=context.rng.randrange(context.duration_seconds),
        index_name="edr",
        source_type="edr",
        event_code="behavior_assessment",
        host=context.secondary_host,
        username=context.username,
        src_ip=None,
        dst_ip=None,
        event_data={
            "behavior": "powershell_child_process",
            "parent_process": "CompanyPortal.exe",
            "signature": "valid",
            "disposition": "approved_inventory_script",
        },
        alert_title="PowerShell launched by software inventory agent",
        alert_severity="low",
    )


def _render_expected_actions(
    actions: tuple[ResponseExpectation, ...],
    context: TemplateContext,
) -> tuple[ResponseExpectation, ...]:
    replacements = {
        "host": context.host,
        "username": context.username,
        "attacker_ip": context.attacker_ip,
        "external_ip": context.external_ip,
    }
    return tuple(
        ResponseExpectation(
            action_type=action.action_type,
            target=action.target.format_map(replacements),
        )
        for action in actions
    )


def generate_shift(
    seed: int,
    template: AttackTemplate | str,
    *,
    duration_minutes: int = 30,
    noise_events_per_minute: int = 12,
    start_time: datetime = DEFAULT_SHIFT_START,
    include_lookalike: bool = True,
) -> GeneratedShift:
    """Generate a reproducible shift. Ground truth is internal grading data."""
    try:
        selected_template = AttackTemplate(template)
    except ValueError as error:
        supported = ", ".join(item.value for item in AttackTemplate)
        raise ValueError(f"Unknown attack template. Choose one of: {supported}") from error
    if duration_minutes < 1 or duration_minutes > 480:
        raise ValueError("duration_minutes must be between 1 and 480")
    if noise_events_per_minute < 0:
        raise ValueError("noise_events_per_minute must be zero or greater")
    if noise_events_per_minute * duration_minutes > MAX_BACKGROUND_EVENTS:
        raise ValueError(f"Generated background is limited to {MAX_BACKGROUND_EVENTS} events")
    if start_time.tzinfo is None or start_time.utcoffset() is None:
        raise ValueError("start_time must include a timezone")

    rng = Random(seed)
    host = f"WS-{rng.randint(10, 99):03d}"
    secondary_host = f"FS-{rng.randint(1, 20):02d}"
    username = rng.choice(("a.morgan", "j.smith", "r.patel", "m.chen"))
    workstation_ip = f"10.20.{rng.randint(1, 8)}.{rng.randint(10, 240)}"
    attacker_ip = f"198.51.100.{rng.randint(10, 240)}"
    external_ip = f"203.0.113.{rng.randint(10, 240)}"
    domain_label = rng.choice(("invoice", "share", "secure-mail"))
    domain_id = rng.randint(100, 999)
    malicious_domain = f"{domain_label}-{domain_id}.example.test"
    duration_seconds = duration_minutes * 60
    chain_id = f"chain-{selected_template.value}"
    context = TemplateContext(
        rng=rng,
        duration_seconds=duration_seconds,
        host=host,
        secondary_host=secondary_host,
        username=username,
        workstation_ip=workstation_ip,
        attacker_ip=attacker_ip,
        external_ip=external_ip,
        malicious_domain=malicious_domain,
    )
    definition = TEMPLATE_DEFINITIONS[selected_template]

    drafts: list[_EventDraft] = [
        _EventDraft(
            offset_seconds=event.offset_seconds,
            index_name=event.index_name,
            source_type=event.source_type,
            event_code=event.event_code,
            host=event.host,
            username=event.username,
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            event_data=event.event_data,
            chain_id=chain_id,
            alert_title=event.alert_title,
            alert_severity=event.alert_severity,
        )
        for event in definition.build(context)
    ]

    noise_count = noise_events_per_minute * duration_minutes
    for _ in range(noise_count):
        drafts.append(
            _make_background_event(
                rng,
                rng.randrange(duration_seconds),
                (host, secondary_host),
                (username, "svc.backup"),
                workstation_ip,
                external_ip,
            )
        )
    if include_lookalike:
        drafts.append(_make_lookalike(context))

    drafts.sort(key=lambda event: event.offset_seconds)
    logs: list[GeneratedLog] = []
    alerts: list[GeneratedAlert] = []
    expected_verdicts: list[tuple[str, Literal["true_positive", "false_positive"]]] = []
    chain_alert_ids: list[str] = []

    for index, event in enumerate(drafts, start=1):
        event_id = f"evt-{index:06d}"
        occurred_at = start_time + timedelta(seconds=event.offset_seconds)
        logs.append(
            GeneratedLog(
                id=event_id,
                index_name=event.index_name,
                source_type=event.source_type,
                occurred_at=occurred_at,
                host=event.host,
                username=event.username,
                src_ip=event.src_ip,
                dst_ip=event.dst_ip,
                event_data={**event.event_data, "event_code": event.event_code},
            )
        )
        if event.alert_title is None:
            continue
        alert_id = f"alert-{len(alerts) + 1:04d}"
        alerts.append(
            GeneratedAlert(
                id=alert_id,
                chain_id=event.chain_id,
                title=event.alert_title,
                severity=event.alert_severity or "low",
                source=event.source_type,
                occurred_at=occurred_at,
                details={"event_id": event_id, "host": event.host, "username": event.username},
            )
        )
        verdict: Literal["true_positive", "false_positive"] = (
            "true_positive" if event.chain_id is not None else "false_positive"
        )
        expected_verdicts.append((alert_id, verdict))
        if event.chain_id is not None:
            chain_alert_ids.append(alert_id)

    return GeneratedShift(
        seed=seed,
        template=selected_template,
        started_at=start_time,
        duration_minutes=duration_minutes,
        logs=tuple(logs),
        alerts=tuple(alerts),
        ground_truth=GroundTruth(
            expected_verdicts=tuple(expected_verdicts),
            correlated_alert_groups=(tuple(chain_alert_ids),) if chain_alert_ids else (),
            expected_actions=_render_expected_actions(definition.expected_actions, context),
            technique_ids=definition.technique_ids,
            key_entities=(
                host,
                secondary_host,
                username,
                workstation_ip,
                attacker_ip,
                external_ip,
                malicious_domain,
            ),
            indicators_of_compromise=(attacker_ip, external_ip, malicious_domain),
        ),
    )
