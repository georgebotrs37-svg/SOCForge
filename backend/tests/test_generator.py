from datetime import UTC, datetime

import pytest

from app.generators import AttackTemplate, generate_shift


@pytest.mark.parametrize("template", list(AttackTemplate))
def test_same_seed_generates_identical_shift(template: AttackTemplate) -> None:
    first = generate_shift(seed=42017, template=template, noise_events_per_minute=3)
    second = generate_shift(seed=42017, template=template, noise_events_per_minute=3)

    assert first == second


def test_different_seeds_change_generated_environment() -> None:
    first = generate_shift(seed=1, template=AttackTemplate.BRUTE_FORCE, include_lookalike=False)
    second = generate_shift(seed=2, template=AttackTemplate.BRUTE_FORCE, include_lookalike=False)

    assert first.logs != second.logs


@pytest.mark.parametrize(
    ("template", "required_event_codes"),
    [
        (AttackTemplate.PHISHING_MACRO, {"4624", "1", "3", "11", "13"}),
        (AttackTemplate.BRUTE_FORCE, {"4624", "4625", "4672", "1"}),
        (AttackTemplate.RANSOMWARE_PRECURSOR, {"1", "3", "11"}),
    ],
)
def test_templates_emit_linked_attack_alerts_and_telemetry(
    template: AttackTemplate,
    required_event_codes: set[str],
) -> None:
    shift = generate_shift(seed=99, template=template, noise_events_per_minute=0)
    event_codes = {str(log.event_data["event_code"]) for log in shift.logs}
    attack_alerts = [alert for alert in shift.alerts if alert.chain_id is not None]

    assert required_event_codes <= event_codes
    assert len(attack_alerts) >= 2
    assert len({alert.chain_id for alert in attack_alerts}) == 1
    assert len(shift.ground_truth.correlated_alert_groups[0]) == len(attack_alerts)
    assert all(
        verdict == "true_positive"
        for alert_id, verdict in shift.ground_truth.expected_verdicts
        if alert_id in {alert.id for alert in attack_alerts}
    )


def test_background_covers_all_requested_source_families() -> None:
    shift = generate_shift(
        seed=5,
        template=AttackTemplate.BRUTE_FORCE,
        duration_minutes=10,
        noise_events_per_minute=20,
        include_lookalike=False,
    )
    source_types = {log.source_type for log in shift.logs}

    assert {
        "windows_security",
        "sysmon",
        "dns",
        "proxy",
        "firewall",
        "edr",
        "email_gateway",
    } <= source_types
    windows_codes = {
        str(log.event_data["event_code"])
        for log in shift.logs
        if log.source_type == "windows_security"
    }
    sysmon_codes = {
        str(log.event_data["event_code"])
        for log in shift.logs
        if log.source_type == "sysmon"
    }

    assert {"4624", "4625", "4688", "4672"} <= windows_codes
    assert {"1", "3", "7", "11", "13"} <= sysmon_codes


def test_lookalike_alert_has_separate_false_positive_ground_truth() -> None:
    shift = generate_shift(
        seed=13,
        template=AttackTemplate.RANSOMWARE_PRECURSOR,
        noise_events_per_minute=0,
    )
    verdicts = dict(shift.ground_truth.expected_verdicts)
    lookalike = next(alert for alert in shift.alerts if alert.chain_id is None)

    assert verdicts[lookalike.id] == "false_positive"
    assert lookalike.details["host"] != ""


def test_generated_timestamps_are_sorted_and_within_shift_bounds() -> None:
    start = datetime(2026, 10, 10, 12, 30, tzinfo=UTC)
    shift = generate_shift(
        seed=7,
        template=AttackTemplate.PHISHING_MACRO,
        duration_minutes=5,
        noise_events_per_minute=2,
        start_time=start,
    )

    timestamps = [log.occurred_at for log in shift.logs]

    assert timestamps == sorted(timestamps)
    assert all(start <= timestamp < start.replace(minute=35) for timestamp in timestamps)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"duration_minutes": 0}, "duration_minutes must be between"),
        ({"noise_events_per_minute": -1}, "noise_events_per_minute must be zero"),
        ({"duration_minutes": 480, "noise_events_per_minute": 105}, "limited to"),
    ],
)
def test_generation_rejects_invalid_size_parameters(kwargs: dict[str, int], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        generate_shift(seed=1, template=AttackTemplate.PHISHING_MACRO, **kwargs)


def test_generation_requires_timezone_aware_start_time() -> None:
    with pytest.raises(ValueError, match="start_time must include a timezone"):
        generate_shift(
            seed=1,
            template=AttackTemplate.PHISHING_MACRO,
            start_time=datetime(2026, 1, 1),
        )
