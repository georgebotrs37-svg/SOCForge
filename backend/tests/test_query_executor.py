from datetime import UTC, datetime, timedelta

import pytest

from app.generators import AttackTemplate, generate_shift
from app.query_engine import QueryExecutionError, execute_query


def sample_logs() -> list[dict[str, object]]:
    start = datetime(2026, 10, 10, 12, 0, tzinfo=UTC)
    return [
        {
            "index": "windows",
            "event_id": 4625,
            "src_ip": "198.51.100.12",
            "host": "WS-011",
            "occurred_at": start,
            "bytes_out": 1024,
        },
        {
            "index": "windows",
            "event_id": "4625",
            "src_ip": "198.51.100.12",
            "host": "WS-011",
            "occurred_at": start + timedelta(minutes=2),
            "bytes_out": 3072,
        },
        {
            "index": "windows",
            "event_id": 4624,
            "src_ip": "198.51.100.18",
            "host": "WS-018",
            "occurred_at": start + timedelta(minutes=5),
            "bytes_out": 512,
        },
        {
            "index": "sysmon",
            "event_id": 1,
            "src_ip": "10.20.1.10",
            "host": "FS-01",
            "occurred_at": start + timedelta(minutes=8),
            "bytes_out": 5120,
        },
    ]


def test_filters_wildcards_and_grouped_stats() -> None:
    result = execute_query(
        "index=windows event_id=4625 | stats count by src_ip "
        "| where count > 1 | sort -count",
        sample_logs(),
    )

    assert result == [{"src_ip": "198.51.100.12", "count": 2}]


def test_search_supports_bare_ipv4_and_wildcard_filters() -> None:
    exact = execute_query("src_ip=198.51.100.12", sample_logs())
    wildcard = execute_query("host=WS-* event_id=4625", sample_logs())

    assert len(exact) == 2
    assert len(wildcard) == 2


def test_boolean_filters_support_parentheses_and_precedence() -> None:
    result = execute_query(
        "(host=WS-* OR host=FS-*) AND event_id!=4624",
        sample_logs(),
    )

    assert len(result) == 3
    assert all(row["event_id"] != 4624 for row in result)


def test_stats_supports_common_aggregations_and_aliases() -> None:
    result = execute_query(
        "index=windows | stats count, sum(bytes_out) as total, "
        "avg(bytes_out) as mean, min(bytes_out) as low, "
        "max(bytes_out) as high, dc(src_ip) as unique_sources by index",
        sample_logs(),
    )

    assert result == [
        {
            "index": "windows",
            "count": 3,
            "total": 4608,
            "mean": 1536.0,
            "low": 512,
            "high": 3072,
            "unique_sources": 2,
        }
    ]


def test_relative_time_range_and_latest_boundary() -> None:
    now = datetime(2026, 10, 10, 12, 10, tzinfo=UTC)
    result = execute_query(
        "index=windows earliest=-5m latest=now | table host,event_id",
        sample_logs(),
        now=now,
    )

    assert result == [
        {"host": "WS-018", "event_id": 4624},
    ]


def test_eval_arithmetic_and_string_functions() -> None:
    result = execute_query(
        "index=windows | eval kib=bytes_out/1024, normalized=lower(host) "
        "| where kib >= 1 | sort -kib | table normalized,kib",
        sample_logs(),
    )

    assert result == [
        {"normalized": "ws-011", "kib": 3.0},
        {"normalized": "ws-011", "kib": 1.0},
    ]


def test_dedup_sort_and_head_keep_first_matching_row() -> None:
    result = execute_query(
        "index=windows | dedup src_ip | sort -bytes_out | head 1",
        sample_logs(),
    )

    assert len(result) == 1
    assert result[0]["host"] == "WS-011"


def test_search_can_use_generated_log_objects_directly() -> None:
    shift = generate_shift(
        seed=11,
        template=AttackTemplate.BRUTE_FORCE,
        noise_events_per_minute=0,
        include_lookalike=False,
    )

    result = execute_query("index=windows event_id=4625 | stats count", shift.logs)

    assert result == [{"count": 6}]


def test_query_errors_on_bad_time_and_division_by_zero() -> None:
    with pytest.raises(QueryExecutionError, match="Invalid time value"):
        execute_query("earliest=yesterday-ish", sample_logs())
    with pytest.raises(QueryExecutionError, match="Division by zero"):
        execute_query("index=windows | eval invalid=bytes_out/0", sample_logs())


def test_query_input_limit_can_be_configured_for_soc_workload() -> None:
    with pytest.raises(QueryExecutionError, match="1-row limit"):
        execute_query("index=windows", sample_logs(), max_input_rows=1)


def test_time_range_rejects_earliest_after_latest() -> None:
    with pytest.raises(QueryExecutionError, match="earliest cannot be later than latest"):
        execute_query(
            'earliest="2026-10-10T12:10:00Z" latest="2026-10-10T12:00:00Z"',
            [],
        )
