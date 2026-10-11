import pytest

from app.query_engine import QuerySyntaxError, parse_query
from app.query_engine.ast import (
    BinaryExpression,
    DedupCommand,
    EvalCommand,
    HeadCommand,
    SortCommand,
    StatsCommand,
    TableCommand,
    TimeRange,
    WhereCommand,
)


def test_parser_builds_filter_and_pipeline_ast() -> None:
    query = parse_query(
        "index=windows event_id=4625 earliest=-15m latest=now "
        "| stats count by src_ip | where count > 10 | sort -count | head 5"
    )

    assert isinstance(query.search.condition, BinaryExpression)
    assert query.search.time_range == TimeRange(earliest="-15m", latest="now")
    assert isinstance(query.pipeline[0], StatsCommand)
    assert isinstance(query.pipeline[1], WhereCommand)
    assert isinstance(query.pipeline[2], SortCommand)
    assert isinstance(query.pipeline[3], HeadCommand)


def test_parser_accepts_boolean_groups_and_wildcards() -> None:
    query = parse_query(
        'search (host=WS-* OR host=FS-*) AND severity!="informational"'
    )

    assert isinstance(query.search.condition, BinaryExpression)
    assert query.pipeline == ()


def test_parser_accepts_eval_dedup_and_table() -> None:
    query = parse_query(
        "index=proxy | eval kib=bytes_out/1024, host_lower=lower(host) "
        "| dedup src_ip | table host_lower,kib"
    )

    assert isinstance(query.pipeline[0], EvalCommand)
    assert isinstance(query.pipeline[1], DedupCommand)
    assert isinstance(query.pipeline[2], TableCommand)


def test_parser_accepts_unquoted_ipv4_filter_values() -> None:
    query = parse_query("src_ip=198.51.100.12")

    assert isinstance(query.search.condition, BinaryExpression)


@pytest.mark.parametrize(
    ("query", "message"),
    [
        ("", "Query cannot be empty"),
        ("index= | head 2", "Expected a field or value"),
        ("index=windows |", "Query cannot end with a pipe"),
        ("index=windows | explode", "Unsupported pipeline command"),
        ("index=windows | stats avg by host", "avg requires a field"),
        ("index=windows | head 1.5", "head row count must be an integer"),
        ("index=windows | table", "table requires at least one field"),
        ("x" * 10_001, "character limit"),
    ],
)
def test_parser_reports_clear_syntax_errors(query: str, message: str) -> None:
    with pytest.raises(QuerySyntaxError, match=message):
        parse_query(query)
