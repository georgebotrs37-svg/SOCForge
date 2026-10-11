import fnmatch
import json
import math
import re
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from app.core.config import get_settings
from app.query_engine.ast import (
    BinaryExpression,
    DedupCommand,
    EvalCommand,
    Expression,
    FieldReference,
    FunctionCall,
    HeadCommand,
    Literal,
    SearchCommand,
    SortCommand,
    StatsCommand,
    TableCommand,
    UnaryExpression,
    WhereCommand,
)
from app.query_engine.lexer import QuerySyntaxError
from app.query_engine.parser import parse_query

MAX_INPUT_ROWS = 100_000
_RELATIVE_TIME = re.compile(r"^([+-])(\d+(?:\.\d+)?)([smhdw])$", re.IGNORECASE)
_TIME_UNITS = {
    "s": 1,
    "m": 60,
    "h": 3600,
    "d": 86400,
    "w": 604800,
}


class QueryExecutionError(ValueError):
    """A valid query cannot be evaluated against the supplied events."""


class LogRecordLike(Protocol):
    id: str
    index_name: str
    source_type: str
    occurred_at: datetime
    host: str | None
    username: str | None
    src_ip: str | None
    dst_ip: str | None
    event_data: Mapping[str, Any]


QueryRecord = Mapping[str, Any] | LogRecordLike
QueryResult = list[dict[str, Any]]


def _to_row(record: QueryRecord) -> dict[str, Any]:
    if isinstance(record, Mapping):
        source: dict[str, Any] = dict(record)
    else:
        source = {
            field: getattr(record, field)
            for field in (
                "id",
                "index_name",
                "source_type",
                "occurred_at",
                "host",
                "username",
                "src_ip",
                "dst_ip",
                "event_data",
            )
            if hasattr(record, field)
        }

    nested = source.get("event_data")
    flattened = dict(nested) if isinstance(nested, Mapping) else {}
    flattened.update(source)
    source = flattened
    if "index" not in source and "index_name" in source:
        source["index"] = source["index_name"]
    if "event_id" not in source:
        event_id = source.get("event_code")
        if event_id is not None:
            source["event_id"] = event_id
    event_time = source.get("_time", source.get("occurred_at", source.get("timestamp")))
    if event_time is not None:
        source.setdefault("_time", event_time)
        source.setdefault("timestamp", event_time)
    return source


def _resolve_time(value: str, now: datetime) -> datetime:
    if value.casefold() == "now":
        return now
    relative = _RELATIVE_TIME.fullmatch(value)
    if relative is not None:
        sign, amount_text, unit = relative.groups()
        seconds = float(amount_text) * _TIME_UNITS[unit.casefold()]
        delta = timedelta(seconds=seconds)
        return now - delta if sign == "-" else now + delta
    try:
        resolved = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise QueryExecutionError(
            f"Invalid time value {value!r}; use now, a relative duration, or ISO 8601"
        ) from error
    if resolved.tzinfo is None or resolved.utcoffset() is None:
        resolved = resolved.replace(tzinfo=UTC)
    return resolved.astimezone(UTC)


def _resolve_time_range(
    search: SearchCommand,
    now: datetime,
) -> tuple[datetime | None, datetime | None]:
    if search.time_range.earliest is None and search.time_range.latest is None:
        return None, None
    earliest = (
        _resolve_time(search.time_range.earliest, now)
        if search.time_range.earliest is not None
        else None
    )
    latest = (
        _resolve_time(search.time_range.latest, now)
        if search.time_range.latest is not None
        else None
    )
    if earliest is not None and latest is not None and earliest > latest:
        raise QueryExecutionError("earliest cannot be later than latest")
    return earliest, latest


def _time_in_range(
    row: Mapping[str, Any],
    earliest: datetime | None,
    latest: datetime | None,
) -> bool:
    if earliest is None and latest is None:
        return True
    value = next(
        (
            row[field]
            for field in ("_time", "timestamp", "occurred_at")
            if row.get(field) is not None
        ),
        None,
    )
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as error:
            raise QueryExecutionError(f"Invalid event timestamp {value!r}") from error
    if not isinstance(value, datetime):
        return False
    if value.tzinfo is None or value.utcoffset() is None:
        value = value.replace(tzinfo=UTC)
    value = value.astimezone(UTC)
    return (earliest is None or value >= earliest) and (latest is None or value <= latest)


def _numeric(value: Any) -> int | float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _freeze(value: Any) -> object:
    if isinstance(value, Mapping):
        return json.dumps(value, sort_keys=True, default=str)
    if isinstance(value, (list, tuple, set)):
        return json.dumps(list(value), sort_keys=True, default=str)
    try:
        hash(value)
    except TypeError:
        return repr(value)
    return value


def _compare_values(left: Any, right: Any) -> int:
    if left is None or right is None:
        return (left is not None) - (right is not None)
    left_number, right_number = _numeric(left), _numeric(right)
    if left_number is not None and right_number is not None:
        return (left_number > right_number) - (left_number < right_number)
    if isinstance(left, datetime) and isinstance(right, datetime):
        if left.tzinfo is None or left.utcoffset() is None:
            left = left.replace(tzinfo=UTC)
        if right.tzinfo is None or right.utcoffset() is None:
            right = right.replace(tzinfo=UTC)
        left = left.astimezone(UTC)
        right = right.astimezone(UTC)
        return int(left > right) - int(left < right)
    left_text, right_text = str(left).casefold(), str(right).casefold()
    return (left_text > right_text) - (left_text < right_text)


def _equal_values(left: Any, right: Any) -> bool:
    if isinstance(right, str) and any(character in right for character in "*?"):
        return fnmatch.fnmatchcase(str(left).casefold(), right.casefold())
    if left is None or right is None:
        return left is right
    left_number, right_number = _numeric(left), _numeric(right)
    if left_number is not None and right_number is not None:
        return left_number == right_number
    if isinstance(left, str) and isinstance(right, str):
        return left.casefold() == right.casefold()
    return bool(left == right)


def _evaluate(expression: Expression, row: Mapping[str, Any]) -> Any:
    if isinstance(expression, Literal):
        return expression.value
    if isinstance(expression, FieldReference):
        return row.get(expression.name)
    if isinstance(expression, UnaryExpression):
        value = _evaluate(expression.operand, row)
        if expression.operator == "not":
            return not bool(value)
        number = _numeric(value)
        if number is None:
            raise QueryExecutionError(f"Unary minus requires a number, got {value!r}")
        return -number
    if isinstance(expression, FunctionCall):
        arguments = [_evaluate(argument, row) for argument in expression.arguments]
        return _evaluate_function(expression.name, arguments)
    if isinstance(expression, BinaryExpression):
        operator = expression.operator.casefold()
        left = _evaluate(expression.left, row)
        if operator == "and":
            return bool(left) and bool(_evaluate(expression.right, row))
        if operator == "or":
            return bool(left) or bool(_evaluate(expression.right, row))
        right = _evaluate(expression.right, row)
        if operator in {"=", "=="}:
            return _equal_values(left, right)
        if operator == "!=":
            return not _equal_values(left, right)
        if left is None or right is None:
            return False
        comparison = _compare_values(left, right)
        if operator == ">":
            return comparison > 0
        if operator == ">=":
            return comparison >= 0
        if operator == "<":
            return comparison < 0
        if operator == "<=":
            return comparison <= 0
        if operator == "+" and isinstance(left, str) and isinstance(right, str):
            return left + right
        left_number, right_number = _numeric(left), _numeric(right)
        if left_number is None or right_number is None:
            raise QueryExecutionError(
                f"Operator {expression.operator!r} requires numeric operands"
            )
        if operator == "+":
            return left_number + right_number
        if operator == "-":
            return left_number - right_number
        if operator == "*":
            return left_number * right_number
        if operator == "/":
            if right_number == 0:
                raise QueryExecutionError("Division by zero in eval expression")
            return left_number / right_number
        if operator == "%":
            if right_number == 0:
                raise QueryExecutionError("Modulo by zero in eval expression")
            return left_number % right_number
    raise QueryExecutionError(f"Unsupported expression: {expression!r}")


def _evaluate_function(name: str, arguments: list[Any]) -> Any:
    if name == "coalesce":
        if not arguments:
            raise QueryExecutionError("coalesce requires at least one argument")
        return next((argument for argument in arguments if argument is not None), None)
    if name in {"lower", "upper", "abs", "round", "tostring"} and len(arguments) != (
        2 if name == "round" else 1
    ):
        raise QueryExecutionError(f"{name} received an invalid number of arguments")
    if name == "lower":
        return str(arguments[0]).lower() if arguments[0] is not None else None
    if name == "upper":
        return str(arguments[0]).upper() if arguments[0] is not None else None
    if name == "tostring":
        return str(arguments[0]) if arguments[0] is not None else None
    if name == "abs":
        number = _numeric(arguments[0])
        if number is None:
            raise QueryExecutionError("abs requires a numeric argument")
        return abs(number)
    if name == "round":
        number = _numeric(arguments[0])
        digits = _numeric(arguments[1])
        if (
            number is None
            or digits is None
            or not float(digits).is_integer()
            or not math.isfinite(float(number))
            or not math.isfinite(float(digits))
        ):
            raise QueryExecutionError("round requires a number and a finite precision")
        return round(number, int(digits))
    raise QueryExecutionError(f"Unsupported eval function {name!r}")


def _apply_stats(rows: QueryResult, command: StatsCommand) -> QueryResult:
    groups: dict[tuple[object, ...], list[dict[str, Any]]] = {}
    for row in rows:
        key = tuple(_freeze(row.get(field)) for field in command.group_by)
        groups.setdefault(key, []).append(row)
    if not command.group_by and not groups:
        groups[()] = []

    result: QueryResult = []
    for group_key, members in groups.items():
        output = {
            field: members[0].get(field) if members else group_value
            for field, group_value in zip(command.group_by, group_key, strict=True)
        }
        for aggregation in command.aggregations:
            values = (
                [row.get(aggregation.field) for row in members]
                if aggregation.field is not None
                else []
            )
            present = [value for value in values if value is not None]
            function = aggregation.function
            if function == "count":
                value: Any = len(members) if aggregation.field is None else len(present)
            elif function == "dc":
                value = len({_freeze(item) for item in present})
            elif function in {"sum", "avg"}:
                numeric = [_numeric(item) for item in present]
                numeric_values = [item for item in numeric if item is not None]
                if len(numeric_values) != len(present):
                    raise QueryExecutionError(
                        f"{function} received a non-numeric value in {aggregation.field!r}"
                    )
                if not numeric_values:
                    value = None
                elif function == "sum":
                    value = sum(numeric_values)
                else:
                    value = sum(numeric_values) / len(numeric_values)
            elif function in {"min", "max"}:
                if not present:
                    value = None
                else:
                    value = sorted(present, key=lambda item: _Comparable(item))[0]
                    if function == "max":
                        value = sorted(present, key=lambda item: _Comparable(item))[-1]
            else:
                raise QueryExecutionError(f"Unsupported stats aggregation {function!r}")
            output[aggregation.output_field] = value
        result.append(output)
    return result


class _Comparable:
    def __init__(self, value: Any) -> None:
        self.value = value

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, _Comparable):
            return NotImplemented
        return _compare_values(self.value, other.value) < 0


def _sort_rows(rows: QueryResult, command: SortCommand) -> QueryResult:
    result = rows.copy()
    for key in reversed(command.keys):
        def sort_key(row: dict[str, Any], field: str = key.field) -> _Comparable:
            return _Comparable(row.get(field))

        result.sort(key=sort_key, reverse=key.descending)
    return result


def _apply_pipeline(rows: QueryResult, command: object) -> QueryResult:
    if isinstance(command, WhereCommand):
        return [row for row in rows if bool(_evaluate(command.condition, row))]
    if isinstance(command, EvalCommand):
        for row in rows:
            for assignment in command.assignments:
                row[assignment.field] = _evaluate(assignment.expression, row)
        return rows
    if isinstance(command, StatsCommand):
        return _apply_stats(rows, command)
    if isinstance(command, DedupCommand):
        unique: list[dict[str, Any]] = []
        seen: set[tuple[object, ...]] = set()
        for row in rows:
            key = tuple(_freeze(row.get(field)) for field in command.fields)
            if key not in seen:
                seen.add(key)
                unique.append(row)
        return unique
    if isinstance(command, SortCommand):
        return _sort_rows(rows, command)
    if isinstance(command, HeadCommand):
        return rows[: command.count]
    if isinstance(command, TableCommand):
        return [{field: row.get(field) for field in command.fields} for row in rows]
    raise QueryExecutionError(f"Unsupported pipeline command {command!r}")


def execute_query(
    query: str,
    records: Iterable[QueryRecord],
    *,
    now: datetime | None = None,
    max_input_rows: int | None = None,
) -> QueryResult:
    """Parse and execute a query against a bounded collection of log records."""
    input_limit = get_settings().max_query_rows if max_input_rows is None else max_input_rows
    if input_limit < 1:
        raise QueryExecutionError("max_input_rows must be positive")
    reference_time = now or datetime.now(UTC)
    if reference_time.tzinfo is None or reference_time.utcoffset() is None:
        raise QueryExecutionError("now must include a timezone")
    reference_time = reference_time.astimezone(UTC)
    try:
        parsed = parse_query(query)
        earliest, latest = _resolve_time_range(parsed.search, reference_time)
    except QuerySyntaxError:
        raise

    rows: QueryResult = []
    input_count = 0
    for record in records:
        input_count += 1
        if input_count > input_limit:
            raise QueryExecutionError(f"Query input exceeds the {input_limit}-row limit")
        row = _to_row(record)
        if _time_in_range(row, earliest, latest) and (
            parsed.search.condition is None
            or bool(_evaluate(parsed.search.condition, row))
        ):
            rows.append(row)

    for command in parsed.pipeline:
        rows = _apply_pipeline(rows, command)
    return rows
