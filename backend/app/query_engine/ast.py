from __future__ import annotations

from dataclasses import dataclass
from typing import TypeAlias


@dataclass(frozen=True, slots=True)
class Literal:
    value: object


@dataclass(frozen=True, slots=True)
class FieldReference:
    name: str


@dataclass(frozen=True, slots=True)
class UnaryExpression:
    operator: str
    operand: Expression


@dataclass(frozen=True, slots=True)
class BinaryExpression:
    operator: str
    left: Expression
    right: Expression


@dataclass(frozen=True, slots=True)
class FunctionCall:
    name: str
    arguments: tuple[Expression, ...]


Expression: TypeAlias = Literal | FieldReference | UnaryExpression | BinaryExpression | FunctionCall


@dataclass(frozen=True, slots=True)
class TimeRange:
    earliest: str | None = None
    latest: str | None = None


@dataclass(frozen=True, slots=True)
class SearchCommand:
    condition: Expression | None = None
    time_range: TimeRange = TimeRange()


@dataclass(frozen=True, slots=True)
class WhereCommand:
    condition: Expression


@dataclass(frozen=True, slots=True)
class EvalAssignment:
    field: str
    expression: Expression


@dataclass(frozen=True, slots=True)
class EvalCommand:
    assignments: tuple[EvalAssignment, ...]


@dataclass(frozen=True, slots=True)
class Aggregation:
    function: str
    field: str | None = None
    alias: str | None = None

    @property
    def output_field(self) -> str:
        if self.alias is not None:
            return self.alias
        if self.field is None:
            return self.function
        return f"{self.function}_{self.field}"


@dataclass(frozen=True, slots=True)
class StatsCommand:
    aggregations: tuple[Aggregation, ...]
    group_by: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DedupCommand:
    fields: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SortKey:
    field: str
    descending: bool = False


@dataclass(frozen=True, slots=True)
class SortCommand:
    keys: tuple[SortKey, ...]


@dataclass(frozen=True, slots=True)
class HeadCommand:
    count: int


@dataclass(frozen=True, slots=True)
class TableCommand:
    fields: tuple[str, ...]


PipelineCommand: TypeAlias = (
    WhereCommand
    | EvalCommand
    | StatsCommand
    | DedupCommand
    | SortCommand
    | HeadCommand
    | TableCommand
)


@dataclass(frozen=True, slots=True)
class Query:
    search: SearchCommand
    pipeline: tuple[PipelineCommand, ...]
