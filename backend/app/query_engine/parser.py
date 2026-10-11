import ast as python_ast
from collections.abc import Sequence

from app.query_engine.ast import (
    Aggregation,
    BinaryExpression,
    DedupCommand,
    EvalAssignment,
    EvalCommand,
    Expression,
    FieldReference,
    FunctionCall,
    HeadCommand,
    Literal,
    PipelineCommand,
    Query,
    SearchCommand,
    SortCommand,
    SortKey,
    StatsCommand,
    TableCommand,
    TimeRange,
    UnaryExpression,
    WhereCommand,
)
from app.query_engine.lexer import QuerySyntaxError, Token, tokenize

_COMPARISONS = {"=", "==", "!=", ">", "<", ">=", "<="}
_AGGREGATIONS = {"count", "sum", "avg", "min", "max", "dc"}
_ARITHMETIC_PRECEDENCE = {"+": 1, "-": 1, "*": 2, "/": 2, "%": 2}
_BOOLEAN_PRECEDENCE = {"or": 1, "and": 2}
MAX_QUERY_LENGTH = 10_000
MAX_PIPELINE_COMMANDS = 32


class _StageParser:
    def __init__(self, tokens: Sequence[Token]) -> None:
        self.tokens = tokens
        self.position = 0

    def peek(self, offset: int = 0) -> Token | None:
        index = self.position + offset
        return self.tokens[index] if index < len(self.tokens) else None

    def consume(self) -> Token:
        token = self.peek()
        if token is None:
            raise QuerySyntaxError("Unexpected end of query")
        self.position += 1
        return token

    def accept_value(self, value: str) -> bool:
        token = self.peek()
        if token is not None and token.value.casefold() == value.casefold():
            self.position += 1
            return True
        return False

    def expect_kind(self, kind: str, expected: str | None = None) -> Token:
        token = self.peek()
        if token is None or token.kind != kind:
            location = f" at position {token.position}" if token else " at end of query"
            raise QuerySyntaxError(f"Expected {expected or kind.lower()}{location}")
        return self.consume()

    def expect_word(self, expected: str) -> Token:
        token = self.peek()
        if token is None or token.kind != "WORD" or token.value.casefold() != expected.casefold():
            location = f" at position {token.position}" if token else " at end of query"
            raise QuerySyntaxError(f"Expected {expected!r}{location}")
        return self.consume()

    def parse_boolean(self, minimum_precedence: int = 1, *, implicit_and: bool) -> Expression:
        left = self._parse_boolean_atom(implicit_and=implicit_and)
        while True:
            token = self.peek()
            if token is None:
                break

            operator = token.value.casefold() if token.kind == "WORD" else ""
            if operator in _BOOLEAN_PRECEDENCE:
                precedence = _BOOLEAN_PRECEDENCE[operator]
                if precedence < minimum_precedence:
                    break
                self.consume()
            elif implicit_and and self._starts_boolean_atom(token):
                operator = "and"
                precedence = _BOOLEAN_PRECEDENCE[operator]
            else:
                break

            right = self.parse_boolean(precedence + 1, implicit_and=implicit_and)
            left = BinaryExpression(operator, left, right)
        return left

    def _starts_boolean_atom(self, token: Token) -> bool:
        if token.kind in {"LPAREN", "STRING", "NUMBER", "RELATIVE_TIME"}:
            return True
        return token.kind == "WORD" and token.value.casefold() not in {
            "and",
            "or",
            "by",
            "as",
        }

    def _parse_boolean_atom(self, *, implicit_and: bool) -> Expression:
        if self.accept_value("not"):
            return UnaryExpression(
                "not",
                self._parse_boolean_atom(implicit_and=implicit_and),
            )
        token = self.peek()
        if token is not None and token.kind == "LPAREN":
            self.consume()
            expression = self.parse_boolean(implicit_and=implicit_and)
            self.expect_kind("RPAREN", "')'")
            return expression

        left = self._parse_condition_operand(right_side=False)
        operator = self.peek()
        if operator is None or operator.kind != "OP" or operator.value not in _COMPARISONS:
            location = f" at position {operator.position}" if operator else " at end of query"
            raise QuerySyntaxError(f"Expected a comparison operator{location}")
        self.consume()
        right = self._parse_condition_operand(right_side=True)
        return BinaryExpression(operator.value, left, right)

    def _parse_condition_operand(self, *, right_side: bool) -> Literal | FieldReference:
        token = self.peek()
        if token is None:
            raise QuerySyntaxError("Expected a field or value at end of query")
        self.consume()
        if token.kind == "STRING":
            try:
                value = python_ast.literal_eval(token.value)
            except (SyntaxError, ValueError) as error:
                raise QuerySyntaxError(f"Invalid string at position {token.position}") from error
            if not isinstance(value, str):
                raise QuerySyntaxError(f"Expected a string at position {token.position}")
            return Literal(value)
        if token.kind == "NUMBER":
            return Literal(float(token.value) if "." in token.value else int(token.value))
        if token.kind not in {"WORD", "RELATIVE_TIME", "IPV4"}:
            raise QuerySyntaxError(f"Expected a field or value at position {token.position}")

        value = token.value
        lowered = value.casefold()
        if lowered in {"true", "false", "null"}:
            return Literal({"true": True, "false": False, "null": None}[lowered])
        if right_side or token.kind == "IPV4":
            return Literal(value)
        return FieldReference(value)

    def parse_value_expression(self, minimum_precedence: int = 0) -> Expression:
        left = self._parse_value_primary()
        while True:
            token = self.peek()
            if token is None or token.kind != "OP":
                break
            precedence = _ARITHMETIC_PRECEDENCE.get(token.value)
            if precedence is None or precedence < minimum_precedence:
                break
            operator = self.consume().value
            right = self.parse_value_expression(precedence + 1)
            left = BinaryExpression(operator, left, right)
        return left

    def _parse_value_primary(self) -> Expression:
        token = self.consume()
        if token.kind in {"NUMBER", "IPV4"}:
            if token.kind == "IPV4":
                return Literal(token.value)
            return Literal(float(token.value) if "." in token.value else int(token.value))
        if token.kind == "STRING":
            try:
                value = python_ast.literal_eval(token.value)
            except (SyntaxError, ValueError) as error:
                raise QuerySyntaxError(f"Invalid string at position {token.position}") from error
            if not isinstance(value, str):
                raise QuerySyntaxError(f"Expected a string at position {token.position}")
            return Literal(value)
        if token.kind == "OP" and token.value == "-":
            return UnaryExpression("-", self.parse_value_expression(3))
        if token.kind == "LPAREN":
            expression = self.parse_value_expression()
            self.expect_kind("RPAREN", "')'")
            return expression
        if token.kind != "WORD":
            raise QuerySyntaxError(f"Expected a value at position {token.position}")

        lowered = token.value.casefold()
        if lowered in {"true", "false", "null"}:
            return Literal({"true": True, "false": False, "null": None}[lowered])
        next_token = self.peek()
        if next_token is not None and next_token.kind == "LPAREN":
            self.consume()
            arguments: list[Expression] = []
            next_token = self.peek()
            if next_token is not None and next_token.kind != "RPAREN":
                while True:
                    arguments.append(self.parse_value_expression())
                    next_token = self.peek()
                    if next_token is None or next_token.kind != "COMMA":
                        break
                    self.consume()
            self.expect_kind("RPAREN", "')'")
            return FunctionCall(token.value.casefold(), tuple(arguments))
        return FieldReference(token.value)


def _split_stages(tokens: Sequence[Token]) -> list[list[Token]]:
    stages: list[list[Token]] = [[]]
    for token in tokens:
        if token.kind == "PIPE":
            if not stages[-1]:
                raise QuerySyntaxError(f"Empty pipeline stage at position {token.position}")
            stages.append([])
        else:
            stages[-1].append(token)
    if not stages[-1]:
        raise QuerySyntaxError("Query cannot end with a pipe")
    return stages


def _extract_time_range(tokens: Sequence[Token]) -> tuple[list[Token], TimeRange]:
    remaining: list[Token] = []
    values: dict[str, str] = {}
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if (
            token.kind == "WORD"
            and token.value.casefold() in {"earliest", "latest"}
            and index + 2 < len(tokens)
            and tokens[index + 1].kind == "OP"
            and tokens[index + 1].value == "="
        ):
            key = token.value.casefold()
            if key in values:
                raise QuerySyntaxError(f"{key} may only be specified once")
            value_token = tokens[index + 2]
            if value_token.kind not in {"WORD", "STRING", "NUMBER", "RELATIVE_TIME"}:
                raise QuerySyntaxError(f"Expected a {key} value at position {value_token.position}")
            if value_token.kind == "STRING":
                try:
                    parsed_value = python_ast.literal_eval(value_token.value)
                except (SyntaxError, ValueError) as error:
                    raise QuerySyntaxError(
                        f"Invalid {key} value at position {value_token.position}"
                    ) from error
                if not isinstance(parsed_value, str):
                    raise QuerySyntaxError(f"Expected a string for {key}")
                values[key] = parsed_value
            else:
                values[key] = value_token.value
            index += 3
            continue
        remaining.append(token)
        index += 1
    return remaining, TimeRange(values.get("earliest"), values.get("latest"))


def _parse_search(tokens: Sequence[Token]) -> SearchCommand:
    remaining, time_range = _extract_time_range(tokens)
    if remaining and remaining[0].kind == "WORD" and remaining[0].value.casefold() == "search":
        remaining = remaining[1:]
    if not remaining:
        return SearchCommand(time_range=time_range)
    parser = _StageParser(remaining)
    condition = parser.parse_boolean(implicit_and=True)
    token = parser.peek()
    if token is not None:
        raise QuerySyntaxError(f"Unexpected token {token.value!r} at position {token.position}")
    return SearchCommand(condition=condition, time_range=time_range)


def _parse_field_list(parser: _StageParser, command_name: str) -> tuple[str, ...]:
    fields: list[str] = []
    while parser.peek() is not None:
        token = parser.peek()
        if token is not None and token.kind == "COMMA":
            parser.consume()
            continue
        if token is None or token.kind != "WORD":
            raise QuerySyntaxError(
                f"Expected a field name for {command_name} at position "
                f"{token.position if token else 'end of query'}"
            )
        fields.append(parser.consume().value)
    if not fields:
        raise QuerySyntaxError(f"{command_name} requires at least one field")
    return tuple(fields)


def _parse_stats(parser: _StageParser) -> StatsCommand:
    aggregations: list[Aggregation] = []
    group_by: tuple[str, ...] = ()
    while parser.peek() is not None:
        token = parser.peek()
        if token is not None and token.kind == "WORD" and token.value.casefold() == "by":
            parser.consume()
            group_by = _parse_field_list(parser, "stats by")
            break
        if token is not None and token.kind == "COMMA":
            parser.consume()
            continue
        if token is None or token.kind != "WORD" or token.value.casefold() not in _AGGREGATIONS:
            raise QuerySyntaxError(
                f"Expected an aggregation function at position "
                f"{token.position if token else 'end of query'}"
            )
        function = parser.consume().value.casefold()
        field: str | None = None
        next_token = parser.peek()
        if next_token is not None and next_token.kind == "LPAREN":
            parser.consume()
            field_token = parser.expect_kind("WORD", "field name")
            field = field_token.value
            parser.expect_kind("RPAREN", "')'")
        elif function != "count":
            token = parser.peek()
            raise QuerySyntaxError(
                f"{function} requires a field in parentheses at position "
                f"{token.position if token else 'end of query'}"
            )
        alias: str | None = None
        if parser.accept_value("as"):
            alias = parser.expect_kind("WORD", "aggregation alias").value
        aggregations.append(Aggregation(function, field, alias))
    if not aggregations:
        raise QuerySyntaxError("stats requires at least one aggregation")
    return StatsCommand(tuple(aggregations), group_by)


def _parse_pipeline(tokens: Sequence[Token]) -> PipelineCommand:
    command = tokens[0]
    if command.kind != "WORD":
        raise QuerySyntaxError(f"Expected a pipeline command at position {command.position}")
    parser = _StageParser(tokens[1:])
    name = command.value.casefold()

    if name == "where":
        if parser.peek() is None:
            raise QuerySyntaxError("where requires a condition")
        condition = parser.parse_boolean(implicit_and=False)
        token = parser.peek()
        if token is not None:
            raise QuerySyntaxError(f"Unexpected token {token.value!r} at position {token.position}")
        return WhereCommand(condition)
    if name == "eval":
        assignments: list[EvalAssignment] = []
        while parser.peek() is not None:
            field = parser.expect_kind("WORD", "field name").value
            parser.expect_kind("OP", "'='")
            expression = parser.parse_value_expression()
            assignments.append(EvalAssignment(field, expression))
            if parser.peek() is None:
                break
            parser.expect_kind("COMMA", "',' between eval assignments")
        if not assignments:
            raise QuerySyntaxError("eval requires at least one assignment")
        return EvalCommand(tuple(assignments))
    if name == "stats":
        return _parse_stats(parser)
    if name == "dedup":
        return DedupCommand(_parse_field_list(parser, "dedup"))
    if name == "sort":
        keys: list[SortKey] = []
        while parser.peek() is not None:
            token = parser.peek()
            if token is not None and token.kind == "COMMA":
                parser.consume()
                continue
            descending = False
            token = parser.peek()
            if token is not None and token.kind == "OP" and token.value in {"+", "-"}:
                descending = parser.consume().value == "-"
            field = parser.expect_kind("WORD", "sort field").value
            keys.append(SortKey(field, descending))
        if not keys:
            raise QuerySyntaxError("sort requires at least one field")
        return SortCommand(tuple(keys))
    if name == "head":
        count_token = parser.expect_kind("NUMBER", "non-negative row count")
        if "." in count_token.value:
            raise QuerySyntaxError("head row count must be an integer")
        token = parser.peek()
        if token is not None:
            raise QuerySyntaxError(f"Unexpected token {token.value!r} at position {token.position}")
        return HeadCommand(int(count_token.value))
    if name == "table":
        return TableCommand(_parse_field_list(parser, "table"))
    raise QuerySyntaxError(f"Unsupported pipeline command {command.value!r}")


def parse_query(query: str) -> Query:
    if not query.strip():
        raise QuerySyntaxError("Query cannot be empty")
    if len(query) > MAX_QUERY_LENGTH:
        raise QuerySyntaxError(f"Query exceeds the {MAX_QUERY_LENGTH}-character limit")
    tokens = tokenize(query)
    stages = _split_stages(tokens)
    if len(stages) - 1 > MAX_PIPELINE_COMMANDS:
        raise QuerySyntaxError(
            f"Query exceeds the {MAX_PIPELINE_COMMANDS}-command pipeline limit"
        )
    search = _parse_search(stages[0])
    pipeline = tuple(_parse_pipeline(stage) for stage in stages[1:])
    return Query(search, pipeline)
