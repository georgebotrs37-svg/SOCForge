import re
from dataclasses import dataclass


class QuerySyntaxError(ValueError):
    """A query cannot be tokenized or parsed."""


@dataclass(frozen=True, slots=True)
class Token:
    kind: str
    value: str
    position: int


_TOKEN_PATTERN = re.compile(
    r"""
    (?P<SPACE>\s+)
    |(?P<STRING>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')
    |(?P<RELATIVE_TIME>-\d+(?:\.\d+)?[smhdw])
    |(?P<OP>>=|<=|!=|==|=|>|<|\+|-|\*|/|%)
    |(?P<PIPE>\|)
    |(?P<LPAREN>\()
    |(?P<RPAREN>\))
    |(?P<COMMA>,)
    |(?P<IPV4>\d{1,3}(?:\.\d{1,3}){3})
    |(?P<NUMBER>\d+(?:\.\d+)?)
    |(?P<WORD>[A-Za-z_][A-Za-z0-9_.$:?*~-]*)
    |(?P<INVALID>.)
    """,
    re.IGNORECASE | re.VERBOSE,
)


def tokenize(query: str) -> list[Token]:
    tokens: list[Token] = []
    for match in _TOKEN_PATTERN.finditer(query):
        kind = match.lastgroup
        value = match.group()
        if kind == "SPACE":
            continue
        if kind == "INVALID":
            raise QuerySyntaxError(f"Unexpected character {value!r} at position {match.start()}")
        tokens.append(Token(kind or "", value, match.start()))
    return tokens
