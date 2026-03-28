from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class KeywordExpr:
    """Case-insensitive partial name match, or exact quoted path lookup."""
    keyword: str
    exact: bool  # True if the keyword was a quoted path like "/path/to/elem"


@dataclass
class HasAttrExpr:
    """@attr — element has the attribute (any value)."""
    attr_name: str


@dataclass
class AttrEqualsExpr:
    """@attr=value or @attr="exact" — attribute equals/contains."""
    attr_name: str
    value: str
    exact: bool  # True if value was quoted → exact match; False → case-insensitive contains


@dataclass
class AttrNotEqualsExpr:
    """@attr!=value — attribute does not equal/contain value."""
    attr_name: str
    value: str
    exact: bool


@dataclass
class AttrGtExpr:
    """@attr>number — numeric greater-than comparison."""
    attr_name: str
    value: float


@dataclass
class AttrLtExpr:
    """@attr<number — numeric less-than comparison."""
    attr_name: str
    value: float


@dataclass
class AttrRegexExpr:
    """@attr=~"regex" — regex partial match against attribute value."""
    attr_name: str
    pattern: str


@dataclass
class AndExpr:
    """expr1 AND expr2 — sequential filter: apply right to result of left."""
    left: Expression
    right: Expression


@dataclass
class OrExpr:
    """expr1 OR expr2 — union: evaluate both on original model, combine results."""
    left: Expression
    right: Expression


@dataclass
class NotExpr:
    """NOT expr — complement: subtract inner result from current model."""
    inner: Expression


@dataclass
class ParenExpr:
    """(expr) — grouping, controls evaluation order."""
    inner: Expression


@dataclass
class DepSearchExpr:
    """FROM --> TO or FROM -- TO — direct dependency search.

    from_expr=None means wildcard (any element as source).
    to_expr=None means wildcard (any element as target).
    dep_type is shorthand for dep_attr_value when dep_attr_name='type'.
    """
    from_expr: Optional[Expression]  # None = wildcard *
    to_expr: Optional[Expression]    # None = wildcard *
    directed: bool                   # True for -->, False for --
    dep_type: Optional[str] = None   # shorthand: -deptype->
    dep_attr_name: Optional[str] = None   # -@attr-> attribute filter on the edge
    dep_attr_value: Optional[str] = None  # -@attr=value-> value filter on the edge


@dataclass
class ChainSearchExpr:
    """FROM ---> TO — find all directed multi-hop chains (transitive paths).

    DFS traversal with cycle detection and max depth limit.
    """
    from_expr: Optional[Expression]  # None = wildcard *
    to_expr: Optional[Expression]    # None = wildcard *
    dep_type: Optional[str] = None
    dep_attr_name: Optional[str] = None
    dep_attr_value: Optional[str] = None


@dataclass
class ShortestPathExpr:
    """FROM --- TO — find shortest undirected path between two elements.

    BFS ignoring edge direction.
    """
    from_expr: Optional[Expression]  # None = wildcard *
    to_expr: Optional[Expression]    # None = wildcard *


# Union type for all expression nodes — used as type hints throughout.
Expression = (
    KeywordExpr | HasAttrExpr | AttrEqualsExpr | AttrNotEqualsExpr | AttrGtExpr | AttrLtExpr
    | AttrRegexExpr | AndExpr | OrExpr | NotExpr | ParenExpr | DepSearchExpr
    | ChainSearchExpr | ShortestPathExpr
)
