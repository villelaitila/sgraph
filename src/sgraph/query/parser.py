"""Recursive descent parser for the SGraph Query Language.

Priority order (first match wins):
  1. OR    — tried first so AND binds tighter (standard math precedence)
  2. AND   — sequential filter, binds tighter than OR
  3. Parentheses
  4. Shortest Path  (--- undirected BFS)
  5. Chain Search   (---> all directed multi-hop paths)
  6. Dep Search     (-->, --, and typed variants -type-> etc.)
  7. NOT
  8. Attribute filters (@attr=~"…", @attr=…, @attr!=…, @attr>…, @attr<…, @attr)
  9. Keyword / Exact Path (fallback)

Both OR and AND splitting respect parentheses: the operator must appear
at nesting depth 0 (not inside any parenthesised group).  This allows
expressions like ``(@type=file OR @type=dir) AND @loc>100`` to parse
correctly as AND(Paren(OR(…)), GT(…)).
"""
from __future__ import annotations

import re
from typing import Optional

from sgraph.query.expressions import (
    AndExpr,
    AttrEqualsExpr,
    AttrGtExpr,
    AttrLtExpr,
    AttrNotEqualsExpr,
    AttrRegexExpr,
    ChainSearchExpr,
    DepSearchExpr,
    Expression,
    HasAttrExpr,
    KeywordExpr,
    NotExpr,
    OrExpr,
    ParenExpr,
    ShortestPathExpr,
)


def parse(expression: str) -> Expression:
    """Parse an SGraph Query Language string into an AST.

    Args:
        expression: Raw query string, e.g. ``'@type=file AND @loc>500'``.

    Returns:
        The root AST node representing the full expression.

    Raises:
        ValueError: If the expression cannot be parsed.
    """
    s = expression.strip()
    if not s:
        raise ValueError("Empty query expression")
    return _parse(s)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse(s: str) -> Expression:
    """Core dispatch — tries each rule in priority order."""
    s = s.strip()

    result = (_try_or(s) or _try_and(s) or _try_paren(s)
              or _try_shortest_path(s) or _try_chain_search(s)
              or _try_dep_search(s)
              or _try_not(s) or _try_attr(s) or _try_keyword(s))

    if result is None:
        raise ValueError(f"Cannot parse expression: {s!r}")
    return result


def _find_top_level_operator(s: str, op: str) -> int:
    """Find the index of *op* at parenthesis depth 0, or -1 if not found.

    Scans left-to-right, tracking paren depth and skipping quoted regions.
    Returns the start index of the first match at depth 0.
    """
    depth = 0
    in_quote = False
    quote_char = ''
    i = 0
    while i < len(s):
        ch = s[i]
        if in_quote:
            if ch == quote_char:
                in_quote = False
            i += 1
            continue
        if ch in ('"', "'"):
            in_quote = True
            quote_char = ch
            i += 1
            continue
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        elif depth == 0 and s[i:i + len(op)] == op:
            return i
        i += 1
    return -1


# ---------------------------------------------------------------------------
# 1. OR  (tried first so AND binds tighter — standard precedence)
# ---------------------------------------------------------------------------

def _try_or(s: str) -> Optional[Expression]:
    """Split on first top-level ` OR ` (spaces required)."""
    idx = _find_top_level_operator(s, ' OR ')
    if idx == -1:
        return None
    left_src = s[:idx].strip()
    right_src = s[idx + 4:].strip()
    return OrExpr(left=_parse(left_src), right=_parse(right_src))


# ---------------------------------------------------------------------------
# 2. AND
# ---------------------------------------------------------------------------

def _try_and(s: str) -> Optional[Expression]:
    """Split on first top-level ` AND ` (spaces required)."""
    idx = _find_top_level_operator(s, ' AND ')
    if idx == -1:
        return None
    left_src = s[:idx].strip()
    right_src = s[idx + 5:].strip()
    return AndExpr(left=_parse(left_src), right=_parse(right_src))


# ---------------------------------------------------------------------------
# 3. Parentheses
# ---------------------------------------------------------------------------

def _try_paren(s: str) -> Optional[Expression]:
    """Match (…) wrapping the ENTIRE expression."""
    if not (s.startswith('(') and s.endswith(')')):
        return None
    # Verify the opening paren closes at the very end, not earlier.
    depth = 0
    for i, ch in enumerate(s):
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        if depth == 0 and i < len(s) - 1:
            # Closing paren found before the end — not a simple wrapper
            return None
    inner = s[1:-1].strip()
    return ParenExpr(inner=_parse(inner))


# ---------------------------------------------------------------------------
# 4. Shortest Path  ( --- )
# ---------------------------------------------------------------------------

def _try_shortest_path(s: str) -> Optional[Expression]:
    """Parse ``FROM --- TO`` (undirected shortest path, BFS).

    Must appear at depth 0, surrounded by spaces: `` --- ``.
    Tried before chain search and dep search to avoid ambiguity.
    """
    idx = _find_top_level_operator(s, ' --- ')
    if idx == -1:
        return None
    # Verify this is exactly --- not ---- or --->
    after = idx + 5  # position after ' --- '
    before = idx  # position of ' '
    # Check the character before the operator is not '-' (would be ----)
    if before > 0 and s[before - 1] == '-':
        return None
    # Check the character after is not '-' or '>' (would be ----> or ---->)
    if after < len(s) and s[after] in ('-', '>'):
        return None

    from_src = s[:idx].strip()
    to_src = s[after:].strip()
    return ShortestPathExpr(
        from_expr=_parse_dep_endpoint(from_src),
        to_expr=_parse_dep_endpoint(to_src),
    )


# ---------------------------------------------------------------------------
# 5. Chain Search  ( ---> and --type-> )
# ---------------------------------------------------------------------------

# Matches: " ---> " or " --label-> " (label between the -- and ->)
_CHAIN_PATTERN = re.compile(
    r' ('
    r'--->'                            # plain chain
    r'|--[^-\s>][^>]*->'              # --label->  (label between -- and ->)
    r') '
)


def _try_chain_search(s: str) -> Optional[Expression]:
    """Parse ``FROM ---> TO`` and ``FROM --type-> TO`` (chain search, all paths)."""
    in_quote = False
    quote_char = ''
    depth = 0
    i = 0
    op_match: Optional[re.Match[str]] = None
    while i < len(s):
        ch = s[i]
        if in_quote:
            if ch == quote_char:
                in_quote = False
            i += 1
            continue
        if ch in ('"', "'"):
            in_quote = True
            quote_char = ch
            i += 1
            continue
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        if depth == 0:
            m = _CHAIN_PATTERN.match(s, i)
            if m:
                op_match = m
                break
        i += 1

    if op_match is None:
        return None

    op_text = op_match.group(1)
    from_src = s[:op_match.start()].strip()
    to_src = s[op_match.end():].strip()

    from_expr = _parse_dep_endpoint(from_src)
    to_expr = _parse_dep_endpoint(to_src)

    dep_type: Optional[str] = None
    dep_attr_name: Optional[str] = None
    dep_attr_value: Optional[str] = None

    # Extract label: strip leading --, trailing ->
    inner = op_text[2:]  # remove leading --
    if inner.endswith('>'):
        inner = inner[:-1]
    inner = inner.rstrip('-')

    if inner:
        if inner.startswith('@'):
            attr_part = inner[1:]
            if '=' in attr_part:
                dep_attr_name, dep_attr_value = attr_part.split('=', 1)
            else:
                dep_attr_name = attr_part
        else:
            dep_type = inner

    return ChainSearchExpr(
        from_expr=from_expr,
        to_expr=to_expr,
        dep_type=dep_type,
        dep_attr_name=dep_attr_name,
        dep_attr_value=dep_attr_value,
    )


# ---------------------------------------------------------------------------
# 6. Dependency search  (-->  --  -type->  -@attr->  -@attr=val->)
# ---------------------------------------------------------------------------

# Pattern matches one of:
#   " --> "          plain directed
#   " -label-> "     directed with label (type or @attr)
#   " -- "           plain undirected (not --- or --->)
#   " -label- "      undirected with label
# Operator must be surrounded by spaces (spec requirement).
_DEP_PATTERN = re.compile(
    r' ('
    r'-->'                            # plain directed
    r'|-[^-\s>][^>]*->'              # -label->  (label cannot start with -)
    r'|--(?![-\->])'                  # plain undirected: -- not followed by - or >
    r'|-[^-\s>][^>]*-(?!>)'          # -label-   (undirected, not followed by >)
    r') '
)


def _try_dep_search(s: str) -> Optional[Expression]:
    """Parse FROM --> TO, FROM -- TO and typed/attribute variants."""
    # Walk the string to find the operator, skipping quoted and parenthesised regions.
    in_quote = False
    quote_char = ''
    depth = 0
    i = 0
    op_match: Optional[re.Match[str]] = None
    while i < len(s):
        ch = s[i]
        if in_quote:
            if ch == quote_char:
                in_quote = False
            i += 1
            continue
        if ch in ('"', "'"):
            in_quote = True
            quote_char = ch
            i += 1
            continue
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        if depth == 0:
            m = _DEP_PATTERN.match(s, i)
            if m:
                op_match = m
                break
        i += 1

    if op_match is None:
        return None

    op_text = op_match.group(1)  # the operator token without surrounding spaces
    from_src = s[:op_match.start()].strip()
    to_src = s[op_match.end():].strip()

    from_expr = _parse_dep_endpoint(from_src)
    to_expr = _parse_dep_endpoint(to_src)

    directed = op_text.endswith('>')
    dep_type: Optional[str] = None
    dep_attr_name: Optional[str] = None
    dep_attr_value: Optional[str] = None

    # Extract the label between the dashes
    inner = op_text.lstrip('-')
    if inner.endswith('>'):
        inner = inner[:-1]
    inner = inner.rstrip('-')

    if inner:
        if inner.startswith('@'):
            attr_part = inner[1:]
            if '=' in attr_part:
                dep_attr_name, dep_attr_value = attr_part.split('=', 1)
            else:
                dep_attr_name = attr_part
        else:
            dep_type = inner

    return DepSearchExpr(
        from_expr=from_expr,
        to_expr=to_expr,
        directed=directed,
        dep_type=dep_type,
        dep_attr_name=dep_attr_name,
        dep_attr_value=dep_attr_value,
    )


def _parse_dep_endpoint(s: str) -> Optional[Expression]:
    """Parse a dep-search endpoint.  Returns None for wildcard ``*``."""
    if s in ('*', '"*"', ''):
        return None
    return _parse(s)


# ---------------------------------------------------------------------------
# 5. NOT
# ---------------------------------------------------------------------------

def _try_not(s: str) -> Optional[Expression]:
    """Match ``NOT <expr>``."""
    if not s.startswith('NOT '):
        return None
    inner = s[4:].strip()
    return NotExpr(inner=_parse(inner))


# ---------------------------------------------------------------------------
# 6. Attribute filters
# ---------------------------------------------------------------------------

# @attr=~"pattern"
_RE_REGEX_MATCH = re.compile(r'^@([\w\-]+)=~"(.+)"$')

# @attr="exact value"  — quoted exact match
_RE_ATTR_EQ_QUOTED = re.compile(r'^@([\w\-]+)="([^"]*)"$')

# @attr=value  — unquoted, contains match (value cannot start with ~ or contain ")
_RE_ATTR_EQ_UNQUOTED = re.compile(r'^@([\w\-]+)=([^"~][^"]*)$')

# @attr!="exact" or @attr!=value
_RE_ATTR_NEQ_QUOTED = re.compile(r'^@([\w\-]+)!="([^"]*)"$')
_RE_ATTR_NEQ_UNQUOTED = re.compile(r'^@([\w\-]+)!=([^"]+)$')

# @attr>number
_RE_ATTR_GT = re.compile(r'^@([\w\-]+)>([\d.]+)$')

# @attr<number
_RE_ATTR_LT = re.compile(r'^@([\w\-]+)<([\d.]+)$')

# @attr (bare — attribute existence)
_RE_HAS_ATTR = re.compile(r'^@([\w\-]+)$')


def _try_attr(s: str) -> Optional[Expression]:
    """Try all attribute filter patterns in priority order."""
    # Regex match must be tried before equals (both start with @attr=)
    m = _RE_REGEX_MATCH.match(s)
    if m:
        return AttrRegexExpr(attr_name=m.group(1), pattern=m.group(2))

    # Not-equals (quoted then unquoted)
    m = _RE_ATTR_NEQ_QUOTED.match(s)
    if m:
        return AttrNotEqualsExpr(attr_name=m.group(1), value=m.group(2), exact=True)

    m = _RE_ATTR_NEQ_UNQUOTED.match(s)
    if m:
        return AttrNotEqualsExpr(attr_name=m.group(1), value=m.group(2), exact=False)

    m = _RE_ATTR_GT.match(s)
    if m:
        return AttrGtExpr(attr_name=m.group(1), value=float(m.group(2)))

    m = _RE_ATTR_LT.match(s)
    if m:
        return AttrLtExpr(attr_name=m.group(1), value=float(m.group(2)))

    # Equals: quoted before unquoted
    m = _RE_ATTR_EQ_QUOTED.match(s)
    if m:
        return AttrEqualsExpr(attr_name=m.group(1), value=m.group(2), exact=True)

    m = _RE_ATTR_EQ_UNQUOTED.match(s)
    if m:
        return AttrEqualsExpr(attr_name=m.group(1), value=m.group(2), exact=False)

    m = _RE_HAS_ATTR.match(s)
    if m:
        return HasAttrExpr(attr_name=m.group(1))

    return None


# ---------------------------------------------------------------------------
# 7. Keyword / Exact Path fallback
# ---------------------------------------------------------------------------

def _try_keyword(s: str) -> Optional[Expression]:
    """Fallback: quoted string = exact path, unquoted = keyword search."""
    if s.startswith('"') and s.endswith('"') and len(s) >= 2:
        path = s[1:-1]
        return KeywordExpr(keyword=path, exact=True)
    # Treat anything else as a keyword.
    return KeywordExpr(keyword=s, exact=False)
