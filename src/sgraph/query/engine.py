"""High-level entry point for the SGraph Query Language."""
from __future__ import annotations

from sgraph import SGraph
from sgraph.query.evaluator import evaluate
from sgraph.query.parser import parse


def query(model: SGraph, expression: str, max_depth: int = 20) -> SGraph:
    """Execute an SGraph Query Language expression against a model.

    Parses *expression* into an AST and evaluates it against *model*,
    returning a new SGraph containing only the matching elements and the
    dependency edges connecting them.

    The original *model* is never mutated.

    Args:
        model: The source model to query.
        expression: An SGraph QL expression string, e.g.::

            '@type=file AND @loc>500'
            '"/src/web" --> "/src/db"'
            '"/" AND NOT "/External"'
        max_depth: Maximum hop count for chain search (``--->``). Defaults to 20.

    Returns:
        A new :class:`~sgraph.SGraph` with matching elements and their
        connecting associations.

    Raises:
        ValueError: If *expression* cannot be parsed.

    Examples::

        from sgraph import SGraph
        from sgraph.query import query

        model = SGraph.parse_xml_or_zipped_xml('model.xml.zip')

        # All Python files with more than 500 lines
        result = query(model, '@type=file AND @loc>500')

        # Dependencies from web module to db module
        result = query(model, '"/src/web" --> "/src/db"')

        # Everything except external dependencies
        result = query(model, '"/" AND NOT "/External"')
    """
    ast = parse(expression)
    return evaluate(ast, model, total_model=model, max_depth=max_depth)
