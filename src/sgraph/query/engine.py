"""High-level entry point for the SGraph Query Language."""
from __future__ import annotations

from sgraph import SGraph
from sgraph.query.evaluator import evaluate
from sgraph.query.parser import parse
from sgraph.query.result import QueryResult


def query(model: SGraph, expression: str, max_depth: int = 20) -> QueryResult:
    """Execute an SGraph Query Language expression against a model.

    Parses *expression* into an AST and evaluates it against *model*,
    returning a :class:`~sgraph.query.result.QueryResult` that bundles
    the filtered sub-graph together with any ordered chains discovered
    by chain-search expressions.

    The original *model* is never mutated.

    Args:
        model: The source model to query.
        expression: An SGraph QL expression string, e.g.::

            '@type=file AND @loc>500'
            '"/src/web" --> "/src/db"'
            '"/" AND NOT "/External"'
        max_depth: Maximum hop count for chain search (``--->``). Defaults to 20.

    Returns:
        A :class:`QueryResult` with two fields:

        - ``subgraph`` — the filtered :class:`~sgraph.SGraph`
        - ``chains`` — tuple of ordered :class:`~sgraph.SElement` tuples
          (one per discovered chain). Empty for queries that do not
          contain a ``--->`` chain search.

    Raises:
        ValueError: If *expression* cannot be parsed.

    Examples::

        from sgraph import SGraph
        from sgraph.query import query

        model = SGraph.parse_xml_or_zipped_xml('model.xml.zip')

        # All Python files with more than 500 lines
        result = query(model, '@type=file AND @loc>500')
        for elem in result.subgraph.rootNode.children:
            ...

        # Dependencies from web module to db module — chains is populated
        result = query(model, '"/src/web" ---> "/src/db"', max_depth=10)
        for chain in result.chains:
            for elem in chain:
                ...
    """
    ast = parse(expression)
    chains: list = []
    subgraph = evaluate(
        ast, model, total_model=model, max_depth=max_depth,
        chain_collector=chains,
    )
    return QueryResult(subgraph=subgraph, chains=tuple(chains))
