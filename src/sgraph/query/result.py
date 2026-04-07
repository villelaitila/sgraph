"""QueryResult — wraps a query's sub-graph plus metadata.

Returned from :func:`sgraph.query.query`. The :attr:`subgraph` field is
the same SGraph the query language has always produced (filtered
elements + relevant associations). The :attr:`chains` field is a tuple
of ordered element tuples — each chain is one DFS walk discovered by a
chain search expression. For non-chain queries (filters, attribute
matches, etc.) ``chains`` is the empty tuple.

Example::

    from sgraph.query import query

    result = query(model, '"/leaf" ---> "/ancestor"', max_depth=30)

    # Same as before — sub-graph access
    for elem in result.subgraph.rootNode.children:
        ...

    # New — ordered chains in a single field
    for chain in result.chains:
        # chain is tuple[SElement, ...] starting at "/leaf"
        # and ending at "/ancestor"
        for elem in chain:
            ...
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sgraph.selement import SElement
    from sgraph.sgraph import SGraph


@dataclass(frozen=True)
class QueryResult:
    """Result of a query language evaluation.

    Attributes:
        subgraph: The filtered sub-SGraph. Always present.
        chains: Tuple of ordered element tuples discovered by chain
            search expressions (``"a" ---> "b"``). Each chain is one
            DFS walk in start-to-end order. For queries that do not
            contain a chain search (filters, attribute matches), the
            tuple is empty.
    """
    subgraph: 'SGraph'
    chains: tuple[tuple['SElement', ...], ...] = field(default_factory=tuple)
