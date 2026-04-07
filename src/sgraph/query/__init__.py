"""SGraph Query Language — filter and traverse SGraph models.

Public API::

    from sgraph.query import query, QueryResult

    result = query(model, '@type=file AND @loc>500')
    elements = result.subgraph                # filtered SGraph
    # Chain searches also populate result.chains:
    result = query(model, '"/leaf" ---> "/ancestor"', max_depth=30)
    for chain in result.chains:
        ...
"""
from sgraph.query.engine import query
from sgraph.query.result import QueryResult

__all__ = ['query', 'QueryResult']
