"""SGraph Query Language — filter and traverse SGraph models.

Public API::

    from sgraph.query import query

    result = query(model, '@type=file AND @loc>500')
"""
from sgraph.query.engine import query

__all__ = ['query']
