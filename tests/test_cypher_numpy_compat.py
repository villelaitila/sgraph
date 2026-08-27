"""Regression test: Cypher numeric functions under NumPy 2.0.

NumPy 2.0 removed the ``np.float_`` alias that spycy <= 0.0.3 references in
toInteger/toFloat/toString and result conversion. ``sgraph.cypher`` restores
the alias before importing spycy; this test locks that in so a spycy or numpy
upgrade cannot silently reintroduce the crash
(AttributeError: `np.float_` was removed in the NumPy 2.0 release).
"""

import pytest

pytest.importorskip("spycy")

from sgraph import SGraph
from sgraph.cypher import cypher_query


def build_model() -> SGraph:
    model = SGraph()
    for path, loc in [("/proj/a.py", "10"), ("/proj/b.py", "250")]:
        elem = model.createOrGetElementFromPath(path)
        elem.setType("file")
        elem.attrs["loc"] = loc
    return model


def test_to_integer_in_where_and_return():
    model = build_model()
    result = cypher_query(
        model,
        "MATCH (f:file) WHERE toInteger(f.loc) > 100 "
        "RETURN f.name, toInteger(f.loc) AS loc",
    )
    assert len(result) == 1
    row = result.iloc[0] if hasattr(result, "iloc") else result[0]
    assert row["loc"] == 250


def test_to_float_and_to_string():
    model = build_model()
    result = cypher_query(
        model,
        "MATCH (f:file) RETURN toString(toFloat(f.loc)) AS s ORDER BY s",
    )
    assert len(result) == 2
