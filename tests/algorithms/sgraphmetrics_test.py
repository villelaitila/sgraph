from typing import Any

from sgraph import SGraph
from sgraph.algorithms.sgraphmetrics import SGraphMetrics


MODELFILE = '../modelfile.xml'


# Helper for creating the model
def get_model() -> Any:
    x = '/root/e1/orphan\n'\
        '/root/e1:/root/e_u4:\n'\
        '/root/e1/sub1:/root/e_u2/sub:initialize\n'\
        '/root/e1/sub2:/root/e_u2/sub:initialize\n'\
        '/root/e1:/root/i_u2:use\n'\
        '/root/i_u2:/root/e_u2/sub:use\n'\
        '/root/e2/sub2:/root/e_u3:call\n'
    g = SGraph.parse_deps_lines(x.splitlines())
    return g



def test_calculate_model_stats():
    graph = get_model()
    dependenciesCount, nodesCount, depTypeCounts, depToElemRatio = graph.calculate_model_stats()
    assert dependenciesCount == 6
    assert depToElemRatio == 0.46
    assert depTypeCounts == {'initialize': 2, 'use': 2, 'call': 1, '': 1}
    assert nodesCount == 13


def test_calculate_association_density():
    g = get_model()
    density, assocs, _ = SGraphMetrics().calculate_association_density(g, '/root', 1)
    assert density == 1.0
    density, assocs, _ = SGraphMetrics().calculate_association_density(g, '/root', 99)
    assert round(density, 3) == 0.5
    density, assocs, _ = SGraphMetrics().calculate_association_density(g, '/root', 3)
    assert round(density, 3) == 0.5
    density, assocs, _ = SGraphMetrics().calculate_association_density(g, '/root', 2)
    assert round(density, 3) == 0.833