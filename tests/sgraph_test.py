import copy
import os
from typing import Any

from sgraph import SGraph
from sgraph.loader import ModelLoader

MODELFILE = 'modelfile.xml'
MINI_MODELFILE = 'mini_model.xml'

# Helper for creating the model
def get_model(file_name: str) -> Any:
    dirname: str = os.path.dirname(__file__)
    filename: str = str(os.path.join(dirname, file_name))
    model_loader = ModelLoader()
    model = model_loader.load_model(filename)
    return model

def test_deepcopy():
    graph1 = get_model(MODELFILE)
    graph2 = copy.deepcopy(graph1)
    assert graph1.rootNode.getNodeCount() == graph2.rootNode.getNodeCount()
    elem_names_1 = list([x.name for x in graph1.rootNode.children[0].children])
    elem_names_2 = list([x.name for x in graph2.rootNode.children[0].children])
    assert elem_names_1 == elem_names_2
    assert graph1.rootNode.getEACount() == graph2.rootNode.getEACount()
    assert graph1.produce_deps_tuples() == graph2.produce_deps_tuples()
    assert graph1.calculate_model_stats() == graph2.calculate_model_stats()


def test_repr_empty_model():
    """Empty SGraph should produce a useful repr, not the default <object at 0x...>."""
    graph = SGraph()
    text = repr(graph)
    assert text.startswith('<SGraph ')
    assert 'object at 0x' not in text
    assert 'elements=0' in text


def test_repr_single_root_shows_root_path():
    """Single top-level child should appear as root=/<name> with element count."""
    graph = SGraph()
    graph.createOrGetElementFromPath('/junit4/src/main/java/Foo.java')
    graph.createOrGetElementFromPath('/junit4/src/main/java/Bar.java')
    text = repr(graph)
    assert text.startswith('<SGraph ')
    assert 'root=/junit4' in text
    # 6 elements under /junit4: junit4, src, main, java, Foo.java, Bar.java.
    # The synthetic empty root is excluded from the count.
    count_token = next(part for part in text.split() if part.startswith('elements='))
    count = int(count_token.split('=')[1].rstrip('>'))
    assert count == 6


def test_repr_multi_root_lists_top_level_children():
    """Multiple top-level children should be visible (not collapsed to one)."""
    graph = get_model(MINI_MODELFILE)
    text = repr(graph)
    assert text.startswith('<SGraph ')
    # mini_model.xml has two top-level elements: nginx and bar.
    assert 'nginx' in text
    assert 'bar' in text


def test_repr_distinguishes_distinct_instances():
    """Two SGraphs loaded from the same file are different objects;
    their reprs must differ so logs don't suggest they're the same."""
    graph1 = get_model(MODELFILE)
    graph2 = get_model(MODELFILE)
    assert graph1 is not graph2
    assert repr(graph1) != repr(graph2)


def test_repr_does_not_walk_entire_tree():
    """repr() must not call the unbounded full-tree getNodeCount(): on huge
    models that would stall debuggers/loggers/exception formatters."""
    from unittest.mock import patch
    from sgraph.selement import SElement

    graph = SGraph()
    graph.createOrGetElementFromPath('/junit4/src/Foo.java')

    with patch.object(SElement, 'getNodeCount',
                      side_effect=AssertionError(
                          'repr() must not call full-tree getNodeCount()')):
        text = repr(graph)
    assert 'root=/junit4' in text
    assert 'elements=' in text


def test_repr_count_is_capped_on_large_models():
    """When the model exceeds the repr cap, the count must be marked with '+'."""
    graph = SGraph()
    # Create more elements than the cap to force truncation. Use a small
    # cap override to keep the test fast.
    for i in range(50):
        graph.createOrGetElementFromPath(f'/proj/dir{i}/file.py')
    original = SGraph._REPR_COUNT_LIMIT
    SGraph._REPR_COUNT_LIMIT = 10
    try:
        text = repr(graph)
    finally:
        SGraph._REPR_COUNT_LIMIT = original
    assert 'elements=10+' in text or 'elements=11+' in text


def test_repr_with_empty_child_name():
    """Edge case: a child with an empty name must not produce a misleading 'root=/'."""
    from sgraph.selement import SElement
    graph = SGraph()
    SElement(graph.rootNode, '')
    text = repr(graph)
    assert text.startswith('<SGraph ')
    # Should fall back to '?' rather than the bare-slash form.
    assert 'root=/?' in text


def test_repr_multi_root_omits_count_when_small():
    """When ≤3 top-level children, count=N is redundant with the visible list."""
    graph = get_model(MINI_MODELFILE)  # 2 top-level children: nginx, bar
    text = repr(graph)
    assert 'nginx' in text and 'bar' in text
    assert 'count=' not in text
