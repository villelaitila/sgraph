from sgraph import SGraph
from sgraph.algorithms.pagerank import calculate_page_rank



def test_pagerank_simple():
    # Create a simple graph
    graph = SGraph.parse_deps_lines([
        '/UI_1:/Middleware_1:',
        '/Middleware_1:/Repository_1:'])

    calculate_page_rank(graph, d=0.85, max_iterations=100)

    # Check that the page rank values are as expected
    assert round(graph.findElementFromPath('/UI_1').attrs['page_rank'], 4) == 0.1844
    assert round(graph.findElementFromPath('/Middleware_1').attrs['page_rank'], 4) == 0.3412
    assert round(graph.findElementFromPath('/Repository_1').attrs['page_rank'], 4) == 0.4744



def test_pagerank_simple_variation1():
    # Create a simple graph
    graph = SGraph.parse_deps_lines([
        '/UI_1:/Middleware_1:',
        '/Middleware_1:/Repository_1:',
        '/Middleware_2:/Repository_2:'])

    calculate_page_rank(graph, d=0.85, max_iterations=100)

    # Check that the pagerank values are as expected
    assert round(graph.findElementFromPath('/UI_1').attrs['page_rank'], 4) == 0.1209
    assert round(graph.findElementFromPath('/Middleware_1').attrs['page_rank'], 4) == 0.2236
    assert round(graph.findElementFromPath('/Repository_1').attrs['page_rank'], 4) == 0.311
    assert round(graph.findElementFromPath('/Middleware_2').attrs['page_rank'], 4) == 0.1209
    assert round(graph.findElementFromPath('/Repository_2').attrs['page_rank'], 4) == 0.2236


def test_pagerank_loops():
    # Create a simple graph
    graph = SGraph.parse_deps_lines([
        '/A:/B:',
        '/A:/C:',
        '/B:/C:',
        '/C:/A:'])

    calculate_page_rank(graph, d=0.85, max_iterations=100)

    # Check that the PageRank values are as expected
    assert round(graph.findElementFromPath('/A').attrs['page_rank'], 4) == 0.3878
    assert round(graph.findElementFromPath('/B').attrs['page_rank'], 4) == 0.2148
    assert round(graph.findElementFromPath('/C').attrs['page_rank'], 4) == 0.3974


