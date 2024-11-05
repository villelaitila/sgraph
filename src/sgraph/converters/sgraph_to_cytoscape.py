from sgraph import ModelApi
from sgraph import SGraph


def node(elem_id, name, parent=''):
    d = {'id': elem_id, 'label': name}
    if parent:
        d['parent'] = parent
    obj = {'group': 'nodes', 'data': d}
    return obj


class EdgeCounter:
    def __init__(self):
        self.counter = 0

    def next(self):
        self.counter += 1
        return self.counter


def edge(edgecounter, src='', target=''):
    d = {'id': f'e{edgecounter.next()}'}
    if src:
        d['source'] = src
    if target:
        d['target'] = target
    obj = {'group': 'edges', 'data': d}
    return obj


def graph_to_cyto(g):
    edgecounter = EdgeCounter()
    """
    graph = [
        node('n0'),
        node('n1', parent='n0'),
        node('n2', parent='n0'),
        node('n3', parent='n0'),
        node('n4', parent='n0'),
        edge(edgecounter, src='n1', target='n2'),
        edge(edgecounter, src='n1', target='n3')
    ]"""
    elemcounter = EdgeCounter()

    def mark_ids(elem):
        elem.attrs['elem_id'] = 'n' + str(elemcounter.next())
        if elem.parent is not None and elem.parent.parent is not None:
            elem.attrs['parent'] = str(elem.parent.attrs['elem_id'])
        elem.attrs['label'] = elem.name
        # for association in elem.outgoing:
        #    association.attrs['edge_id'] = 'e' + str(edgecounter.next())

    for elem in g.rootNode.children:
        elem.traverseElements(mark_ids)

    graph = []

    def convert_graph_elems(elem_to_be_handled):
        parent = elem_to_be_handled.attrs.get('parent', '')
        graph.append(
            node(elem_to_be_handled.attrs['elem_id'], elem_to_be_handled.attrs['label'],
                 parent=parent))

    for elem in g.rootNode.children:
        elem.traverseElements(convert_graph_elems)

    def convert_graph_assocs(elem):
        for association in elem.outgoing:
            source_id = association.fromElement.attrs['elem_id']
            target_id = association.toElement.attrs['elem_id']
            graph.append(edge(edgecounter, source_id, target_id))

    for elem in g.rootNode.children:
        elem.traverseElements(convert_graph_assocs)

    # Useful place for more verbose debug outputs
    # graph_json = json.dumps(graph)
    # print(f'returning {graph_json}')
    return graph


def main():
    import sys
    g = SGraph.parse_xml_or_zipped_xml(sys.argv[1])
    central_element_path = sys.argv[2]
    # Print this way for debugging pursposes: print(g.to_deps(fname=None))
    elem = g.createOrGetElementFromPath(central_element_path)
    subg = ModelApi.filter_model(elem, g)

    # Print this way for debugging purposes: print(subg.to_xml(fname=None))
    graph_json = graph_to_cyto(subg)
    print(graph_json)


if __name__ == '__main__':
    main()
