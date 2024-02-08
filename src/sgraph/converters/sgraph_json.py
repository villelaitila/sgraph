import json

from sgraph import SGraph, SElement


def sgraph_element_to_dict(element: SElement):
    """
    Converts a SElement into a dictionary, including its children elements.
    :param element: SElement object
    :return: dictionary that contains JSON-serializable data
    """
    output = {'name': element.name, 'attrs': element.attrs}
    if element.outgoing:
        output['outbound'] = []
        for association in element.outgoing:
            output['outbound'].append({
                'referred': association.toElement.getPath(),
                'type': association.deptype,
                'attrs': association.attrs
            })
    if element.incoming:
        output['inbound'] = []
        for association in element.outgoing:
            output['inbound'].append({
                'referring': association.fromElement.getPath(),
                'type': association.deptype,
                'attrs': association.attrs
            })
    output['elements'] = {}
    for child in element.children:
        output['elements'][child.name] = sgraph_element_to_dict(child)
    return output


def sgraph_to_dict(graph):
    """
    Converts SGraph to dictionary. The dictionary is nested and contains all the elements and
    associations in the graph. All associations are stored twice, in the 'outbound' and 'inbound'
     lists.
    :param graph: SGraph object
    :return: dictionary that contains JSON-serializable data
    """
    output = {'modelAttrs': graph.modelAttrs, 'elements': {}}
    for child in graph.rootNode.children:
        output['elements'][child.name] = sgraph_element_to_dict(child)
    return output


def sgraph_to_json(graph: SGraph):
    """Converts SGraph to JSON."""
    return json.dumps(sgraph_to_dict(graph), indent=2)


def sgraph_to_json_file(graph: SGraph, outputfile_path: str):
    """Converts SGraph to JSON and creates a file."""
    with open(outputfile_path, 'w') as output:
        json.dump(sgraph_to_dict(graph), output, indent=2)
