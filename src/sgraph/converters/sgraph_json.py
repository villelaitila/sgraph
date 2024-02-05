import json
import sys
import os
from sgraph import SGraph


def sgraph_element_to_dict(element):
    output = {'name': element.name, 'attrs': element.attrs}
    if element.outgoing:
        output['outbound'] = []
        for ea in element.outgoing:
            output['outbound'].append({'used': ea.toElement.getPath(), 'deptype': ea.deptype,
                                       'attrs': ea.attrs})
    if element.incoming:
        output['inbound'] = []
        for ea in element.outgoing:
            output['inbound'].append({'used': ea.fromElement.getPath(), 'deptype': ea.deptype,
                                      'attrs': ea.attrs})
    output['elements'] = {}
    for child in element.children:
        output['elements'][child.name] = sgraph_element_to_dict(child)
    return output


def sgraph_to_dict(graph):
    output = {'modelAttrs': graph.modelAttrs, 'elements': {}}
    for child in graph.rootNode.children:
        output['elements'][child.name] = sgraph_element_to_dict(child)
    return output

def sgraph_to_json(graph):
    """Converts SGraph to JSON."""
    return json.dumps(sgraph_to_dict(graph), indent=2)


def sgraph_to_json_file(graph: SGraph, outputfile_path: str):
    """Converts SGraph to JSON."""
    with open(outputfile_path, 'w') as output:
        json.dump(sgraph_to_dict(graph), output, indent=2)
