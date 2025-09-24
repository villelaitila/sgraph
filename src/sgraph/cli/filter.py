
import sys
import argparse
import zipfile
import io


from sgraph.modelapi import ModelApi, FilterAssocations, HaveAttributes
from sgraph import SGraph, SElement, SElementAssociation
from typing import Optional


# Filtering CLI to be used like this:
#  cat model.xml | python3 filter.py --query 'element_name' | python3 -m sgraph.converters.xml_to_dot | dot -Tpng -o filtered_model.png
# model in, model out

def traverse_graph_and_add_assoications_within(orig_model: SGraph, new_model: SGraph, new_model_to_orig_model: dict[SElement, SElement], orig_model_to_new_model: dict[SElement, SElement]):
    stack: list[SElement] = [new_model.rootNode]
    while stack:
        elem = stack.pop(0)
        total_elem = new_model_to_orig_model[elem]
        for association in total_elem.outgoing:
            target_elem: SElement = association.toElement
            if target_elem in orig_model_to_new_model:
                target_elem_new = orig_model_to_new_model[target_elem]

                ea: SElementAssociation = SElementAssociation(elem, target_elem_new, association.deptype, association.attrs)
                ea.initElems()
        
        stack.extend(elem.children)


def filter_model(graph: SGraph, query: str, direction: str, deps_level: int, detail_level: Optional[int]):
    matching_elems: list[SElement] = []
    stack = [graph.rootNode]
    while stack:
        elem = stack.pop(0)
        if query in elem.name:
            matching_elems.append(elem)
        stack.extend(elem.children)
    
    # create a new graph with the matching elements
    new_graph = SGraph()
    new_model_to_orig_model: dict[SElement, SElement] = {}
    orig_model_to_new_model: dict[SElement, SElement] = {}
    for elem2 in matching_elems:
        new_elem, created = new_graph.create_or_get_element(elem2)
        if created:
            new_model_to_orig_model[new_elem] = elem2
            orig_model_to_new_model[elem2] = new_elem
    
    if deps_level == 0:
        pass
    elif deps_level == 1:
        traverse_graph_and_add_assoications_within(graph, new_graph, new_model_to_orig_model, orig_model_to_new_model)

    elif deps_level == 2:
        if direction == 'outbound':
            new_graph = ModelApi.filter_model(new_graph.rootNode, new_graph, FilterAssocations.Direct, FilterAssocations.Ignore, HaveAttributes.IncludeCopy)
        elif direction == 'inbound':
            new_graph = ModelApi.filter_model(new_graph.rootNode, new_graph, FilterAssocations.Ignore, FilterAssocations.Direct, HaveAttributes.IncludeCopy)
        elif direction == 'both':
            new_graph = ModelApi.filter_model(new_graph.rootNode, new_graph, FilterAssocations.Direct, FilterAssocations.Direct, HaveAttributes.IncludeCopy)
        elif direction == 'undirected':
            raise Exception('Undirected dependencies are not supported for deps_level 2')
        elif direction == 'none':
            raise ValueError(f"Invalid direction: {direction} and deps_level: {deps_level} combination")
        else:
            raise ValueError(f"Invalid direction: {direction}")
    elif deps_level >= 3:
        if direction == 'outbound':
            new_graph = ModelApi.filter_model(new_graph.rootNode, new_graph, FilterAssocations.DirectAndIndirect, FilterAssocations.Ignore, HaveAttributes.IncludeCopy)
        elif direction == 'inbound':
            new_graph = ModelApi.filter_model(new_graph.rootNode, new_graph, FilterAssocations.Ignore, FilterAssocations.DirectAndIndirect, HaveAttributes.IncludeCopy)
        elif direction == 'both':
            new_graph = ModelApi.filter_model(new_graph.rootNode, new_graph, FilterAssocations.DirectAndIndirect, FilterAssocations.DirectAndIndirect, HaveAttributes.IncludeCopy)
        elif direction == 'undirected':
            raise Exception('Undirected dependencies not implemented yet.')
        elif direction == 'none':
            raise ValueError(f"Invalid direction: {direction} and deps_level: {deps_level} combination")
        else:
            raise ValueError(f"Invalid direction: {direction}")

    if detail_level is None:
        return new_graph

    # detail level is for reducing the elements that are too deep in the hierarchy

    max_detail_level = new_graph.rootNode.getMaxDepth(detail_level)
    if max_detail_level <= detail_level:
        return new_graph
    else:
        new_model_to_orig_model: dict[SElement, SElement] = {}
        orig_model_to_new_model: dict[SElement, SElement] = {}

        def handle_elem(elem: SElement, current_level: int):
            if current_level > detail_level:
                return
            new_elem, created = sub_graph.create_or_get_element(elem)
            if created:
                new_model_to_orig_model[new_elem] = elem
                orig_model_to_new_model[elem] = new_elem
            for child in elem.children:
                handle_elem(child, current_level + 1)


        sub_graph = SGraph()
        handle_elem(new_graph.rootNode, 0)

        stack = [new_graph.rootNode]
        deps: list[tuple[list[SElement], list[SElement], str, dict[str, str | int | list[str]]]] = []
        while stack:
            elem: SElement = stack.pop(0)
            ancestors: list[SElement] = list(reversed(elem.getAncestors()))[0:detail_level]

            for association in elem.outgoing:
                target_elem: SElement = association.toElement
                target_ancestors: list[SElement] = list(reversed(target_elem.getAncestors()))[0:detail_level]

                deps.append((ancestors, target_ancestors, association.deptype, association.attrs))

            for child in elem.children:
                stack.append(child)

        for dep in deps:
            from_ancestors, to_ancestors, deptype, attrs = dep
            if len(from_ancestors) == 0 or len(to_ancestors) == 0:
                continue
            from_elem = from_ancestors[-1]
            to_elem = to_ancestors[-1]
            if from_elem in orig_model_to_new_model and to_elem in orig_model_to_new_model:
                from_elem_new = orig_model_to_new_model[from_elem]
                to_elem_new = orig_model_to_new_model[to_elem]
                ea: SElementAssociation = SElementAssociation(from_elem_new, to_elem_new, deptype, attrs)
                ea.initElems()

        
        return sub_graph

    
    return new_graph



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Filter model')
    parser.add_argument('--query', type=str, required=True, help='Query to filter model')
    parser.add_argument('--direction', type=str, required=False, help='Direction of the dependency traversal: inbound, outbound, both, none, undirected. Default is both.')
    parser.add_argument('--deps-level', type=int, required=False, help='Deps level to filter model: default is 0. Number 1 means that dependencies are shown between the elements in the scope.')
    parser.add_argument('--detail-level', type=int, required=False, help='Detail level to filter model')
    
    parser.add_argument('--model-file', type=str, required=False, help='Model file to filter')
    # boolean to indicate the model is a zip file
    # Make a toggle for using zipped model content from stdin
    parser.add_argument('--zip', action='store_true', help='Indicates that the model (stdin) is a zip file')
    args = parser.parse_args()

    graph: SGraph | None = None

    if args.model_file:
        graph = SGraph.parse_xml_or_zipped_xml(args.model_file)
    else:

        # zip file or xml file
        filehandle = sys.stdin

        if args.zip:
            zip_bytes = sys.stdin.buffer.read()
            zfile = zipfile.ZipFile(io.BytesIO(zip_bytes))
            data = zfile.open(zfile.namelist()[0], 'r')
            filehandle = io.TextIOWrapper(data)
            zfile.close()

        graph = SGraph.parse_xml_or_zipped_xml(filehandle)

    filtered_model = filter_model(graph, args.query, args.direction, args.deps_level, args.detail_level)

    filtered_model.to_xml(None)