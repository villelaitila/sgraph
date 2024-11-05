from __future__ import annotations

import io
import json
import os
import zipfile

from sgraph import ModelApi, SGraph
from sgraph.converters import sbom_cyclonedx_generator
from sgraph.converters.sgraph_to_cytoscape import graph_to_cyto
from sgraph.exceptions import ModelNotFoundException


def extract_subgraph_as_json(analysis_target_name: str, output_dir: str, element_path: str,
                             _recursion: str, flavour: str):
    """
    Extracts subraph as JSOn. recursion parameter not yet supported.
    :param analysis_target_name:
    :param output_dir:
    :param element_path:
    :param _recursion:
    :param flavour:
    :return:
    """
    subgraph = extract_filtered_subgraph(analysis_target_name, output_dir, element_path)
    return produce_output(flavour, subgraph)


def extract_filtered_subgraph(analysis_target_name: str, output_dir: str, element_path: str):
    graph = extract_and_load(analysis_target_name, output_dir)
    elem = graph.createOrGetElementFromPath(element_path)
    if elem:
        # TODO handle also recursion param
        return ModelApi.filter_model(elem, graph)
    else:
        raise Exception(f'Element path {element_path} not found')


def extract_and_load(analysis_target_name: str, output_dir: str):
    modelfile = get_latest_model(output_dir, analysis_target_name)
    if modelfile is None:
        raise ModelNotFoundException(
            f'Cannot find model for {analysis_target_name} under {output_dir}')
    with zipfile.ZipFile(modelfile) as zfile:
        # We need to support old and new file names (if analysis is not run
        # for a long time, there can be modelfile in the old location but not
        # in the new location) so don't use hardcoded filename here
        file_name = zfile.namelist()[0]
        data = zfile.open(file_name, 'r')
        data = io.TextIOWrapper(data)
        zfile.close()
        graph = SGraph.parse_xml_file_or_stream(data)
        return graph


def produce_output(outputformat: str, subg: SGraph):
    if outputformat == 'cytoscape':
        return graph_to_cyto(subg)
    elif outputformat == 'softagram':
        return subg.to_xml(None, stdout=False)
    elif outputformat == 'cyclonedx-bom':
        model_sbom = sbom_cyclonedx_generator.generate_from_sgraph(subg)
        return json.dumps(model_sbom, indent=4)
    else:
        raise Exception(f'Unsupported outputformat {outputformat}')


def get_latest_model(output_dir: str, analysis_target_name: str):
    target_dir = output_dir + '/' + analysis_target_name
    modelpaths = []
    if os.path.isdir(target_dir):
        for o in os.listdir(target_dir):
            ts_dir = target_dir + '/' + o
            if os.path.isdir(ts_dir):
                # Try the new location first
                modelpath = ts_dir + '/model.xml.zip'
                if os.path.exists(modelpath):
                    modelpaths.append(modelpath)
    if modelpaths:
        modelpaths.sort()
        modelpath = modelpaths[-1]
    else:
        modelpath = None
    return modelpath
