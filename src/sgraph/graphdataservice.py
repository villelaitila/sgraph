import io
import os
import zipfile

from sgraph.converters.sgraph_to_cytoscape import graph_to_cyto
from sgraph import ModelApi
from sgraph import SGraph


def extract_subgraph_as_json(analysis_target_name, output_dir, element_path, recursion, flavour):
    modelfile = get_latest_model(output_dir, analysis_target_name)
    if modelfile is None:
        raise Exception(f'Cannot find model for {analysis_target_name} under {output_dir}')
    with open(modelfile, 'rb') as filehandle:
        zfile = zipfile.ZipFile(filehandle)
        data = zfile.open('modelfile.xml', 'r')
        data = io.TextIOWrapper(data)
        zfile.close()
        graph = SGraph.parse_xml(data)
        elem = graph.createOrGetElementFromPath(element_path)
        if elem:
            # TODO handle also recursion param
            subgraph = ModelApi().filter_model(elem)
            return produce_output(flavour, subgraph)
        else:
            raise Exception(f'Element path {element_path} not found')


def produce_output(outputformat, subg):
    if outputformat == 'cytoscape':
        return graph_to_cyto(subg)
    elif outputformat == 'softagram':
        return subg.to_xml(None, stdout=False)
    else:
        raise Exception(f'Unsupported outputformat {outputformat}')


def get_latest_model(output_dir, analysis_target_name):
    target_dir = output_dir + '/' + analysis_target_name
    modelpaths = []
    if os.path.isdir(target_dir):
        for o in os.listdir(target_dir):
            ts_dir = target_dir + '/' + o
            if os.path.isdir(ts_dir):
                modelpath = ts_dir + '/dependency/modelfile.xml.zip'
                if os.path.exists(modelpath):
                    modelpaths.append(modelpath)
    if modelpaths:
        modelpaths.sort()
        modelpath = modelpaths[-1]
    else:
        modelpath = None
    return modelpath
