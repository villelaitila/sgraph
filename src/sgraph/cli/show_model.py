import os
import sys

from sgraph import SGraph

"""
Use like this:
 python3 show_model.py     (to get the last model from your /softagram/output)
 python3 show_model.py path/to/modelfile.xml
 python3 show_model.py .softagram/download/api/..../modelfile.xml
 python3 show_model.py /opt/softagram/output/.../modelfile.xml
 python3 show_model.py /softagram/output/.../modelfile.xml
 python3 show_model.py 12345-afa1243-aafa1234-1234

"""


def show_model(f, output_format='txt'):
    egm = SGraph.parse_xml(f)
    if output_format == 'txt':
        egm.to_deps(None)
    else:
        egm.to_xml(None)
    # TODO Support also visual outputs for small models, e.g. graphviz generated png/svg.


def adjust_path(model_to_load, inside_container):
    input_path = '/softagram/input'
    if inside_container and model_to_load.startswith('/opt' + input_path):
        model_to_load = model_to_load[4:]
    elif not inside_container and model_to_load.startswith(input_path):
        model_to_load = '/opt' + model_to_load
    return model_to_load


def get_project_dirname_from_input_path(path):
    """
    Turn .../projects/uid/name or .../projects/uid/name/foo... to uid
    :param path: ../projects/uid/path
    :return: project ID
    """
    pos = path.find('/projects/')
    if pos != -1:
        pos2 = path.find('/', pos + 10)
        if pos2 != -1:
            return path[pos+10:pos2]
        else:
            return path[pos+10:]


def show_model_file(model_to_load=None, output_format='txt'):
    modelfilepath = None #  To keep Code Inspect satisfied, actually never None because of raise()

    if model_to_load is not None:
        if os.path.isfile(model_to_load):
            modelfilepath = model_to_load
    show_model(modelfilepath, output_format)


def main():
    model_file_path_or_project_id_or_project_name_or_None = None
    if len(sys.argv) > 1:
        model_file_path_or_project_id_or_project_name_or_None = sys.argv[1]
    show_model_file(model_file_path_or_project_id_or_project_name_or_None)


if __name__ == '__main__':
    main()
