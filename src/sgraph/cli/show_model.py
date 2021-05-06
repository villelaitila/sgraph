import sys
import os
from enum import Enum


"""
Use like this:
 python3 show_model.py     (to get the last model from your /softagram/output)
 python3 show_model.py path/to/modelfile.xml
 python3 show_model.py .softagram/download/api/..../modelfile.xml
 python3 show_model.py /opt/softagram/output/.../modelfile.xml
 python3 show_model.py /softagram/output/.../modelfile.xml
 python3 show_model.py 12345-afa1243-aafa1234-1234

"""


class Mode(Enum):
    OUTSIDE_CONTAINER = 1
    OUTSIDE_CONTAINER_WITH_DOCKER = 2
    INSIDE_CONTAINER = 3


def os_system(cmd):
    print(cmd)
    return os.system(cmd)

def fix_cmd(cmd):
    if 'darwin' in sys.platform.lower() and cmd.startswith('find'):
        # Require gfind if on OSX!
        return 'g' + cmd.replace('xargs ', 'gxargs ')
    return cmd

def get_mode():
    outputdir = '/softagram/output'
    if not os.path.exists('/.dockerenv'):
        if os.system('docker ps') == 0:
            return Mode.OUTSIDE_CONTAINER_WITH_DOCKER, '/opt' + outputdir
        else:
            return Mode.OUTSIDE_CONTAINER, '/opt' + outputdir
    else:
        return Mode.INSIDE_CONTAINER, outputdir


def find_latest_model(outputdir, project, max_age_days=7):
    """
    Find the latest model
    :param outputdir:
    :param project:
    :param max_age_days: max age is to make this really fast.
    :return:
    """
    max_age_min = max_age_days * 24 * 60
    if project is not None:
        cmd = 'find ' + outputdir + '/projects/' + project \
              + ' -name \'modelfile.xm*\' -type f |xargs --no-run-if-empty ls -ta |head'
    else:
        cmd = 'find ' + outputdir + '/projects -maxdepth 5 -mmin -' + str(max_age_min) \
              + ' -name \'modelfile.xm*\' -type f |xargs --no-run-if-empty ls -ta |head'
    out = os.popen(fix_cmd(cmd)).read().splitlines()
    print(fix_cmd(cmd), out)
    if len(out) > 0:
        filepath = out[0].strip()
        print('Using file: ' + filepath)
        return filepath
    else:
        return None


def extract_model(modelpath, tmpdir):
    os.system('unzip -o -d ' + tmpdir + ' ' + modelpath)
    return tmpdir + '/modelfile.xml'


def show_model(f, mode, output_format='txt'):
    if mode == Mode.OUTSIDE_CONTAINER_WITH_DOCKER:
        if f.startswith('/opt/softagram'):
            f = f[4:]
        dckr = 'docker exec -ti softagram bash'
        os_system(dckr + ' -c "python3 /usr/lib/python3.8/sgraph/converters/xml_to_deps.py ' + f + '"')

    elif mode == Mode.OUTSIDE_CONTAINER or mode == Mode.INSIDE_CONTAINER:

        if output_format == 'txt':
            # Translate xml to txt
            from sgraph.sgraph import SGraph
            egm = SGraph.parse_xml(f)
            egm.to_deps(None)
        else:
            os.system('cat ' + f)
    else:
        raise Exception('Unknown mode {}'.format(mode))


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
    mode, outputdir = get_mode()

    modelfilepath = None #  To keep Code Inspect satisfied, actually never None because of raise()

    if model_to_load is not None:

        model_to_load = adjust_path(model_to_load, mode == mode.INSIDE_CONTAINER)

        if os.path.isfile(model_to_load):
            modelfilepath = model_to_load
        else:
            if '/' in model_to_load:
                raise Exception('Given path {} does not exist..'.format(model_to_load))

            if os.path.isdir(outputdir + '/' + model_to_load):
                project_dir_name = model_to_load
                modelfilepath = find_latest_model(outputdir, project_dir_name)
                print('Resolved model: ' + model_to_load + ' ==> ' + project_dir_name + ' ==> ' +
                      modelfilepath)

            else:
                # Try to resolve project dir based on model_to_load
                projectsdir = outputdir.replace('/output', '/input') + '/projects'
                cmd = 'find {} -maxdepth 2 -name {} |cut -f 1,2,3,4,5,6 -d /;'.format(projectsdir,
                                                                                      model_to_load)
                project_ids = set()
                print(cmd)
                with os.popen(cmd) as p:
                    for line in p:
                        project_dirname = get_project_dirname_from_input_path(line.strip())
                        if project_dirname is not None:
                            project_ids.add(project_dirname)

                if len(project_ids) == 1:
                    project_dir_name = next(iter(project_ids))
                    print('Resolved ID: ' + model_to_load + ' ==> ' + project_dir_name)
                    modelfilepath = find_latest_model(outputdir, project_dir_name)
                    if modelfilepath is None:
                        raise Exception('Could not find any analysis model matching {} under '
                                        '{}'.format(project_dir_name, outputdir))
                    print('Resolved model: ' + model_to_load + ' ==> ' + project_dir_name + ' ==> ' +
                          modelfilepath)


                elif len(project_ids) > 1:
                    raise Exception('Unambiguous name {}, got several project dirs {}, please use '
                                    'dir name instead'.format(model_to_load, sorted(project_ids)))
                elif len(project_ids) == 0:
                    raise Exception('Error: Could not resolve project directory based on {}'.format(
                        model_to_load))
    else:
        modelfilepath = find_latest_model(outputdir, None)
        print('Resolved model: ' + outputdir + ' ==> ' + modelfilepath)

    if modelfilepath.endswith('.zip'):
        extracted = extract_model(modelfilepath, '/tmp')
    else:
        extracted = modelfilepath

    if mode == Mode.OUTSIDE_CONTAINER_WITH_DOCKER:
        new_location = outputdir + '/modelfile.xml'
        os.system('sudo cp ' + extracted + ' ' + new_location)
        extracted = new_location

    show_model(extracted, mode, output_format)


def main():
    model_file_path_or_project_id_or_project_name_or_None = None
    if len(sys.argv) > 1:
        model_file_path_or_project_id_or_project_name_or_None = sys.argv[1]
    show_model_file(model_file_path_or_project_id_or_project_name_or_None)


if __name__ == '__main__':
    main()
