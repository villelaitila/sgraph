import os
import sys
import zipfile
from collections import defaultdict
from typing import Dict, Set
import subprocess

import pandas as pd
from pandas.errors import EmptyDataError


def read_attrs_to_list_of_dicts(filepath, sep='\t'):
    df = read_attrs(filepath, sep)
    data = df.to_dict()
    out = []
    for element_id in sorted(data.keys()):
        attributes_entry = data[element_id]
        out.append(attributes_entry)
    return out


def read_attrs(filepath, sep='\t'):
    print(f'read_attrs {filepath}')
    fname = filepath.split('/')[-1]
    if fname.endswith('.zip'):
        fn = fname[:fname.rfind('.zip')]

        zf = zipfile.ZipFile(filepath)
        df = pd.read_csv(zf.open(fn), header=0, sep=sep).transpose()
    else:
        with open(filepath) as f:
            df = pd.read_csv(f, header=0, sep=sep).transpose()
    return df


def read_csv_attrs(filepath, sep='\t', zip_format=True):
    if zip_format:
        fnamezip = filepath.split('/')[-1]
        fn = fnamezip[:fnamezip.rfind('.zip')]

        zf = zipfile.ZipFile(filepath)
        df = pd.read_csv(zf.open(fn), header=0, sep=sep)
    else:
        df = pd.read_csv(filepath, header=0, sep=sep)
    return df


def get_project_files(output_dir, target, log):
    """ Returns project files based on git commits

    :param output_dir:
    :param target:
    :param log:
    :return: set: file paths
    """

    filepaths_set = set()
    full_output_dir = output_dir + '/' + target

    if os.path.isdir(full_output_dir):
        attr_filename = 'attr_git_propagated.csv.zip'
        cmd = 'find {} -name {} | xargs ls -rta | tail -1' \
            .format(full_output_dir, attr_filename)

        csv_filename = None
        p = os.popen(cmd)
        for one_line in p.read().splitlines():
            csv_filename = one_line.strip()
        p.close()

        if not csv_filename or attr_filename not in csv_filename:
            log.error("Cannot locate {} for determining project files".format(attr_filename))
        else:
            commitdata_dataframe = read_attrs(csv_filename, sep=',')
            data = commitdata_dataframe.to_dict()

            for element_id in sorted(data.keys()):
                fileinfo = data[element_id]
                if 'id' in fileinfo:
                    filepaths_set.add(fileinfo['id'])
    else:
        log.warning('Cannot locate directory: {}'.format(full_output_dir))

    return filepaths_set


def get_klocs_for_project(project_id):
    """ Returns loc count (*1000) for the project.

    :param project_id: Project's Id.
    :return: loc count (*1000)
    """
    output_dir = '/softagram/output/projects/{}'.format(str(project_id))
    klocs = 0

    # kloc is not indexed at the moment and calculating it takes too long on
    # slow disks in some enterprise environments where there is a lot of
    # existing analysis history. Thus, disable calculating it in enterprise
    # deployments until it is indexed.
    deployment_type = os.environ.get('DEPLOYMENT_TYPE', 'enterprise').lower()
    disable_kloc = deployment_type == 'enterprise'

    if not disable_kloc and os.path.isdir(output_dir):
        # WARNING: This is very slow with slow disks
        cmd = 'find ' + output_dir + ' -name attr_languages.csv.zip | xargs ls -rta | tail -1 '
        csv_filename = None

        p = os.popen(cmd)
        for one_line in p.read().splitlines():
            csv_filename = one_line.strip()
        p.close()

        if csv_filename and ".zip" in csv_filename and os.path.isfile(csv_filename):
            klocs = get_klocs(csv_filename, zip_format=True)

    return klocs


def get_klocs_for_active_project(main_dir, zip_format=True):
    """ Returns loc count (*1000) for the project.

    :param main_dir: Output directory of project's main analysis target
    :param zip_format: True if csv is zipped, otherwise False
    :return: loc count (*1000)
    """
    csv_filename = main_dir + '/content/loc/attr_languages.csv'
    if zip_format:
        csv_filename += ".zip"

    # to check that kloc calculation is really available
    if not os.path.isfile(csv_filename):
        return 0

    return get_klocs(csv_filename, zip_format)


def get_klocs(csv_filename, zip_format=True):
    """ Returns loc count (*1000) based on the project's attribute file.

    :param csv_filename: filename for the csv file
    :param zip_format: True if csv is zipped, otherwise False
    :return: loc count (*1000)
    """
    kloc_total = 0
    included_loc_infos = [
        'loc_cplusplus', 'loc_c', 'loc_java', 'loc_javascript', 'loc_python', 'loc_scala',
        'loc_php', 'loc_csharp', 'loc_c_or_cplusplus_header'
    ]

    if csv_filename:
        loc_attributes = read_csv_attrs(csv_filename, sep=',', zip_format=zip_format)
        data = loc_attributes.to_dict()

        for element_id in sorted(data.keys()):
            if element_id in included_loc_infos:
                if data[element_id][0]:
                    kloc_total += (data[element_id][0] / 1000)

    return int(kloc_total)


def get_relative_project_path(project_dir, git_dir):
    """Return relative project path of absolute git repo path

    /softagram/input/projects/c2d6d783-cef7-4197-b682-46ae297473d8/Project/subfolder/git-repo
    -->
    /Project/subfolder/git-repo

    :param project_dir: Project dir, e.g. /softagram/foo/bla/parallel/stuff/UUID/Projectname
    :param git_dir: absolute path to Git repo, so usually like /softagram/.........../repo
    :return: model path compatible repo path, e.g. /Softagram/softagram-web-frontend,
                                               or  /Customer/Hiearchy/Group1/Section/repo1
    """
    uuid_dir = project_dir[:project_dir.rfind('/')]
    return git_dir.replace(uuid_dir, '')


def detect_git_modified_files(base_sha, head_sha, repo_dir, log, project_dir) -> Dict:
    """Detect which files were touched between git commits

    :param project_dir: Project dir, e.g. /softagram/foo/bla/parallel/stuff/UUID/Projectname
    :param base_sha: base SHA, e.g merge-base of a pull request
    :param head_sha: head SHA, e.g latest commit of a pull request
    :param repo_dir: absolute path of repo dir
    :param log: logging
    :return: Dict: modified filepaths relative to model root, and their
                   change attributes
    """
    return get_files_modified_since_fork(repo_dir, base_sha, head_sha, log, project_dir)


def get_files_modified_since_fork(repo_dir, base_sha, head_sha, log, project_dir) -> Dict:
    """Get changed files and their status in head tree compared to base tree.

    Skip submodule changes. They require further processing to find out which
    files have actually been changed under the submodule. Also special logic
    might be needed for recursive submodules; in some cases we only analyse them
    on first level even if there are recursive submodules.

    Sample diff output and resulting parsed data:

    git -C /path/to/softagram-live diff -r --no-commit-id --name-status 098e22a1...47a69d81
    A       src/analysis/metrics/software_metrics.py
    M       src/common/dataformats/softagramxml/attribute_loader.py
    M       src/common/dataformats/softagramxml/datamodel.py
    M       src/db/schema/schema.py
    M       src/web/app/app.py
    R083    src/web/utils.py  src/web/common/utils.py
    D       tests/analysis/metrics/test_software_metrics.py

    ==>

    {
        '/Project/Repo/src/analysis/metrics/software_metrics.py': {
            'change_type': 'added'
        },
        '/Project/Repo/src/common/dataformats/softagramxml/attribute_loader.py': {
            'change_type': 'changed'
        },
        ...
        '/Project/Repo/src/web/utils.py': {
            'change_type': 'removed'
        },
        '/Project/Repo/src/web/common/utils.py': {
            'change_type': 'added'
        },
        ...
    }

    :param project_dir: Project dir, e.g. /softagram/foo/bla/parallel/stuff/UUID/Projectname
    :param repo_dir: absolute path of git repo
    :param base_sha: commit sha of the branch fork point
    :param head_sha: commit sha of the branch tip
    :param log: logging facility to use
    :return: Dict of modified files including the type of change
             (added, changed, removed)
    """
    filepath_status = defaultdict(dict)
    relative_project_path = get_relative_project_path(project_dir, repo_dir)

    # Parse file statuses (added, changed, removed)
    diff_cmd = 'git -C {} diff --ignore-submodules=all --no-commit-id --name-status -r {}...{}' \
        .format(repo_dir, base_sha, head_sha)
    log.info("Git diff_cmd: {}".format(diff_cmd))
    diff_result = subprocess.getoutput(diff_cmd).strip().splitlines()

    # Commented out this diff result logging
    # log.info("Git diff_result: {}".format(diff_result))
    # because causes BlockingIOError

    for f in diff_result:
        file_status, path = f.split(None, 1)
        file_status = file_status[0]  # strip score of rename and copy operations
        options = dict(A='added', M='changed', D='removed', R='renamed')
        change_type = options.get(file_status, 'unknown')

        if change_type == 'renamed':
            # SG desktop visualization is based on added/removed/changed - other states are not
            # visualized with colors yet, thus handle a rename as add+remove
            paths = path.split('\t', 1)
            path1 = '{}/{}'.format(relative_project_path, paths[0])
            path2 = '{}/{}'.format(relative_project_path, paths[1])
            # noinspection PyTypeChecker
            filepath_status[path1]['change_type'] = 'removed'
            # noinspection PyTypeChecker
            filepath_status[path2]['change_type'] = 'added'
        else:
            p = '{}/{}'.format(relative_project_path, path)
            # noinspection PyTypeChecker
            filepath_status[p]['change_type'] = change_type

    return filepath_status


def get_files_modified_by_commit(main_dir, commit_sha, repo_name) -> Set[str]:
    """
    :param main_dir:
    :param commit_sha:
    :param repo_name:
    :return: set of modified files
    """
    filepath_status = dict()

    git_dir = find_git_dir(main_dir, repo_name)
    committed_files_cmd = 'git -C {} diff-tree --ignore-submodules=all --no-commit-id --name-stat' \
                          'us -r {}'
    files = subprocess.getoutput(committed_files_cmd.format(git_dir, commit_sha)) \
        .strip().splitlines()
    for f in files:
        status, path = f.split(None, 1)
        options = dict(A='added', M='changed', D='removed')
        change_type = options.get(status, 'unknown')
        filepath_status[str('/'.join([repo_name, path]))] = change_type

    commitdata_dataframe = read_attrs(main_dir + '/git/attr_git_propagated.csv.zip', sep=',')
    filepaths_set = set()
    data = commitdata_dataframe.to_dict()
    parents_set = set()
    for element_id in sorted(data.keys()):
        fileinfo = data[element_id]

        for commit in fileinfo['latest_commits'].split(';'):
            commit_fields = commit.split(' ')
            short_sha = commit_fields[0]
            if commit_sha.startswith(short_sha):
                element_path = fileinfo['id']
                splitted = element_path.split('/')
                for i in range(len(splitted)):
                    if i > 1:
                        parents_set.add('/'.join(splitted[:i]))

                filepaths_set.add(element_path)

    files = filepaths_set.difference(parents_set)
    if len(files) == 0:
        sys.stderr.write('Could not find any files..\n')
    return files


def autodetect_csv_separator(attrfilepath):
    if attrfilepath.endswith('.zip'):
        import zipfile
        zf = zipfile.ZipFile(attrfilepath)
        filename = attrfilepath[attrfilepath.rfind('/') + 1:].replace('.zip', '')
        f = zf.open(filename)
        line1 = f.readline().decode()
        line2 = f.readline().decode()
    else:
        f = open(attrfilepath)
        line1 = f.readline()
        line2 = f.readline()
    f.close()
    if '\t' in line1 and '\t' in line2:
        return '\t'
    elif ',' in line1 and ',' in line2:
        tabcount = (line1 + line2).count('\t')
        commacount = (line1 + line2).count(',')
        if tabcount >= commacount:
            return '\t'
        else:
            return ','
    return ','


def read_attrs_generic(attrfilepath):
    """
    TODO Use Git log instead of this approach?
    Later, let's consider getting repo path from get_commits_after_forkpoint and then
    using git log --name-only --oneline or similar.
    :param attrfilepath:
    :return:
    """
    if not os.path.exists(attrfilepath):
        if os.path.exists(attrfilepath + '.zip'):
            attrfilepath += '.zip'

    if not os.path.exists(attrfilepath):
        return [], []
        # raise Exception('Cannot find attribute file')

    # TODO Autodetect csv separator based on first line characters.
    separator = autodetect_csv_separator(attrfilepath)
    try:
        commitdata_dataframe = read_attrs(attrfilepath, sep=separator)
        data = commitdata_dataframe.to_dict()
        first = True
        columns = []
        entries = []
        for element_id in sorted(data.keys()):
            attributes_entry = data[element_id]
            if first:
                columns = list(sorted(set(attributes_entry.keys())))
                if 'id' in columns:
                    columns.remove('id')
                first = False
            if 'id' in attributes_entry:
                entries.append((attributes_entry['id'], attributes_entry))
            else:
                raise Exception(
                    'Error: the attribute file does not have id column. Keys are {}\n'.format(
                        list(attributes_entry.keys())))
        return columns, entries
    except EmptyDataError:
        return [], []


def find_git_dir(output_dir, repo_id):
    project_id = output_dir.split('/')[4]
    path = '/softagram/input/projects/{}/{}'.format(project_id, repo_id)
    if not os.path.exists(path):
        raise Exception("Invalid git repo path: {}".format(path))

    return path


def get_all_forkpoints(project_id, projects_dir, history_size=10):
    """ Get repos using forkpoint infos.

    :param projects_dir: projects output directory
    :param project_id: project id
    :param history_size: limits find operation to the latest analysis results
    :return: set: found repo info containing repo_name, repo_id, project_name, and project id
    """

    repos = set()

    project_folder = projects_dir + '/' + str(project_id)
    if os.path.isdir(project_folder):
        cmd = 'find {} -name attr_fork_points.csv.zip | xargs ls -rta | tail -{}'.\
            format(project_folder, history_size)

        p = os.popen(cmd)
        for one_line in p.read().splitlines():
            csv_filename = one_line.strip()

            if csv_filename and ".zip" in csv_filename and os.path.isfile(csv_filename):
                forkdata_dataframe = read_attrs(csv_filename, sep='\t')

                for repo, repoinfo in forkdata_dataframe.to_dict().items():
                    # example format for 'id': /mbed_project/mbed-os-example-blinky/mbed-os
                    if isinstance(repoinfo['id'], str):
                        repo_path_inside_proj = repoinfo['id']
                        add_repo(project_id, repo_path_inside_proj, repos)
                    elif isinstance(repo, str):
                        # sometimes pandas puts stuff differently... repoinfo is not useful
                        repo_path_inside_proj = repo
                        add_repo(project_id, repo_path_inside_proj, repos)
                    else:
                        sys.stderr.write('ERROR: unexpected data with pandas in ' + csv_filename +
                                         '\n')
    return repos


def add_repo(project_id, repo_path_inside_proj, repos):
    parts = repo_path_inside_proj.split('/')
    if len(parts) > 1:
        project_name = parts[1]
        repo_name = parts[-1]
        repos.add((repo_name, repo_path_inside_proj, project_name, project_id))


def get_commits_after_forkpoint(main_dir, base_sha, head_sha, repo_name, log, secure_repo_name):
    """List commit hashes between base_sha and head_sha

    :param main_dir: model directory
    :param base_sha: base SHA i.e. point of the history when the branch started
        diverging from the main branch.
    :param head_sha: head SHA i.e. current tip of the branch
    :param repo_name: Repository folder name on disk
    :param log: logger object
    :param secure_repo_name: repo name in secure form
    :return: list of commit sha1 hashes
    """
    forkdata_dataframe = read_attrs(main_dir + '/git/attr_fork_points.csv.zip', sep='\t')

    repo_id = None
    commits = []

    for repo, repoinfo in forkdata_dataframe.to_dict().items():
        log.debug('Repo info for {} is {}'.format(repo, repoinfo))

        if 'id' in repoinfo and (repoinfo['id'].split('/')[-1] == repo_name
                                 or repoinfo['id'].split('/')[-1] == secure_repo_name):
            repo_id = repoinfo['id']
            git_dir = find_git_dir(main_dir, repoinfo['id'])
            cmd = 'git -C "{}" rev-list "{}..{}"'.format(git_dir, base_sha, head_sha)
            commits = [c.strip() for c in subprocess.getoutput(cmd).splitlines()]

        elif 'fork_point' in repoinfo:
            if repoinfo['fork_point'] == base_sha:
                commits = repoinfo['commits_after_fork_point'].split(';')
            else:
                # TODO: Sometimes the fork point SHA does not match with base SHA.
                # Workaround: Repo name is also very reliable way to ensure we
                # use the fork info from the correct line.
                repo_name_from_file = repoinfo['id'].split('/')[-1]
                if repo_name_from_file == repo_name:
                    log.warning('Repository {} base SHA {} and fork point SHA '
                                '{} do not match.'.format(repo_name, base_sha,
                                                          repoinfo['fork_point']))
                    commits = repoinfo['commits_after_fork_point'].split(';')
                elif repo_name_from_file == secure_repo_name:
                    log.warning('Repository {} base SHA {} and fork point SHA '
                                '{} do not match.'.format(secure_repo_name, base_sha,
                                                          repoinfo['fork_point']))
                    commits = repoinfo['commits_after_fork_point'].split(';')

        else:
            log.debug("Looking for {} or {}, found {} (main_dir {}, repoinfo {})".format(
                repo_name, secure_repo_name, repoinfo['id'].split('/')[-1], main_dir, repoinfo))
    return repo_id, commits


def get_developers(attrfile_filepath, days=365, zip_format=True):
    """ Returns loc count (*1000) based on the project's attribute file.

    :param days:
    :param attrfile_filepath:
    :param zip_format: True if csv is zipped, otherwise False
    :return: loc count (*1000)
    """
    attributes = read_csv_attrs(attrfile_filepath, sep=',', zip_format=zip_format)
    data = attributes.to_dict()
    developers = set()
    for _ in sorted(['author_list_' + str(days)]):
        for developer in data['author_list_' + str(days)][0].split(';'):
            developers.add(developer)
    return sorted(developers)
