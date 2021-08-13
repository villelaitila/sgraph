import json
import sys
import time
from collections import defaultdict

from sgraph import SGraph


def valid_for_bom(elem):
    return 'version' in elem.attrs or ' of version ' in elem.name or ' of tag ' in elem.name or \
        'license' in elem.attrs


def extract_version(elem):
    if 'version' in elem.attrs:
        return elem.attrs['version']
    if 'versions' in elem.attrs:
        return elem.attrs['versions']
    if ' of version ' in elem.name:
        return elem.name.split(' of version ')[-1].strip()
    if ' of tag ' in elem.name:
        return elem.name.split(' of tag ')[-1].strip()


def incoming_deps(elem, elem_name_patterns, deptypes):
    for ea in elem.incoming:
        name_pat = False
        for n in elem_name_patterns:
            if n in ea.fromElement.name:
                name_pat = True
                break
        if name_pat:
            for deptype in deptypes:
                if ea.typeEquals(deptype):
                    return True


def bom_ref(elem, v):
    pkgid = elem.name  # todo also use url like github.com/foo/reponame
    if 'from' in elem.attrs:
        pkgid = elem.name

    pkgid = clean_name(pkgid)
    if elem.attrs.get('repotype', '') == 'NPM':
        pkgtype = 'npm'
    elif elem.attrs.get('repotype', '') == 'APT':
        pkgtype = 'deb'
    elif elem.parent.name == 'Python' or elem.attrs.get('repotype', '') == 'PIP':
        pkgtype = 'pypi'  # ??
    elif elem.parent.name == 'Go':
        pkgtype = 'golang'
    elif elem.parent.name == 'Maven':
        pkgtype = 'maven'
    elif elem.parent.name == 'Java':
        pkgtype = '??Java'
    elif incoming_deps(elem, ['csproj', 'vbproj'], ['assembly_ref']):
        pkgtype = 'nuget'
    elif '/External/Docker/Image/' in elem.getPath():
        pkgtype = 'docker'
        pkgid = elem.getPath().split('/External/Docker/Image/')[1]
        if ' of tag ' in pkgid:
            pkgid = pkgid.split(' of tag ')[0]
    else:
        if pkgid == 'react':
            print('b')

        pkgtype = '???'

    v = v.lstrip('^')
    return f'pkg:{pkgtype}/{pkgid}@{v}'


license_mapping = {'FOOBAR': 'XYZZY'}


def resolve_license_spdx_id(license, elem):
    acceptable_licenses = {'MIT'}
    if license in acceptable_licenses:
        return license
    else:
        if license in license_mapping:
            return license_mapping[license]
        return 'SPDX_OTHER_TODO'


def bom_licenses(elem):
    license_url = {
        'MIT': 'https://spdx.org/licenses/MIT.html',
        'GPL': 'TODO',
        'SPDX_OTHER_TODO': ''
    }
    if 'license' in elem.attrs:
        license_spdx_id = resolve_license_spdx_id(elem.attrs['license'], elem)
        return [{'license': {'id': license_spdx_id, 'url': license_url[license_spdx_id]}}]
    return []


def file_extension(e):
    if e is None or e.typeEquals('dir'):
        return ''
    elif e.typeEquals('file'):
        if '.' in e.name:
            return e.name.split('.')[-1]
        else:
            return ''
    return file_extension(e.parent)


def clean_name(name):
    if ' of version ' in name:
        return name.split(' of version ')[0].strip().replace('__slash__', '/')
    if ' of tag ' in name:
        return name.split(' of tag ')[0].strip().replace('__slash__', '/')
    return name.replace('__slash__', '/')


def elem_as_bom_data(elem, other_externals_by_name):
    """
    "bom-ref": "pkg:golang/github.com/0xAX/notificator@v0.0.0-20191016112426-3962a5ea8da1",
      "type": "library",
      "name": "github.com/0xAX/notificator",
      "version": "v0.0.0-20191016112426-3962a5ea8da1",
      "scope": "required",
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "8fd1da69f6a90db3db1910e4bba7bf1d1b3a28131c287896726d7ff526f19e5e"
        }
      ],
      "licenses": [
        {
          "license": {
            "id": "BSD-3-Clause",
            "url": "https://spdx.org/licenses/BSD-3-Clause.html"
          }
        }
      ],
      "purl": "pkg:golang/github.com/0xAX/notificator@v0.0.0-20191016112426-3962a5ea8da1",
      "externalReferences": [
        {
          "url": "https://github.com/0xAX/notificator",
          "type": "vcs"
        }
      ]

    :param elem:
    :return:
    """
    licenses = bom_licenses(elem)
    # type scope
    if 'version' in elem.attrs and ';' in elem.attrs['version']:
        usages = list(map(lambda x: x.fromElement.getPath(), elem.incoming))[0:3]

        for v in elem.attrs['version'].split(';'):
            ref = bom_ref(elem, v)
            data = {
                'name': clean_name(elem.name),
                'version': v,
                'bom-ref': ref,
                'purl': ref,
                'licenses': licenses,
                'scope': '?',
                'example-usages': usages,
                'description': ''
            }
            if 'resolved' in elem.attrs:
                # TODO Handle multiple values
                urls = elem.attrs['resolved'].split(';')
                if len(urls) > 1:
                    for url in urls:
                        if v in url:
                            # value comes from list: { 'vcs'| 'issue-tracker'| 'website'| '
                            # advisories'| 'bom'| 'mailing-list'| 'social'| 'chat'| 'documentation'|
                            # 'support'| 'distribution'| 'license'| 'build-meta'| 'build-system'|
                            # 'other'}

                            data['externalReferences'] = [{
                                'type':
                                    'distribution',  # todo https://github.com/CycloneDX/cyclonedx-dotnet-library/blob/a2118389b3dee0623771015e68f4574562146e4a/CycloneDX.Core/Models/v1_2/ExternalReference.cs  # noqa
                                'url': url
                            }]
                            break
                else:
                    data['externalReferences'] = [{
                        'type': 'distribution',
                        'url': [elem.attrs['resolved']]
                    }]
            yield data
        return

    if valid_for_bom(elem):
        v = extract_version(elem)
        if v is None:
            v = ''
        ref = bom_ref(elem, v)
        return {
            'name': clean_name(elem.name),
            'version': v,
            'bom-ref': ref,
            'purl': ref,
            'licenses': licenses,
            'scope': '?',
            'example-usages': list(map(lambda x: x.fromElement.getPath(), elem.incoming))[0:3],
            'description': ''
        }
    else:
        if elem.incoming:
            dep_summary = defaultdict(int)
            for ea in elem.incoming:
                dep_summary[(file_extension(ea.fromElement), ea.deptype)] += 1
            if len(other_externals_by_name[clean_name(elem.name)]) > 1:
                print('Other similarly named exists: ')
                for e in other_externals_by_name[clean_name(elem.name)]:
                    print('  - ' + e.getPath())
            print(elem.getPath())


def contains_incoming_ea_from_elems(e, elem_patterns):
    for ea in e.incoming:
        for pat in elem_patterns:
            if pat in ea.fromElement.name:
                return True


def combine_elems(elem, other_externals_by_name):
    if not valid_for_bom(elem):
        dep_summary = defaultdict(int)
        pkg_deps = defaultdict(int)
        for ea in elem.incoming:
            if ea.deptype != 'new' and ea.deptype != 'inherits':
                pkg_deps[(file_extension(ea.fromElement), ea.deptype)] += 1
            dep_summary[(file_extension(ea.fromElement), ea.deptype)] += 1

        if len(other_externals_by_name[clean_name(elem.name)]) > 1:
            print('Other similarly named exists: ')
            all_n = other_externals_by_name[clean_name(elem.name)]
            for e in all_n:
                print('  - ' + e.getPath())
                dep_summary_1 = defaultdict(int)
                for ea in e.incoming:
                    dep_summary_1[(file_extension(ea.fromElement), ea.deptype)] += 1
                print('     * ' + str(dict(dep_summary_1)))
                for d in dep_summary_1:
                    e.attrs.setdefault('user_exts', set()).add(d[0])

            if len(all_n) < 2:
                if len(pkg_deps) > 0:
                    print(dict(dep_summary))
                    print(elem.getPath())

            while len(all_n) > 1:
                under_ext = None
                better_place = None
                for e in all_n:
                    if e.parent.name == 'External':
                        under_ext = e
                    else:
                        if better_place is not None and \
                                len(e.getPath()) > len(better_place.getPath()):
                            better_place = e
                        elif better_place is None:
                            better_place = e
                if under_ext is None and better_place:
                    for n in all_n:
                        if n != better_place and n.parent == better_place.parent:
                            under_ext = n
                if under_ext and better_place:
                    if better_place.parent.name == 'PIP' and \
                            contains_incoming_ea_from_elems(under_ext, ['Dockerfile', '.py']):
                        print('MERGING:'
                              '  ' + better_place.getPath() + ' another elem ' +
                              under_ext.getPath())
                        better_place.merge(under_ext)
                        all_n.remove(under_ext)
                    else:
                        print(better_place.getPath())
                        break
                else:
                    break


def analyze_3rdparty(external_elem, sbom):
    stack = list(external_elem.children)
    other_externals_by_name = {}
    while stack:
        elem = stack.pop(0)
        other_externals_by_name.setdefault(clean_name(elem.name), []).append(elem)
        stack += elem.children

    stack = list(external_elem.children)
    while stack:
        elem = stack.pop(0)
        combine_elems(elem, other_externals_by_name)
        stack += elem.children

    stack = list(external_elem.children)
    other_externals_by_name = {}
    while stack:
        elem = stack.pop(0)
        other_externals_by_name.setdefault(clean_name(elem.name), []).append(elem)
        stack += elem.children

    stack = list(external_elem.children)
    while stack:
        elem = stack.pop(0)
        for bom_component in elem_as_bom_data(elem, other_externals_by_name):
            sbom.components.append(bom_component)
        stack += elem.children


class SBOM:
    BASIC_INFO = {
        'bomFormat': 'CycloneDX',
        'specVersion': '1.3',
        'serialNumber': 'urn:uuid:1f860713-54b9-4253-ba5a-9554851904af',  # TODO what?
        'version': 1,
        'metadata': {
            'timestamp': time.ctime(),
            'tools': {
                'vendor': 'Softagram',
                'name': 'Softagram analyzer',
                'version': '3.0.x'
            }
        }
    }

    def __init__(self):
        self.metadata_component = {}
        self.components = []

    def as_cyclonedx_json(self):
        data = SBOM.BASIC_INFO
        data['metadata']['component'] = self.metadata_component
        data['components'] = self.components
        return data


def analyze_component_section(elem, sbom):
    """
    ],
    "component": {
      "bom-ref": "pkg:golang/github.com/ProtonMail/proton-bridge@v1.6.3",
      "type": "application",
      "name": "github.com/ProtonMail/proton-bridge",
      "version": "v1.6.3",
      "purl": "pkg:golang/github.com/ProtonMail/proton-bridge@v1.6.3",
      "externalReferences": [
        {
          "url": "https://github.com/ProtonMail/proton-bridge",
          "type": "vcs"
        }
      ]
    }
    :param elem:
    :param sbom:
    :return:
    """
    c = {
        'bom-ref': '',
        'type': 'application',
        'name': elem.name,
        'version': '',
        'purl': '',
        'externalReferences': []
    }
    for repo in elem.children:
        if 'type' in repo.attrs:
            if 'repo_url' in repo.attrs:
                c['externalReferences'].append({'url': repo['repo_url'], 'type': 'vcs'})
            else:
                # HACK
                c['externalReferences'].append({
                    'url': f'https://github.com/softagram/{repo.name}',
                    'type': 'vcs'
                })
    sbom.metadata_component = c


def generate_from_sgraph(sgraph: SGraph):
    """
    :return:
    """
    sbom = SBOM()
    for elem in sgraph.rootNode.children:
        print(elem.name)
        for repo_or_ext in elem.children:
            if repo_or_ext.name == 'External' and repo_or_ext.getType() not in {'dir', 'repo'}:
                analyze_3rdparty(repo_or_ext, sbom)
        analyze_component_section(elem, sbom)
    return sbom.as_cyclonedx_json()


if __name__ == '__main__':
    g = SGraph.parse_xml(sys.argv[1])
    sbom = generate_from_sgraph(g)
    with open(sys.argv[2], 'w') as f:
        json.dump(sbom, f, indent=4)
