import copy
import re
import uuid
from datetime import datetime
import json
import sys
from collections import Counter, defaultdict

from sgraph import SGraph, SElement

# Fixed namespace for deterministic UUID v5 generation of SBOM serial numbers.
SGRAPH_SBOM_NS = uuid.uuid5(uuid.NAMESPACE_URL, "https://softagram.com/sgraph/sbom")


def deterministic_serial(element_path: str) -> str:
    """Generate a deterministic urn:uuid: serial number from an element path.
    Same path always yields the same UUID (v5, namespace-based)."""
    return f"urn:uuid:{uuid.uuid5(SGRAPH_SBOM_NS, element_path)}"


def slugify_bom_ref(name: str) -> str:
    """Convert element name to a URL-safe bom-ref slug."""
    slug = name.lower().replace('_', '-').replace(' ', '-')
    slug = re.sub(r'[^a-z0-9-]', '', slug)
    slug = re.sub(r'-+', '-', slug).strip('-')
    return slug


def valid_for_bom(elem):
    return 'version' in elem.attrs or ' of version ' in elem.name or ' of tag ' in elem.name \
           or 'license' in elem.attrs


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
    for association in elem.incoming:
        name_pat = False
        for n in elem_name_patterns:
            if n in association.fromElement.name:
                name_pat = True
                break
        if name_pat:
            for deptype in deptypes:
                if association.deptype == deptype:
                    return True


def parents_parent_or_parent_name_equals(elem, name):
    if elem.parent.name == name:
        return True
    return elem.parent.parent and elem.parent.parent.name == name


# purl requires the type to start with a letter and to hold only [a-z0-9.-] in its canonical
# form (https://github.com/package-url/purl-spec), so an unresolved ecosystem cannot be spelled
# '???'. That yields purls a purl-parsing consumer rejects, leaving the component unmatchable
# against vulnerability data. 'generic' is the purl type for packages that fit no other type,
# and the only registered type with no default package repository — which is exactly the case
# for a binary committed into source control.
FALLBACK_PURL_TYPE = 'generic'

# Ecosystem signal for binaries committed straight into a repository: their repotype names no
# ecosystem (the analyzer's own declaration that it could not identify one) and they have no
# ecosystem-named ancestor, so the extension of the file referencing them is the only remaining
# signal.
#
# A type is inferred only when the inferred name is by itself a complete identifier for that type.
# nuget prohibits a namespace, so the assembly name is the whole identity and inference yields a
# complete, matchable identifier.
# maven requires a groupId that no file extension can supply, so inference cannot yield a complete
# identifier at all: .jar/.war/.aar are deliberately unmapped and fall through to the fallback.
# Same rule, opposite outcomes, because the type definitions differ. pypi and gem also prohibit a
# namespace, so whl/egg/gem are safe to infer.
#
# This fixes the purl TYPE only. Package names are still emitted unencoded throughout this
# module, so a spec-valid type does not by itself make a purl spec-conforming.
PURL_TYPE_BY_REFERENCING_EXTENSION = {
    'dll': 'nuget',
    'exe': 'nuget',
    'nupkg': 'nuget',
    'whl': 'pypi',
    'egg': 'pypi',
    'gem': 'gem',
}

PURL_TYPE_SOURCE_PROPERTY = 'purlTypeResolution'


def infer_pkgtype_from_referencing_files(elem):
    """Infer a purl type from the extensions of the files referencing this element.

    Associations onto the element's parent count as well, mirroring
    produce_source_code_references: a reference often lands on the package directory rather than
    on its versioned child. A reference onto a directory therefore votes for every element under
    that directory whose type is not resolved by some stronger signal.

    Ties are broken alphabetically so generated SBOMs stay byte-stable between runs, independent
    of association traversal order. Only the extensions that voted for the winning type are
    reported, so the provenance never cites evidence that argued for a different type.

    :param elem: the external element whose purl type is being resolved
    :return: (pkgtype, extensions) or (None, []) when no referencing file gives a hint.
    """
    votes = Counter()
    extensions_by_pkgtype = defaultdict(set)
    incoming = elem.incoming + (elem.parent.incoming if elem.parent else [])
    for association in incoming:
        extension = file_extension(association.fromElement).lower()
        pkgtype = PURL_TYPE_BY_REFERENCING_EXTENSION.get(extension)
        if pkgtype is not None:
            votes[pkgtype] += 1
            extensions_by_pkgtype[pkgtype].add(extension)
    if not votes:
        return None, []
    winner = min(votes, key=lambda candidate: (-votes[candidate], candidate))
    return winner, sorted(extensions_by_pkgtype[winner])


def purl_for(elem, v):
    """Build the purl of an element and report how its package type was resolved.

    :param elem: the external element to describe
    :param v: the version string of that element
    :return: (purl, properties) where properties is a list of CycloneDX property dicts. It is
             non-empty only when the type was inferred or fell back; a type resolved from an
             attribute naming an ecosystem, or from an ecosystem-named ancestor, is not a guess
             and gets no property.
    """
    properties: list[dict] = []
    pkgid = clean_name(elem.name)  # todo also use url like github.com/foo/reponame
    if elem.attrs.get('repotype', '') == 'NPM' or parents_parent_or_parent_name_equals(elem, 'NPM'):
        pkgtype = 'npm'
    elif elem.attrs.get('repotype', '') == 'APT' or parents_parent_or_parent_name_equals(
            elem, 'APT'):
        pkgtype = 'deb'
    elif elem.parent.name == 'Python' or elem.attrs.get(
            'repotype', '') == 'PIP' or parents_parent_or_parent_name_equals(elem, 'PIP'):
        pkgtype = 'pypi'  # ??
    elif elem.parent.name == 'Go':
        pkgtype = 'golang'
    elif elem.parent.name == 'Maven':
        pkgtype = 'maven'
    elif incoming_deps(elem, ['csproj', 'vbproj'],
                       ['assembly_ref']) or parents_parent_or_parent_name_equals(
                           elem, 'Assemblies'):
        pkgtype = 'nuget'
    elif '/External/Docker/Image/' in elem.getPath():
        pkgtype = 'docker'
        pkgid = elem.getPath().split('/External/Docker/Image/')[1]
        if ' of tag ' in pkgid:
            pkgid = pkgid.split(' of tag ')[0]
    else:
        pkgtype, extensions = infer_pkgtype_from_referencing_files(elem)
        if pkgtype is not None:
            properties.append({
                'name': PURL_TYPE_SOURCE_PROPERTY,
                'value': 'inferred from referencing file extension: ' + ','.join(extensions)
            })
        else:
            pkgtype = FALLBACK_PURL_TYPE
            properties.append({'name': PURL_TYPE_SOURCE_PROPERTY, 'value': 'ecosystem unresolved'})

    v = v.lstrip('^')
    return f'pkg:{pkgtype}/{pkgid}@{v}', properties


def bom_ref(elem, v):
    """Return only the purl of an element, without its type-resolution provenance.

    Backward-compatible public wrapper around purl_for; do not remove.
    """
    return purl_for(elem, v)[0]


# TODO License mapping not implemented
license_mapping_to_spdx_id = {}


def resolve_license_spdx_id(license):
    acceptable_licenses = {'MIT'}
    if license in acceptable_licenses:
        return license
    else:
        if license in license_mapping_to_spdx_id:
            return license_mapping_to_spdx_id[license]
        return 'UNKNOWN LICENSE'  # TODO What is the proper value for this?


def bom_licenses(elem):
    """
    TODO License handling is still work-in-progress.
    :param elem:
    :return:
    """
    license_url = {
        'MIT': 'https://spdx.org/licenses/MIT.html',
        'GPL': 'TODO',
        'SPDX_OTHER_TODO': ''
    }
    if 'license' in elem.attrs:
        license_spdx_id = resolve_license_spdx_id(elem.attrs['license'])
        return [{
            'license': {
                'id': license_spdx_id,
                'url': license_url.get(license_spdx_id, 'UNKNOWN')
            }
        }]
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


def produce_source_code_references(elem, external_root) -> tuple[list[str], list[str]]:
    """
    Produce direct and indirect source code references for the given element.
    :param elem: The element to analyze.
    :param external_root: The External element of the model (ancestor of all externals)
    :return: A tuple containing two lists:
             - direct_paths: List of direct source code reference paths.
             - indirect_dependencies: List of indirect dependency paths.
    """
    direct_paths = []
    handled = set()
    externals_set = set()

    for incoming_assoc in elem.incoming + elem.parent.incoming:
        if not incoming_assoc.fromElement.isDescendantOf(external_root):
            if incoming_assoc.fromElement not in handled:
                handled.add(incoming_assoc.fromElement)
                direct_paths.append(incoming_assoc.fromElement.getPath())
        else:
            if incoming_assoc.fromElement not in externals_set:
                externals_set.add(incoming_assoc.fromElement)

    indirect_dependencies_set = set()
    handled = set()
    for external_dependency in externals_set:
        stack = list((external_dependency,))
        while stack:
            e = stack.pop(0)
            if e not in handled:
                handled.add(e)
                if not e.isDescendantOf(external_root):
                    indirect_dependencies_set.add(e)
                else:
                    if e.incoming:
                        for inc in e.incoming:
                            if inc.fromElement not in handled:
                                stack.append(inc.fromElement)
                    if e.parent.incoming:
                        for inc in e.parent.incoming:
                            if inc.fromElement not in handled:
                                stack.append(inc.fromElement)

    indirect_dependencies = []
    for d in indirect_dependencies_set:
        indirect_dependencies.append(d.getPath())

    return direct_paths, indirect_dependencies


def elem_as_bom_data(elem, other_externals_by_name, external_root, noisy=False):
    """
    Example data of an element:
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

    :param elem: element
    :param other_externals_by_name: dict of external elements by name
    :param external_root:
    :param noisy: whether to print noisy output to stderr about possible issues
    :return:
    """
    licenses = bom_licenses(elem)
    output = []

    # Check for some legacy cases that were previosly the convention.
    if ';' in elem.attrs.get('version', '') or ';' in elem.attrs.get('versions', ''):
        raise Exception(
            f'Multiple versions associated to a single element {elem.getPath()}, cannot continue'
        )  # Multiple versions exist, as merged element (legacy way in sgraph, won't

    if valid_for_bom(elem):
        v = extract_version(elem)
        if v is None:
            v = ''
        ref, purl_properties = purl_for(elem, v)

        direct_deps, indirect_deps = produce_source_code_references(elem, external_root)
        direct_deps_paths = ';'.join(sorted(direct_deps))

        custom_properties = []  # noqa
        custom_properties.append({'name': 'sourceCodeReferences', 'value': direct_deps_paths})
        custom_properties.extend(purl_properties)

        if indirect_deps:
            custom_properties.append({'name': 'indirectExposureCount', 'value': len(indirect_deps)})

            abstracted_indirect = []
            for d in indirect_deps:
                x = d.split('/')[0:4]
                abstracted_indirect.append('/'.join(x))
            custom_properties.append({'name': 'indirectExposurePaths', 'value': ';'.join(sorted(abstracted_indirect))})

        component = {
            'name': clean_name(elem.name),
            'version': v,
            'bom-ref': ref,
            'purl': ref,
            'type': 'library',
            'licenses': licenses,
            'scope': 'required',
            'properties': custom_properties,
            'description': ''
        }
        output.append(component)
    else:
        if elem.incoming:
            dep_summary = defaultdict(int)
            for association in elem.incoming:
                dep_summary[(file_extension(association.fromElement), association.deptype)] += 1
            if len(other_externals_by_name[clean_name(elem.name)]) > 1:
                other_excluding_parent = list(
                    filter(lambda x: x != elem.parent,
                           other_externals_by_name[clean_name(elem.name)]))
                if len(other_excluding_parent) > 1:
                    if noisy:
                        sys.stderr.write(f'Processing {elem.getPath()} Other similarly named exists  : \n')
                    for e in other_excluding_parent:
                        sys.stderr.write('  - ' + e.getPath() + '\n')

    return output


def contains_incoming_ea_from_elems(e, elem_patterns):
    for association in e.incoming:
        for pat in elem_patterns:
            if pat in association.fromElement.name:
                return True
    return False


def combine_elems(elem, other_externals_by_name):
    if not valid_for_bom(elem):
        dep_summary = defaultdict(int)
        pkg_deps = defaultdict(int)
        for association in elem.incoming:
            if association.deptype != 'new' and association.deptype != 'inherits':
                pkg_deps[(file_extension(association.fromElement), association.deptype)] += 1
            dep_summary[(file_extension(association.fromElement), association.deptype)] += 1

        if len(other_externals_by_name[clean_name(elem.name)]) > 1:
            other_excluding_parent = list(
                filter(lambda x: x != elem.parent, other_externals_by_name[clean_name(elem.name)]))
            if len(other_excluding_parent) > 1:
                sys.stderr.write('Other similarly named exists     : ')

                all_n = other_excluding_parent
                for e in other_excluding_parent:
                    sys.stderr.write('  - ' + e.getPath() + ' ')
                    dep_summary_1 = defaultdict(int)
                    for association in e.incoming:
                        dep_summary_1[(file_extension(
                            association.fromElement), association.deptype)] += 1
                    sys.stderr.write('     * ' + str(dict(dep_summary_1)) + ' ')
                    for d in dep_summary_1:
                        e.attrs.setdefault('user_exts', set()).add(d[0])

                while len(all_n) > 1:
                    under_ext = None
                    better_place = None
                    for e in all_n:
                        if e.parent.name == 'External':
                            under_ext = e
                        else:
                            if better_place is not None and len(e.getPath()) > len(
                                    better_place.getPath()):
                                better_place = e
                            elif better_place is None:
                                better_place = e
                    if under_ext is None and better_place:
                        for n in all_n:
                            if n != better_place and n.parent == better_place.parent:
                                under_ext = n
                    if under_ext and better_place:
                        if better_place.parent.name == 'PIP' and contains_incoming_ea_from_elems(
                                under_ext, ['Dockerfile', '.py']):
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


def analyze_3rdparty(external_root, sbom):
    stack = list(external_root.children)
    other_externals_by_name: dict[str, list[SElement]] = {}
    while stack:
        elem = stack.pop(0)
        other_externals_by_name.setdefault(clean_name(elem.name), []).append(elem)
        stack += elem.children
    """
    stack = list(external_elem.children)
    while stack:
        elem = stack.pop(0)
        combine_elems(elem, other_externals_by_name)
        stack += elem.children
    """

    stack = list(external_root.children)
    seen_refs = set()
    while stack:
        elem = stack.pop(0)
        for bom_component in elem_as_bom_data(elem, other_externals_by_name, external_root):
            if bom_component['bom-ref'] not in seen_refs:
                seen_refs.add(bom_component['bom-ref'])
                sbom.components.append(bom_component)
        stack += elem.children


class SBOM:

    BASIC_INFO = {
        'bomFormat': 'CycloneDX',
        'specVersion': '1.7',
        'serialNumber': '<REPLACED LATER>',  # TODO what?
        'version': 1,
        'metadata': {
            'timestamp': '<REPLACED LATER>',
            'tools': [{
                'vendor': 'Softagram',
                'name': 'Softagram Analyzer',
                'version': '3.0'
            }]
        }
    }

    def __init__(self):
        self.metadata_component = {}
        self.components = []

    def as_cyclonedx_json(self):
        data = copy.deepcopy(SBOM.BASIC_INFO)

        # RFC 3339 format
        data['metadata']['timestamp'] = datetime.now().isoformat() + 'Z'

        data['metadata']['component'] = self.metadata_component
        data['components'] = self.components

        # RFC-4122: ^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$
        data['serialNumber'] = f'urn:uuid:{uuid.uuid4()}'
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
        'bom-ref': elem.getPath(),
        'type': 'application',
        'name': elem.name,
        'version': '',
        'purl': '',
        'externalReferences': []
    }
    for repo in elem.children:
        if 'type' in repo.attrs:
            if 'repo_url' in repo.attrs:
                c['externalReferences'].append({'url': repo.attrs['repo_url'], 'type': 'vcs'})
            else:
                # HACK
                c['externalReferences'].append({
                    'url': f'https://UNKNOWN-REPOSITORY_LOCATION/{repo.name}',
                    'type': 'vcs'
                })
    sbom.metadata_component = c


def generate_from_sgraph(sgraph: SGraph):
    """
    :return:
    """
    sbom = SBOM()
    for elem in sgraph.rootNode.children:
        for repo_or_ext in elem.children:
            if repo_or_ext.name == 'External' and repo_or_ext.getType() not in {'dir', 'repo'}:
                analyze_3rdparty(repo_or_ext, sbom)
        analyze_component_section(elem, sbom)
    return sbom.as_cyclonedx_json()


def _collect_3rdparty_for_subtree(subtree_root, external_root, other_externals_by_name):
    """Walk all descendants of subtree_root and collect External dependencies as BOM components.
    Uses the ORIGINAL (non-generalized) model so version info is preserved."""
    if external_root is None:
        return []
    components = []
    seen_refs = set()
    stack = [subtree_root]
    while stack:
        elem = stack.pop(0)
        for assoc in elem.outgoing:
            target = assoc.toElement
            if target.isDescendantOf(external_root) or target == external_root:
                for component in elem_as_bom_data(target, other_externals_by_name, external_root):
                    if component['bom-ref'] not in seen_refs:
                        seen_refs.add(component['bom-ref'])
                        components.append(component)
        stack += elem.children
    return components


def generate_multi_from_sgraph(sgraph: SGraph, level: int = 3) -> list[dict]:
    """Generate one CycloneDX 1.7 SBOM per element at the given level.

    Uses the ORIGINAL model for 3rd-party component collection (preserves version info),
    and a generalized model for inter-repo dependency detection.

    :param sgraph: The loaded SGraph model
    :param level: Tree depth at which to split into separate SBOMs
    :return: List of CycloneDX SBOM dicts
    """
    from sgraph.algorithms.generalizer import generalize_model

    # --- Original model: find content elements and External root ---
    orig_content_elements = []
    orig_external_root = None

    def collect_orig(elem, current_level):
        nonlocal orig_external_root
        if elem.name == 'External' and not elem.typeEquals('dir') and not elem.typeEquals('repo'):
            orig_external_root = elem
            return
        if current_level == level:
            orig_content_elements.append(elem)
            return
        if current_level < level:
            for child in elem.children:
                collect_orig(child, current_level + 1)

    for root_child in sgraph.rootNode.children:
        collect_orig(root_child, 1)

    # Build external name lookup from original model
    other_externals_by_name = {}
    if orig_external_root is not None:
        stack = list(orig_external_root.children)
        while stack:
            e = stack.pop(0)
            other_externals_by_name.setdefault(clean_name(e.name), []).append(e)
            stack += e.children

    # --- Generalized model: for inter-repo dependency detection ---
    generalized = generalize_model(sgraph, level_to_generalize=level)

    gen_content_elements = []
    gen_external_root = None

    def collect_gen(elem, current_level):
        nonlocal gen_external_root
        if elem.name == 'External' and not elem.typeEquals('dir') and not elem.typeEquals('repo'):
            gen_external_root = elem
            return
        if current_level == level:
            gen_content_elements.append(elem)
            return
        if current_level < level:
            for child in elem.children:
                collect_gen(child, current_level + 1)

    for root_child in generalized.rootNode.children:
        collect_gen(root_child, 1)

    # Build path -> serial/ref mappings for all content elements (using original paths)
    elem_serials = {}
    elem_bom_refs = {}
    for elem in orig_content_elements:
        path = elem.getPath()
        elem_serials[path] = deterministic_serial(path)
        elem_bom_refs[path] = slugify_bom_ref(elem.name)

    # Build generalized element lookup by path for cross-repo deps
    gen_elem_by_path = {elem.getPath(): elem for elem in gen_content_elements}

    sboms = []
    for orig_elem in orig_content_elements:
        sbom = SBOM()
        path = orig_elem.getPath()
        serial = elem_serials[path]
        ref = elem_bom_refs[path]

        # Metadata component
        sbom.metadata_component = {
            'bom-ref': ref,
            'type': 'application',
            'name': orig_elem.name,
            'version': '',
            'purl': '',
            'externalReferences': []
        }

        # 3rd party components from original model (preserves version info)
        sbom.components = _collect_3rdparty_for_subtree(
            orig_elem, orig_external_root, other_externals_by_name
        )

        # Dependencies section
        depends_on = []

        # 3rd party purl refs
        for component in sbom.components:
            depends_on.append(component['bom-ref'])

        # Internal cross-repo dependencies from generalized model (BOM-Link URNs)
        gen_elem = gen_elem_by_path.get(path)
        if gen_elem is not None:
            for assoc in gen_elem.outgoing:
                target_path = assoc.toElement.getPath()
                if target_path in elem_serials and target_path != path:
                    target_serial_uuid = elem_serials[target_path].replace('urn:uuid:', '')
                    target_ref = elem_bom_refs[target_path]
                    bom_link = f"urn:cdx:{target_serial_uuid}/1#{target_ref}"
                    if bom_link not in depends_on:
                        depends_on.append(bom_link)

        dependencies = [{'ref': ref, 'dependsOn': depends_on}]

        # Serialize
        data = sbom.as_cyclonedx_json()
        data['serialNumber'] = serial
        data['dependencies'] = dependencies
        sboms.append(data)

    return sboms


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Generate CycloneDX SBOM from sgraph model')
    parser.add_argument('model', help='Path to model XML file')
    parser.add_argument('output', help='Path to output SBOM JSON file')
    parser.add_argument('--level', type=int, default=None,
                        help='Generate one SBOM per element at this tree depth. '
                             'Without this flag, generates a single SBOM (legacy behavior).')
    args = parser.parse_args()

    g = SGraph.parse_xml_or_zipped_xml(args.model)

    if args.level is not None:
        result = generate_multi_from_sgraph(g, level=args.level)
    else:
        result = generate_from_sgraph(g)

    with open(args.output, 'w') as f:
        json.dump(result, f, indent=4)
