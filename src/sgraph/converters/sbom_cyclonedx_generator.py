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
    # The coordinate branch demands an incoming reference where the version branches do not:
    # version-management redirection leaves versionless elements behind after re-pointing their
    # references at versioned ones, and coordinates alone cannot tell those husks apart from a
    # BOM-managed dependency something still uses.
    #
    # parent_version alone deliberately does NOT qualify. Stored models predating
    # coordinate-carrying parents hold parent_version-only elements, and admitting them splices
    # the space-bearing element name into a generic purl. On models that do carry coordinates,
    # the coordinate branch already admits every parent, so a parent_version clause would add
    # nothing there and regress everything before.
    #
    # The coordinates must also be usable, not merely present: charset-rejected ones (a ${}
    # groupId resolved only in an external parent) build no maven purl, and versionless there
    # is nothing spec-clean left to emit — the fallback would splice the space-bearing element
    # name into a generic purl.
    return 'version' in elem.attrs or ' of version ' in elem.name or ' of tag ' in elem.name \
           or 'license' in elem.attrs \
           or (is_maven_coordinate(elem.attrs.get('groupId', ''))
               and is_maven_coordinate(elem.attrs.get('artifactId', ''))
               and bool(elem.incoming))


def extract_version(elem):
    """The element's version, with sgraph's path-separator encoding decoded.

    Decoding happens here rather than in purl_for so the component's disclosed version field
    carries the true value too, not only the purl. Every source is decoded, not just the two that
    read the version out of a name: an analyzer that copies a name-derived version into the
    attribute carries the encoding with it, and which source a given element used is not
    something the caller can see.
    """
    version = None
    if 'version' in elem.attrs:
        version = elem.attrs['version']
    elif 'versions' in elem.attrs:
        version = elem.attrs['versions']
    elif ' of version ' in elem.name:
        version = elem.name.split(' of version ')[-1].strip()
    elif ' of tag ' in elem.name:
        version = elem.name.split(' of tag ')[-1].strip()
    elif 'parent_version' in elem.attrs:
        version = elem.attrs['parent_version']
    if version is None:
        return None
    return version.replace(VERSION_PATH_SEPARATOR_ENCODING, '/')


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
# This table fixes the purl TYPE only. Package names are still emitted unencoded throughout this
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

# CycloneDX classifies a component by what it is, and 'library' — the value every component
# carried before this mapping — is wrong for an image. Consumers route components by type, so an
# image classified as a library is scanned as application code rather than as a base layer: the
# misclassification changes what a consumer does with the row, not merely how it reads.
# 'container' is a value of the component type enum in the CycloneDX 1.7 schema
# (bom-1.7.schema.json), described there as a packaging and/or runtime format that isolates
# software through virtualization technology.
#
# Keyed on the purl type rather than on the branch of purl_for that produced it, so a future
# producer of the same purl type is classified correctly without a second edit here.
#
# 'oci' is the purl type registered for the same artifact class, and nothing emits it today: the
# docker branch of purl_for is the only producer of an image purl in this module. It is mapped for
# forward compatibility, which is also why the oci case is asserted directly on the function below
# rather than through a fixture — no model can reach a purl the generator never builds, and a
# fixture that appeared to would be testing a hand-written string, not this code.
CYCLONEDX_TYPE_BY_PURL_TYPE = {
    'docker': 'container',
    'oci': 'container',
}

DEFAULT_CYCLONEDX_TYPE = 'library'

# Package identity is case-insensitive in some ecosystems and case-significant in others, so the
# deduplication key is folded only where the ecosystem's own purl type definition says two
# spellings are one package. nuget's records that the name is "case-preserving, but
# case-insensitive"; pypi's sets case_sensitive false.
#
# npm is deliberately absent even though its names have been lowercase by rule since 2015: its
# type definition sets case_sensitive true, because mixed-case packages predating that rule were
# grandfathered in, so JSONStream and jsonstream are two real packages. maven is case-significant
# in both coordinates, golang's names are lowercase by rule so folding would be a rule that never
# fires, and generic names are opaque. Folding any of them would merge two distinct components
# into one and lose a row — a worse defect than the duplicate it set out to remove.
#
# pypi also normalizes '_' to '-', which is deliberately NOT applied: that rewrites the name
# rather than its case, and belongs with the percent-encoding migration that is still deferred.
CASE_INSENSITIVE_PURL_TYPES = {'nuget', 'pypi'}


def purl_type_of(purl):
    """The type segment of a purl, or '' when the string is not one."""
    if not purl.startswith('pkg:'):
        return ''
    return purl[len('pkg:'):].split('/', 1)[0]


def cyclonedx_component_type(purl):
    """Map a purl to its CycloneDX component type, defaulting to 'library'.

    The type is read off the emitted purl rather than passed in alongside it, so a component's
    declared class and its identifier cannot disagree: there is one source of truth, the string
    the consumer actually receives.

    A string that is not a purl, including an empty one, takes the default. That is the value
    every component carried before this mapping existed, so an unparseable purl leaves the row
    exactly as it was rather than dropping it or inventing a class for it. None is not handled:
    purl_for always returns a string, and a guard for a caller that does not exist would be
    untested code asserting a contract nothing relies on.
    """
    return CYCLONEDX_TYPE_BY_PURL_TYPE.get(purl_type_of(purl), DEFAULT_CYCLONEDX_TYPE)


def dedup_key(bom_ref):
    """The identity under which two emitted components count as the same package.

    Folds the key only. The emitted purl keeps whatever casing the model gave it, because
    rewriting it to a folded form would change the identifier a consumer resolves — that is a
    migration, not a deduplication, and it is not what this fix buys.

    .lower() rather than .casefold(): these type definitions are about ASCII case, and Unicode
    caseless matching would additionally merge names the ecosystems keep distinct.
    """
    if purl_type_of(bom_ref) in CASE_INSENSITIVE_PURL_TYPES:
        return bom_ref.lower()
    return bom_ref


# Maven's model validator restricts groupId and artifactId to [A-Za-z0-9._-] at ERROR severity
# for every POM, and that set is a strict subset of the characters purl leaves unencoded. So a
# coordinate that passes this guard is spliced into the purl verbatim and needs no encoding
# step, which is what makes deferring encoding coherent rather than a shortcut.
MAVEN_COORDINATE = re.compile(r'^[A-Za-z0-9._-]+$')

# A version the analyzer captured before the build resolved it, in either dialect it is written
# in: ${...} is Maven and Gradle property syntax, $(...) is MSBuild's. Matched with fullmatch,
# deliberately: a version that merely contains an expression, such as '1.0-${suffix}', is partly
# known, and dropping the known part would change which components exist under a rule nobody has
# measured. Widening this to a substring search is the tempting simplification to refuse.
#
# '${}' and '$()' do not match, because '.+' requires content. An expression naming no property
# resolves to nothing in any build either, so the narrower reading costs nothing.
UNRESOLVED_VERSION = re.compile(r'\$\{.+\}|\$\(.+\)')

# sgraph encodes '/' inside an element name as '__slash__', and a version lifted out of such a
# name inherits the encoding. clean_name already decodes it out of names; versions were left raw,
# so both the disclosed version and the purl advertised a literal '__slash__' that matches
# nothing in any ecosystem.
VERSION_PATH_SEPARATOR_ENCODING = '__slash__'

# A version that is a URL names a place to fetch from, not a release. It identifies no published
# version and matches no advisory, so carrying it in the purl asserts a version that exists
# nowhere. Anchored at the start: a version that merely begins with a scheme-like word is not a
# URL, and one that merely contains a URL is partly known — the same reasoning that keeps
# UNRESOLVED_VERSION a fullmatch.
URL_SHAPED_VERSION = re.compile(r'^[a-zA-Z][a-zA-Z0-9+.-]*://')

# Names the reason a component has a disclosed version but a versionless purl, so a consumer can
# tell "no version was known" from "the known value was not a version".
VERSION_SOURCE_PROPERTY = 'versionSource'


def is_unresolved_version(version):
    """Whether a version is wholly a build-property expression, and so names no published release.

    One predicate for every purl type. The rule began inside maven_purl and was applied nowhere
    else, so every other ecosystem spliced the raw expression into its purl — a string that is
    either non-canonical raw or canonical-but-unmatchable percent-encoded, and matches nothing
    either way. maven_purl still routes through this rather than touching the pattern directly,
    so the maven path and the shared path cannot drift apart.
    """
    return bool(UNRESOLVED_VERSION.fullmatch(version))


def is_maven_coordinate(value):
    """Whether a value can be a Maven groupId or artifactId, and so a purl component.

    The dot check is not redundant with the pattern: '.' and '..' match it and are not ids.
    Maven's local repository layout uses coordinate ids verbatim as directory names, so
    accepting them would splice a path-traversal segment into the position where a namespace
    belongs. No real coordinate is a dot, so removing this clause leaves every test drawn from
    coordinate data green.
    """
    return bool(MAVEN_COORDINATE.fullmatch(value)) and value not in {'.', '..'}


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


def file_stem(elem):
    """The name of a referencing element with its own extension removed.

    The extension comes from file_extension rather than an independent rsplit('.'), so this
    inherits that helper's t="file" handling instead of adding a second, subtly different
    assumption about what a filename looks like. When file_extension resolved the extension from
    an ancestor rather than from this element, the name does not end with it and the whole name is
    returned — which is correct, since such an element is not a file and has no stem to speak of.
    """
    extension = file_extension(elem)
    if extension and elem.name.lower().endswith('.' + extension.lower()):
        return elem.name[:-(len(extension) + 1)]
    return elem.name


def referencing_files_named_after(elem):
    """The referencing files whose stem is this element's own name, sorted and deduplicated.

    An external whose name is exactly the stem of a file referencing it is not a package that file
    depends on — it IS that committed binary, recorded as an external because the analyzer had
    nowhere else to put it. A real package reference never looks like this: Ionic.Zip is referenced
    from Consumer.dll, not from Ionic.Zip.dll.

    Returns names, not paths, and sorted: the same binary is often referenced from several
    directories (the acceptance data has one referenced from both an installer output and an
    update directory), and those collapse to a single citation, while a genuine Foo.exe + Foo.dll
    pair stays two. Sorting mirrors the tie-breaking in infer_pkgtype_from_referencing_files and
    exists for the same reason: without it the emitted provenance would depend on association
    traversal order and the SBOM would stop being byte-stable between runs.
    """
    name = clean_name(elem.name).lower()
    matches = set()
    for association in elem.incoming + (elem.parent.incoming if elem.parent else []):
        if file_stem(association.fromElement).lower() == name:
            matches.add(association.fromElement.name)
    return sorted(matches)


def maven_purl(elem, version):
    """Build the maven purl from an element's coordinates, or None when it has none usable.

    The maven type definition makes the namespace required and names groupId as its native
    name, so a single-segment pkg:maven/<artifact> is not merely unencoded, it is unmatchable:
    Maven Central identity is groupId:artifactId. Both coordinates are read straight off the
    element, so this is a projection of what the model already holds, not an inference about it.

    None covers absent, partial and charset-rejected coordinates alike: they take the same
    residual, so the caller does not need to tell them apart.

    An unresolved version yields a versionless purl rather than one carrying the expression. A
    purl version must be percent-encoded, so the expression would be either non-canonical raw or
    canonical-but-unmatchable encoded; omitting it yields a purl that is canonical and still
    matches at package level. An empty version takes the same branch: appending it would leave a
    trailing '@', which is not a canonical versionless purl but a malformed versioned one. So
    does a semicolon-joined multi-value, the shape attribute transfer produces when two poms
    name one parent at different versions: it asserts a version that exists nowhere, while the
    raw value stays disclosed in the component's version field.
    """
    group_id = elem.attrs.get('groupId', '')
    artifact_id = elem.attrs.get('artifactId', '')
    if not (is_maven_coordinate(group_id) and is_maven_coordinate(artifact_id)):
        return None
    if not version or ';' in version or is_unresolved_version(version):
        return f'pkg:maven/{group_id}/{artifact_id}'
    return f'pkg:maven/{group_id}/{artifact_id}@{version}'


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
    # Coordinates read from attributes are not a guess, so no resolution property is appended.
    elif elem.parent.name == 'Maven':
        maven = maven_purl(elem, v.lstrip('^'))
        if maven is not None:
            return maven, properties
        pkgtype = FALLBACK_PURL_TYPE
        properties.append({
            'name': PURL_TYPE_SOURCE_PROPERTY,
            'value': 'maven coordinates unavailable'
        })
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
        # A committed binary must not be typed from the extension of the file that IS it. The
        # inference would answer nuget for a .exe, and pkg:nuget/softagram_windows-x64@1.95.0
        # asserts a public NuGet package that does not exist — a dependency-confusion-shaped false
        # positive for any consumer that resolves purls. 'generic' is the purl type with no default
        # package repository, which is exactly what a binary committed into source control is.
        #
        # Checked only when a type was actually inferred: with no inferred type the element already
        # takes the fallback, and claiming this reason there would cite evidence nothing acted on.
        # The provenance value REPLACES the inference one rather than joining it, so the component
        # never cites extension evidence the code declined to use.
        #
        # Known and accepted false positive: a vendored third-party binary — Newtonsoft.Json.dll
        # committed into the repo, referencing external Newtonsoft.Json — matches this rule and is
        # downgraded to generic, losing a real vulnerability match. Shipping as designed, on two
        # grounds that are measured rather than assumed: this branch is reached at all by only 17
        # components across 72 stored models (16 via exe, 1 via whl; no .dll has ever won a vote),
        # and every downgrade carries provenance naming the referencing files, so the decision is
        # auditable rather than silent.
        #
        # What is NOT claimed: that the vendored shape is rare. It does not occur anywhere in that
        # corpus, but the corpus holds essentially no vendored .NET content, so this is absence of
        # evidence, not evidence of absence. The one real discriminating case measured — aiortc, a
        # genuine public PyPI package inferred from a .whl in odoo-fullstack — is correctly spared,
        # because its name is not the stem of the file referencing it.
        self_reference_files = referencing_files_named_after(elem)
        if pkgtype is not None and self_reference_files:
            pkgtype = FALLBACK_PURL_TYPE
            properties.append({
                'name': PURL_TYPE_SOURCE_PROPERTY,
                'value': 'referencing file is the binary itself: ' + ','.join(self_reference_files)
            })
        elif pkgtype is not None:
            properties.append({
                'name': PURL_TYPE_SOURCE_PROPERTY,
                'value': 'inferred from referencing file extension: ' + ','.join(extensions)
            })
        else:
            pkgtype = FALLBACK_PURL_TYPE
            properties.append({'name': PURL_TYPE_SOURCE_PROPERTY, 'value': 'ecosystem unresolved'})

    v = v.lstrip('^')
    # Both rules live here rather than in each branch above, so a purl type added later inherits
    # them. The maven branch returns before reaching this point and applies the unresolved rule
    # itself through the same predicate; a maven version is a POM <version> and never a URL.
    if is_unresolved_version(v):
        return f'pkg:{pkgtype}/{pkgid}', properties
    if URL_SHAPED_VERSION.match(v):
        # Disclosed rather than dropped: the raw value stays in the component's version field,
        # and this property records why the purl carries no version.
        properties.append({'name': VERSION_SOURCE_PROPERTY, 'value': v})
        return f'pkg:{pkgtype}/{pkgid}', properties
    # The versionless-inclusion rule made an empty version reachable here, not only in
    # maven_purl: charset-rejected coordinates drop a versionless element to this splice.
    if not v:
        return f'pkg:{pkgtype}/{pkgid}', properties
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

    These components describe 3rd-party packages, not model elements, so they deliberately get
    neither the 'group'/'softagram:elementPath' pair nor a vcs reference from
    _add_element_location / _add_vcs_reference. Their identity is the purl; their position in
    the External subtree is an artefact of how the analyzer records dependencies, not a location
    a consumer should navigate by. Locating them would also misattribute them: the ancestor walk
    for a repo_url would climb out of External to the analyzed organisation's own repository.

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
            'type': cyclonedx_component_type(ref),
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
            key = dedup_key(bom_component['bom-ref'])
            if key not in seen_refs:
                seen_refs.add(key)
                sbom.components.append(bom_component)
        stack += elem.children


ELEMENT_PATH_PROPERTY = 'softagram:elementPath'


def _add_element_location(component, elem):
    """Publish where elem sits in the model, on a component that describes elem.

    'group' carries the parent's full path rather than its bare name so that two identically
    named groups under different roots stay distinguishable, and is omitted for a top-level
    element, whose parent is the model root and has no path of its own.

    The element's own path goes into a property because CycloneDX sets additionalProperties:
    false on component, leaving properties[] as the only schema-valid place for it. It is also
    the exact string deterministic_serial() hashes, so publishing it verbatim lets a consumer
    verify the document's identity without loading the model.

    Call once per component: this overwrites 'group' and appends to 'properties'. elem must be
    attached to a model. A detached element is not merely unsupported here, it is dangerous:
    getPath() would return a bare name with no leading slash, and publishing that as an
    elementPath yields a document a consumer cannot resolve and cannot detect as broken.
    Raising at the call site is the better failure.
    """
    parent_path = elem.parent.getPath()
    if parent_path:
        component['group'] = parent_path
    component.setdefault('properties', []).append({
        'name': ELEMENT_PATH_PROPERTY,
        'value': elem.getPath()
    })


def _add_vcs_reference(component, elem):
    """Publish the repository URL of elem, or of the nearest ancestor carrying one.

    The walk upwards is what makes the field correct rather than merely absent on a
    directory-level SBOM: the directory has no remote of its own, but the repository it lives
    in does, and that is the VCS location of its contents. The NEAREST carrier wins, because a
    sub-repo's own remote describes it better than its estate's does.

    A blank attribute is not an answer, so the walk continues past it. Stopping there would
    publish an empty url and, worse, suppress a real remote one level further up.

    Nothing is emitted when no ancestor carries a usable repo_url. An invented URL is worse
    than a missing one, because a consumer cannot tell it from a real one.

    Call this only for components describing INTERNAL model elements. Were it run against a
    3rd-party component in the External subtree, the walk would climb out to the estate root
    and attribute that package to the analyzed organisation's own repository.

    The walk deliberately reaches past the repository, up to the group and the estate root: it
    has no reliable way to recognise a repository boundary, since repo elements are not required
    to carry a 'type' attribute. The consequence is worth knowing. A repository that genuinely
    has no remote, sitting under a group that does, reports the GROUP's url as its own. The
    convention places repo_url on repo elements (docs/graph-conventions.md), which keeps this
    rare, but it is inheritance by proximity, not proof of ownership.
    """
    ancestor = elem
    while ancestor is not None:
        repo_url = ancestor.attrs.get('repo_url', '').strip()
        if repo_url:
            component.setdefault('externalReferences', []).append({'url': repo_url, 'type': 'vcs'})
            return
        ancestor = ancestor.parent


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
    # Location only, deliberately: this path builds its own vcs references just above, from the
    # element's typed CHILDREN rather than its ancestors, and fabricates a placeholder url for a
    # typed child that has no repo_url. That placeholder is a defect, but removing it changes
    # output for existing consumers and is a separate decision, so _add_vcs_reference is neither
    # adopted here nor allowed to touch it. Note the cardinality differs as a result: this path
    # can emit one vcs reference per child, where _add_vcs_reference emits at most one.
    _add_element_location(c, elem)
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
                    key = dedup_key(component['bom-ref'])
                    if key not in seen_refs:
                        seen_refs.add(key)
                        components.append(component)
        stack += elem.children
    return components


def _transitive_components_and_dependencies(root_path, gen_elem_by_path, orig_elem_by_path,
                                            elem_serials, elem_bom_refs, orig_external_root,
                                            other_externals_by_name):
    """Inline everything reachable from root_path into one self-contained BOM.

    Dependency-Track resolves dependency refs only within a single uploaded BOM: the BOM-Link
    URNs of the default mode are never followed into other projects, so the exposure chain
    root -> internal element -> vulnerable 3rd-party component stays invisible there. Inlining
    the reachable internal elements as components, together with the 3rd-party components of
    the whole chain, makes the chain resolvable inside one project. Each inlined internal
    component still points to its own standalone SBOM via an externalReference of type 'bom'.

    :return: (components, dependencies) for the SBOM of the element at root_path
    """
    # Breadth-first walk over the generalized cross-element graph
    order = [root_path]
    direct_internal = {}
    queue = [root_path]
    while queue:
        path = queue.pop(0)
        targets = []
        gen_elem = gen_elem_by_path.get(path)
        if gen_elem is not None:
            for assoc in gen_elem.outgoing:
                target_path = assoc.toElement.getPath()
                if target_path in elem_bom_refs and target_path != path \
                        and target_path not in targets:
                    targets.append(target_path)
        direct_internal[path] = targets
        for target_path in targets:
            if target_path not in order:
                order.append(target_path)
                queue.append(target_path)

    # 3rd-party components of every element in the chain, deduplicated on the same case-folded
    # key the per-subtree walk uses — a case-variant spelling arriving from another element of
    # the chain is the same package, not a second one. dependsOn refs are canonicalized to the
    # surviving spelling so no entry references a folded-away component. Components pulled in
    # through an internal element are annotated with the element that routed them here.
    components = []
    surviving_ref_by_key = {}
    external_refs_of = {}
    for path in order:
        elem = orig_elem_by_path[path]
        ext_components = _collect_3rdparty_for_subtree(elem, orig_external_root,
                                                       other_externals_by_name)
        refs = []
        for component in ext_components:
            key = dedup_key(component['bom-ref'])
            if key not in surviving_ref_by_key:
                surviving_ref_by_key[key] = component['bom-ref']
                if path != root_path:
                    component.setdefault('properties', []).append({
                        'name': 'softagram:via',
                        'value': elem.name
                    })
                components.append(component)
            refs.append(surviving_ref_by_key[key])
        external_refs_of[path] = refs

    # Reachable internal elements become components of this BOM. They describe model elements,
    # so they publish their location and repository too: a consumer of one transitive BOM can
    # then place every link of the exposure chain in the tree, not only the element the BOM is
    # rooted at.
    for path in order[1:]:
        serial_uuid = elem_serials[path].replace('urn:uuid:', '')
        internal_elem = orig_elem_by_path[path]
        internal_component = {
            'bom-ref': elem_bom_refs[path],
            'type': 'library',
            'name': internal_elem.name,
            'version': '',
            'purl': '',
            'properties': [{'name': 'softagram:internal', 'value': 'true'}],
            'externalReferences': [{'url': f'urn:cdx:{serial_uuid}/1', 'type': 'bom'}],
        }
        _add_element_location(internal_component, internal_elem)
        _add_vcs_reference(internal_component, internal_elem)
        components.append(internal_component)

    # Multi-entry dependency graph: every ref resolves within this BOM
    dependencies = []
    for path in order:
        depends_on = list(external_refs_of[path])
        depends_on += [elem_bom_refs[target] for target in direct_internal[path]]
        dependencies.append({'ref': elem_bom_refs[path], 'dependsOn': depends_on})

    return components, dependencies


def _content_elements_at_level(model, level):
    """Content elements at the given tree depth, and the model's External root.

    The External subtree is excluded from content wherever it appears on the way down: it holds
    the 3rd-party components the content elements depend on, not content itself.
    """
    content_elements = []
    external_root = None

    def collect(elem, current_level):
        nonlocal external_root
        if elem.name == 'External' and not elem.typeEquals('dir') and not elem.typeEquals('repo'):
            external_root = elem
            return
        if current_level == level:
            content_elements.append(elem)
            return
        if current_level < level:
            for child in elem.children:
                collect(child, current_level + 1)

    for root_child in model.rootNode.children:
        collect(root_child, 1)
    return content_elements, external_root


def _multi_sbom_context(sgraph, level):
    """Everything shared by the SBOMs of one level: content elements, lookups, identities.

    Uses the ORIGINAL model for 3rd-party component collection (preserves version info),
    and a generalized model for inter-element dependency detection.

    bom-refs are slugified element names, suffixed deterministically ('-2', '-3', ... in
    traversal order) when several content elements share a name — at repo level names are
    unique, but a dir-level split makes collisions ordinary (every repo has a 'src').
    """
    from sgraph.algorithms.generalizer import generalize_model

    orig_content_elements, orig_external_root = _content_elements_at_level(sgraph, level)

    # Build external name lookup from original model
    other_externals_by_name = {}
    if orig_external_root is not None:
        stack = list(orig_external_root.children)
        while stack:
            e = stack.pop(0)
            other_externals_by_name.setdefault(clean_name(e.name), []).append(e)
            stack += e.children

    generalized = generalize_model(sgraph, level_to_generalize=level)
    gen_content_elements, _ = _content_elements_at_level(generalized, level)

    # Path -> serial/ref/element mappings for all content elements (using original paths)
    elem_serials = {}
    elem_bom_refs = {}
    orig_elem_by_path = {}
    used_refs = {}
    for elem in orig_content_elements:
        path = elem.getPath()
        elem_serials[path] = deterministic_serial(path)
        ref = slugify_bom_ref(elem.name)
        used_refs[ref] = used_refs.get(ref, 0) + 1
        if used_refs[ref] > 1:
            ref = f'{ref}-{used_refs[ref]}'
        elem_bom_refs[path] = ref
        orig_elem_by_path[path] = elem

    return {
        'orig_content_elements': orig_content_elements,
        'orig_external_root': orig_external_root,
        'other_externals_by_name': other_externals_by_name,
        'elem_serials': elem_serials,
        'elem_bom_refs': elem_bom_refs,
        'orig_elem_by_path': orig_elem_by_path,
        'gen_elem_by_path': {elem.getPath(): elem for elem in gen_content_elements},
    }


def _sbom_for_content_element(orig_elem, ctx, transitive):
    """One CycloneDX SBOM dict for one content element of a level context."""
    sbom = SBOM()
    path = orig_elem.getPath()
    serial = ctx['elem_serials'][path]
    ref = ctx['elem_bom_refs'][path]

    # Metadata component
    sbom.metadata_component = {
        'bom-ref': ref,
        'type': 'application',
        'name': orig_elem.name,
        'version': '',
        'purl': '',
        'externalReferences': []
    }
    _add_element_location(sbom.metadata_component, orig_elem)
    _add_vcs_reference(sbom.metadata_component, orig_elem)

    if transitive:
        sbom.components, dependencies = _transitive_components_and_dependencies(
            path, ctx['gen_elem_by_path'], ctx['orig_elem_by_path'], ctx['elem_serials'],
            ctx['elem_bom_refs'], ctx['orig_external_root'], ctx['other_externals_by_name']
        )
    else:
        # 3rd party components from original model (preserves version info)
        sbom.components = _collect_3rdparty_for_subtree(
            orig_elem, ctx['orig_external_root'], ctx['other_externals_by_name']
        )

        # Dependencies section
        depends_on = []

        # 3rd party purl refs
        for component in sbom.components:
            depends_on.append(component['bom-ref'])

        # Internal cross-element dependencies from generalized model (BOM-Link URNs)
        gen_elem = ctx['gen_elem_by_path'].get(path)
        if gen_elem is not None:
            for assoc in gen_elem.outgoing:
                target_path = assoc.toElement.getPath()
                if target_path in ctx['elem_serials'] and target_path != path:
                    target_serial = ctx['elem_serials'][target_path].replace('urn:uuid:', '')
                    target_ref = ctx['elem_bom_refs'][target_path]
                    bom_link = f"urn:cdx:{target_serial}/1#{target_ref}"
                    if bom_link not in depends_on:
                        depends_on.append(bom_link)

        dependencies = [{'ref': ref, 'dependsOn': depends_on}]

    data = sbom.as_cyclonedx_json()
    data['serialNumber'] = serial
    data['dependencies'] = dependencies
    return data


def generate_multi_from_sgraph(sgraph: SGraph, level: int = 3,
                               transitive: bool = False) -> list[dict]:
    """Generate one CycloneDX 1.7 SBOM per element at the given level.

    :param sgraph: The loaded SGraph model
    :param level: Tree depth at which to split into separate SBOMs
    :param transitive: Inline the transitive closure of internal dependencies into each SBOM
        so consumers that cannot follow BOM-Links across uploads (e.g. Dependency-Track) see
        the full exposure chain within one BOM
    :return: List of CycloneDX SBOM dicts
    """
    ctx = _multi_sbom_context(sgraph, level)
    return [_sbom_for_content_element(orig_elem, ctx, transitive)
            for orig_elem in ctx['orig_content_elements']]


def generate_for_element_from_sgraph(sgraph: SGraph, element_path: str,
                                     transitive: bool = False) -> dict:
    """Generate one CycloneDX 1.7 SBOM for the element at the given path.

    The element (typically /Project/repo or /Project/repo/dir) becomes the SBOM's metadata
    component and its descendants define the scope. Its peers at the same tree depth form the
    internal-dependency universe — the same universe the level-based multi mode uses — so with
    transitive=True the SBOM inlines the chain of directly and indirectly used internal
    elements and their 3rd-party components, exactly like the multi mode does per element.

    :param sgraph: The loaded SGraph model
    :param element_path: Path of the element to root the SBOM at
    :param transitive: Inline the transitive closure of internal dependencies
    :return: One CycloneDX SBOM dict
    :raises ValueError: When no element exists at the path, or it is in the External subtree
    """
    path = element_path.rstrip('/')
    if not path.startswith('/'):
        raise ValueError(f"Element path must be absolute (start with '/'): {element_path}")

    if sgraph.findElementFromPath(path) is None:
        raise ValueError(f'No element found at path {path}')

    level = path.count('/')
    ctx = _multi_sbom_context(sgraph, level)
    orig_elem = ctx['orig_elem_by_path'].get(path)
    if orig_elem is None:
        # The element exists but the level walk never reached it: it is the External root
        # itself or lives inside the External subtree, which holds 3rd-party components,
        # not content to root an SBOM at.
        raise ValueError(f'Element at {path} is in the External subtree, not content')

    return _sbom_for_content_element(orig_elem, ctx, transitive)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Generate CycloneDX SBOM from sgraph model')
    parser.add_argument('model', help='Path to model XML file')
    parser.add_argument('output', help='Path to output SBOM JSON file')
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument('--level', type=int, default=None,
                       help='Generate one SBOM per element at this tree depth. '
                            'Without this flag, generates a single SBOM (legacy behavior).')
    scope.add_argument('--element-path', default=None,
                       help='Generate one SBOM rooted at the element at this path '
                            '(e.g. /Project/repo/dir); its descendants define the scope.')
    parser.add_argument('--transitive', action='store_true',
                        help='Inline the transitive closure of internal dependencies into '
                             'each SBOM so the full exposure chain resolves within one BOM '
                             '(for consumers like Dependency-Track that do not follow '
                             'BOM-Links across uploads). Requires --level or --element-path.')
    args = parser.parse_args()

    if args.transitive and args.level is None and args.element_path is None:
        parser.error('--transitive requires --level or --element-path')

    g = SGraph.parse_xml_or_zipped_xml(args.model)

    if args.element_path is not None:
        result = generate_for_element_from_sgraph(g, args.element_path,
                                                  transitive=args.transitive)
    elif args.level is not None:
        result = generate_multi_from_sgraph(g, level=args.level, transitive=args.transitive)
    else:
        result = generate_from_sgraph(g)

    with open(args.output, 'w') as f:
        json.dump(result, f, indent=4)
