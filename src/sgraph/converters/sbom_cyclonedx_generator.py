import copy
import re
import uuid
from datetime import datetime
import json
import sys
from collections import Counter, defaultdict

from sgraph import SGraph, SElement
from sgraph.converters.external_root_semantics import (canonical_purl_name,
                                                       repair_npm_package_name)

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
    #
    # A licence deliberately does NOT qualify, and neither does a hash: both are facts ABOUT a
    # package, never evidence that the element carrying one IS a package. Admitting on a licence
    # published an element the model never claimed was installed — including elements with no
    # incoming reference at all, which then appeared as declared dependencies of an estate that
    # never referenced them — and, on the import graph, an unresolved code symbol whose purl type
    # falls back to 'generic': a licence on /External/Python/starlette/responses/Response emitted
    # 'pkg:generic/Response', a generic-ecosystem package named after a Python class. The clause
    # cost zero rows when it was removed (External elements carrying 'license': 0 across the 16
    # stored models, 0 across three produced by the current analyzer set), so nothing relied on
    # it; what it did carry was a silent emission for the first producer to stamp the attribute.
    return 'version' in elem.attrs or ' of version ' in elem.name or ' of tag ' in elem.name \
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
# This table fixes the purl TYPE only. Names are now canonicalised where their definitions
# license it — an npm scope's leading '@' is percent encoded and a pypi name is folded — but the
# module still emits every other name unencoded, so a spec-valid type does not by itself make a
# purl spec-conforming.
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
# pypi's '_' to '-' normalization IS now applied, at the point the purl is built, so pypi refs
# arrive here already folded and this entry never changes one. It is retained as a guard for refs
# constructed elsewhere — bom_ref's callers, and anything reading a stored purl — rather than as a
# live fold. nuget's is the only fold that can still change a generator-built ref, because its names
# are emitted with the casing the model gave them and its definition sets case_sensitive true. That
# is a statement of capability, not of observation: measured across the stored models, the pypi fold
# joins two spellings in two documents and the nuget fold joins none, despite some three hundred
# mixed-case nuget ids — no two of them collide.
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

    Folds the key only. For nuget the emitted purl still keeps whatever casing the model gave it,
    because rewriting it would change the identifier a consumer resolves — that is a migration,
    not a deduplication, and it was not what this fix bought. For pypi that migration has since
    been made deliberately, with its own measurement and release note, so those refs arrive
    already folded and this function finds nothing left to fold in them.

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


NAME_RESOLUTION_PROPERTY = 'packageNameResolution'


def resolved_purl(elem, v):
    """Build the purl of an element, repairing an install-path identity, and report both.

    :param elem: the external element to describe
    :param v: the version string of that element
    :return: (purl, repaired_name or None, properties). properties is non-empty only when the
             type was inferred or fell back, or when the name was repaired; a type resolved from
             an attribute naming an ecosystem, or from an ecosystem-named ancestor, is not a
             guess and gets no property.

    The repair is applied once, after the type is resolved and before the version splice. That
    position is forced rather than chosen: the maven branch returns earlier and must not be
    reached by it, the docker branch replaces pkgid with a path of its own, and FOUR returns
    follow the splice point - a per-branch repair would apply to one of them and miss three.

    The name leaves through the return value because the caller needs it too: the component's
    'name' field is built from the element name a second time, outside this function, and a
    repaired purl beside an unrepaired name would name a package the document does not identify.
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
            # Returns before the repair seam: a maven id is not a path.
            return maven, None, properties
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
    # The version gate is the only guard on the repair ITSELF, and valid_for_bom blocks two
    # further routes to emission today — the parent_version-only route and the 'versions' plural
    # route both compute a repair that then emits nothing. It reads the stripped parameter
    # rather than the element: bom_ref is public and its caller may pass a version the element
    # does not carry, and dedup_key keys on the resulting ref, so disagreeing about a version
    # here would split one package's identity in two. Stripped, because '^' alone is non-empty
    # before this line and empty after it.
    #
    # Ungated, the rule would rewrite 363 unversioned slash-bearing npm ids across the 16 stored
    # models: 'wrap-ansi-cjs/strip-ansi' carrying no version is one of them, and the same id
    # occurs versioned elsewhere. Two reasons the gate is explicit rather than left to the call
    # path. The tail-is-the-package rule was established by matching each element's version
    # against the leaf's and against the prefix's, so an unversioned element carries no evidence
    # either way and a repair there asserts what cannot be falsified. And an unversioned element
    # emits no component, so the repair could improve no purl — while an admission rule widened
    # later would, ungated, start emitting versionless rows for packages named only by the chain
    # that required them.
    repaired_name = None
    if pkgtype == 'npm' and v and '/' in pkgid:
        repair = repair_npm_package_name(pkgid)
        if repair is not None:
            # The rule id is returned for the per-rule counters the coverage report will keep;
            # the disclosed text is the same for both rules, because what a consumer needs is
            # the id the model gave, not which branch matched it.
            repaired_name = repair[0]
            properties.append({
                'name': NAME_RESOLUTION_PROPERTY,
                'value': f'repaired from install path: {pkgid}'
            })
            pkgid = repaired_name

    # Canonicalised ONCE, before the four returns below, rather than per branch: a purl type
    # added later inherits the rule instead of needing its own copy. The id only — the component's
    # 'name' field keeps whatever the model said, because the model's spelling is still true and a
    # provenance property on 1 224 rows would duplicate a field that is already there. A1 is the
    # opposite case: it rewrites the name, because there the name denoted nothing.
    pkgid = canonical_purl_name(pkgtype, pkgid)

    # Both rules live here rather than in each branch above, so a purl type added later inherits
    # them. The maven branch returns before reaching this point and applies the unresolved rule
    # itself through the same predicate; a maven version is a POM <version> and never a URL.
    if is_unresolved_version(v):
        return f'pkg:{pkgtype}/{pkgid}', repaired_name, properties
    if URL_SHAPED_VERSION.match(v):
        # Disclosed rather than dropped: the raw value stays in the component's version field,
        # and this property records why the purl carries no version.
        properties.append({'name': VERSION_SOURCE_PROPERTY, 'value': v})
        return f'pkg:{pkgtype}/{pkgid}', repaired_name, properties
    # The versionless-inclusion rule made an empty version reachable here, not only in
    # maven_purl: charset-rejected coordinates drop a versionless element to this splice.
    if not v:
        return f'pkg:{pkgtype}/{pkgid}', repaired_name, properties
    return f'pkg:{pkgtype}/{pkgid}@{v}', repaired_name, properties


def purl_for(elem, v):
    """Build the purl of an element and report how its package type was resolved.

    Backward-compatible 2-tuple wrapper around resolved_purl; do not remove. A caller that also
    needs the repaired name calls resolved_purl directly.
    """
    purl, _repaired_name, properties = resolved_purl(elem, v)
    return purl, properties


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


EVIDENCE_KEY = '_evidence'
SUPERSEDED_PROPERTY = 'supersededIdentifiers'


def _property(component, name):
    for prop in component.get('properties', []):
        if prop['name'] == name:
            return prop
    return None


def _set_property(component, name, value):
    """Update a property in place, or append it when the component does not carry it yet.

    In place, because the order properties were emitted in is part of the output: a merged row
    that re-rendered by appending would reorder every row it touched.
    """
    existing = _property(component, name)
    if existing is not None:
        existing['value'] = value
    else:
        component.setdefault('properties', []).append({'name': name, 'value': value})


def merge_component_evidence(surviving, duplicate):
    """Fold a duplicate into the component that survives, as the UNION of what both elements know.

    Which row survives is decided by document order, a traversal artefact, so first-wins is
    correct only when the duplicate carries nothing the survivor lacks — a condition no fold site
    ever checked. Measured before this existed: seven of sixteen affected rows lost evidence, two
    of them keeping sourceCodeReferences as a name while its value was emptied.

    The merge reproduces, for the union of the elements, exactly the deduplication the
    single-element path applies: references are a set, the indirect count is the cardinality of
    the union rather than a sum (the set is of elements, and the overlap is largest exactly when
    a merge is most likely), and the abstracted paths are not re-deduplicated because the
    single-element path does not re-deduplicate them either.
    """
    surviving_evidence = surviving.setdefault(EVIDENCE_KEY, {
        'direct': [],
        'indirect': [],
        'superseded': []
    })
    empty = {'direct': [], 'indirect': [], 'superseded': []}
    duplicate_evidence = duplicate.get(EVIDENCE_KEY, empty)
    for field in ('direct', 'indirect', 'superseded'):
        surviving_evidence[field] = sorted(
            set(surviving_evidence[field]) | set(duplicate_evidence[field]))

    duplicate_ref = duplicate.get('bom-ref')
    if duplicate_ref and duplicate_ref != surviving.get('bom-ref'):
        surviving_evidence['superseded'] = sorted(
            set(surviving_evidence['superseded']) | {duplicate_ref})

    _keep_the_shorter_depth(surviving, duplicate)

    # A repair provenance describes how THIS row's identity was derived. If any merged element
    # published the identity without being repaired, the row would be claiming a derivation that
    # is not the only account of it, so the claim is retracted rather than qualified.
    if _property(surviving, NAME_RESOLUTION_PROPERTY) is not None:
        if _property(duplicate, NAME_RESOLUTION_PROPERTY) is None:
            surviving['properties'] = [
                prop for prop in surviving['properties'] if prop['name'] != NAME_RESOLUTION_PROPERTY
            ]


def finalize_components(components):
    """Re-render the evidence-derived properties and drop the collection-time key.

    Called once per document at the render boundary rather than in any collection function:
    collection functions nest — the transitive walk folds across what the per-subtree collector
    returns — so a pass that must observe the completed state of a document belongs where the
    document is rendered. Idempotent, and it never touches a component that carries no evidence,
    which is every internal component.
    """
    for component in components:
        evidence = component.pop(EVIDENCE_KEY, None)
        if evidence is None:
            continue
        _set_property(component, 'sourceCodeReferences', ';'.join(sorted(set(evidence['direct']))))
        indirect = sorted(set(evidence['indirect']))
        if indirect:
            _set_property(component, 'indirectExposureCount', str(len(indirect)))
            _set_property(component, 'indirectExposurePaths', ';'.join(
                sorted('/'.join(d.split('/')[0:4]) for d in indirect)))
        if evidence['superseded']:
            _set_property(component, SUPERSEDED_PROPERTY, ';'.join(sorted(evidence['superseded'])))


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
        ref, repaired_name, purl_properties = resolved_purl(elem, v)

        direct_deps, indirect_deps = produce_source_code_references(elem, external_root)
        direct_deps_paths = ';'.join(sorted(direct_deps))

        custom_properties = []  # noqa
        custom_properties.append({'name': 'sourceCodeReferences', 'value': direct_deps_paths})
        custom_properties.extend(purl_properties)

        if indirect_deps:
            # str(): CycloneDX types properties[].value as a string, so a bare int here
            # fails schema validation and takes the whole document down with it.
            custom_properties.append(
                {'name': 'indirectExposureCount', 'value': str(len(indirect_deps))})

            abstracted_indirect = []
            for d in indirect_deps:
                x = d.split('/')[0:4]
                abstracted_indirect.append('/'.join(x))
            custom_properties.append({'name': 'indirectExposurePaths', 'value': ';'.join(sorted(abstracted_indirect))})

        component = {
            'name': repaired_name if repaired_name is not None else clean_name(elem.name),
            'version': v,
            'bom-ref': ref,
            'purl': ref,
            'type': cyclonedx_component_type(ref),
            'licenses': licenses,
            'scope': 'required',
            'properties': custom_properties,
            'description': '',
            # Raw paths, not the rendered strings: indirectExposurePaths is truncated to four
            # segments, so no string-level merge could recover the elements or count them.
            EVIDENCE_KEY: {
                'direct': list(direct_deps),
                'indirect': list(indirect_deps),
                'superseded': []
            }
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
                if len(other_excluding_parent) > 1 and noisy:
                    sys.stderr.write(
                        f'Processing {elem.getPath()} Other similarly named exists  : \n')
                    for e in other_excluding_parent:
                        sys.stderr.write('  - ' + e.getPath() + '\n')

    return output


def analyze_3rdparty(external_root, sbom):
    stack = list(external_root.children)
    other_externals_by_name: dict[str, list[SElement]] = {}
    while stack:
        elem = stack.pop(0)
        other_externals_by_name.setdefault(clean_name(elem.name), []).append(elem)
        stack += elem.children
    stack = list(external_root.children)
    surviving_component_by_key = {}
    while stack:
        elem = stack.pop(0)
        for bom_component in elem_as_bom_data(elem, other_externals_by_name, external_root):
            key = dedup_key(bom_component['bom-ref'])
            if key not in surviving_component_by_key:
                surviving_component_by_key[key] = bom_component
                sbom.components.append(bom_component)
            else:
                merge_component_evidence(surviving_component_by_key[key], bom_component)
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
        # Everything in this list is now final: the evidence collected while components were
        # folded is rendered into properties here, once, where every document passes.
        finalize_components(self.components)
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


# A manifest-declared edge's deptype names the manifest that declared it, and a declaration made
# in a development-only section carries the reserved 'dev_' prefix on that same name. So the
# prefix qualifies an edge, it does not name a different kind of edge, and a consumer that
# matches on the literal deptype silently loses every development declaration.
def deptype_base(deptype):
    """The deptype with the reserved development prefix removed.

    Only 'dev_' is stripped, separator included: 'development' is a deptype in its own right, not
    a prefixed one, and a prefix test without the separator would rewrite it into 'elopment'.
    """
    return deptype[len('dev_'):] if deptype.startswith('dev_') else deptype


# The deptype bases that mean "this package depends on that package", and are therefore the only
# edges the External -> External closure may follow.
#
# An allow-list rather than "follow every edge between two externals", because the External
# subtree also holds code-level edges — a symbol in one external referencing a symbol in another,
# recorded by the language analyzers with deptypes like 'inherits' or 'use'. Those describe how
# code is written, not what a manifest declares, and following them would fill the BOM with
# packages the project never depends on. A dependency a consumer cannot act on is worse than an
# absent one: it sends someone to patch a package that is not there.
#
# Stated as bases, so deptype_base is what a caller matches against and a development-section
# declaration traverses exactly like a production one. Whether such a package should then be
# scoped differently in the BOM is a separate question this registry does not answer.
#
# How much data stands behind each entry differs sharply, and the difference matters before a
# green test suite is read as evidence about real models. Measured across the stored model
# corpus, 'packagejson' — written by the npm audit analyzer — and 'package_reference' — written
# by the .NET analyzer — carry every External -> External edge in the models produced before the
# lockfile analyzers ran. On models produced with the production analyzer set (2026-08) the
# anticipatory entries turned out to be right: 'packagelock' carries 1 581 edges,
# 'dev_packagelock' 410 and 'pip' 208, every one of them covered by this registry and the
# uncovered set empty. The 410 dev_packagelock edges are the first real evidence that
# deptype_base's dev_ handling is load-bearing rather than anticipatory. What has not changed is
# the point: a green test suite is not evidence about real models, and each entry below still
# differs sharply in how much data stands behind it.
#
# 'pubspec' is anticipatory, deliberately kept. A deptype here names the MANIFEST that declared
# the edge, and the same name covers both the file -> package edge and the package -> package
# one: 'packagejson' is written by the manifest analyzer for the first and by the audit analyzer
# for the second. So when Dart's resolved closure is stored it arrives under this same name, and
# a missing entry fails silently — the closure comes back empty with nothing to say why. An
# unused entry cannot fail the opposite way, because the closure only follows edges whose SOURCE
# is already an external: a manifest file's own 'pubspec' edges never reach this test.
#
# 'nuget' is the weakest entry: unlike the others it names an installer rather than a manifest,
# and no analyzer emits it as a deptype at all — the .NET analyzer writes 'package_reference'.
# It is left in place because removing an entry can only lose edges, never gain wrong ones, but
# it is the one entry here with no emitter to point at.
PACKAGE_DEPENDENCY_DEPTYPES = {
    'packagelock',
    'packagejson',
    'pip',
    'nuget',
    'package_reference',
    'pubspec',
}

# How many package hops separate a component from the analyzed code: 1 for a package the code
# itself declares, 2 for one that package pulls in, and so on. Emitted only when the closure was
# actually walked, so its absence means the BOM makes no depth claim rather than "everything here
# is direct" — see _collect_3rdparty_for_subtree.
DEPENDENCY_DEPTH_PROPERTY = 'dependencyDepth'

# Where a package-to-package edge was declared, as the model path of the directory whose manifest
# declared it, and the separator joining several such paths. The External subtree is project-wide:
# every repository's resolved tree lands in the same External/<ecosystem> elements and shares the
# versioned ones, so an edge on its own says nothing about which repository put it there. Written
# by the analyzers; the spelling has to match theirs.
DECLARING_SCOPE_ATTRIBUTE = 'declared_in'
DECLARING_SCOPE_SEPARATOR = '//'


def _declared_within_reach(assoc, subtree_path):
    """Whether an edge's declaring scope and the subtree being collected are on the same line.

    Followed when the scope IS the subtree, an ancestor of it, or a descendant of it. Ancestor
    matters because a lockfile sits at a repository root while a directory-level document is
    rooted below it; descendant matters because a whole-project document contains every
    repository's lockfile. A plain "scope is under the subtree" test would empty the closure of
    every directory-level document, turning the flag into a no-op at exactly the granularity
    that is otherwise the expensive one.

    NO declaring scope means TRAVERSE, not skip. Every model stored before the attribute existed
    carries none, and the pip and NuGet analyzers still record none; reading absence as "skip"
    would silently empty those closures, which is a worse failure than the cross-repository
    contamination the attribute removes. Absence is unknown provenance, and unknown provenance
    keeps the behaviour that was there before.
    """
    declared = assoc.attrs.get(DECLARING_SCOPE_ATTRIBUTE)
    if not declared or not isinstance(declared, str):
        return True
    for scope in declared.split(DECLARING_SCOPE_SEPARATOR):
        if scope == subtree_path or subtree_path.startswith(scope + '/') \
                or scope.startswith(subtree_path + '/'):
            return True
    return False


def _collect_3rdparty_for_subtree(subtree_root, external_root, other_externals_by_name,
                                  transitive_externals=False, max_depth=None):
    """Collect the External dependencies of a subtree as BOM components.

    Two stages. The first walks the descendants of subtree_root and collects the externals they
    point at — the packages the analyzed code itself declares, at depth 1. The second, run only
    when transitive_externals is set, continues from those across External -> External
    associations, so the resolved closure a lockfile declares reaches the BOM too. Without it a
    package that only another package depends on is invisible here, however many such edges the
    model holds.

    The second stage follows ASSOCIATIONS ONLY, never element children. Findings — vulnerabilities
    and deprecations — are stored as children of versioned external elements, and a versioned
    element is itself a child of its package element, so a child-descending walk would emit
    findings and unreferenced sibling versions as though they were packages the project depends
    on.

    Uses the ORIGINAL (non-generalized) model so version info is preserved.

    :param transitive_externals: follow External -> External package edges (opt-in: the closure
        multiplies component counts, and the default output must stay what it was)
    :param max_depth: deepest depth to emit, or None for the whole closure
    :return: (components, edges, direct_refs) where edges are (from_bom_ref, to_bom_ref) pairs of
        the External -> External hops actually followed, and direct_refs the bom-refs of the
        packages the subtree itself declares. The callers build the dependency graph from the
        two: a hop becomes an entry of its own, and direct_refs is what keeps a declared package
        under the element even when some other package pulls it in as well.
    """
    if external_root is None:
        return [], [], []

    components = []
    # dedup key -> the bom-ref spelling that survived under it, and element -> that same ref, so
    # an element met twice is described once and always by the surviving spelling.
    surviving_ref_by_key = {}
    surviving_component_by_key = {}
    ref_by_element = {}
    edges = []
    seen_edges = set()

    def emit(elem, depth):
        """Describe an external once, and report the bom-ref under which it is known here."""
        if elem in ref_by_element:
            return ref_by_element[elem]
        ref = None
        for component in elem_as_bom_data(elem, other_externals_by_name, external_root):
            # Depth is published only in closure mode. Tagging depth 1 unconditionally would
            # change every existing default-mode BOM, which is exactly what the opt-in exists to
            # prevent; tagging nothing at depth 1 in closure mode would leave a consumer reading
            # an absent property as if it meant "direct". So: all components or none.
            #
            # Attached BEFORE the fold decides, so a discarded duplicate carries a depth for the
            # merge to compare. Previously it was attached only to survivors, which made "the
            # primitive received something to compare" a per-site accident rather than a contract.
            if transitive_externals:
                component.setdefault('properties', []).append({
                    'name': DEPENDENCY_DEPTH_PROPERTY,
                    'value': str(depth)
                })
            key = dedup_key(component['bom-ref'])
            if key in surviving_ref_by_key:
                merge_component_evidence(surviving_component_by_key[key], component)
                ref = surviving_ref_by_key[key]
                continue
            surviving_ref_by_key[key] = component['bom-ref']
            surviving_component_by_key[key] = component
            components.append(component)
            ref = component['bom-ref']
        if ref is not None:
            ref_by_element[elem] = ref
        return ref

    def is_external(elem):
        return elem.isDescendantOf(external_root) or elem == external_root

    direct_externals = []
    seen_direct = set()
    direct_refs = []
    seen_direct_refs = set()
    stack = [subtree_root]
    while stack:
        elem = stack.pop(0)
        for assoc in elem.outgoing:
            target = assoc.toElement
            if is_external(target):
                ref = emit(target, 1)
                if ref is not None and ref not in seen_direct_refs:
                    seen_direct_refs.add(ref)
                    direct_refs.append(ref)
                # Seeded whether or not it yielded a component: an unversioned package element
                # describes nothing itself, yet still carries the edges to what it resolves to.
                if target not in seen_direct:
                    seen_direct.add(target)
                    direct_externals.append(target)
        stack += elem.children

    if not transitive_externals:
        return components, edges, direct_refs

    # Breadth-first, so the depth first recorded for a package is the shortest route to it — the
    # same first-wins rule deduplication uses, and what keeps a cycle from deepening forever.
    subtree_path = subtree_root.getPath()
    visited = set(direct_externals)
    frontier = [(elem, 1) for elem in direct_externals]
    # What the closure declined to follow, for the report below.
    skipped_deptypes = set()
    skipped_edges = 0
    followed_any = False
    while frontier:
        elem, depth = frontier.pop(0)
        if max_depth is not None and depth >= max_depth:
            continue
        for assoc in elem.outgoing:
            base = deptype_base(assoc.deptype)
            if base not in PACKAGE_DEPENDENCY_DEPTYPES:
                # Recorded only for a target inside External: an edge from a package into the
                # analyzed code is not a package relation anybody expected to follow, and
                # counting it would drown the report in noise.
                if is_external(assoc.toElement):
                    skipped_deptypes.add(base)
                    skipped_edges += 1
                continue
            if not _declared_within_reach(assoc, subtree_path):
                continue
            target = assoc.toElement
            if not is_external(target):
                continue
            followed_any = True
            target_ref = emit(target, depth + 1)
            from_ref = ref_by_element.get(elem)
            # An edge is recorded even when its target was already reached by a shorter route:
            # the hop is real and a graph built from these pairs needs it. An endpoint that
            # describes no component (an unversioned package element) has no ref to name, so
            # that hop is traversed but not recorded.
            if from_ref is not None and target_ref is not None:
                edge = (from_ref, target_ref)
                if edge not in seen_edges:
                    seen_edges.add(edge)
                    edges.append(edge)
            if target not in visited:
                visited.add(target)
                frontier.append((target, depth + 1))

    _report_unrecognized_package_edges(subtree_path, followed_any, skipped_deptypes,
                                       skipped_edges)
    return components, edges, direct_refs


def _report_unrecognized_package_edges(subtree_path, followed_any, skipped_deptypes,
                                       skipped_edges):
    """Say so when the closure followed nothing while edges between externals were skipped.

    A closure that reaches nothing produces a document identical to the default one, so on its
    own it cannot be told apart from a model that simply holds no package-to-package edges. That
    ambiguity is not hypothetical: this module's own registry carries deptypes no analyzer emits,
    and without this line nothing in the output says so.

    Reported ONLY when nothing at all was followed. Externals also carry code-level edges — a
    symbol in one referencing a symbol in another — which the allow-list exists to skip, so a
    line per skipped edge would fire on nearly every model and teach a reader to ignore it. One
    line in the one case where the reader has a question to ask is the whole point.
    """
    if followed_any or not skipped_deptypes:
        return
    sys.stderr.write(
        f'Warning: the external dependency closure of {subtree_path} followed no edge, '
        f'while {skipped_edges} edge(s) between external elements were skipped as non-package '
        f'deptypes: {", ".join(sorted(skipped_deptypes))}\n')


def _external_dependency_entries(edges):
    """Turn External -> External hops into dependency graph entries, one per source package.

    Entries follow the order the hops were recorded — breadth-first outward from the declared
    dependencies — so the graph reads in the direction a consumer traces an exposure path, and
    stays byte-stable between runs.

    Hops are deduplicated again here even though the collector already does it per subtree: in
    the internal closure the hops of several elements are concatenated, and two elements
    depending on the same package see the same hop out of it.
    """
    depends_on_by_ref = {}
    for from_ref, to_ref in edges:
        depends_on = depends_on_by_ref.setdefault(from_ref, [])
        if to_ref not in depends_on:
            depends_on.append(to_ref)
    return [{'ref': ref, 'dependsOn': depends_on}
            for ref, depends_on in depends_on_by_ref.items()]


def _externals_hanging_off_element(refs, direct_refs, edges):
    """The external refs that belong in the element's own dependsOn.

    A package the analyzed code declares stays here however else it is reachable. A manifest
    declaration is a direct dependency, and another package happening to pull the same one in
    does not make it less so.

    A package reached only through another one moves under that other package instead. Listing
    it here would tell a consumer the element depends on it directly, which contradicts the
    dependencyDepth published on that very component and is exactly the claim the closure exists
    to refine.

    A package that no recorded hop names stays here too. An unversioned package element
    describes no component of its own, yet still carries the hops out of it, so a hop through one
    has no source ref to be recorded under. Its target is a real component either way, and a
    component named by no entry is unreachable in a consumer's tree — worse than one attached a
    level too shallow.

    With no hops at all — every default-mode document — nothing is attached elsewhere and this
    returns refs unchanged. The default path is that case of this rule, not a branch around it.
    """
    attached = {to_ref for _, to_ref in edges}
    direct = set(direct_refs)
    return [ref for ref in refs if ref in direct or ref not in attached]


# The purl type of a package published INSIDE the analyzed estate. Deliberately 'generic' and
# not the ecosystem's own type, whatever the ecosystem attribute says.
#
# pkg:npm/<name>@<v> asserts an identity in the public npm registry. Either that name is not
# published there, in which case the npm type buys nothing over generic, or it is and belongs to
# someone else, in which case this component silently inherits a stranger's advisories — the
# dependency-confusion-shaped false positive FALLBACK_PURL_TYPE already exists to avoid for an
# in-house binary mistyped as a NuGet package. Same reasoning, same answer: 'generic' is the only
# registered purl type with no default package repository, which is exactly what an internally
# published package is.
#
# One constant rather than a literal at the splice, so reversing this ruling is a one-line change
# rather than a hunt through the module.
INTERNAL_PACKAGE_PURL_TYPE = 'generic'

# Ecosystem and name are published as properties because the purl no longer carries either: the
# generic type erases the ecosystem, and a consumer that wants to know which registry the package
# would live in must not have to guess it back out of the identifier. Prefixed like
# 'softagram:internal' and 'softagram:via' on the same component, because all three state facts
# read out of the model rather than descriptions this generator derived.
PACKAGE_ECOSYSTEM_PROPERTY = 'softagram:packageEcosystem'
PACKAGE_NAME_PROPERTY = 'softagram:packageName'


def _package_identity_in_subtree(level_elem):
    """The package a content element publishes, or None when that is not unambiguous.

    Reads the ecosystem-neutral triple the analyzers stamp on a package element — 'package_name',
    'version' and 'ecosystem' — and nothing else. Deliberately NOT 'npm_package_name': that is a
    long-standing npm-only attribute stamped on the package.json FILE element with its own
    existing consumers, and this converter serves pip, NuGet, Maven, Dart and Go, where the same
    internal-package problem exists unchanged. Because the triple is neutral, an internal pip or
    NuGet package resolves through this function the day it carries one — there is no npm branch
    here and a second one must not be added.

    The version is read through extract_version so a package element inherits the module's single
    decoding rule; requiring the attribute itself is what keeps the search to elements the
    analyzer actually stamped, rather than admitting every element whose NAME happens to carry a
    version.

    Ambiguity is answered with None, never with a guess. A monorepo publishing several packages
    has no single identity, and naming the element after an arbitrary member of the set would be
    a claim no consumer could check. None reproduces the pre-identity behaviour exactly, so an
    ambiguous element costs a consumer nothing it had before.

    :param level_elem: the content element an SBOM or an inlined component describes
    :return: (ecosystem, name, version), with ecosystem None when the element does not name one,
             or None when the subtree publishes no package or several indistinguishable ones.
    """
    candidates = []
    stack = [level_elem]
    while stack:
        elem = stack.pop(0)
        name = elem.attrs.get('package_name', '').strip()
        if name and elem.attrs.get('version', '').strip():
            version = extract_version(elem)
            candidates.append((elem, elem.attrs.get('ecosystem', '').strip() or None, name,
                               version))
        stack += elem.children

    if not candidates:
        return None
    if len(candidates) > 1:
        # The package something OUTSIDE the element points at is the one this element is depended
        # upon AS. An incoming association from inside is one sibling package using another, and
        # says nothing about which package a depending element resolved.
        depended_upon = [candidate for candidate in candidates
                         if _has_incoming_from_outside(candidate[0], level_elem)]
        if len(depended_upon) != 1:
            return None
        candidates = depended_upon

    _, ecosystem, name, version = candidates[0]
    return ecosystem, name, version


def _has_incoming_from_outside(elem, level_elem):
    """Whether anything outside level_elem's subtree points at elem."""
    return any(not (assoc.fromElement == level_elem
                    or assoc.fromElement.isDescendantOf(level_elem))
               for assoc in elem.incoming)


def _internal_element_component(bom_ref, elem, serial):
    """A component describing an internal model element, inlined into another element's document.

    Publishes the package the element itself publishes, when it publishes one unambiguously.
    Before that, every such component was named after the ELEMENT — a repository or a directory —
    with no version and no purl, so a consumer saw a row named after a repository where the
    package belonged and had no identifier to resolve it by.

    The identity does not displace what the component already said: the element's location, its
    repository and the BOM-Link to its own document answer where this thing lives, which is a
    different question from which package it is, and a consumer tracing an exposure path needs
    both. The bom-ref stays the element's slug in particular — the dependency graph of this
    document and the BOM-Links of every other one name the element by it.

    :param serial: the 'urn:uuid:...' serial of the element's own standalone SBOM
    """
    component = {
        'bom-ref': bom_ref,
        'type': 'library',
        'name': elem.name,
        'version': '',
        'purl': '',
        'properties': [{'name': 'softagram:internal', 'value': 'true'}],
        'externalReferences': [{
            'url': f"urn:cdx:{serial.replace('urn:uuid:', '')}/1",
            'type': 'bom'
        }],
    }
    identity = _package_identity_in_subtree(elem)
    if identity is not None:
        ecosystem, name, version = identity
        component['name'] = name
        component['version'] = version
        component['purl'] = f'pkg:{INTERNAL_PACKAGE_PURL_TYPE}/{name}@{version}'
        component['properties'].append({'name': PACKAGE_NAME_PROPERTY, 'value': name})
        # An element that names no ecosystem still has an identity: the ecosystem decides no part
        # of the purl, so its absence omits one property rather than suppressing the package.
        if ecosystem is not None:
            component['properties'].append({
                'name': PACKAGE_ECOSYSTEM_PROPERTY,
                'value': ecosystem
            })
    _add_element_location(component, elem)
    _add_vcs_reference(component, elem)
    return component


def _depth_property(component):
    """The component's depth property dict, or None when it publishes no depth."""
    for prop in component.get('properties', []):
        if prop['name'] == DEPENDENCY_DEPTH_PROPERTY:
            return prop
    return None


def _keep_the_shorter_depth(surviving, duplicate):
    """Lower a surviving component's depth to a shorter route found through another element.

    Each element of an inlined chain is walked breadth-first on its own, so within one walk the
    first depth recorded is already the shortest. Across the merge it is not: the surviving
    component is simply the first ENCOUNTERED, and traversal starts at the root, so without this
    a package the root reaches at the end of a long chain keeps that depth even when an inlined
    element declares it outright.

    That is not merely imprecise, it is self-contradictory: the dependency graph of the SAME
    document keeps such a package under the element that declares it, so the document would
    assert a direct dependency and a distance of three about one package. Only the property is
    lowered —
    which component object survives, and the bom-ref every entry names, stay exactly as the merge
    decided.

    Absent on either side means no claim to compare: the depth property is published in closure
    mode only, and there it is on every 3rd-party component, so this is a guard rather than a
    case that arises.
    """
    surviving_depth = _depth_property(surviving)
    duplicate_depth = _depth_property(duplicate)
    if surviving_depth is None or duplicate_depth is None:
        return
    if int(duplicate_depth['value']) < int(surviving_depth['value']):
        surviving_depth['value'] = duplicate_depth['value']


def _transitive_components_and_dependencies(root_path, gen_elem_by_path, orig_elem_by_path,
                                            elem_serials, elem_bom_refs, orig_external_root,
                                            other_externals_by_name, transitive_externals=False,
                                            max_depth=None):
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
    external_edges = []

    def surviving(ref):
        """The spelling of ref that survived the cross-element merge."""
        return surviving_ref_by_key[dedup_key(ref)]

    surviving_component_by_key = {}
    for path in order:
        elem = orig_elem_by_path[path]
        ext_components, ext_edges, ext_direct = _collect_3rdparty_for_subtree(
            elem, orig_external_root, other_externals_by_name, transitive_externals, max_depth)
        refs = []
        for component in ext_components:
            key = dedup_key(component['bom-ref'])
            if key not in surviving_ref_by_key:
                surviving_ref_by_key[key] = component['bom-ref']
                surviving_component_by_key[key] = component
                if path != root_path:
                    component.setdefault('properties', []).append({
                        'name': 'softagram:via',
                        'value': elem.name
                    })
                components.append(component)
            else:
                merge_component_evidence(surviving_component_by_key[key], component)
            refs.append(surviving_ref_by_key[key])

        # Both ends of a hop take the same canonicalization the refs above take. A hop is
        # recorded per subtree, before the merge knows which spelling survives it, so an
        # uncanonicalized endpoint would name a component the merge folded away.
        hops = [(surviving(from_ref), surviving(to_ref)) for from_ref, to_ref in ext_edges]
        external_edges += hops
        external_refs_of[path] = _externals_hanging_off_element(
            refs, [surviving(ref) for ref in ext_direct], hops)

    # Reachable internal elements become components of this BOM. They describe model elements,
    # so they publish their location and repository too: a consumer of one transitive BOM can
    # then place every link of the exposure chain in the tree, not only the element the BOM is
    # rooted at.
    for path in order[1:]:
        components.append(_internal_element_component(elem_bom_refs[path],
                                                      orig_elem_by_path[path],
                                                      elem_serials[path]))

    # Multi-entry dependency graph: every ref resolves within this BOM
    dependencies = []
    for path in order:
        depends_on = list(external_refs_of[path])
        depends_on += [elem_bom_refs[target] for target in direct_internal[path]]
        dependencies.append({'ref': elem_bom_refs[path], 'dependsOn': depends_on})
    dependencies += _external_dependency_entries(external_edges)

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


def _sbom_for_content_element(orig_elem, ctx, transitive, transitive_externals=False,
                              max_depth=None):
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
            ctx['elem_bom_refs'], ctx['orig_external_root'], ctx['other_externals_by_name'],
            transitive_externals, max_depth
        )
    else:
        # 3rd party components from original model (preserves version info)
        sbom.components, external_edges, direct_external_refs = _collect_3rdparty_for_subtree(
            orig_elem, ctx['orig_external_root'], ctx['other_externals_by_name'],
            transitive_externals, max_depth
        )

        # Dependencies section
        # 3rd party purl refs, minus the ones a package-to-package hop attaches deeper down
        depends_on = _externals_hanging_off_element(
            [component['bom-ref'] for component in sbom.components], direct_external_refs,
            external_edges)

        # Internal cross-element dependencies from the generalized model. The BOM-Link federates
        # across documents for a consumer that follows it; the component is what a consumer that
        # does NOT follow links across uploads can see at all, and without it a dependency that
        # resolves inside the estate is invisible in practice.
        #
        # The component is emitted ONLY when the element publishes a package identity. Without
        # one it would be a row named after a repository or a directory, with no version and no
        # purl — the same shape the missing-identifier complaint was about — and since nothing in
        # the released product stamps the identity attributes yet, EVERY such row on a model
        # stored today would come out that way. So the default view stays exactly what it was
        # until the element can carry real coordinates, and the consumer loses nothing it has.
        #
        # The transitive view deliberately does NOT take this rule: inlining internal elements is
        # long-standing behaviour its consumers already receive, and suppressing rows there would
        # remove a dependency they can see today. Identity improves those rows; its absence must
        # not delete them.
        gen_elem = ctx['gen_elem_by_path'].get(path)
        if gen_elem is not None:
            inlined_targets = set()
            for assoc in gen_elem.outgoing:
                target_path = assoc.toElement.getPath()
                if target_path not in ctx['elem_serials'] or target_path == path:
                    continue
                if target_path in inlined_targets:
                    continue
                inlined_targets.add(target_path)
                target_serial = ctx['elem_serials'][target_path]
                target_ref = ctx['elem_bom_refs'][target_path]
                target_elem = ctx['orig_elem_by_path'][target_path]
                if _package_identity_in_subtree(target_elem) is not None:
                    sbom.components.append(_internal_element_component(
                        target_ref, target_elem, target_serial))
                    depends_on.append(target_ref)
                depends_on.append(
                    f"urn:cdx:{target_serial.replace('urn:uuid:', '')}/1#{target_ref}")

        dependencies = [{'ref': ref, 'dependsOn': depends_on}]
        dependencies += _external_dependency_entries(external_edges)

    data = sbom.as_cyclonedx_json()
    data['serialNumber'] = serial
    data['dependencies'] = dependencies
    return data


def _validated_max_depth(max_depth):
    """The cap as given, once it is one the closure can honour.

    A cap below 1 excludes every component the walk could emit, so it states nothing a caller can
    have meant. Treating it as 1 instead answers a different question than the one asked and says
    nothing about the substitution, which is worse than a refusal: what comes back looks exactly
    like what was requested.

    None is not a cap and stays None. Raised rather than clamped: clamping would keep the silence
    this removes, and the web API already turns a ValueError from this module into a validation
    error for the request that carried the value.
    """
    if max_depth is not None and max_depth < 1:
        raise ValueError(f'max_depth must be 1 or greater, or None for no cap; got {max_depth}')
    return max_depth


def generate_multi_from_sgraph(sgraph: SGraph, level: int = 3, transitive: bool = False,
                               transitive_externals: bool = False,
                               max_depth: int | None = None) -> list[dict]:
    """Generate one CycloneDX 1.7 SBOM per element at the given level.

    :param sgraph: The loaded SGraph model
    :param level: Tree depth at which to split into separate SBOMs
    :param transitive: Inline the transitive closure of internal dependencies into each SBOM
        so consumers that cannot follow BOM-Links across uploads (e.g. Dependency-Track) see
        the full exposure chain within one BOM
    :param transitive_externals: Also follow External -> External package edges, so a package
        reachable only through another package becomes a component tagged with its depth. Off by
        default: the closure multiplies component counts on models that carry it, and every
        existing consumer of the default output must keep receiving exactly what it received.
    :param max_depth: Deepest dependency depth to emit when transitive_externals is set, or None
        for the whole closure. 1 or greater.
    :return: List of CycloneDX SBOM dicts
    :raises ValueError: When max_depth is below 1
    """
    max_depth = _validated_max_depth(max_depth)
    ctx = _multi_sbom_context(sgraph, level)
    return [_sbom_for_content_element(orig_elem, ctx, transitive, transitive_externals, max_depth)
            for orig_elem in ctx['orig_content_elements']]


def generate_for_element_from_sgraph(sgraph: SGraph, element_path: str,
                                     transitive: bool = False,
                                     transitive_externals: bool = False,
                                     max_depth: int | None = None) -> dict:
    """Generate one CycloneDX 1.7 SBOM for the element at the given path.

    The element (typically /Project/repo or /Project/repo/dir) becomes the SBOM's metadata
    component and its descendants define the scope. Its peers at the same tree depth form the
    internal-dependency universe — the same universe the level-based multi mode uses — so with
    transitive=True the SBOM inlines the chain of directly and indirectly used internal
    elements and their 3rd-party components, exactly like the multi mode does per element.

    :param sgraph: The loaded SGraph model
    :param element_path: Path of the element to root the SBOM at
    :param transitive: Inline the transitive closure of internal dependencies
    :param transitive_externals: Also follow External -> External package edges, so a package
        reachable only through another package becomes a component tagged with its depth. Off by
        default: the closure multiplies component counts on models that carry it, and every
        existing consumer of the default output must keep receiving exactly what it received.
    :param max_depth: Deepest dependency depth to emit when transitive_externals is set, or None
        for the whole closure. 1 or greater.
    :return: One CycloneDX SBOM dict
    :raises ValueError: When no element exists at the path, when it is in the External subtree,
        or when max_depth is below 1
    """
    max_depth = _validated_max_depth(max_depth)
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

    return _sbom_for_content_element(orig_elem, ctx, transitive, transitive_externals, max_depth)


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
    parser.add_argument('--transitive-externals', action='store_true',
                        help='Also follow package-to-package edges inside External, so a '
                             'package reachable only through another package becomes a '
                             'component tagged with its dependencyDepth. Requires --level or '
                             '--element-path.')
    parser.add_argument('--max-depth', type=int, default=None,
                        help='Deepest dependency depth to emit with --transitive-externals. '
                             'Without it the whole closure is emitted.')
    args = parser.parse_args()

    if args.transitive and args.level is None and args.element_path is None:
        parser.error('--transitive requires --level or --element-path')

    # The legacy single-SBOM mode does not take either option, so accepting them there would
    # produce output that silently ignores what was asked for.
    if args.transitive_externals and args.level is None and args.element_path is None:
        parser.error('--transitive-externals requires --level or --element-path')

    if args.max_depth is not None and not args.transitive_externals:
        parser.error('--max-depth requires --transitive-externals')

    # Checked here as well as in the generators, so the message names the flag that was typed
    # rather than the parameter it maps to, and exits the way every other CLI misuse exits.
    if args.max_depth is not None and args.max_depth < 1:
        parser.error('--max-depth must be 1 or greater')

    g = SGraph.parse_xml_or_zipped_xml(args.model)

    if args.element_path is not None:
        result = generate_for_element_from_sgraph(g, args.element_path,
                                                  transitive=args.transitive,
                                                  transitive_externals=args.transitive_externals,
                                                  max_depth=args.max_depth)
    elif args.level is not None:
        result = generate_multi_from_sgraph(g, level=args.level, transitive=args.transitive,
                                            transitive_externals=args.transitive_externals,
                                            max_depth=args.max_depth)
    else:
        result = generate_from_sgraph(g)

    with open(args.output, 'w') as f:
        json.dump(result, f, indent=4)
