# coding: utf-8
"""What the children of the External subtree MEAN, as data rather than as tacit knowledge.

The children of `External` are not interchangeable. Three distinct kinds share the level —
package registries, import graphs and standard-library namespaces — and confusing them is the
single largest source of misidentification: an element under an import-graph root carrying no
version is normally a module reference, not a missing dependency.

That knowledge lived only in scattered producer comments, one of them ending in a question mark.
This module is where it lives now.

**This module imports nothing from sbom_cyclonedx_generator, ever.** Model facts arrive as
injected callables, which is what keeps the boundary one-directional and lets the registry be
tested without a model. The generator imports FROM here; `external_identification` imports from
both. The direction is `semantics <- generator <- identification` and it is acyclic.

Why `converters/` and not the package root: `docs/graph-conventions.md` opens with "The data model
itself is convention-agnostic", so a software-architecture registry at the package root would
contradict the library's own declared neutrality. `converters/` is already convention-committed.
"""
import builtins
import sys

KIND_REGISTRY = 'registry'
KIND_IMPORT_GRAPH = 'import graph'
KIND_STDLIB = 'stdlib'
KIND_FILESYSTEM = 'filesystem'
KIND_IMAGE = 'image'

ROLE_PACKAGE = 'package'
ROLE_VERSIONED_INSTANCE = 'versioned instance'
ROLE_SUBPATH = 'subpath'
ROLE_CODE_SYMBOL = 'code symbol'
ROLE_STDLIB = 'stdlib'
ROLE_FILESYSTEM = 'filesystem'
ROLE_IMAGE = 'image'
ROLE_FINDING = 'finding'
ROLE_UNKNOWN = 'unknown'

# What the producer says the version segment of an element name MEANS. The model has long used a
# single node shape -- `package of version X` -- for an installed release, for an advisory's
# affected range, and for a constraint declared in a manifest, with nothing distinguishing them.
# Only the first is inventory, and every consumer that had to infer which was which inferred
# differently.
VERSION_KIND_ATTRIBUTE = 'version_kind'

# A version element the producer invented so a finding would have a parent, named after the
# advisory's affected range. Nothing is installed at it.
VERSION_KIND_ADVISORY_RANGE = 'advisory_range'


def is_advisory_materialised(elem):
    """Whether the producer marked this element as an advisory's range rather than an install.

    Reads the attribute and NOTHING else. Absence means installed, which is what keeps every model
    analysed before the producer stamped it readable and byte-identical -- a structural fallback
    guessing from tree shape would change what those models emit, and the whole point of the
    attribute is to stop consumers guessing.

    Only the one value suppresses. 'declared_range' is the intended sibling and names a different
    population -- one element per declaring dependent, each with real incoming edges -- so keying
    on the mere presence of the attribute would silently drop those the day they are stamped.
    """
    return elem.attrs.get(VERSION_KIND_ATTRIBUTE) == VERSION_KIND_ADVISORY_RANGE


# Layer 1: root -> ecosystem, a TOTAL function whose unknown answer is None.
#
# Keyed by PATH FRAGMENT rather than by root name, because two roots one level below `Docker` mean
# opposite things: Docker/Image holds image identities, Docker/FilesysReference holds COPY sources,
# which are filesystem paths and not packages of any ecosystem. Lookup takes the longest key that
# is a segment-boundary prefix, so a root can carry a general rule and a specific one at once.
#
# None is a real answer, not a gap: it means "this root asserts no ecosystem", and a None
# ecosystem never joins, never matches and never types. PythonLibs is None deliberately — typing
# the standard library as pypi would make stdlib `dataclasses` joinable to the real PyPI backport
# package `dataclasses@0.8`, because a join requires both ecosystems to be equal and non-None.
ROOT_ECOSYSTEM = {
    'APT': 'deb',
    'Assemblies': 'nuget',
    'Docker': None,
    'Docker/FilesysReference': None,
    'Docker/Image': 'docker',
    'Go': 'golang',
    'Go/Standard_Go': None,
    'JVM': None,
    'JVM/Maven': 'maven',
    'Java': None,
    'Maven': 'maven',
    'NPM': 'npm',
    'PIP': 'pypi',
    # An analyzer's catch-all bucket is a filesystem-shaped namespace, not a registry one:
    # the pip analyzer files what it could not resolve here, and read as a registry namespace
    # every node beneath it becomes a package the BOM failed to identify — coverage failures
    # invented out of an analyzer's own bookkeeping. A row rather than a shape predicate
    # because exactly one such bucket exists corpus-wide.
    'PIP/Unknown Requirements Files': None,
    'Python': 'pypi',
    'PythonLibs': None,
}

# Layer 1b: root -> the KINDS it carries, as a set, because a root can be more than one thing.
# NPM carries both registry entries and import-graph entries; modelling kind as a property of the
# root alone would be a lie the first time anyone read it. A root absent from this table is
# unknown, which is a different fact from a root that is known to assert no ecosystem.
ROOT_KINDS = {
    'APT': {KIND_REGISTRY},
    'Assemblies': {KIND_REGISTRY},
    'Docker': set(),
    'Docker/FilesysReference': {KIND_FILESYSTEM},
    'Docker/Image': {KIND_IMAGE},
    'Go': {KIND_IMPORT_GRAPH},
    'Go/Standard_Go': {KIND_STDLIB},
    'JVM': set(),
    'JVM/Maven': {KIND_REGISTRY},
    'Java': set(),
    'Maven': {KIND_REGISTRY},
    'NPM': {KIND_REGISTRY, KIND_IMPORT_GRAPH},
    'PIP': {KIND_REGISTRY},
    'PIP/Unknown Requirements Files': {KIND_FILESYSTEM},
    'Python': {KIND_IMPORT_GRAPH},
    'PythonLibs': {KIND_STDLIB},
}

# Import name -> distribution name, ecosystem-keyed so an alias can never cross ecosystems.
IMPORT_NAME_ALIASES = {
    'pypi': {
        'yaml': 'pyyaml',
        'jwt': 'pyjwt',
        'dotenv': 'python-dotenv',
        'PIL': 'pillow',
        'cv2': 'opencv-python',
    },
}

# Modules removed from the standard library, which sys.stdlib_module_names no longer reports but
# stored models still contain. Frozen deliberately: the interpreter's own list is version-specific
# and this supplement records what that costs rather than hiding it.
STDLIB_SUPPLEMENT = frozenset({'distutils', 'imp', 'asynchat', 'smtpd'})

# Builtin FUNCTIONS and classes are not stdlib MODULES, but they are equally not packages, and
# routing them into 'unresolved code symbol' is a misfiling rather than a finer distinction: that
# category's name asserts something false about a name that resolves to the interpreter.
PYTHON_BUILTINS = frozenset(dir(builtins))

# HISTORICAL rather than current-Node, deliberately. 'sys' is the long-deprecated require('sys')
# alias and still appears in stored models; a list of what Node ships today would miss it and
# report a builtin as a missing npm package — a phantom a consumer would hunt for and never find.
NODE_BUILTINS = frozenset({
    'assert',
    'buffer',
    'child_process',
    'cluster',
    'console',
    'constants',
    'crypto',
    'dgram',
    'dns',
    'domain',
    'events',
    'freelist',
    'fs',
    'http',
    'http2',
    'https',
    'module',
    'net',
    'os',
    'path',
    'perf_hooks',
    'process',
    'punycode',
    'querystring',
    'readline',
    'repl',
    'stream',
    'string_decoder',
    'sys',
    'timers',
    'tls',
    'tty',
    'url',
    'util',
    'v8',
    'vm',
    'worker_threads',
    'zlib',
})


def _segment_prefixes(key):
    """Every segment-boundary prefix of a path fragment, longest first."""
    segments = key.split('/')
    for end in range(len(segments), 0, -1):
        yield '/'.join(segments[:end])


def ecosystem_of_root(root_key):
    """The purl type a root asserts, or None when it asserts none. Total, never raises.

    Longest matching prefix wins, on segment boundaries, so Go/Standard_Go answers separately from
    Go and 'Gopher' matches neither.
    """
    for candidate in _segment_prefixes(root_key):
        if candidate in ROOT_ECOSYSTEM:
            return ROOT_ECOSYSTEM[candidate]
    return None


def external_relative_segments(elem, external_root=None):
    """The element's path segments below the External root, outermost first.

    Pass the root when the caller has it: the stop condition then compares element IDENTITY
    rather than the name 'External', which is stricter and immune to a model that happens to hold
    an element of that name somewhere else in the tree.
    """
    segments = []
    node = elem
    while node is not None and node.parent is not None:
        segments.insert(0, node.name)
        if (node.parent is external_root
                if external_root is not None else node.parent.name == 'External'):
            return segments
        node = node.parent
    return []


def ecosystem_of(elem, external_root=None):
    """The ecosystem the root governing this element asserts, or None when it asserts none."""
    return ecosystem_of_root(external_root_key(elem, external_root))


def external_root_key(elem, external_root=None):
    """Which registry rule governs this element — the matched fragment, not its first segment.

    Returning the matched key rather than a bare root name is what lets a caller explain a
    classification: 'Docker/Image' and 'Docker/FilesysReference' are different answers, and a
    consumer of the report can see which rule fired.
    """
    segments = external_relative_segments(elem, external_root)
    for end in range(len(segments), 0, -1):
        candidate = '/'.join(segments[:end])
        if candidate in ROOT_ECOSYSTEM:
            return candidate
    return segments[0] if segments else ''


def is_root_node(elem):
    """Whether this element IS a registry root rather than something under one.

    A root node is structure, not an external: `/External/NPM` is where npm packages live, not a
    package called NPM. Decided by asking whether the element's own External-relative path is a
    key of the registry, so the registry stays the single place that knows what a root is and a
    two-level root like Docker/Image is recognised as readily as NPM.
    """
    return '/'.join(external_relative_segments(elem)) in ROOT_ECOSYSTEM


def is_stdlib_name(root_key, name):
    """Whether a name denotes the standard library or a builtin of the root's language.

    The name must already be DECODED — the caller applies clean_name, because decoding an element
    name is the generator's job and this module does not import it. Only the first dot-segment is
    tested: xml.etree.ElementTree is stdlib because xml is.

    The interpreter's own list is the source for Python, so it moves with the interpreter; the
    supplement records the modules that have since been removed, which is a cost of that choice
    made visible rather than hidden.
    """
    first_segment = name.split('.')[0].split('/')[0]
    if KIND_STDLIB in ROOT_KINDS.get(root_key, set()):
        return True
    ecosystem = ecosystem_of_root(root_key)
    if ecosystem == 'pypi':
        return (first_segment in getattr(sys, 'stdlib_module_names', frozenset())
                or first_segment in STDLIB_SUPPLEMENT or first_segment in PYTHON_BUILTINS)
    if ecosystem == 'npm':
        return first_segment in NODE_BUILTINS
    return False


IMAGE_INSIDE = 'inside_image'
IMAGE_IDENTITY = 'image_identity'
IMAGE_NAME_SEGMENT = 'image_name_segment'
IMAGE_UNTAGGED_CHAIN = 'untagged_image_chain'
IMAGE_UNMATCHED = 'unmatched_image_element'


def _tagged_ancestor_below_root(elem, root_depth):
    """Whether an ancestor strictly between elem and the image root carries a tag."""
    node = elem.parent
    while node is not None and len(external_relative_segments(node)) > root_depth:
        if ' of tag ' in node.name:
            return True
        node = node.parent
    return False


def _has_tagged_descendant(elem):
    """Whether anything beneath elem carries a tag, i.e. the image name continues downward."""
    stack = list(elem.children)
    while stack:
        node = stack.pop()
        if ' of tag ' in node.name:
            return True
        stack += node.children
    return False


def role_of(elem, root_key, *, has_version, is_stdlib_name, has_package_evidence=None):
    """What this element IS, given the root that governs it and two injected model facts.

    :param has_version: Callable[[SElement], bool], called on elem AND on elem.parent
    :param is_stdlib_name: Callable[[str, str], bool], (root_key, name) -> bool
    :param has_package_evidence: Callable[[SElement], bool] defeating the stdlib rule. A NO-OP
        inside the coverage classifier, which only ever sees elements that emit nothing, and
        load-bearing for every other caller — the join first. Do not delete it as dead: the
        classifier is the one caller for which it cannot fire.

    The version fact is a callable rather than a boolean precisely because a finding is decided
    STRUCTURALLY — a child of a versioned instance — which requires asking about the parent. That
    is what makes it survive a new advisory source whose id spelling this module has never seen;
    the name shape is corroborating evidence in a report, never the test.

    What is deliberately NOT here: whether a child of this element emits. Roles say what an
    element is; having an emitting child is a fact about coverage and belongs to the classifier.
    """
    kinds = ROOT_KINDS.get(root_key, set())

    # Findings are advisory nodes, and producers write them under REGISTRY roots. Ungated, the
    # rule fired inside an unpacked container image: '/Docker/Image/intra-app of tag build/usr' is
    # a directory whose parent carries a tag, and extract_version reads a tag as a version —
    # correct for building a purl, and no evidence of an advisory at all.
    #
    # Third instance of one defect: a classification rule reading tree position without asking
    # what kind of root it sits under. The subpath rule did it on registry roots and the image
    # rule did it at the wrong depth; this was the last rule left ungated.
    parent = elem.parent
    if (KIND_REGISTRY in kinds and parent is not None and parent.name != 'External'
            and has_version(parent)):
        return ROLE_FINDING
    segments = external_relative_segments(elem)
    root_depth = len(root_key.split('/')) if root_key else 0

    if KIND_FILESYSTEM in kinds:
        return ROLE_FILESYSTEM
    if KIND_IMAGE in kinds:
        structure = image_structure(elem, root_key)
        if structure == IMAGE_IDENTITY:
            return ROLE_IMAGE
        if structure == IMAGE_UNMATCHED:
            return ROLE_UNKNOWN
        return ROLE_FILESYSTEM

    # Stdlib-ness belongs to the DEPTH-1 element under the ecosystem root and is INHERITED by
    # everything beneath it: if urllib is stdlib then urllib/error is, and if odoo is not then
    # nothing under it is. Reading the element's own name instead finds 'http' in odoo/http and
    # reports a third-party package's internals as the standard library.
    #
    # And the rule is defeated by ANY evidence of a real package, not merely by a version: it
    # asserts a NEGATIVE — there is no package here — and a negative must clear the broadest
    # available contrary evidence, where A1's version gate is narrow because it ASSERTS an
    # identity and must demand specific evidence. punycode, string_decoder and process are
    # published npm packages that exist BECAUSE they shadow builtin names, which is the sharpest
    # demonstration that the name was never the signal.
    depth_one_name = segments[root_depth] if len(segments) > root_depth else elem.name
    if KIND_STDLIB in kinds or is_stdlib_name(root_key, depth_one_name):
        if has_package_evidence is None or not has_package_evidence(elem):
            return ROLE_STDLIB
    if has_version(elem):
        return ROLE_VERSIONED_INSTANCE
    if not kinds:
        return ROLE_UNKNOWN
    if len(external_relative_segments(elem)) <= 2:
        return ROLE_PACKAGE

    # Deeper than package depth, and what that MEANS depends on the root's kind.
    #
    # A subpath is an import-graph concept: it exists because code imported a path inside a
    # package. Under a pure registry root there is no such thing — PIP/django/django is the
    # instance node of the package django, and calling it a subpath reports the instance as
    # covered by its own package, which is true, useless, and absorbs rows that belong in the
    # residue. /PIP/whitenoise/whitenoise is exactly that: a package candidate with no version,
    # counted as covered because of a rule that never asked what kind of root it was under.
    if KIND_IMPORT_GRAPH not in kinds:
        return ROLE_PACKAGE

    # NPM carries both kinds, so the two structures are identical — a child of a package element —
    # and the VERSION is the only thing that separates a versioned instance from an import
    # subpath. That is a legitimate use of the version, and it is NOT the refuted one: separating
    # an install path from an import subpath was settled by NAME SHAPE, because a slash inside a
    # single element's name is a different structure from nested elements. Here the structures
    # coincide and the version is the only discriminator there is.
    return ROLE_SUBPATH


def image_structure(elem, root_key):
    """Which part of an image an element under Docker/Image is: four cases and a residual.

    ' of tag ' is a BOUNDARY marker, not an identity marker. Everything above it is part of the
    image's NAME — ghcr.io and astral-sh are segments of one name, not three images — and
    everything below it is the image's filesystem.

    The identity clause is narrow on purpose. Written as "carries a tag, or has no tagged
    descendant" it was a rule for a LEAF applied to a TREE: a locally built image that was never
    tagged made every element of its filesystem an identity, root to leaf, so build/app/package.json
    was reported as a package the BOM failed to identify. What distinguishes that case is that it
    is a CHAIN, not that it lacks a tag — the eight genuinely untagged single references are real
    dependencies with an implicit :latest and must stay identities.

    The residual matters as much as the cases. The clause set this replaces was TOTAL, so its own
    instruction to report anything matching nothing could never fire: a total rule set has no
    residual, and an unmeasured shape got a default instead of a question.
    """
    root_depth = len(root_key.split('/')) if root_key else 0
    segments = external_relative_segments(elem)
    if _tagged_ancestor_below_root(elem, root_depth):
        return IMAGE_INSIDE
    if ' of tag ' in elem.name:
        return IMAGE_IDENTITY
    if len(segments) == root_depth + 1 and not elem.children:
        return IMAGE_IDENTITY
    if _has_tagged_descendant(elem):
        return IMAGE_NAME_SEGMENT

    head = elem
    while len(external_relative_segments(head)) > root_depth + 1 and head.parent is not None:
        head = head.parent
    size, tagged = 0, False
    stack = [head]
    while stack:
        node = stack.pop()
        size += 1
        tagged = tagged or ' of tag ' in node.name
        stack += node.children
    if not tagged and size > 1:
        return IMAGE_UNTAGGED_CHAIN
    return IMAGE_UNMATCHED


def canonical_purl_name(pkgtype, name):
    """The spelling of a name that purl-spec licenses PUBLISHING for this type.

    Narrow on purpose. pypi is case-insensitive and replaces underscore with dash; its dot rule is
    scoped by the spec to distribution FILE names, not to the name component, so dots are
    preserved here. npm and nuget are case-sensitive and are left alone.

    npm is the opposite: case_sensitive true, because old mixed-case packages were grandfathered
    in, and its definition states that the scope's leading '@' is always percent encoded. Only a
    LEADING '@' — an '@' anywhere else belongs to something that is not a scope, and a yarn
    protocol alias puts one in the version.

    Cross-reference: `match_key` is the OTHER operation and applies a wider rule. Publishing an
    identifier and matching two identifiers are not the same thing, and one function serving both
    would force a choice between a spec-conformant purl and a working join.
    """
    if pkgtype == 'pypi':
        return name.lower().replace('_', '-')
    if pkgtype == 'npm' and name.startswith('@'):
        return '%40' + name[1:]
    return name


def match_key(ecosystem, name):
    """The spelling two names must share to be the SAME package within one ecosystem.

    Wider than `canonical_purl_name` by design: pypi folds runs of dot, underscore and dash
    together per PEP 503, so `zope.interface` matches `zope-interface` while still being published
    with its dots. nuget folds case. npm is identity — its ids are case-sensitive and old
    mixed-case packages were grandfathered in.
    """
    if ecosystem is None:
        return None
    if ecosystem == 'pypi':
        folded = name.lower()
        result = []
        previous_was_separator = False
        for character in folded:
            if character in '-_.':
                if not previous_was_separator:
                    result.append('-')
                previous_was_separator = True
            else:
                result.append(character)
                previous_was_separator = False
        return ''.join(result)
    if ecosystem == 'nuget':
        return name.lower()
    return name


def repair_npm_package_name(name):
    """Return (package, rule_id) for an npm install path, or None when the name is already one.

    The npm lockfile analyzers record a nested install as the whole install path: the leading
    segments are the dependency chain that REQUIRED the package and the tail is the package
    itself. 'wrap-ansi-cjs/strip-ansi' is strip-ansi installed under wrap-ansi-cjs, and splicing
    it into a purl unchanged asserts a package published nowhere.

    One uniform rule: the tail is the package. A leading '@' marks the REQUIRER's scope and moves
    nothing — the opposite reading, repairing to the leading '@scope/pkg', was refuted on the
    versions these elements carry, which matched the leaf and never the prefix. The tail is two
    segments when it is itself scoped, which is why 'a/@scope/b' looks back one segment.

    Pure by design, taking no model and no corroboration predicate: a nested install exists
    precisely BECAUSE the required version differs from the one hoisted to the top level, so the
    leaf usually appears nowhere else in the model and a corroboration requirement would be
    anti-correlated with the cases the repair is for. It would also make an emitted identifier
    depend on what else happened to be analysed.

    Lives here rather than in the generator because it is pure string logic with two consumers:
    the generator APPLIES it to a purl under a version gate, and the coverage report READS it to
    learn which package an install-path name refers to, with no gate, because reading a name
    asserts nothing.

    A name whose TAIL is empty is refused rather than normalised: it is a malformity the repair
    cannot reason about, and inventing a reading for it is the defect this function removes. A
    doubled separator with a usable tail is not a malformity of that kind - 'a//b' installs 'b'.
    """
    segments = name.split('/')
    if len(segments) == 1:
        return None
    if name.startswith('@') and len(segments) == 2:
        return None
    if segments[-2].startswith('@'):
        tail, rule_id = '/'.join(segments[-2:]), 'install-path-scoped-leaf'
    else:
        tail, rule_id = segments[-1], 'install-path'
    if not tail or '' in tail.split('/'):
        return None
    return tail, rule_id
