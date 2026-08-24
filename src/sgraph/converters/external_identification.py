# coding: utf-8
"""Who is this external, and what do we fail to identify about it.

Half of what a BOM is for is telling a consumer what it does NOT cover. A component list alone
cannot say that: an external the analyzer saw and the generator dropped leaves no trace in the
document, so a consumer cannot distinguish "this estate depends on nothing else" from "we could
not identify the rest".

This module walks the External subtree, puts every element it meets into exactly one category,
and reports the categories with counts and sample paths.

**Anti-Goodhart, by construction rather than by policy.** A single coverage score would be gamed
the moment anyone was measured on it, and the cheapest way to raise it is to widen the
not-a-package filter. So: the buckets CONSERVE (they sum to an independently counted walk);
membership in the largest ones is PROVABLE (exhibit the covering component); there is no scalar,
only four outcome classes of distinct meaning; and there is NO numeric constant in this module
except SAMPLE_CAP, which a test asserts by parsing the source. The corpus these categories were
measured on was produced without the lockfile analyzers running, so a threshold tuned to it would
encode a measurement gap as a rule.

**Import direction:** this module imports from `external_root_semantics` and from
`sbom_cyclonedx_generator`. The generator must never import this module. It reads six names from
the generator — `valid_for_bom`, `extract_version`, `clean_name`, `bom_ref`, `dedup_key` and
`FALLBACK_PURL_TYPE`. The first three were foreseen; `bom_ref` and `dedup_key` are needed because
the report must distinguish elements that EMIT from the rows a consumer RECEIVES after folding,
and a purl builder has no pure home to be moved to the way the name repair did.
"""
from sgraph.converters.external_root_semantics import (
    ROLE_FILESYSTEM, ROLE_FINDING, ROLE_IMAGE, ROLE_PACKAGE, ROLE_STDLIB, ROLE_SUBPATH,
    ROLE_VERSIONED_INSTANCE, ecosystem_of_root, external_relative_segments, external_root_key,
    ecosystem_of, is_root_node, is_stdlib_name, match_key, repair_npm_package_name, role_of)
from sgraph.converters.sbom_cyclonedx_generator import (bom_ref, clean_name, dedup_key,
                                                        extract_version, valid_for_bom)

SAMPLE_CAP = 10

OUTCOME_COVERED_ELSEWHERE = 'coveredElsewhere'
OUTCOME_NOT_A_PACKAGE = 'notAPackage'
OUTCOME_VERSION_UNKNOWN_BY_DESIGN = 'versionUnknownByDesign'
OUTCOME_COULD_NOT_IDENTIFY = 'couldNotIdentify'

CATEGORY_SUBPATH_OF_EMITTED_PACKAGE = 'subpath_of_emitted_package'
CATEGORY_SUBPATH_OF_UNIDENTIFIED_PACKAGE = 'subpath_of_unidentified_package'
CATEGORY_UNVERSIONED_INSTALL_PATH = 'unversioned_install_path'
CATEGORY_UNRESOLVED_CODE_SYMBOL = 'unresolved_code_symbol'
CATEGORY_STDLIB_OR_BUILTIN = 'stdlib_or_builtin'
CATEGORY_NOT_A_PACKAGE_ROOT = 'not_a_package_root'
CATEGORY_DOCKER_IMAGE_IDENTITY = 'docker_image_identity'
CATEGORY_DECLARED_BOUND = 'declared_bound'
CATEGORY_FINDING_UNDER_VERSIONED_PACKAGE = 'finding_under_versioned_package'
CATEGORY_PACKAGE_CANDIDATE_WITHOUT_VERSION = 'package_candidate_without_version'

# The outcome each category reports when its members agree, which they do everywhere except
# unversioned install paths — those depend on whether the package their TAIL names was emitted.
DEFAULT_OUTCOME = {
    CATEGORY_SUBPATH_OF_EMITTED_PACKAGE: OUTCOME_COVERED_ELSEWHERE,
    CATEGORY_SUBPATH_OF_UNIDENTIFIED_PACKAGE: OUTCOME_NOT_A_PACKAGE,
    CATEGORY_UNVERSIONED_INSTALL_PATH: OUTCOME_COULD_NOT_IDENTIFY,
    CATEGORY_UNRESOLVED_CODE_SYMBOL: OUTCOME_NOT_A_PACKAGE,
    CATEGORY_STDLIB_OR_BUILTIN: OUTCOME_NOT_A_PACKAGE,
    CATEGORY_NOT_A_PACKAGE_ROOT: OUTCOME_NOT_A_PACKAGE,
    CATEGORY_DOCKER_IMAGE_IDENTITY: OUTCOME_COULD_NOT_IDENTIFY,
    CATEGORY_DECLARED_BOUND: OUTCOME_VERSION_UNKNOWN_BY_DESIGN,
    CATEGORY_FINDING_UNDER_VERSIONED_PACKAGE: OUTCOME_NOT_A_PACKAGE,
    CATEGORY_PACKAGE_CANDIDATE_WITHOUT_VERSION: OUTCOME_COULD_NOT_IDENTIFY,
}

# Categories whose members CLAIM to be packages, and therefore the only ones for which "how
# many distinct packages" is a defined question. For a code symbol, a filesystem path or a stdlib
# module the field is absent rather than zero, because zero would read as "we looked and found
# none". A count is published where it means something, or not at all.
PACKAGE_CLAIMING_CATEGORIES = frozenset({
    CATEGORY_PACKAGE_CANDIDATE_WITHOUT_VERSION,
    CATEGORY_DECLARED_BOUND,
    CATEGORY_UNVERSIONED_INSTALL_PATH,
    CATEGORY_DOCKER_IMAGE_IDENTITY,
})

SUMMARY_PROPERTIES = ('coverageComponentsEmitted', 'coverageNotAPackage',
                      'coverageVersionUnknownByDesign', 'coverageCouldNotIdentify')


def _external_root(model):
    stack = list(model.rootNode.children)
    while stack:
        elem = stack.pop(0)
        if elem.name == 'External':
            return elem
        stack += elem.children
    return None


def _has_version(elem):
    return bool(extract_version(elem))


def _emitted_reference(elem):
    """The dedup key a consumer would receive for this element, or None when it emits nothing."""
    if not valid_for_bom(elem):
        return None
    return dedup_key(bom_ref(elem, extract_version(elem) or ''))


def package_identity(elem, external_root):
    """The (ecosystem, key) pair that decides when two elements are ONE package.

    Three consumers by design — the distinct-package count, the join index and the collision
    detector — because one function computing it is what stops two of them disagreeing about what
    a package is. The distinct count collapsing /External/Python/click with
    /External/PIP/click/click is the same claim the join makes when it resolves them.

    Two rules, both deliberately borrowed rather than invented:

    `match_key` does the folding. Not a rule of this module's own: the cheapest way to shrink a
    distinct-package count is to loosen the fold, and loosening this one breaks the join's tests.

    `repair_npm_package_name` resolves an install path to the package it installs, so
    wrap-ansi-cjs/strip-ansi and string-width-cjs/strip-ansi are one package rather than two.
    This is a READING use of the repair and needs no version gate — the gate exists because
    APPLYING a repair to an emitted purl asserts an identity, while reading a name to learn which
    package it refers to asserts nothing. Keying on the raw name would have had the report assert
    that the whole path names a package, which is the reading A1 measured and refuted, while the
    emitter asserted the tail.

    The repair is npm-gated and a no-op for any name without a separator, so applying it here
    universally is safe and strictly more consistent than a per-category variant. The PIP
    `<package>/<package>` shape needs no special case either: both nodes carry the same name.
    """
    ecosystem = ecosystem_of(elem, external_root)
    name = clean_name(elem.name)
    repaired = repair_npm_package_name(name) if ecosystem == 'npm' else None
    return ecosystem, match_key(ecosystem, repaired[0] if repaired else name)


def _classify(elem, root_key, emitted_keys):
    """Which category this element belongs to. Order is the whole design; see below.

    Stdlib precedes the code-symbol test because a stdlib module reached by a 'ref' edge is both.
    The code-symbol test precedes the subpath test because `starlette/responses/Response` is both
    deep and ref-only, and calling it a missing subpath reports a package that never existed.
    Install-path shape precedes nested-subpath shape because only the former can be mistaken for
    the latter, and crediting an install path to the requirer named in its leading segment would
    report `wrap-ansi-cjs` as covering `strip-ansi`.
    """
    if is_root_node(elem):
        # The root itself is structure: /External/NPM is where npm packages live, not a package
        # called NPM. It is walked because conservation counts every descendant, and it is not a
        # package, so it says so rather than landing in the residue as a failed identification.
        return CATEGORY_NOT_A_PACKAGE_ROOT, DEFAULT_OUTCOME[CATEGORY_NOT_A_PACKAGE_ROOT]

    # The stdlib predicate is given an element name and must see it decoded, which is the
    # generator's clean_name — so the caller applies it and the pure module stays pure.
    role = role_of(elem, root_key, has_version=_has_version,
                   is_stdlib_name=lambda key, name: is_stdlib_name(key, clean_name(name)),
                   has_package_evidence=valid_for_bom)
    if role == ROLE_FINDING:
        return CATEGORY_FINDING_UNDER_VERSIONED_PACKAGE, DEFAULT_OUTCOME[
            CATEGORY_FINDING_UNDER_VERSIONED_PACKAGE]
    if role == ROLE_STDLIB:
        return CATEGORY_STDLIB_OR_BUILTIN, DEFAULT_OUTCOME[CATEGORY_STDLIB_OR_BUILTIN]
    if role == ROLE_FILESYSTEM:
        return CATEGORY_NOT_A_PACKAGE_ROOT, DEFAULT_OUTCOME[CATEGORY_NOT_A_PACKAGE_ROOT]
    if role == ROLE_IMAGE:
        return CATEGORY_DOCKER_IMAGE_IDENTITY, DEFAULT_OUTCOME[CATEGORY_DOCKER_IMAGE_IDENTITY]

    deptypes = {association.deptype for association in elem.incoming}
    if deptypes and deptypes <= {'ref'}:
        return CATEGORY_UNRESOLVED_CODE_SYMBOL, DEFAULT_OUTCOME[CATEGORY_UNRESOLVED_CODE_SYMBOL]

    name = clean_name(elem.name)
    if ecosystem_of_root(root_key) == 'npm' and '/' in name:
        repair = repair_npm_package_name(name)
        if repair is not None:
            covered = repair[0] in {key.rsplit('@', 1)[0].split('/', 1)[-1] for key in emitted_keys}
            return CATEGORY_UNVERSIONED_INSTALL_PATH, (OUTCOME_COVERED_ELSEWHERE
                                                       if covered else OUTCOME_COULD_NOT_IDENTIFY)

    # Ahead of the subpath rules: a constraint is the producer stating what it knows about this
    # element's identity, and a shape rule must not outrank a producer-stated fact. Redundant with
    # the kind gate for registry roots today, and the right precedence the moment a producer
    # stamps a constraint under a dual-kind root.
    #
    # Read only from an element whose ROLE licenses it (pi6): a constraint on a finding node is a
    # back-reference to the package the advisory concerns, not this element's own version bound.
    if 'constraint' in elem.attrs and role in (ROLE_PACKAGE, ROLE_VERSIONED_INSTANCE):
        return CATEGORY_DECLARED_BOUND, DEFAULT_OUTCOME[CATEGORY_DECLARED_BOUND]

    if role == ROLE_SUBPATH:
        ancestor = elem.parent
        while ancestor is not None and len(external_relative_segments(ancestor)) > 1:
            if any(_emitted_reference(child) for child in ancestor.children):
                return CATEGORY_SUBPATH_OF_EMITTED_PACKAGE, OUTCOME_COVERED_ELSEWHERE
            ancestor = ancestor.parent
        return CATEGORY_SUBPATH_OF_UNIDENTIFIED_PACKAGE, DEFAULT_OUTCOME[
            CATEGORY_SUBPATH_OF_UNIDENTIFIED_PACKAGE]

    return CATEGORY_PACKAGE_CANDIDATE_WITHOUT_VERSION, DEFAULT_OUTCOME[
        CATEGORY_PACKAGE_CANDIDATE_WITHOUT_VERSION]


def external_coverage_report(model):
    """Machine-readable coverage of one model's External subtree. Model-wide, not per-document.

    Every element under External lands in exactly one place: it emits, it is a parent whose child
    emits, or it is classified. `unreferenced` is carried as an ORTHOGONAL flag rather than as a
    bucket, because an element can be stdlib AND unreferenced — a bucket would steal it from the
    category that actually describes it, and a consumer asking which stdlib modules were seen
    would silently receive the wrong answer.
    """
    root = _external_root(model)
    categories = {
        name: {
            'elementCount': 0,
            'referencedElementCount': 0,
            'unreferencedElementCount': 0,
            'samples': [],
            'outcomes': set(),
            'packages': set()
        }
        for name in DEFAULT_OUTCOME
    }
    ledger = {
        'elementsWalked': 0,
        'emittingElements': 0,
        'componentsEmitted': 0,
        'benignVersionedChildParentElements': 0,
        'outcomes': {
            OUTCOME_COVERED_ELSEWHERE: {
                'elementCount': 0
            },
            OUTCOME_NOT_A_PACKAGE: {
                'elementCount': 0
            },
            OUTCOME_VERSION_UNKNOWN_BY_DESIGN: {
                'elementCount': 0
            },
            OUTCOME_COULD_NOT_IDENTIFY: {
                'elementCount': 0
            }
        }
    }

    if root is not None:
        emitted_keys = set()
        stack = list(root.children)
        while stack:
            elem = stack.pop()
            stack += elem.children
            key = _emitted_reference(elem)
            if key is not None:
                emitted_keys.add(key)

        stack = list(root.children)
        while stack:
            elem = stack.pop()
            stack += elem.children
            ledger['elementsWalked'] += 1
            if valid_for_bom(elem):
                ledger['emittingElements'] += 1
                continue
            if any(valid_for_bom(child) for child in elem.children):
                ledger['benignVersionedChildParentElements'] += 1
                continue
            category, outcome = _classify(elem, external_root_key(elem), emitted_keys)
            bucket = categories[category]
            bucket['elementCount'] += 1
            bucket['referencedElementCount' if elem.incoming else 'unreferencedElementCount'] += 1
            bucket['outcomes'].add(outcome)
            bucket['samples'].append(elem.getPath())
            if category in PACKAGE_CLAIMING_CATEGORIES:
                bucket['packages'].add(package_identity(elem, root))
            ledger['outcomes'][outcome]['elementCount'] += 1
        ledger['componentsEmitted'] = len(emitted_keys)

    for name, bucket in categories.items():
        outcomes = bucket.pop('outcomes')
        packages = bucket.pop('packages')
        bucket['outcome'] = outcomes.pop() if len(outcomes) == 1 else DEFAULT_OUTCOME[name]
        bucket['samples'] = sorted(bucket['samples'])[:SAMPLE_CAP]
        if name in PACKAGE_CLAIMING_CATEGORIES:
            bucket['distinctPackageCount'] = len(packages)

    return {
        'ledger':
            ledger,
        'categories':
            categories,
        'externalsDeclaredButNothingEmitted': (ledger['elementsWalked'] > 0
                                               and ledger['componentsEmitted'] == 0),
    }


def render_coverage_report(report):
    """The operator's view of the same data, as lines. Returns them rather than printing.

    Returning lines keeps the choice of channel with the caller: a report written to stderr from
    inside a library is exactly the behaviour this phase removed from the generator.
    """
    ledger = report['ledger']
    lines = [
        f'elements walked: {ledger["elementsWalked"]}',
        f'  emitting elements: {ledger["emittingElements"]}'
        f'   components emitted: {ledger["componentsEmitted"]}',
        f'  benign versioned-child parent elements: '
        f'{ledger["benignVersionedChildParentElements"]}'
    ]
    for name in sorted(report['categories']):
        bucket = report['categories'][name]
        if not bucket['elementCount']:
            continue
        # Where the unit is packages, lead with packages. Tens of thousands of element paths
        # drown the categories a reader must act on, and the aggregation that makes the count
        # honest is the same one that makes it readable — not a second mechanism invented at the
        # rendering layer.
        if 'distinctPackageCount' in bucket:
            headline = (f'{bucket["distinctPackageCount"]} packages, across '
                        f'{bucket["elementCount"]} elements')
        else:
            headline = f'{bucket["elementCount"]} elements'
        lines.append(f'  {name}: {headline} ({bucket["outcome"]}) '
                     f'referenced {bucket["referencedElementCount"]} / '
                     f'unreferenced {bucket["unreferencedElementCount"]}')
        lines += [f'      {sample}' for sample in bucket['samples']]
    if report['externalsDeclaredButNothingEmitted']:
        lines.append('  ALARM: externals were declared and no component was emitted')
    return lines


def attach_coverage_summary(document, report):
    """Attach four fixed-cardinality counts to a document's metadata.

    Opt-in by being called: no generator path calls this, which is what keeps every document
    byte-identical by default. That safety lives in the call graph, where a test can check it,
    rather than in a parameter default, where it would be invisible — and a function named
    attach_ that did not attach would be a silent no-op, which is the defect class this sprint
    exists to remove.

    Four numbers of distinct meaning rather than a score: CycloneDX has nowhere natural for a
    taxonomy, consumers ignore properties they do not know, and fixed cardinality can never bloat
    a document. Values are strings because CycloneDX types a property value as a string.
    """
    ledger = report['ledger']
    outcomes = ledger['outcomes']
    values = (ledger['componentsEmitted'], outcomes[OUTCOME_NOT_A_PACKAGE]['elementCount'],
              outcomes[OUTCOME_VERSION_UNKNOWN_BY_DESIGN]['elementCount'],
              outcomes[OUTCOME_COULD_NOT_IDENTIFY]['elementCount'])
    properties = document.setdefault('metadata', {}).setdefault('properties', [])
    for name, value in zip(SUMMARY_PROPERTIES, values):
        properties.append({'name': name, 'value': str(value)})
    return document
