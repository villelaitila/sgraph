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
only five outcome classes of distinct meaning; and there is NO numeric constant in this module
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
    ROLE_UNKNOWN, ROLE_VERSIONED_INSTANCE, ecosystem_of_root, external_relative_segments,
    external_root_key,
    IMAGE_UNMATCHED, IMAGE_UNTAGGED_CHAIN, IMPORT_NAME_ALIASES, KIND_IMAGE, KIND_REGISTRY,
    ROOT_KINDS, ecosystem_of, image_structure, is_root_node, is_stdlib_name, match_key,
    repair_npm_package_name, role_of)
from sgraph.converters.sbom_cyclonedx_generator import (bom_ref, clean_name, dedup_key,
                                                        extract_version, valid_for_bom)

SAMPLE_CAP = 10

OUTCOME_COVERED_ELSEWHERE = 'coveredElsewhere'
OUTCOME_NOT_A_PACKAGE = 'notAPackage'
OUTCOME_VERSION_UNKNOWN_BY_DESIGN = 'versionUnknownByDesign'
OUTCOME_COULD_NOT_IDENTIFY = 'couldNotIdentify'

# The fifth outcome, and the only one that reports the LIBRARY's own limit rather than the
# model's. The other four all say something about the element; this one says that no rule exists
# to say anything about it, which is a different kind of fact and is why it is not folded into
# any of them.
#
# couldNotIdentify would be a claim that an identification was attempted and failed. notAPackage
# would be a claim that the element is not one. Under a root with no rule, neither is supported —
# such a root can hold real packages at package depth and code symbols one level deeper, and
# nothing available here separates them. Publishing either would be an invented answer, and the
# invented answer in the couldNotIdentify direction is what made the headline unusable: 80 659
# elements across the 20 local models, 68 689 of them under a single root.
OUTCOME_UNKNOWN_ROOT_KIND = 'unknownRootKind'

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
CATEGORY_JOINED_TO_VERSIONED_SIBLING = 'joined_to_versioned_sibling'
CATEGORY_UNKNOWN_ROOT_KIND = 'unknown_root_kind'

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
    CATEGORY_JOINED_TO_VERSIONED_SIBLING: OUTCOME_COVERED_ELSEWHERE,
    CATEGORY_UNKNOWN_ROOT_KIND: OUTCOME_UNKNOWN_ROOT_KIND,
}

# Categories whose members CLAIM to be packages, and therefore the only ones for which "how
# many distinct packages" is a defined question. For a code symbol, a filesystem path or a stdlib
# module the field is absent rather than zero, because zero would read as "we looked and found
# none". A count is published where it means something, or not at all.
#
# CATEGORY_UNKNOWN_ROOT_KIND is deliberately absent: its members make no claim either way, so
# counting distinct packages among them would answer a question none of them asked.
PACKAGE_CLAIMING_CATEGORIES = frozenset({
    CATEGORY_PACKAGE_CANDIDATE_WITHOUT_VERSION,
    CATEGORY_DECLARED_BOUND,
    CATEGORY_UNVERSIONED_INSTALL_PATH,
    CATEGORY_DOCKER_IMAGE_IDENTITY,
})

# Five now rather than four. The count that moved out of couldNotIdentify is published here
# rather than dropped, because the goal is a headline that means what it says, not a smaller one:
# a consumer that wants the old total can still add the two, and a consumer that wants to act on
# it can now see that what it needs is rules for a handful of roots rather than identification
# work on tens of thousands of elements.
SUMMARY_PROPERTIES = ('coverageComponentsEmitted', 'coverageNotAPackage',
                      'coverageVersionUnknownByDesign', 'coverageCouldNotIdentify',
                      'coverageUnknownRootKind')

# Composition aggregate values, from bom-1.6.schema.json — the default specVersion, whose
# aggregateType enum holds the same ten values as 1.7's. Three of the ten are reachable from a
# coverage ledger; the reasoning for which three, and for the one that is deliberately
# unreachable, is in coverage_compositions.
#
# All three named below are also in the 1.4 enum, which defines six values rather than ten
# (it lacks the first-party/third-party proprietary and opensource refinements added in 1.5).
# So a coverage document stays valid at every version the generator can declare, and the
# selectable specVersion does not reach this decision.
AGGREGATE_INCOMPLETE = 'incomplete'
AGGREGATE_UNKNOWN = 'unknown'
AGGREGATE_NOT_SPECIFIED = 'not_specified'


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


def _emits_within(elem):
    """Whether anything in this element's own subtree emits a component."""
    stack = list(elem.children)
    while stack:
        node = stack.pop()
        if valid_for_bom(node):
            return True
        stack += node.children
    return False


def build_join_index(model):
    """Every identity this model already publishes, mapped to the ref that publishes it.

    Built from EMITTING elements under REGISTRY roots only, which is guard G5 (the target must
    already exist) and half of G2 (the join runs import-graph → registry, never the reverse) made
    structural rather than checked. Keyed by package_identity, so an install path can find the
    package it installs: keyed on raw names the index would hold strip-ansi while the element
    asked for wrap-ansi-cjs/strip-ansi, and the recovery could never happen.
    """
    root = _external_root(model)
    index = {}
    if root is None:
        return index
    stack = list(root.children)
    while stack:
        elem = stack.pop()
        stack += elem.children
        if not valid_for_bom(elem):
            continue
        if KIND_REGISTRY not in ROOT_KINDS.get(external_root_key(elem, root), set()):
            continue
        index.setdefault(package_identity(elem, root), bom_ref(elem, extract_version(elem) or ''))
    return index


def internal_published_identities(model):
    """Identities the estate publishes ITSELF, for flagging a join that may be first-party.

    The playwright shape: an internal repository publishing a package whose name a public one also
    uses. A join onto such a name is recorded and flagged rather than suppressed — suppressing it
    silently would be the same class of error the flag exists to surface.
    """
    identities = set()
    root = _external_root(model)
    stack = list(model.rootNode.children)
    while stack:
        elem = stack.pop()
        stack += elem.children
        if root is not None and (elem is root or elem.isDescendantOf(root)):
            continue
        name = elem.attrs.get('package_name', '').strip()
        ecosystem = elem.attrs.get('ecosystem', '').strip() or None
        if name and ecosystem:
            identities.add((ecosystem, match_key(ecosystem, name)))
    return identities


def resolve_identity_by_join(elem, index, external_root, internal_identities=frozenset()):
    """Resolve an unversioned external against an identity the model already publishes.

    Returns an evidence record or None. Five guards, and the first is the one that matters: a
    naive name join measured 12 % cross-ecosystem false positives, so both ecosystems must be
    equal AND non-None — which makes a cross-ecosystem join impossible by construction rather
    than unlikely, and lets the gate assert zero instead of a rate.

    This is an identity RESOLUTION and never an emission: nothing here appends to a component
    list, so the join's diff on every generated document is empty by construction.
    """
    if valid_for_bom(elem):
        return None
    # An element whose own subtree emits is covered BY ITSELF — /External/PIP/click is the package
    # node of click of version 8.4.2 — and joining it to its own child would corroborate nothing
    # while inflating the join count with every package in the model. The ledger already counts
    # these as benign versioned-child parents, so they are never residue either.
    if _emits_within(elem):
        return None
    ecosystem, key = package_identity(elem, external_root)
    if ecosystem is None or key is None:
        return None

    covering = index.get((ecosystem, key))
    rule = 'exact'
    if covering is None:
        alias = IMPORT_NAME_ALIASES.get(ecosystem, {}).get(key)
        if alias is None:
            return None
        covering = index.get((ecosystem, match_key(ecosystem, alias)))
        rule = f'alias:{key}'
    if covering is None:
        return None

    return {
        'element': elem.getPath(),
        'coveringRef': covering,
        'ecosystem': ecosystem,
        'matchRule': rule,
        'collisionRisk': (ecosystem, key) in internal_identities,
    }


def _image_sub_label(elem, root_key):
    """The image structure of an element, when it is under an image root and worth naming."""
    if KIND_IMAGE not in ROOT_KINDS.get(root_key, set()) or is_root_node(elem):
        # The root itself is structure, not part of any image: /External/Docker/Image is where
        # images live, and counting it into a chain would inflate every chain by one.
        return None
    return image_structure(elem, root_key)


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

    # Last before the residue, because it removes elements the residue was never entitled to. Any
    # rule that CAN say something has already had its turn above; what is left under a root with
    # no entry in ROOT_KINDS is unreasoned-about rather than unidentified.
    #
    # Gated on the ROOT rather than on the role alone, and the gate is the distinction ROOT_KINDS
    # draws about itself: "A root absent from this table is unknown, which is a different fact
    # from a root that is known to assert no ecosystem." Docker, JVM and Java are IN the table
    # mapped to an empty set — the tables have looked at them and have an answer — so they keep
    # today's category. Only genuine absence reaches this line.
    #
    # This is emphatically NOT the inference that a root's absence from a table makes its contents
    # non-packages. Some of them are packages: an unmapped JavaScript or TypeScript root holds
    # real npm packages at package depth beside code symbols one level deeper, and this category
    # covers both because nothing available here separates them. It reports the missing rule, and
    # the repair is to add the rule — measure the root, then give it a ROOT_KINDS row — not to
    # guess from shape, which is how a wrong answer gets locked in.
    if role == ROLE_UNKNOWN and root_key not in ROOT_KINDS:
        return CATEGORY_UNKNOWN_ROOT_KIND, DEFAULT_OUTCOME[CATEGORY_UNKNOWN_ROOT_KIND]

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
    unclassified_image_elements = []
    join_index = build_join_index(model)
    internal_identities = internal_published_identities(model)
    joins = []
    categories = {
        name: {
            'elementCount': 0,
            'referencedElementCount': 0,
            'unreferencedElementCount': 0,
            'samples': [],
            'subLabels': {},
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
            },
            OUTCOME_UNKNOWN_ROOT_KIND: {
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
            category, outcome = _classify(elem, external_root_key(elem, root), emitted_keys)
            # The join is tried only on the residue: an element the taxonomy can already explain
            # is explained, and re-explaining it as a join would move rows out of categories that
            # were right about them.
            if category == CATEGORY_PACKAGE_CANDIDATE_WITHOUT_VERSION:
                record = resolve_identity_by_join(elem, join_index, root, internal_identities)
                if record is not None:
                    joins.append(record)
                    category = CATEGORY_JOINED_TO_VERSIONED_SIBLING
                    outcome = OUTCOME_COVERED_ELSEWHERE
            bucket = categories[category]
            bucket['elementCount'] += 1
            bucket['referencedElementCount' if elem.incoming else 'unreferencedElementCount'] += 1
            bucket['outcomes'].add(outcome)
            bucket['samples'].append(elem.getPath())
            sub_label = _image_sub_label(elem, external_root_key(elem, root))
            if sub_label == IMAGE_UNTAGGED_CHAIN:
                bucket['subLabels'].setdefault(sub_label, {'elementCount': 0})
                bucket['subLabels'][sub_label]['elementCount'] += 1
            elif sub_label == IMAGE_UNMATCHED:
                unclassified_image_elements.append(elem.getPath())
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
        'joins':
            sorted(joins, key=lambda record: record['element']),
        # A shape that matches no image clause is named rather than defaulted: the rule set it
        # replaced was total, so it could never say 'I do not know what this is'.
        'unclassifiedImageElements':
            sorted(unclassified_image_elements),
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


def coverage_compositions(report, subject_ref=None):
    """The completeness claim, in the slot CycloneDX defines for it.

    The five counts stay in metadata properties, because a composition holds `aggregate`,
    `assemblies`, `dependencies` and `vulnerabilities` and nothing else — a ten-category taxonomy
    with counts and samples has no home here, and the schema sets additionalProperties:false so
    inventing one is invalid rather than merely unconventional. What DOES belong here is the one
    thing a custom property cannot say in a vocabulary consumers already read: whether this
    document's third-party assembly is complete.

    **'complete' is unreachable by construction, and that is a limit rather than an omission.**
    The enum defines it as "no further relationships ... are KNOWN to exist". The ledger proves
    only that every element the walk SAW was classified; it never proves the analyzer saw
    everything, and between those two lies every dependency an unrun analyzer would have found.
    Claiming completeness makes a consumer stop looking, which is the dangerous direction for a
    security artifact, so the strongest honest claim is the enum's own 'unknown' — "a best-effort
    ... but the completeness is inconclusive". A test asserts no ledger state reaches 'complete'.

    An empty walk is 'not_specified' rather than 'unknown': with no External subtree the model
    cannot distinguish "this estate depends on nothing" from "no dependency analyzer ran", and
    'unknown' would assert the best effort that 'not_specified' correctly declines to assert.

    subject_ref names the component whose assembly this describes. Omitted rather than empty when
    there is none: `assemblies: []` reads as "these zero components are incomplete", while an
    absent key reads as "the subject was not named", which is what is true.
    """
    ledger = report['ledger']
    # Both unidentified and unreasoned-about elements make the assembly incomplete, and the second
    # is here deliberately. Splitting the count out of couldNotIdentify must not soften the
    # completeness claim as a side effect: an element under a root with no rule may perfectly well
    # be a package that never reached the document, so relationships beyond those listed do exist.
    # Reading only couldNotIdentify would have flipped such a document to the weaker 'unknown' the
    # moment the split shipped — a consumer told the assembly is merely inconclusive rather than
    # incomplete, on the strength of a bookkeeping change. A test pins that flip.
    unexplained = (ledger['outcomes'][OUTCOME_COULD_NOT_IDENTIFY]['elementCount'] +
                   ledger['outcomes'][OUTCOME_UNKNOWN_ROOT_KIND]['elementCount'])
    if not ledger['elementsWalked']:
        aggregate = AGGREGATE_NOT_SPECIFIED
    elif unexplained:
        aggregate = AGGREGATE_INCOMPLETE
    else:
        aggregate = AGGREGATE_UNKNOWN
    composition = {'aggregate': aggregate}
    if subject_ref is not None:
        composition['assemblies'] = [subject_ref]
    return [composition]


def attach_coverage_compositions(document, report):
    """Attach the completeness claim to a document, naming that document's own subject.

    Opt-in by being called, like attach_coverage_summary and for the same reason: default-off
    lives in the call graph, where a test over every public entry point can check it, rather than
    in a parameter default, where it would be invisible.

    The subject is the metadata component, because the claim is about the assembly of THIS
    document rather than of the model. A document whose metadata component carries no bom-ref
    names no subject, and the composition is then emitted with no assemblies at all.
    """
    subject_ref = document.get('metadata', {}).get('component', {}).get('bom-ref')
    document.setdefault('compositions', []).extend(coverage_compositions(report, subject_ref))
    return document


def attach_coverage_summary(document, report):
    """Attach five fixed-cardinality counts to a document's metadata.

    Opt-in by being called: no generator path calls this, which is what keeps every document
    byte-identical by default. That safety lives in the call graph, where a test can check it,
    rather than in a parameter default, where it would be invisible — and a function named
    attach_ that did not attach would be a silent no-op, which is the defect class this sprint
    exists to remove.

    Five numbers of distinct meaning rather than a score: CycloneDX has nowhere natural for a
    taxonomy, consumers ignore properties they do not know, and fixed cardinality can never bloat
    a document. Values are strings because CycloneDX types a property value as a string.

    The fifth is coverageUnknownRootKind, and it is a split rather than an addition: those
    elements were previously counted into coverageCouldNotIdentify, where they asserted a failed
    identification that was never attempted. A consumer wanting the old total adds the two.
    """
    ledger = report['ledger']
    outcomes = ledger['outcomes']
    values = (ledger['componentsEmitted'], outcomes[OUTCOME_NOT_A_PACKAGE]['elementCount'],
              outcomes[OUTCOME_VERSION_UNKNOWN_BY_DESIGN]['elementCount'],
              outcomes[OUTCOME_COULD_NOT_IDENTIFY]['elementCount'],
              outcomes[OUTCOME_UNKNOWN_ROOT_KIND]['elementCount'])
    properties = document.setdefault('metadata', {}).setdefault('properties', [])
    for name, value in zip(SUMMARY_PROPERTIES, values):
        properties.append({'name': name, 'value': str(value)})
    return document
