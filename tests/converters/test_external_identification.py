"""Tests for the coverage report: what the BOM does not cover, and why.

Half of this sprint's purpose is telling a consumer what the document does NOT contain. A count
alone invites Goodhart — the cheapest way to lower "could not identify" is to widen the
not-a-package filter — so the report ships four outcome classes with per-category counts and
sample paths, conserves every walked element, and defines no numeric constant but SAMPLE_CAP.

The module under test is imported inside the tests rather than at module level, so this file
collects before the module exists.
"""
import pytest

from sgraph import SElement, SElementAssociation, SGraph
from sgraph.converters import sbom_cyclonedx_generator

from ..modelapi_test import get_model_and_model_api

TRACKED_FIXTURES = [
    'converters/modelfile_for_sbom_tests.xml',
    'converters/modelfile_for_sbom_emission_tests.xml',
    'converters/modelfile_for_sbom_binary_refs_tests.xml',
    'converters/modelfile_for_sbom_multi_tests.xml',
    'converters/modelfile_for_sbom_mirrored_tests.xml',
    'converters/modelfile_for_sbom_maven_coordinates_tests.xml',
]


def identification():
    from sgraph.converters import external_identification
    return external_identification


def external_root_of(model):
    stack = list(model.rootNode.children)
    while stack:
        elem = stack.pop(0)
        if elem.name == 'External':
            return elem
        stack += elem.children
    return None


def walk_externals_independently(model):
    """Count External's descendants without asking the classifier anything.

    The left-hand side of the conservation identity must come from somewhere the classifier does
    not participate in. A total derived from what the classifier returned would make the test
    agree with itself no matter what the classifier did.
    """
    root = external_root_of(model)
    if root is None:
        return 0
    total, stack = 0, list(root.children)
    while stack:
        elem = stack.pop()
        total += 1
        stack += elem.children
    return total


def external(model, path, version=None, attrs=None, referenced_by=None, deptype='use'):
    """An element under External, referenced or not, versioned or not."""
    parent_path, _, name = path.rpartition('/')
    parent = model.createOrGetElementFromPath(f'/Org/External/{parent_path}') if parent_path \
        else model.createOrGetElementFromPath('/Org/External')
    elem = SElement(parent, name)
    if version is not None:
        elem.attrs['version'] = version
    for key, value in (attrs or {}).items():
        elem.attrs[key] = value
    if referenced_by is not None:
        referrer = model.createOrGetElementFromPath(f'/Org/repoA/src/{referenced_by}')
        SElementAssociation(referrer, elem, deptype).initElems()
    return elem


def category_of(report, element_path):
    """Which category a given element path was classified into, or None."""
    for name, bucket in report['categories'].items():
        if element_path in bucket['samples']:
            return name
    return None


@pytest.mark.parametrize('fixture', TRACKED_FIXTURES)
def test_the_ledger_conserves_every_walked_element(fixture):
    """The most important test here: every walked element lands in exactly one bucket.

    Conservation is what makes the report auditable rather than a set of numbers nobody can check.
    A category that quietly drops elements would make coverage look better by losing the evidence,
    which is the failure this whole taxonomy exists to prevent.
    """
    model, _ = get_model_and_model_api(fixture)
    report = identification().external_coverage_report(model)
    ledger = report['ledger']

    buckets = (ledger['emittingElements'] + ledger['benignVersionedChildParentElements'] +
               sum(outcome['elementCount'] for outcome in ledger['outcomes'].values()))
    assert buckets == ledger['elementsWalked'], (fixture, ledger)


def test_the_walk_total_is_computed_independently_of_the_classifier():
    """The conservation total must not come from the thing being conserved.

    Asserted against a walk written here, in the test, that never calls the classifier: descend
    External's children transitively and count. If externalsWalked were derived from the sum of
    the categories, the conservation test above would pass for any classifier whatsoever.
    """
    model, _ = get_model_and_model_api('converters/modelfile_for_sbom_tests.xml')
    report = identification().external_coverage_report(model)

    assert report['ledger']['elementsWalked'] == walk_externals_independently(model)
    assert walk_externals_independently(model) > 0


def test_an_emitting_element_and_an_emitted_document_are_counted_separately():
    """4 880 elements emit; 4 846 rows survive dedup. Conflating them produced three wrong numbers.

    The distinction is structural here rather than a footnote: emittingElements counts elements
    that pass admission, componentsEmitted counts the rows a consumer receives after folding.
    """
    model = SGraph(SElement(None, ''))
    external(model, 'NPM/strip-ansi', version='6.0.1', referenced_by='a.js')
    external(model, 'NPM/wrap-ansi-cjs__slash__strip-ansi', version='6.0.1', referenced_by='b.js')

    ledger = identification().external_coverage_report(model)['ledger']

    assert ledger['emittingElements'] == 2
    assert ledger['componentsEmitted'] == 1


def test_a_parent_with_an_emitting_child_is_benign_whether_or_not_it_is_referenced():
    """Being unreferenced does not change what an element IS.

    The ratified benign count came from a population filtered to referenced elements only, which
    removed the majority of these parents from view. The predicate is 'a child of mine emits' and
    says nothing about incoming references.
    """
    model = SGraph(SElement(None, ''))
    referenced = external(model, 'NPM/left-pad', referenced_by='a.js')
    external(model, 'NPM/left-pad/left-pad of version 1.3.0', version='1.3.0')
    unreferenced = external(model, 'NPM/right-pad')
    external(model, 'NPM/right-pad/right-pad of version 2.0.0', version='2.0.0')

    report = identification().external_coverage_report(model)

    assert report['ledger']['benignVersionedChildParentElements'] == 2
    assert referenced.incoming and not unreferenced.incoming


def test_an_unreferenced_element_is_still_classified_by_its_shape():
    """'Unreferenced' is orthogonal to the category axis, not a value on it.

    An element can be stdlib AND unreferenced. A mutually-exclusive bucket for unreferenced
    elements would steal them from the category that actually describes them, so a consumer asking
    'what stdlib modules did you see' would get an answer that silently omits most of them.
    """
    model = SGraph(SElement(None, ''))
    unreferenced_stdlib = external(model, 'PythonLibs/json')

    report = identification().external_coverage_report(model)

    assert category_of(report, unreferenced_stdlib.getPath()) == \
        identification().CATEGORY_STDLIB_OR_BUILTIN


def test_the_referenced_split_is_reported_per_category():
    """Each category reports referenced and unreferenced counts that sum to its total.

    The ratified per-category figures were measured on referenced elements only, so a band applied
    to a whole category would compare an unfiltered classifier against a filtered table. The split
    lets the band apply to the referenced column and the remainder be recorded fresh.
    """
    model = SGraph(SElement(None, ''))
    external(model, 'PythonLibs/json', referenced_by='a.py', deptype='ref')
    external(model, 'PythonLibs/os')

    bucket = identification().external_coverage_report(model)['categories'][
        identification().CATEGORY_STDLIB_OR_BUILTIN]

    assert bucket['referencedElementCount'] == 1
    assert bucket['unreferencedElementCount'] == 1
    assert bucket['referencedElementCount'] + bucket['unreferencedElementCount'] == bucket[
        'elementCount']


def test_an_install_path_is_classified_before_a_nested_subpath():
    """The two npm shapes are mutually exclusive and only one can be mistaken for the other.

    A slash-bearing name is a single element written by the lockfile analyzer; a nested element is
    an import subpath written by the JS import analyzer. Classifying the nested shape first would
    let an install path fall into 'subpath of a package present elsewhere', which credits coverage
    to the requirer named in its leading segment rather than to the package it installs.
    """
    model = SGraph(SElement(None, ''))
    external(model, 'NPM/strip-ansi', version='6.0.1', referenced_by='a.js')
    install_path = external(model, 'NPM/wrap-ansi-cjs__slash__strip-ansi', referenced_by='b.js')

    report = identification().external_coverage_report(model)

    assert category_of(report, install_path.getPath()) == \
        identification().CATEGORY_UNVERSIONED_INSTALL_PATH


def test_an_unversioned_install_path_whose_tail_is_emitted_is_covered_elsewhere():
    """Classified against the TAIL, which is the package, not against the leading requirer."""
    model = SGraph(SElement(None, ''))
    external(model, 'NPM/strip-ansi', version='6.0.1', referenced_by='a.js')
    external(model, 'NPM/wrap-ansi-cjs__slash__strip-ansi', referenced_by='b.js')

    report = identification().external_coverage_report(model)
    bucket = report['categories'][identification().CATEGORY_UNVERSIONED_INSTALL_PATH]

    assert bucket['outcome'] == identification().OUTCOME_COVERED_ELSEWHERE


def test_a_subpath_of_an_emitted_package_is_covered_elsewhere():
    """A nested import subpath is covered by the package element above it, when that emitted."""
    model = SGraph(SElement(None, ''))
    external(model, 'NPM/react-dom/react-dom of version 18.0.0', version='18.0.0',
             referenced_by='a.js')
    subpath = external(model, 'NPM/react-dom/server', referenced_by='b.js')

    report = identification().external_coverage_report(model)

    assert category_of(report, subpath.getPath()) == \
        identification().CATEGORY_SUBPATH_OF_EMITTED_PACKAGE


def test_a_ref_only_element_under_the_python_import_graph_is_a_code_symbol():
    """Incoming deptypes all 'ref' means an unresolved code symbol, not a package.

    Tested before the subpath rule, because a class like starlette/responses/Response is both deep
    and ref-only, and calling it a subpath would report a missing package that never existed.
    """
    model = SGraph(SElement(None, ''))
    symbol = external(model, 'Python/starlette/responses/Response', referenced_by='a.py',
                      deptype='ref')

    report = identification().external_coverage_report(model)

    assert category_of(report, symbol.getPath()) == \
        identification().CATEGORY_UNRESOLVED_CODE_SYMBOL


def test_a_standard_library_module_is_not_a_package():
    """The stdlib is not a dependency, and reporting it as one is noise a consumer must filter."""
    model = SGraph(SElement(None, ''))
    stdlib = external(model, 'Python/json', referenced_by='a.py', deptype='ref')

    report = identification().external_coverage_report(model)

    assert category_of(report, stdlib.getPath()) == identification().CATEGORY_STDLIB_OR_BUILTIN
    assert report['categories'][identification().CATEGORY_STDLIB_OR_BUILTIN]['outcome'] == \
        identification().OUTCOME_NOT_A_PACKAGE


def test_a_docker_copy_source_is_not_a_package_root():
    """COPY sources are filesystem paths inside an image, not packages of any ecosystem."""
    model = SGraph(SElement(None, ''))
    copied = external(model, 'Docker/FilesysReference/etc/nginx.conf', referenced_by='Dockerfile')

    report = identification().external_coverage_report(model)

    assert category_of(report, copied.getPath()) == identification().CATEGORY_NOT_A_PACKAGE_ROOT


def test_a_docker_image_without_a_tag_could_not_be_identified():
    """An image with no tag names no specific artifact, so it is a real identification failure."""
    model = SGraph(SElement(None, ''))
    image = external(model, 'Docker/Image/nginx', referenced_by='Dockerfile')

    report = identification().external_coverage_report(model)

    assert category_of(report, image.getPath()) == identification().CATEGORY_DOCKER_IMAGE_IDENTITY
    assert report['categories'][identification().CATEGORY_DOCKER_IMAGE_IDENTITY]['outcome'] == \
        identification().OUTCOME_COULD_NOT_IDENTIFY


def test_a_declared_bound_is_version_unknown_by_design():
    """A declared range is correct producer behaviour, not a coverage failure.

    Counting it as a failure would push a producer toward inventing a concrete version it does not
    know, which is worse than an honest bound.

    Built at depth 3 under a REGISTRY root, which is where all 38 of them sit in the stored
    models. A depth-1 element would pass under either classification order and under either
    treatment of registry roots, so it could not distinguish the two candidate behaviours and
    would be evidence for neither.
    """
    model = SGraph(SElement(None, ''))
    bound = external(model, 'PIP/django/django', attrs={'constraint': '>=4.0,<5.0'},
                     referenced_by='a.py')

    report = identification().external_coverage_report(model)

    assert category_of(report, bound.getPath()) == identification().CATEGORY_DECLARED_BOUND
    assert report['categories'][identification().CATEGORY_DECLARED_BOUND]['outcome'] == \
        identification().OUTCOME_VERSION_UNKNOWN_BY_DESIGN


def test_a_finding_under_a_versioned_package_is_not_a_package():
    """Advisory nodes are children of versioned instances and must not reach the residue.

    Without this category they would be counted as packages nobody could identify, which is the
    silent wrongness this report exists to remove.
    """
    model = SGraph(SElement(None, ''))
    versioned = external(model, 'NPM/pkg2/pkg2 of version 2.0.0', version='2.0.0',
                         referenced_by='a.js')
    finding = SElement(versioned, 'pkg2_GHSA-0000-0000-0000')
    finding.attrs['package_name'] = 'pkg2'
    finding.attrs['package_version'] = '2.0.0'

    report = identification().external_coverage_report(model)

    assert category_of(report, finding.getPath()) == \
        identification().CATEGORY_FINDING_UNDER_VERSIONED_PACKAGE


def test_a_package_candidate_without_a_version_is_the_residue():
    """What is left after every provable category: a plausible package with no version anywhere."""
    model = SGraph(SElement(None, ''))
    candidate = external(model, 'NPM/some-unresolved-package', referenced_by='a.js')

    report = identification().external_coverage_report(model)

    assert category_of(report, candidate.getPath()) == \
        identification().CATEGORY_PACKAGE_CANDIDATE_WITHOUT_VERSION
    assert report['categories'][
        identification().CATEGORY_PACKAGE_CANDIDATE_WITHOUT_VERSION]['outcome'] == \
        identification().OUTCOME_COULD_NOT_IDENTIFY


def test_benign_parents_are_counted_but_never_reported():
    """388 of them, and crying wolf at that volume guarantees the report is ignored.

    They appear in the ledger, where conservation needs them, and in no category a consumer reads
    as a problem.
    """
    model = SGraph(SElement(None, ''))
    external(model, 'NPM/left-pad', referenced_by='a.js')
    external(model, 'NPM/left-pad/left-pad of version 1.3.0', version='1.3.0')

    report = identification().external_coverage_report(model)

    assert report['ledger']['benignVersionedChildParentElements'] == 1
    assert all('/Org/External/NPM/left-pad' not in sample
               for bucket in report['categories'].values() for sample in bucket['samples'])


def test_every_category_ships_samples():
    """A category with a count and no sample paths is one nobody can audit."""
    model = SGraph(SElement(None, ''))
    external(model, 'Python/json', referenced_by='a.py', deptype='ref')
    external(model, 'NPM/some-unresolved-package', referenced_by='b.js')

    report = identification().external_coverage_report(model)

    for name, bucket in report['categories'].items():
        if bucket['elementCount']:
            assert bucket['samples'], name


def test_samples_are_sorted_and_capped():
    """Sorted so two runs of one model agree, capped so a category cannot bloat the report."""
    model = SGraph(SElement(None, ''))
    for index in range(identification().SAMPLE_CAP + 5):
        external(model, f'NPM/unresolved-{index:02d}', referenced_by='a.js')

    bucket = identification().external_coverage_report(model)['categories'][
        identification().CATEGORY_PACKAGE_CANDIDATE_WITHOUT_VERSION]

    assert len(bucket['samples']) == identification().SAMPLE_CAP
    assert bucket['samples'] == sorted(bucket['samples'])
    assert bucket['elementCount'] == identification().SAMPLE_CAP + 5


def test_externals_declared_but_nothing_emitted_is_reported():
    """The one zero-versus-non-zero alarm the report is allowed to raise.

    An estate with externals and no components is the softagram-live failure this sprint started
    from, and it is the single case where a threshold-free report can still say 'this is wrong'.
    """
    model = SGraph(SElement(None, ''))
    external(model, 'NPM/some-unresolved-package', referenced_by='a.js')

    report = identification().external_coverage_report(model)

    assert report['ledger']['elementsWalked'] > 0
    assert report['ledger']['componentsEmitted'] == 0
    assert report['externalsDeclaredButNothingEmitted'] is True


def test_the_report_introduces_no_threshold():
    """SAMPLE_CAP is the only number this module is allowed to define.

    The corpus these categories were measured on was produced without the lockfile analyzers, so
    any threshold tuned to it would encode a measurement gap as a rule. Asserted structurally
    rather than by review, because a review does not run on every change.
    """
    import ast
    import inspect

    source = inspect.getsource(identification())
    constants = {
        node.targets[0].id: node
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Assign) and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name) and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, (int, float)) and not isinstance(node.value.value, bool)
    }

    assert set(constants) == {'SAMPLE_CAP'}, sorted(constants)


def test_attaching_the_summary_adds_the_coverage_counts():
    """The function attaches, because a function named attach_ that does not attach is a no-op.

    A silent no-op is the defect class this sprint exists to remove: a caller who calls by reflex
    and receives nothing has no way to discover it, while a caller who receives a summary they did
    not want sees it immediately. Fixed cardinality, so the summary can never bloat a document.
    """
    model = SGraph(SElement(None, ''))
    external(model, 'NPM/lodash', version='4.17.21', referenced_by='a.js')
    document = sbom_cyclonedx_generator.generate_from_sgraph(model)
    report = identification().external_coverage_report(model)

    identification().attach_coverage_summary(document, report)

    attached = {prop['name']: prop['value'] for prop in document['metadata']['properties']}
    assert len(attached) == 4
    assert all(isinstance(value, str) for value in attached.values())


@pytest.mark.parametrize('generate', [
    lambda model: [sbom_cyclonedx_generator.generate_from_sgraph(model)],
    lambda model: sbom_cyclonedx_generator.generate_multi_from_sgraph(model, level=2),
    lambda model: [sbom_cyclonedx_generator.generate_for_element_from_sgraph(model, '/Org/repoA')],
])
def test_no_generator_path_attaches_the_summary(generate):
    """Default-off lives in the CALL GRAPH, where it is checkable, not in a parameter default.

    No generator path calls attach_coverage_summary, which is what keeps every document
    byte-identical by default. Asserted over every public entry point rather than argued, because
    "nobody calls it" is exactly the kind of claim that stops being true without anyone noticing.
    """
    model = SGraph(SElement(None, ''))
    external(model, 'NPM/lodash', version='4.17.21', referenced_by='a.js')

    for document in generate(model):
        assert 'properties' not in document['metadata']


def test_a_registry_root_never_produces_a_subpath():
    """Subpaths are an IMPORT_GRAPH concept and do not exist under a pure registry root.

    Under PIP, Assemblies, APT and Maven, an element deeper than package depth is the versioned
    instance node, not a path inside a package. Applying the subpath rule there reported the
    instance as covered by its own package, which is true and useless — and it absorbed rows that
    belong in the residue.
    """
    model = SGraph(SElement(None, ''))
    instance = external(model, 'PIP/django/django of version 4.2.0', version='4.2.0',
                        referenced_by='a.py')
    package_only = external(model, 'Assemblies/NLog/NLog', referenced_by='b.cs')

    report = identification().external_coverage_report(model)

    assert category_of(report, instance.getPath()) is None  # it emits, so it is not classified
    assert category_of(report, package_only.getPath()) != \
        identification().CATEGORY_SUBPATH_OF_EMITTED_PACKAGE
    assert category_of(report, package_only.getPath()) != \
        identification().CATEGORY_SUBPATH_OF_UNIDENTIFIED_PACKAGE


def test_an_unversioned_registry_instance_is_not_a_subpath():
    """The shape that actually moves rows: a package candidate hidden inside a covered bucket.

    /External/PIP/whitenoise/whitenoise is the Strategist's own cited example of 'real package
    candidate, no version'. Classified as a subpath it was counted as covered elsewhere — residue
    reported as not-a-loss, which is the error class this taxonomy exists to remove.
    """
    model = SGraph(SElement(None, ''))
    candidate = external(model, 'PIP/whitenoise/whitenoise', referenced_by='a.py')

    report = identification().external_coverage_report(model)

    assert category_of(report, candidate.getPath()) == \
        identification().CATEGORY_PACKAGE_CANDIDATE_WITHOUT_VERSION
    assert report['categories'][
        identification().CATEGORY_PACKAGE_CANDIDATE_WITHOUT_VERSION]['outcome'] == \
        identification().OUTCOME_COULD_NOT_IDENTIFY


def test_a_versioned_npm_child_is_an_instance_not_a_subpath():
    """NPM is dual-kind, so the version is what separates an instance from an import subpath.

    Legitimate here, and NOT the refuted use of a version: separating an install path from an
    import subpath was settled by NAME SHAPE, because a slash inside one element's name is a
    different structure from nested elements. Here the two structures are identical — a child of a
    package element — and the version is the only thing that distinguishes them.
    """
    model = SGraph(SElement(None, ''))
    instance = external(model, 'NPM/lodash/lodash of version 4.17.21', version='4.17.21',
                        referenced_by='a.js')
    subpath = external(model, 'NPM/react-dom/server', referenced_by='b.js')

    report = identification().external_coverage_report(model)

    assert category_of(report, instance.getPath()) is None  # emits, so never classified
    assert category_of(
        report, subpath.getPath()) in (identification().CATEGORY_SUBPATH_OF_EMITTED_PACKAGE,
                                       identification().CATEGORY_SUBPATH_OF_UNIDENTIFIED_PACKAGE)


def test_a_package_and_its_instance_node_count_as_one_package():
    """The whitenoise shape: two graph nodes, one package a consumer is missing.

    /External/PIP/whitenoise and /External/PIP/whitenoise/whitenoise are both unversioned and both
    classified, so the element count is two. A consumer asking what the BOM does not cover is
    asking about packages, and there is one.
    """
    model = SGraph(SElement(None, ''))
    external(model, 'PIP/whitenoise', referenced_by='a.py')
    external(model, 'PIP/whitenoise/whitenoise', referenced_by='b.py')

    bucket = identification().external_coverage_report(model)['categories'][
        identification().CATEGORY_PACKAGE_CANDIDATE_WITHOUT_VERSION]

    assert bucket['elementCount'] == 2
    assert bucket['distinctPackageCount'] == 1


def test_the_distinct_count_uses_the_shared_match_key():
    """Asserted against match_key directly, so a private folding rule cannot be substituted.

    The cheapest way to shrink a distinct-package count is to loosen the fold. Loosening this one
    breaks A8's join tests, because the same function decides when two names are one package for
    the report and for the join — so the two can never disagree about what a package is.
    """
    from sgraph.converters.external_root_semantics import match_key

    model = SGraph(SElement(None, ''))
    external(model, 'PIP/zope.interface', referenced_by='a.py')
    external(model, 'PIP/zope_interface', referenced_by='b.py')

    bucket = identification().external_coverage_report(model)['categories'][
        identification().CATEGORY_PACKAGE_CANDIDATE_WITHOUT_VERSION]

    assert match_key('pypi', 'zope.interface') == match_key('pypi', 'zope_interface')
    assert bucket['elementCount'] == 2
    assert bucket['distinctPackageCount'] == 1


def test_a_not_a_package_category_publishes_no_distinct_package_count():
    """A count is published where it means something, or not at all.

    'How many distinct packages' is undefined for code symbols, filesystem paths and stdlib
    modules — they are not packages — so the field is absent rather than zero, which would read as
    'we looked and found none'.
    """
    model = SGraph(SElement(None, ''))
    external(model, 'Python/starlette/responses/Response', referenced_by='a.py', deptype='ref')
    external(model, 'PIP/whitenoise', referenced_by='b.py')

    categories = identification().external_coverage_report(model)['categories']

    assert 'distinctPackageCount' not in categories[
        identification().CATEGORY_UNRESOLVED_CODE_SYMBOL]
    assert 'distinctPackageCount' not in categories[identification().CATEGORY_STDLIB_OR_BUILTIN]
    assert 'distinctPackageCount' not in categories[identification().CATEGORY_NOT_A_PACKAGE_ROOT]
    assert 'distinctPackageCount' in categories[
        identification().CATEGORY_PACKAGE_CANDIDATE_WITHOUT_VERSION]


def test_every_published_count_names_its_unit():
    """Mechanical guard on the naming rule, because a rule that lives only in a document decays.

    Every number the report publishes must say what it counts in its own identifier: a reader who
    takes 79 645 elements for 79 645 packages is wrong by about a factor of two, and no amount of
    surrounding prose travels with a number once it is quoted.
    """
    model = SGraph(SElement(None, ''))
    external(model, 'PIP/whitenoise', referenced_by='a.py')
    external(model, 'Python/starlette/responses/Response', referenced_by='b.py', deptype='ref')

    report = identification().external_coverage_report(model)
    unnamed = []

    def check(node, trail):
        if isinstance(node, dict):
            for key, value in node.items():
                check(value, f'{trail}.{key}')
        elif isinstance(node, int) and not isinstance(node, bool):
            leaf = trail.rsplit('.', 1)[-1].lower()
            if not any(unit in leaf for unit in ('element', 'component', 'package')):
                unnamed.append(trail)

    check(report, 'report')
    assert unnamed == []


def test_two_install_paths_of_one_package_count_as_one_package():
    """Two requirer chains installing one package are one package a consumer is missing.

    wrap-ansi-cjs/strip-ansi and string-width-cjs/strip-ansi are two installs of strip-ansi. The
    leading segments name the packages that REQUIRED it, so keying identity on the raw name would
    assert the reading A1 measured and refuted — that the whole path names a package — while the
    emitter asserts the tail. Reading a name to learn which package it refers to needs no version
    gate, because reading asserts nothing.
    """
    model = SGraph(SElement(None, ''))
    external(model, 'NPM/wrap-ansi-cjs__slash__strip-ansi', referenced_by='a.js')
    external(model, 'NPM/string-width-cjs__slash__strip-ansi', referenced_by='b.js')

    bucket = identification().external_coverage_report(model)['categories'][
        identification().CATEGORY_UNVERSIONED_INSTALL_PATH]

    assert bucket['elementCount'] == 2
    assert bucket['distinctPackageCount'] == 1


def test_the_distinct_count_and_the_join_use_one_identity_function():
    """One function decides what a package is, so no two consumers of it can disagree.

    Structural rather than conventional: asserted against package_identity itself, so a private
    composition cannot be substituted at either site. The distinct-package count is one consumer;
    the join index and the collision detector are the others, and if the join keyed on raw names
    an install path could never join the package it installs.
    """
    model = SGraph(SElement(None, ''))
    install_path = external(model, 'NPM/wrap-ansi-cjs__slash__strip-ansi', referenced_by='a.js')
    plain = external(model, 'NPM/strip-ansi', referenced_by='b.js')
    root = identification()._external_root(model)

    assert identification().package_identity(install_path, root) == \
        identification().package_identity(plain, root)
    assert identification().package_identity(plain, root) == ('npm', 'strip-ansi')


# --- classifier corrections found by the differential against the ratified taxonomy (P3e) ---


def test_a_package_named_after_a_stdlib_module_is_not_stdlib():
    """Stdlib-ness belongs to the depth-1 element and is inherited, not read from any segment.

    /External/Python/odoo/http is a module inside the odoo package. Testing the element's own name
    finds 'http', which is a stdlib module name, and reports a third-party package's internals as
    the standard library.
    """
    model = SGraph(SElement(None, ''))
    odoo_http = external(model, 'Python/odoo/http', referenced_by='a.py')

    report = identification().external_coverage_report(model)

    assert category_of(report, odoo_http.getPath()) != \
        identification().CATEGORY_STDLIB_OR_BUILTIN


def test_a_stdlib_submodule_is_stdlib():
    """The inheritance in the other direction: if urllib is stdlib, urllib/error is too."""
    model = SGraph(SElement(None, ''))
    urllib_error = external(model, 'Python/urllib/error', referenced_by='a.py')

    report = identification().external_coverage_report(model)

    assert category_of(report, urllib_error.getPath()) == \
        identification().CATEGORY_STDLIB_OR_BUILTIN


def test_a_dotted_stdlib_name_in_one_element_is_stdlib():
    """The same package written as one dotted element rather than a chain of them."""
    model = SGraph(SElement(None, ''))
    dotted = external(model, 'PythonLibs/xml.etree.ElementTree', referenced_by='a.py')

    report = identification().external_coverage_report(model)

    assert category_of(report, dotted.getPath()) == identification().CATEGORY_STDLIB_OR_BUILTIN


def test_a_python_builtin_is_not_an_unresolved_code_symbol():
    """A builtin is not unresolved: it resolves to the interpreter.

    Routing builtins into 'unresolved code symbol' is not a finer distinction, it is a misfiling
    that happens to share an outcome class — the category's name asserts something false about it.
    """
    model = SGraph(SElement(None, ''))
    builtin = external(model, 'Python/breakpoint', referenced_by='a.py', deptype='ref')

    report = identification().external_coverage_report(model)

    assert category_of(report, builtin.getPath()) == identification().CATEGORY_STDLIB_OR_BUILTIN


def test_a_python_builtin_exception_is_not_residue():
    """Warning, breakpoint, oct and dir are one population and must be judged one way.

    Reported as a package candidate, Warning would be counted among the packages the BOM fails to
    identify — a coverage failure invented out of a builtin exception class.
    """
    model = SGraph(SElement(None, ''))
    warning = external(model, 'Python/Warning', referenced_by='a.py')

    report = identification().external_coverage_report(model)

    assert category_of(report, warning.getPath()) == identification().CATEGORY_STDLIB_OR_BUILTIN


def test_a_node_builtin_is_stdlib_including_deprecated_aliases():
    """The Node list must be HISTORICAL: 'sys' under NPM is the long-deprecated require('sys').

    A current-Node list would miss it and report a builtin as a missing npm package, which is
    exactly the kind of phantom a consumer would go looking for and never find.
    """
    model = SGraph(SElement(None, ''))
    http = external(model, 'NPM/http', referenced_by='a.js')
    deprecated = external(model, 'NPM/sys', referenced_by='b.js')

    report = identification().external_coverage_report(model)

    assert category_of(report, http.getPath()) == identification().CATEGORY_STDLIB_OR_BUILTIN
    assert category_of(report, deprecated.getPath()) == \
        identification().CATEGORY_STDLIB_OR_BUILTIN


def test_a_path_inside_an_image_is_not_an_image_identity():
    """The kind-gate defect one depth down: an image identity is at the image-name position.

    /External/Docker/Image/build/app/dist is a path inside an image, not an image. Reported as an
    image identity it lands in couldNotIdentify and inflates the residue with directories.
    """
    model = SGraph(SElement(None, ''))
    inside = external(model, 'Docker/Image/intra-app of tag build/usr/src/app',
                      referenced_by='Dockerfile')

    report = identification().external_coverage_report(model)

    assert category_of(report, inside.getPath()) == \
        identification().CATEGORY_NOT_A_PACKAGE_ROOT


def test_an_image_identity_is_at_the_image_name_position():
    """Anti-vacuity for the depth gate: the gate must not empty the category it guards."""
    model = SGraph(SElement(None, ''))
    image = external(model, 'Docker/Image/nginx', referenced_by='Dockerfile')

    report = identification().external_coverage_report(model)

    assert category_of(report, image.getPath()) == \
        identification().CATEGORY_DOCKER_IMAGE_IDENTITY


def test_an_analyzer_bucket_is_not_a_registry_namespace():
    """A catch-all bucket an analyzer writes is a filesystem-shaped namespace, not a registry one.

    /External/PIP/Unknown Requirements Files/./requirements.txt is where the pip analyzer files
    what it could not resolve. Read as a registry namespace, every node under it becomes a package
    candidate the BOM failed to identify — coverage failures invented out of an analyzer's own
    bookkeeping. It is a registry ROW rather than a shape predicate because exactly one such
    bucket exists corpus-wide, and a predicate would generalise a rule with one example and no way
    to test the generalisation.
    """
    model = SGraph(SElement(None, ''))
    bucket = external(model, 'PIP/Unknown Requirements Files', referenced_by='a.py')
    dot = external(model, 'PIP/Unknown Requirements Files/.', referenced_by='b.py')
    requirements = external(model, 'PIP/Unknown Requirements Files/./requirements.txt',
                            referenced_by='c.py')

    report = identification().external_coverage_report(model)

    for element in (bucket, dot, requirements):
        assert category_of(report, element.getPath()) == \
            identification().CATEGORY_NOT_A_PACKAGE_ROOT, element.getPath()


def test_a_dotted_npm_name_is_not_a_file():
    """Regression guard for a measured false positive, so the idea cannot be rediscovered.

    A shape rule of "contains a separator and ends in an extension" classified 63 install paths as
    files — a fifth of that category — because npm package names legitimately contain dots. These
    three are real packages, and any future shape predicate that calls them files is wrong in the
    same way.
    """
    model = SGraph(SElement(None, ''))
    scoped = external(model, 'NPM/@nodelib__slash__fs.stat', referenced_by='a.js')
    install_path = external(model, 'NPM/wrap-ansi-cjs__slash__fs.realpath', referenced_by='b.js')
    dotted = external(model, 'NPM/lodash.merge', referenced_by='c.js')

    report = identification().external_coverage_report(model)

    for element in (scoped, install_path, dotted):
        assert category_of(report, element.getPath()) != \
            identification().CATEGORY_NOT_A_PACKAGE_ROOT, element.getPath()


def test_a_dotted_pypi_name_is_not_a_file():
    """The same hazard one ecosystem over, measured rather than reasoned.

    zope.interface and ruamel.yaml end in alphanumeric segments that look exactly like file
    extensions. An extension-based rule that reached bare names would eat them, which is why the
    npm exclusion was not enough and the clause was removed rather than narrowed again.
    """
    model = SGraph(SElement(None, ''))
    zope = external(model, 'PIP/zope.interface', referenced_by='a.py')
    ruamel = external(model, 'PIP/ruamel.yaml', referenced_by='b.py')

    report = identification().external_coverage_report(model)

    for element in (zope, ruamel):
        assert category_of(report, element.getPath()) != \
            identification().CATEGORY_NOT_A_PACKAGE_ROOT, element.getPath()


def test_a_path_inside_a_tagged_image_is_not_a_finding():
    """' of tag ' is a version to purl construction and not a finding signal.

    /External/Docker/Image/intra-app of tag build/usr is a directory in an unpacked image. Its
    parent carries a tag, extract_version reads that as a version, and the finding rule fired on
    the strength of it — reporting image directories as advisory nodes.
    """
    model = SGraph(SElement(None, ''))
    image = external(model, 'Docker/Image/intra-app of tag build', referenced_by='Dockerfile')
    inside = SElement(image, 'usr')
    SElementAssociation(model.createOrGetElementFromPath('/Org/repoA/src/Dockerfile'), inside,
                        'use').initElems()

    report = identification().external_coverage_report(model)

    assert category_of(report, inside.getPath()) == \
        identification().CATEGORY_NOT_A_PACKAGE_ROOT


def test_a_finding_requires_a_registry_root():
    """Findings are advisory nodes, and producers write them under registry roots.

    Third instance of one defect — a classification rule reading tree position without asking what
    kind of root it is under. The subpath rule did it on registry roots, the image rule did it at
    the wrong depth, and this was the last one left ungated.
    """
    model = SGraph(SElement(None, ''))
    versioned = external(model, 'NPM/pkg2/pkg2 of version 2.0.0', version='2.0.0',
                         referenced_by='a.js')
    finding = SElement(versioned, 'pkg2_GHSA-0000-0000-0000')
    finding.attrs['package_name'] = 'pkg2'

    report = identification().external_coverage_report(model)

    assert category_of(report, finding.getPath()) == \
        identification().CATEGORY_FINDING_UNDER_VERSIONED_PACKAGE


def test_a_builtin_name_that_is_a_real_package_is_not_stdlib():
    """punycode, string_decoder and process are published npm packages BECAUSE they shadow builtins.

    That is the sharpest demonstration that the name was never the signal: these packages exist
    precisely because their names collide with Node builtins. An element carrying a version is
    evidence of a package, and evidence beats a name.
    """
    model = SGraph(SElement(None, ''))
    shadowing = external(model, 'NPM/punycode', version='2.3.1', referenced_by='a.js')

    report = identification().external_coverage_report(model)

    assert category_of(report, shadowing.getPath()) is None  # it emits, so it is not classified


def test_the_builtins_gate_reads_admission_not_the_version():
    """A negative claim must clear the BROADEST available contrary evidence, not the narrowest.

    The builtins rule asserts 'there is no package here', so any evidence of a package defeats it —
    which is why it reads the admission predicate rather than the version attribute. A1's gate is
    narrow for the opposite reason: it ASSERTS an identity, so it demands specific evidence.

    This element carries no version attribute at all; its version lives in its name, which is one
    of the routes admission accepts. Gating on the attribute would call it stdlib.
    """
    from sgraph.converters.external_root_semantics import role_of, ROLE_STDLIB
    from sgraph.converters.sbom_cyclonedx_generator import valid_for_bom

    model = SGraph(SElement(None, ''))
    admitted = external(model, 'NPM/http of version 1.0.0', referenced_by='a.js')

    assert valid_for_bom(admitted)
    assert 'version' not in admitted.attrs
    role = role_of(admitted, 'NPM', has_version=lambda e: bool(e.attrs.get('version')),
                   is_stdlib_name=lambda key, name: True, has_package_evidence=valid_for_bom)
    assert role != ROLE_STDLIB


def test_an_image_name_segment_is_not_an_identity():
    """ghcr.io and astral-sh are parts of an image's NAME, not images.

    ' of tag ' marks where the name ends: an untagged element with a tagged descendant is still
    inside the name, so it is neither an identity nor a path in the filesystem.
    """
    model = SGraph(SElement(None, ''))
    segment = external(model, 'Docker/Image/ghcr.io', referenced_by='Dockerfile')
    external(model, 'Docker/Image/ghcr.io/astral-sh/uv of tag python3.13', referenced_by='D2')

    report = identification().external_coverage_report(model)

    assert category_of(report, segment.getPath()) == \
        identification().CATEGORY_NOT_A_PACKAGE_ROOT


def test_a_tagged_element_is_the_image_identity():
    """Anti-vacuity for the boundary rule: the element carrying the tag IS the image.

    Asserted on the ROLE rather than on a report category, because a tagged element emits — a tag
    is a version to the admission predicate — so the classifier never sees it. Testing it through
    the report would have asserted only that emitting elements are not classified, which is true
    of everything that emits and says nothing about the boundary rule.
    """
    from sgraph.converters.external_root_semantics import ROLE_IMAGE, role_of
    from sgraph.converters.sbom_cyclonedx_generator import valid_for_bom

    model = SGraph(SElement(None, ''))
    external(model, 'Docker/Image/ghcr.io', referenced_by='Dockerfile')
    identity = external(model, 'Docker/Image/ghcr.io/astral-sh/uv of tag python3.13',
                        referenced_by='D2')

    assert valid_for_bom(identity)
    assert role_of(identity, 'Docker/Image', has_version=lambda e: bool(e.attrs.get('version')),
                   is_stdlib_name=lambda key, name: False,
                   has_package_evidence=valid_for_bom) == ROLE_IMAGE


def test_a_nested_jvm_maven_root_is_recognised():
    """JVM/Maven is a nested root of the same shape as Docker/Image, and the registry lacked it.

    purl_for types these correctly from their groupId and artifactId, so the emitter was right and
    the registry had the gap — which is what left them with no role at all.
    """
    from sgraph.converters.external_root_semantics import ecosystem_of_root, external_root_key

    model = SGraph(SElement(None, ''))
    artifact = external(model, 'JVM/Maven/org.example.reactor reactor-parent', attrs={
        'groupId': 'org.example.reactor',
        'artifactId': 'reactor-parent'
    }, referenced_by='a.java')

    assert external_root_key(artifact) == 'JVM/Maven'
    assert ecosystem_of_root('JVM/Maven') == 'maven'


# --- the H2 join: identity resolution, never emission (P4 / A8a) ---
#
# A package whose version is already in the model on a SECOND node is not a coverage failure, it
# is a failure to connect two nodes. /External/Python/click carries no version and
# /External/PIP/click/click of version 8.4.2 carries one; the BOM already contains the component,
# so the join changes what the REPORT says and appends nothing to any document.
#
# A naive name join measured 12 % cross-ecosystem false positives, which is why every guard below
# exists and why the gate asserts the zero rather than the total.


def versioned_registry_package(model, root, name, version, referenced_by='a.py'):
    """An emitting package under a registry root — the only shape a join may target."""
    return external(model, f'{root}/{name}/{name} of version {version}', version=version,
                    referenced_by=referenced_by)


def join_records(model):
    identification_module = identification()
    index = identification_module.build_join_index(model)
    internal = identification_module.internal_published_identities(model)
    root = identification_module._external_root(model)
    records = []
    stack = list(root.children)
    while stack:
        elem = stack.pop()
        stack += elem.children
        record = identification_module.resolve_identity_by_join(elem, index, root, internal)
        if record is not None:
            records.append(record)
    return records


def test_an_unversioned_import_joins_its_versioned_registry_sibling():
    """The H2 shape: the version is in the model, on a node the coverage walk treated separately."""
    model = SGraph(SElement(None, ''))
    imported = external(model, 'Python/click', referenced_by='a.py')
    versioned_registry_package(model, 'PIP', 'click', '8.4.2')

    records = join_records(model)

    assert [record['element'] for record in records] == [imported.getPath()]
    assert records[0]['coveringRef'] == 'pkg:pypi/click@8.4.2'
    assert records[0]['ecosystem'] == 'pypi'


def test_a_join_never_crosses_ecosystems():
    """The guard that eliminates both measured false-positive classes, by construction.

    /External/Python/yaml and an npm package called yaml are different packages that share a
    string. Requiring both ecosystems to be equal AND non-None makes the join impossible rather
    than unlikely, which is why the gate asserts zero cross-ecosystem joins rather than a rate.
    """
    model = SGraph(SElement(None, ''))
    external(model, 'Python/yaml', referenced_by='a.py')
    versioned_registry_package(model, 'NPM', 'yaml', '2.9.0', referenced_by='b.js')

    assert join_records(model) == []


def test_a_docker_image_never_joins_a_python_import():
    """An image named odoo and a python module named odoo share nothing but a string."""
    model = SGraph(SElement(None, ''))
    external(model, 'Python/odoo', referenced_by='a.py')
    external(model, 'Docker/Image/odoo of tag 17', referenced_by='Dockerfile')

    assert join_records(model) == []


def test_an_import_alias_joins_its_distribution():
    """import yaml installs PyYAML: the import name and the distribution name differ by design."""
    model = SGraph(SElement(None, ''))
    imported = external(model, 'Python/yaml', referenced_by='a.py')
    versioned_registry_package(model, 'PIP', 'pyyaml', '6.0.2')

    records = join_records(model)

    assert [record['element'] for record in records] == [imported.getPath()]
    assert records[0]['matchRule'] == 'alias:yaml'


def test_an_alias_cannot_cross_ecosystems():
    """The alias table is ecosystem-keyed, so a pypi alias can never resolve an npm name."""
    model = SGraph(SElement(None, ''))
    external(model, 'NPM/yaml', referenced_by='a.js')
    versioned_registry_package(model, 'PIP', 'pyyaml', '6.0.2')

    assert join_records(model) == []


def test_a_join_requires_the_covering_component_to_exist():
    """A repair may only assert an identity the model corroborates.

    Without a versioned sibling there is nothing to join to, and inventing the connection would
    manufacture coverage out of a name.
    """
    model = SGraph(SElement(None, ''))
    external(model, 'Python/click', referenced_by='a.py')

    assert join_records(model) == []


def test_a_stdlib_root_never_joins():
    """PythonLibs asserts no ecosystem, so stdlib dataclasses cannot reach PyPI's dataclasses.

    That backport package is real, and an ecosystem for the stdlib namespace would make the join
    legal. None makes it impossible rather than merely unlikely.
    """
    model = SGraph(SElement(None, ''))
    external(model, 'PythonLibs/dataclasses', referenced_by='a.py')
    versioned_registry_package(model, 'PIP', 'dataclasses', '0.8')

    assert join_records(model) == []


def test_an_install_path_joins_the_package_it_installs():
    """The recovery the shared identity function buys: the install path IS that package.

    Keyed on raw names this join could never happen, because the index would hold strip-ansi and
    the element would ask for wrap-ansi-cjs/strip-ansi.
    """
    model = SGraph(SElement(None, ''))
    install_path = external(model, 'NPM/wrap-ansi-cjs__slash__strip-ansi', referenced_by='a.js')
    versioned_registry_package(model, 'NPM', 'strip-ansi', '6.0.1', referenced_by='b.js')

    records = join_records(model)

    assert [record['element'] for record in records] == [install_path.getPath()]
    assert records[0]['coveringRef'] == 'pkg:npm/strip-ansi@6.0.1'


def test_a_join_adds_no_component_and_changes_no_document():
    """Invariant 2 by construction: the join resolves an identity and emits nothing.

    Compared against the same model's document before the join is computed, field by field —
    because 'report-only' is a claim about output, and only output can check it.
    """
    model = SGraph(SElement(None, ''))
    external(model, 'Python/click', referenced_by='a.py')
    versioned_registry_package(model, 'PIP', 'click', '8.4.2')

    before = sbom_cyclonedx_generator.generate_from_sgraph(model)['components']
    snapshot = [sorted(component.items(), key=str) for component in before]

    assert join_records(model)

    after = sbom_cyclonedx_generator.generate_from_sgraph(model)['components']
    assert [sorted(component.items(), key=str) for component in after] == snapshot


def test_a_joined_element_moves_from_could_not_identify_to_covered_elsewhere():
    """The join's whole visible effect: a residue row becomes a covered one."""
    model = SGraph(SElement(None, ''))
    joined = external(model, 'Python/click', referenced_by='a.py')
    versioned_registry_package(model, 'PIP', 'click', '8.4.2')

    report = identification().external_coverage_report(model)

    assert category_of(report, joined.getPath()) == \
        identification().CATEGORY_JOINED_TO_VERSIONED_SIBLING
    assert report['categories'][
        identification().CATEGORY_JOINED_TO_VERSIONED_SIBLING]['outcome'] == \
        identification().OUTCOME_COVERED_ELSEWHERE


def test_every_join_carries_an_evidence_record():
    """A join nobody can audit is a claim, not a resolution.

    One record per join, no more and no fewer, each naming the element, the covering ref, the
    shared ecosystem and the rule that matched.
    """
    model = SGraph(SElement(None, ''))
    external(model, 'Python/click', referenced_by='a.py')
    versioned_registry_package(model, 'PIP', 'click', '8.4.2')
    external(model, 'Python/yaml', referenced_by='b.py')
    versioned_registry_package(model, 'PIP', 'pyyaml', '6.0.2')

    report = identification().external_coverage_report(model)
    bucket = report['categories'][identification().CATEGORY_JOINED_TO_VERSIONED_SIBLING]

    assert len(report['joins']) == bucket['elementCount']
    for record in report['joins']:
        assert set(record) >= {'element', 'coveringRef', 'ecosystem', 'matchRule', 'collisionRisk'}


def test_a_join_onto_an_internally_published_name_is_flagged():
    """The playwright shape: a first-party package sharing a name with a public one.

    The estate publishes its own click, so resolving an unversioned import to the public package
    may be wrong. The join still records it — suppressing it silently would be the same class of
    error — and flags the risk for the collision detector to upgrade.
    """
    model = SGraph(SElement(None, ''))
    external(model, 'Python/click', referenced_by='a.py')
    versioned_registry_package(model, 'PIP', 'click', '8.4.2')
    internal = model.createOrGetElementFromPath('/Org/repoB/setup.py/click')
    internal.attrs['package_name'] = 'click'
    internal.attrs['ecosystem'] = 'pypi'

    records = join_records(model)

    assert len(records) == 1
    assert records[0]['collisionRisk'] is True


# --- image structure: four cases and a residual (P3h) ---


def test_an_untagged_image_chain_is_not_a_package():
    """A locally built image that was never tagged is a filesystem tree, not a list of packages.

    Every element of the chain, not a sample: the clause this replaces fired on each of them
    independently, so a sample would have passed while the rest of the tree stayed wrong.
    build/app/package.json reported as a package the BOM failed to identify is the shape that
    makes the error visible.
    """
    model = SGraph(SElement(None, ''))
    chain = [
        'Docker/Image/build', 'Docker/Image/build/app', 'Docker/Image/build/app/package.json',
        'Docker/Image/build/app/node_modules', 'Docker/Image/build/app/src',
        'Docker/Image/build/app/src/agents', 'Docker/Image/build/app/src/agents/templates'
    ]
    elements = [external(model, path, referenced_by='Dockerfile') for path in chain]

    report = identification().external_coverage_report(model)

    for element in elements:
        assert category_of(report, element.getPath()) == \
            identification().CATEGORY_NOT_A_PACKAGE_ROOT, element.getPath()
    assert report['categories'][identification().CATEGORY_NOT_A_PACKAGE_ROOT]['subLabels'][
        'untagged_image_chain']['elementCount'] == len(chain)


def test_an_untagged_single_image_reference_is_still_an_identity():
    """The control that stops this fix eating the genuinely untagged references.

    FROM nginx is a real dependency with an implicit :latest, and there are eight of them. What
    distinguishes the chain is that it is a CHAIN, not that it lacks a tag.
    """
    model = SGraph(SElement(None, ''))
    single = external(model, 'Docker/Image/nginx', referenced_by='Dockerfile')

    report = identification().external_coverage_report(model)

    assert category_of(report, single.getPath()) == \
        identification().CATEGORY_DOCKER_IMAGE_IDENTITY


def test_an_element_matching_no_image_clause_is_reported_as_unknown():
    """The residual arm, made reachable and then proved reachable.

    The clause set this replaces was TOTAL, so its own 'report anything that matches nothing'
    instruction could never fire. Here an untagged element sits beside a tagged sibling: no tagged
    ancestor, no tag of its own, not a direct child, no tagged descendant, and its chain is not
    untagged either. It matches nothing, and saying so is better than assigning a default.
    """
    model = SGraph(SElement(None, ''))
    external(model, 'Docker/Image/head/a of tag v1', referenced_by='Dockerfile')
    unmatched = external(model, 'Docker/Image/head/b', referenced_by='D2')

    report = identification().external_coverage_report(model)

    assert unmatched.getPath() in report['unclassifiedImageElements']
