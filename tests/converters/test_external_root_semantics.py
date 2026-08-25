"""Tests for the External-root registry: what each root means, and who owns that knowledge.

The registry encodes tacit knowledge that lived only in scattered producer comments — which
children of External are package registries, which are import graphs, which are standard-library
namespaces. purl_for is deliberately NOT refactored onto it this sprint, so the two copies are
pinned against each other by the equivalence test at the bottom of this file rather than merged.

The module under test is imported inside the tests rather than at module level, so this file
collects (and its count can be pinned) before the module exists.
"""
import pytest

from sgraph import SElement, SElementAssociation, SGraph
from sgraph.converters import sbom_cyclonedx_generator
from sgraph.converters.sbom_cyclonedx_generator import (FALLBACK_PURL_TYPE,
                                                        PURL_TYPE_SOURCE_PROPERTY, bom_ref)

# The roots purl_for actually knows how to type. A literal list rather than the registry's own
# keys ON PURPOSE: iterating the registry would silently skip a root the registry forgot, which is
# the exact drift the equivalence test exists to catch. A new branch in purl_for is added here,
# and then the registry must carry a row for it or the test fails.
KNOWN_ROOTS = [
    'APT',
    'Assemblies',
    'Docker',
    'Docker/FilesysReference',
    'Docker/Image',
    'Go',
    'Go/Standard_Go',
    'Java',
    'Maven',
    'NPM',
    'PIP',
    'Python',
    'PythonLibs',
]


def semantics():
    from sgraph.converters import external_root_semantics
    return external_root_semantics


def external_under(root_path, name, version='1.0', attrs=None):
    """A referenced, versioned external at External/<root_path>/<name>."""
    model = SGraph(SElement(None, ''))
    referrer = model.createOrGetElementFromPath('/Org/repoA/src/app.txt')
    parent = model.createOrGetElementFromPath(f'/Org/External/{root_path}')
    elem = SElement(parent, name)
    elem.attrs['version'] = version
    for key, value in (attrs or {}).items():
        elem.attrs[key] = value
    SElementAssociation(referrer, elem, 'use').initElems()
    return elem


def test_the_root_ecosystem_table_is_total():
    """Every root answers, including one nobody has seen: unknown resolves to None, never KeyError.

    Totality is what lets the classifier ask about any element without guarding every call, and
    None is a real answer — 'this root asserts no ecosystem' — not a missing entry.
    """
    assert semantics().ecosystem_of_root('NPM') == 'npm'
    assert semantics().ecosystem_of_root('SomethingNobodyHasWrittenYet') is None


def test_pythonlibs_asserts_no_ecosystem_but_is_known_as_stdlib():
    """None and 'unknown' are different facts, carried by different tables.

    PythonLibs is the standard library, never a dependency. Typing it as pypi would make stdlib
    'dataclasses' joinable to the real PyPI backport package dataclasses@0.8 — a false positive of
    the measured cross-population kind — because a join requires both ecosystems to be equal and
    non-None. None makes the namespace unjoinable by construction. The knowledge that the root IS
    known lives in ROOT_KINDS instead, so nothing is lost by the None.
    """
    assert semantics().ecosystem_of_root('PythonLibs') is None
    assert semantics().KIND_STDLIB in semantics().ROOT_KINDS['PythonLibs']
    assert 'SomethingNobodyHasWrittenYet' not in semantics().ROOT_KINDS


def test_docker_image_and_filesys_reference_resolve_differently():
    """Two roots one level below Docker mean opposite things, so a name-keyed table cannot work.

    Docker/Image holds image identities; Docker/FilesysReference holds COPY sources, which are
    filesystem paths and not packages at all. Both are children of one External child, so the
    registry is keyed by path fragment rather than by root name.
    """
    assert semantics().ecosystem_of_root('Docker/Image') == 'docker'
    assert semantics().ecosystem_of_root('Docker/FilesysReference') is None
    assert semantics().KIND_FILESYSTEM in semantics().ROOT_KINDS['Docker/FilesysReference']


def test_the_longest_matching_prefix_wins():
    """A root may carry both a general rule and a specific one, and the specific one must win.

    Go is golang; Go/Standard_Go is the standard library and asserts no ecosystem. Matching on
    segment boundaries keeps 'Gopher' from ever matching the 'Go' row.
    """
    assert semantics().ecosystem_of_root('Go') == 'golang'
    assert semantics().ecosystem_of_root('Go/Standard_Go') is None
    assert semantics().ecosystem_of_root('Go/Standard_Go/net/http') is None
    assert semantics().ecosystem_of_root('Gopher') is None


def test_the_root_key_is_the_matched_fragment_not_the_first_segment():
    """external_root_key reports which rule matched, so a caller can explain a classification."""
    elem = external_under('Docker/Image', 'nginx')
    assert semantics().external_root_key(elem) == 'Docker/Image'
    assert semantics().external_root_key(external_under('NPM', 'lodash')) == 'NPM'


def test_role_of_reads_the_parent_through_the_injected_callable():
    """A finding is decided structurally — a child of a VERSIONED INSTANCE — not by name shape.

    That is why the version fact arrives as a callable rather than a boolean: role_of must ask
    about elem.parent, which a boolean computed for elem cannot express. Deciding it structurally
    is what makes it survive a new advisory source, whose ids this module has never seen.
    """
    versioned = external_under('NPM', 'pkg2 of version 2.0.0')
    finding = SElement(versioned, 'pkg2_GHSA-0000-0000-0000')
    finding.attrs['package_name'] = 'pkg2'

    def has_version(elem):
        return ' of version ' in elem.name or 'version' in elem.attrs

    role = semantics().role_of(finding, 'NPM', has_version=has_version,
                               is_stdlib_name=lambda root_key, name: False)
    assert role == semantics().ROLE_FINDING


def test_match_key_and_canonical_purl_name_are_not_the_same_function():
    """Publishing an identifier and matching two identifiers are different operations.

    purl-spec licenses lowercase and underscore-to-dash for pypi and scopes the dot rule to
    distribution FILE names, so the published name keeps its dots. PEP 503 collapses dots, which
    is what internal matching needs. One function for both would force a choice between a
    spec-conformant purl and a working join.
    """
    assert semantics().match_key('pypi', 'zope.interface') == 'zope-interface'
    assert semantics().canonical_purl_name('pypi', 'zope.interface') == 'zope.interface'


def test_the_pure_module_owns_the_name_repair():
    """The repair is pure string logic and belongs in the module that imports nothing.

    It landed in the generator because that is where P2's seam was. The coverage report needs to
    READ it to learn which package an install-path name refers to, and letting
    external_identification import it from the generator would have widened an import exception
    that three phases rely on. The generator keeps working through the same object.
    """
    assert semantics().repair_npm_package_name('wrap-ansi-cjs/strip-ansi') == ('strip-ansi',
                                                                               'install-path')
    assert (sbom_cyclonedx_generator.repair_npm_package_name is semantics().repair_npm_package_name)


@pytest.mark.parametrize('root_key', KNOWN_ROOTS)
def test_the_registry_agrees_with_purl_for_on_every_known_root(root_key):
    """The equivalence test: two copies of the same tacit knowledge, pinned against each other.

    purl_for is not refactored onto the registry this sprint — that would touch every purl test in
    a phase whose invariant is byte-identity — so the duplication is pinned instead. A branch
    added to purl_for without a registry row fails here, which is the whole mechanism by which the
    registry stays the single edit point.

    Two rules, because None is a real answer. For a root with an ecosystem, the emitted purl type
    must equal it. For a root without one, the type must be the fallback or an inferred type, and
    must not be anything derived from the root name — otherwise a root that asserts no ecosystem
    would still be handing one to a consumer.
    """
    attrs = {'groupId': 'org.example', 'artifactId': 'thing'} if root_key == 'Maven' else None
    elem = external_under(root_key, 'thing', attrs=attrs)
    _purl, properties = sbom_cyclonedx_generator.purl_for(elem, '1.0')
    purl_type = bom_ref(elem, '1.0').split(':', 1)[1].split('/', 1)[0]

    ecosystem = semantics().ecosystem_of_root(root_key)
    if ecosystem is not None:
        assert purl_type == ecosystem
        return

    inferred = any(prop['name'] == PURL_TYPE_SOURCE_PROPERTY and 'inferred' in prop['value']
                   for prop in properties)
    assert purl_type == FALLBACK_PURL_TYPE or inferred
    assert purl_type not in {segment.lower() for segment in root_key.split('/')}


# --- A leading scope marker is encoded for every purl type ---
#
# The encoding was written as an npm rule, because the npm definition is where it is stated: "the
# npm scope @ sign prefix is always percent encoded". But the reason it is stated there is not
# npm-specific. '@' is the VERSION SEPARATOR in a purl, so a raw leading '@' in the name component
# makes the string ambiguous to any parser — 'pkg:generic/@example/foo@1.0' can be read as name
# '@example/foo' at version '1.0', or otherwise, depending on where the parser splits. That is a
# well-formedness problem, not an ecosystem courtesy.
#
# The rows that hit it are scoped npm packages whose ecosystem did NOT resolve: they fall through
# to the 'generic' type and so never reached the npm-only branch, and were published with a raw
# '@'. Encoding at the shared point rather than adding a second per-ecosystem branch is what makes
# a purl type added later inherit the rule instead of repeating the defect.


SCOPE_BEARING_PURL_TYPES = ('npm', 'generic', 'nuget', 'golang', 'deb', 'docker', 'pypi')


@pytest.mark.parametrize('pkgtype', SCOPE_BEARING_PURL_TYPES)
def test_a_leading_scope_is_encoded_for_every_purl_type(pkgtype):
    """Not an npm courtesy but a purl well-formedness rule, so it cannot be keyed on ecosystem.

    pypi is in the list even though a scoped pypi name is not a thing anyone publishes: the rule
    is about the character's meaning in the purl string, and a type where the shape cannot occur
    loses nothing by being covered. What matters is that no type is left able to emit a raw one.
    """
    assert semantics().canonical_purl_name(pkgtype, '@example/foo') == '%40example/foo'


@pytest.mark.parametrize('pkgtype', SCOPE_BEARING_PURL_TYPES)
def test_an_already_encoded_scope_is_not_encoded_twice(pkgtype):
    """'%2540example' would name a package that exists in no registry.

    Double encoding is the characteristic failure of moving an encoding step to a shared point:
    the value arrives having already passed through the old one. Asserted for every type rather
    than for the one that used to do the encoding, because after the move any type can be the one
    that receives a pre-encoded name.
    """
    assert semantics().canonical_purl_name(pkgtype, '%40example/foo') == '%40example/foo'


@pytest.mark.parametrize('pkgtype', SCOPE_BEARING_PURL_TYPES)
def test_only_a_leading_at_is_a_scope_marker_for_every_type(pkgtype):
    """The narrow rule survives the widening: an '@' elsewhere is not a scope.

    A yarn protocol alias puts an '@' in the version, and an '@' inside a name belongs to
    something that is not a scope. Widening the rule from one ecosystem to all of them is a change
    of WHICH strings it applies to, and must not become a change of WHERE in the string it looks.
    """
    assert semantics().canonical_purl_name(pkgtype, 'foo@bar') == 'foo@bar'
    assert semantics().canonical_purl_name(pkgtype, 'string-width-cjs') == 'string-width-cjs'


def test_the_pypi_folding_still_runs_before_the_scope_encoding():
    """The two rules compose rather than one shadowing the other.

    pypi returned early, so moving the scope rule below it has to keep the folding reachable. A
    scoped pypi name exercises both in one call, which is the only shape that can tell 'both ran'
    from 'the first one returned'.
    """
    assert semantics().canonical_purl_name('pypi', 'Zope_Interface') == 'zope-interface'
    assert semantics().canonical_purl_name('pypi', '@Zope_Scope/Pkg') == '%40zope-scope/pkg'


def test_the_scope_encoding_does_not_reach_the_match_key():
    """Publishing an identifier and joining two identifiers stay different operations.

    match_key feeds the distinct-package count and the join index, both of which key on names
    read from the MODEL rather than on emitted purls. Encoding a published name must therefore
    leave the key untouched — if it did not, every stored scoped package would stop matching
    itself the moment this shipped.
    """
    assert semantics().match_key('npm', '@example/foo') == '@example/foo'
    assert semantics().match_key('npm', '@example/foo') != semantics().canonical_purl_name(
        'npm', '@example/foo')
