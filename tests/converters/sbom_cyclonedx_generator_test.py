import copy
import re

import pytest

from sgraph import SElement, SElementAssociation, SGraph
from sgraph.converters import sbom_cyclonedx_generator
from sgraph.converters.sbom_cyclonedx_generator import (
    DECLARING_SCOPE_ATTRIBUTE, DECLARING_SCOPE_SEPARATOR, deterministic_serial, deptype_base,
    slugify_bom_ref, generate_multi_from_sgraph, generate_for_element_from_sgraph,
    infer_pkgtype_from_referencing_files
)
from ..modelapi_test import get_model_and_model_api


def test_filter_model():
    model, model_api = get_model_and_model_api('converters/modelfile_for_sbom_tests.xml')
    sbom = sbom_cyclonedx_generator.generate_from_sgraph(model)
    # This helps to show the SBOM
    #   print(json.dumps(sbom, indent=4))
    assert len(sbom['components']) == 6


# --- deterministic_serial tests ---

def test_deterministic_serial_is_stable():
    """Same path always produces the same UUID."""
    path = "/OrgName/GroupA/repoA"
    s1 = deterministic_serial(path)
    s2 = deterministic_serial(path)
    assert s1 == s2
    assert s1.startswith("urn:uuid:")


def test_deterministic_serial_differs_per_path():
    """Different paths produce different UUIDs."""
    s1 = deterministic_serial("/OrgName/GroupA/repoA")
    s2 = deterministic_serial("/OrgName/GroupA/repoB")
    assert s1 != s2


# --- slugify_bom_ref tests ---

def test_slugify_bom_ref():
    assert slugify_bom_ref("online3_invoicepayment") == "online3-invoicepayment"
    assert slugify_bom_ref("my repo name") == "my-repo-name"
    assert slugify_bom_ref("UPPERCASE") == "uppercase"


# --- Multi-SBOM generation tests ---

def test_generate_multi_sboms_at_level_3():
    """Generate per-repo SBOMs from a 3-level model."""
    model, _ = get_model_and_model_api('converters/modelfile_for_sbom_multi_tests.xml')
    result = generate_multi_from_sgraph(model, level=3)

    # Should be a list of SBOM dicts
    assert isinstance(result, list)

    # Should have 2 SBOMs (repoA, repoB) - NOT External/Assemblies/Maven
    assert len(result) == 2

    names = sorted([sbom['metadata']['component']['name'] for sbom in result])
    assert names == ['repoA', 'repoB']

    # Each SBOM should have the default specVersion
    for sbom in result:
        assert sbom['specVersion'] == '1.6'
        assert sbom['serialNumber'].startswith('urn:uuid:')

    # Serial numbers should be deterministic (different per repo)
    serials = [sbom['serialNumber'] for sbom in result]
    assert serials[0] != serials[1]


def test_multi_sbom_contains_3rdparty_components():
    """Each repo-SBOM includes only its own 3rd-party dependencies."""
    model, _ = get_model_and_model_api('converters/modelfile_for_sbom_multi_tests.xml')
    result = generate_multi_from_sgraph(model, level=3)

    repo_a_sbom = next(s for s in result if s['metadata']['component']['name'] == 'repoA')
    repo_b_sbom = next(s for s in result if s['metadata']['component']['name'] == 'repoB')

    repo_a_component_names = [c['name'] for c in repo_a_sbom['components']]
    repo_b_component_names = [c['name'] for c in repo_b_sbom['components']]

    # repoA depends on Newtonsoft.Json (assembly_ref)
    assert 'Newtonsoft.Json' in repo_a_component_names

    # repoB depends on commons-lang3 (use via Maven)
    assert any('commons-lang3' in n for n in repo_b_component_names)


def test_multi_sbom_internal_dependencies():
    """Internal cross-repo dependencies appear as BOM-Link URNs in dependencies section."""
    model, _ = get_model_and_model_api('converters/modelfile_for_sbom_multi_tests.xml')
    result = generate_multi_from_sgraph(model, level=3)

    repo_a_sbom = next(s for s in result if s['metadata']['component']['name'] == 'repoA')

    # repoA should have a dependencies section
    assert 'dependencies' in repo_a_sbom

    # Find repoA's own dependency entry
    repo_a_ref = repo_a_sbom['metadata']['component']['bom-ref']
    repo_a_deps = next(d for d in repo_a_sbom['dependencies'] if d['ref'] == repo_a_ref)

    # Should contain a BOM-Link URN pointing to repoB
    bom_link_deps = [d for d in repo_a_deps['dependsOn'] if d.startswith('urn:cdx:')]
    assert len(bom_link_deps) >= 1

    # The BOM-Link should reference repoB's serial number
    repo_b_sbom = next(s for s in result if s['metadata']['component']['name'] == 'repoB')
    repo_b_serial = repo_b_sbom['serialNumber'].replace('urn:uuid:', '')
    assert any(repo_b_serial in link for link in bom_link_deps)


# --- Transitive multi-SBOM tests ---
#
# Dependency-Track resolves dependency graphs strictly within one uploaded BOM: BOM-Link URNs
# in dependsOn are never followed into other projects, so the exposure chain
# repoA -> repoB -> vulnerable-component is invisible when each repo uploads its own SBOM.
# Transitive mode inlines reachable internal elements and their 3rd-party components into each
# SBOM so the whole chain resolves inside a single BOM.

MULTI_MODEL = 'converters/modelfile_for_sbom_multi_tests.xml'


# find_property is defined with the emission helpers further down; module-level resolution at
# call time lets the earlier tests here use it.


def sbom_of(result, name):
    return next(s for s in result if s['metadata']['component']['name'] == name)


def test_transitive_mode_includes_internal_elements_as_components():
    """repoA's SBOM carries repoB inline as an internal library component."""
    model, _ = get_model_and_model_api(MULTI_MODEL)
    result = generate_multi_from_sgraph(model, level=3, transitive=True)

    repo_a_sbom = sbom_of(result, 'repoA')
    internal = [c for c in repo_a_sbom['components']
                if find_property(c, 'softagram:internal') == 'true']
    assert [c['name'] for c in internal] == ['repoB']
    assert internal[0]['type'] == 'library'
    assert internal[0]['bom-ref'] == slugify_bom_ref('repoB')


def test_transitive_internal_component_links_to_its_standalone_sbom():
    """The inlined internal component carries a BOM-Link to repoB's own SBOM serial."""
    model, _ = get_model_and_model_api(MULTI_MODEL)
    result = generate_multi_from_sgraph(model, level=3, transitive=True)

    repo_a_sbom = sbom_of(result, 'repoA')
    repo_b_component = next(c for c in repo_a_sbom['components'] if c['name'] == 'repoB')
    bom_refs = [r for r in repo_b_component['externalReferences'] if r['type'] == 'bom']

    repo_b_serial = sbom_of(result, 'repoB')['serialNumber'].replace('urn:uuid:', '')
    assert [r['url'] for r in bom_refs] == [f'urn:cdx:{repo_b_serial}/1']


def test_transitive_mode_pulls_indirect_externals_with_provenance():
    """repoB's 3rd-party dependency lands in repoA's SBOM, annotated with its route."""
    model, _ = get_model_and_model_api(MULTI_MODEL)
    result = generate_multi_from_sgraph(model, level=3, transitive=True)

    repo_a_sbom = sbom_of(result, 'repoA')
    components_by_name = {c['name']: c for c in repo_a_sbom['components']}

    commons_lang = next(c for name, c in components_by_name.items() if 'commons-lang3' in name)
    assert find_property(commons_lang, 'softagram:via') == 'repoB'

    # repoA's own direct dependency is not annotated as indirect
    assert find_property(components_by_name['Newtonsoft.Json'], 'softagram:via') is None


def test_transitive_mode_emits_the_exposure_chain_in_dependencies():
    """dependencies expresses repoA -> repoB -> commons-lang3 as a multi-entry graph."""
    model, _ = get_model_and_model_api(MULTI_MODEL)
    result = generate_multi_from_sgraph(model, level=3, transitive=True)

    repo_a_sbom = sbom_of(result, 'repoA')
    entries = {d['ref']: d['dependsOn'] for d in repo_a_sbom['dependencies']}

    root_ref = repo_a_sbom['metadata']['component']['bom-ref']
    repo_b_ref = slugify_bom_ref('repoB')

    assert repo_b_ref in entries[root_ref]
    assert any('Newtonsoft.Json' in ref for ref in entries[root_ref])
    assert any('commons-lang3' in ref for ref in entries[repo_b_ref])

    # No BOM-Link URNs in dependsOn: Dependency-Track drops them as dangling refs
    for depends_on in entries.values():
        assert not any(ref.startswith('urn:cdx:') for ref in depends_on)


def test_every_dependency_ref_resolves_within_the_bom():
    """Every ref and dependsOn entry points at a component of the same BOM (DT-import safety).

    Dependency-Track resolves refs only inside one uploaded document and drops the entry when a
    ref names nothing, so a single dangling ref silently deletes a link of the exposure chain.
    That risk is not specific to one mode: the internal closure merges refs across elements and
    folds case-variant spellings, and the external closure adds edges between packages, so each
    option is a fresh chance to emit a ref nothing resolves. Hence one invariant checked across
    every combination rather than one test per mode — a new option inherits the check by being
    added to the case list.
    """
    cases = [
        ('multi fixture, default', get_model_and_model_api(MULTI_MODEL)[0], dict(level=3)),
        ('multi fixture, internal closure', get_model_and_model_api(MULTI_MODEL)[0],
         dict(level=3, transitive=True)),
        ('multi fixture, both closures', get_model_and_model_api(MULTI_MODEL)[0],
         dict(level=3, transitive=True, transitive_externals=True)),
        ('package chain, external closure', npm_chain_model(3),
         dict(level=2, transitive_externals=True)),
        ('package chain, capped external closure', npm_chain_model(3),
         dict(level=2, transitive_externals=True, max_depth=2)),
    ]

    for description, model, kwargs in cases:
        for sbom in generate_multi_from_sgraph(model, **kwargs):
            known_refs = {c['bom-ref'] for c in sbom['components']}
            known_refs.add(sbom['metadata']['component']['bom-ref'])
            for entry in sbom['dependencies']:
                assert entry['ref'] in known_refs, description
                for ref in entry['dependsOn']:
                    if ref.startswith('urn:cdx:'):
                        continue
                    assert ref in known_refs, f'{description}: {ref}'


def test_a_directly_used_internal_dependency_with_identity_is_a_component_and_keeps_its_link():
    """Default mode emits an internal dependency BOTH as a component and as a BOM-Link.

    A declared dependency resolving inside the estate used to appear only as a 'urn:cdx:'
    BOM-Link in dependsOn, and a consumer that does not follow BOM-Links across uploads —
    Dependency-Track does not — saw no dependency at all.

    The BOM-Link half is unchanged and stays. Emitting the component is an addition, not a
    replacement: dropping the link would trade an invisible dependency for broken cross-document
    federation, which is a different consumer's defect rather than a fix.
    """
    result = generate_multi_from_sgraph(published_package_model(), level=2)

    repo_a_sbom = sbom_of(result, 'repoA')
    assert [c['name'] for c in internal_components(repo_a_sbom)] == ['ui-lib']

    assert len(repo_a_sbom['dependencies']) == 1
    depends_on = repo_a_sbom['dependencies'][0]['dependsOn']
    assert slugify_bom_ref('repoB') in depends_on
    assert any(ref.startswith('urn:cdx:') for ref in depends_on)


def test_a_directly_used_internal_dependency_without_identity_is_only_a_bom_link():
    """Without package identity the default view keeps exactly the output it had before.

    A component named after a repository, with no version and no purl, is the shape the original
    report complained about — and no analyzer in the released product stamps the identity
    attributes, so on every model stored today EVERY such component would come out that way. On
    one real model at directory granularity they would have been 2 656 of 3 168 rows. Emitting
    them would change the default output for every existing consumer and would look like the
    defect rather than the fix, so the component waits until it can carry real coordinates.

    The BOM-Link is unaffected: a consumer that follows links loses nothing it has today.
    """
    model, _ = get_model_and_model_api(MULTI_MODEL)
    result = generate_multi_from_sgraph(model, level=3)

    repo_a_sbom = sbom_of(result, 'repoA')
    assert internal_components(repo_a_sbom) == []

    depends_on = repo_a_sbom['dependencies'][0]['dependsOn']
    assert slugify_bom_ref('repoB') not in depends_on
    assert any(ref.startswith('urn:cdx:') for ref in depends_on)


def test_the_transitive_view_still_inlines_an_internal_element_without_identity():
    """The asymmetry between the two views is deliberate, not an oversight.

    Inlining internal elements is what --transitive has always done; its consumers already
    receive those rows, and suppressing them when identity is absent would remove a dependency
    a consumer can see today. Identity improves those rows where it exists; its absence must not
    delete them. The default view is the opposite case: there the row would be new.
    """
    model, _ = get_model_and_model_api(MULTI_MODEL)
    result = generate_multi_from_sgraph(model, level=3, transitive=True)

    inlined = internal_components(sbom_of(result, 'repoA'))
    assert [c['name'] for c in inlined] == ['repoB']
    assert 'purl' not in inlined[0]


def test_the_third_party_components_are_untouched_by_internal_inlining():
    """The 3rd-party rows are the same rows in the same order, with internal ones appended after.

    A consumer diffing two documents across this change must see an addition, not a reordering,
    and a 3rd-party component must not pick up an internal marker on the way through.
    """
    model, _ = get_model_and_model_api(MULTI_MODEL)
    result = generate_multi_from_sgraph(model, level=3)

    repo_a_sbom = sbom_of(result, 'repoA')
    third_party = [c for c in repo_a_sbom['components']
                   if find_property(c, 'softagram:internal') is None]

    assert [c['bom-ref'] for c in third_party] == ['pkg:nuget/Newtonsoft.Json@13.0.1']
    assert repo_a_sbom['components'][0]['bom-ref'] == 'pkg:nuget/Newtonsoft.Json@13.0.1'
    assert repo_a_sbom['dependencies'][0]['dependsOn'][0] == 'pkg:nuget/Newtonsoft.Json@13.0.1'


def test_the_default_document_gains_the_direct_internal_dependencies_and_no_more():
    """repoA -> repoB -> repoC adds repoB alone: the default document is not a closure.

    Inlining the whole chain is what --transitive exists for, and it multiplies document size.
    This is a defect fix for a handful of direct dependencies and must not quietly turn every
    default document into the transitive one.
    """
    model = SGraph(SElement(None, ''))
    a_file = model.createOrGetElementFromPath('/Org/repoA/src/a.js')
    b_file = model.createOrGetElementFromPath('/Org/repoB/src/b.js')
    c_file = model.createOrGetElementFromPath('/Org/repoC/src/c.js')
    SElementAssociation(a_file, b_file, 'use').initElems()
    SElementAssociation(b_file, c_file, 'use').initElems()

    for repo in ('repoA', 'repoB', 'repoC'):
        model.createOrGetElementFromPath(f'/Org/{repo}/package.json/{repo}-pkg').attrs.update(
            {'package_name': f'{repo}-pkg', 'version': '1.0.0', 'ecosystem': 'npm'})

    result = generate_multi_from_sgraph(model, level=2)

    assert [c['name'] for c in sbom_of(result, 'repoA')['components']] == ['repoB-pkg']
    assert [c['name'] for c in sbom_of(result, 'repoB')['components']] == ['repoC-pkg']
    assert sbom_of(result, 'repoC')['components'] == []


def test_the_default_mode_internal_component_is_the_one_transitive_mode_inlines():
    """One shape for an internal component, whichever mode produced it.

    Two builders would drift: a consumer would then see the same element described differently
    depending on a flag it did not set, and the identity work of one mode would silently not
    reach the other.
    """
    model = published_package_model()

    default_component = internal_components(
        sbom_of(generate_multi_from_sgraph(model, level=2), 'repoA'))
    transitive_component = internal_components(
        sbom_of(generate_multi_from_sgraph(model, level=2, transitive=True), 'repoA'))

    assert default_component == transitive_component
    assert default_component[0]['purl'] == 'pkg:generic/ui-lib@2.1.0'


def test_a_repeated_internal_edge_produces_one_component_and_one_link():
    """Several associations onto the same element are one dependency, not several rows."""
    model = SGraph(SElement(None, ''))
    first = model.createOrGetElementFromPath('/Org/repoA/src/first.js')
    second = model.createOrGetElementFromPath('/Org/repoA/src/second.js')
    used = model.createOrGetElementFromPath('/Org/repoB/src/util.js')
    internal_package_element(model, '/Org/repoB/package.json/util', 'util', '1.0.0', 'npm')
    SElementAssociation(first, used, 'use').initElems()
    SElementAssociation(second, used, 'use').initElems()

    repo_a_sbom = sbom_of(generate_multi_from_sgraph(model, level=2), 'repoA')

    assert len(internal_components(repo_a_sbom)) == 1
    depends_on = repo_a_sbom['dependencies'][0]['dependsOn']
    assert depends_on.count(slugify_bom_ref('repoB')) == 1
    assert len([ref for ref in depends_on if ref.startswith('urn:cdx:')]) == 1


def test_a_selected_element_document_inlines_its_internal_dependencies_too():
    """--element-path takes the same default path, so the fix is not level-mode-only."""
    model = published_package_model()

    sbom = generate_for_element_from_sgraph(model, '/Org/repoA')

    assert [c['name'] for c in internal_components(sbom)] == ['ui-lib']


def test_transitive_mode_terminates_on_dependency_cycles():
    """Mutually dependent repos inline each other once and both externals appear in both SBOMs."""
    model = SGraph(SElement(None, ''))
    a_file = model.createOrGetElementFromPath('/Org/repoA/src/a.cs')
    b_file = model.createOrGetElementFromPath('/Org/repoB/src/b.cs')
    ext_a = model.createOrGetElementFromPath('/Org/External/NuGet/LibA')
    ext_a.attrs['version'] = '1.0.0'
    ext_b = model.createOrGetElementFromPath('/Org/External/NuGet/LibB')
    ext_b.attrs['version'] = '2.0.0'
    SElementAssociation(a_file, b_file, 'use').initElems()
    SElementAssociation(b_file, a_file, 'use').initElems()
    SElementAssociation(a_file, ext_a, 'use').initElems()
    SElementAssociation(b_file, ext_b, 'use').initElems()

    result = generate_multi_from_sgraph(model, level=2, transitive=True)
    assert len(result) == 2

    for name, other in (('repoA', 'repoB'), ('repoB', 'repoA')):
        sbom = sbom_of(result, name)
        component_names = [c['name'] for c in sbom['components']]
        assert component_names.count(other) == 1
        assert 'LibA' in component_names
        assert 'LibB' in component_names


def test_transitive_dedup_folds_case_like_the_per_subtree_walk():
    """A case-variant NuGet id met through an internal element is the same package, not a second.

    The per-subtree collector folds nuget/pypi keys (G5); the cross-subtree merge of transitive
    mode must apply the same key, or the duplicate G5 removed comes back whenever the two
    spellings arrive from different repos.
    """
    model = SGraph(SElement(None, ''))
    a_file = model.createOrGetElementFromPath('/Org/repoA/src/a.cs')
    b_file = model.createOrGetElementFromPath('/Org/repoB/src/b.cs')
    upper = model.createOrGetElementFromPath('/Org/External/Assemblies/NLog')
    upper.attrs['version'] = '5.0.0'
    lower = model.createOrGetElementFromPath('/Org/External/Assemblies/nlog')
    lower.attrs['version'] = '5.0.0'
    SElementAssociation(a_file, b_file, 'use').initElems()
    SElementAssociation(a_file, upper, 'use').initElems()
    SElementAssociation(b_file, lower, 'use').initElems()

    result = generate_multi_from_sgraph(model, level=2, transitive=True)
    repo_a_sbom = sbom_of(result, 'repoA')

    nlog_components = [c for c in repo_a_sbom['components'] if c['name'].lower() == 'nlog']
    assert len(nlog_components) == 1
    # Document order: repoA's own spelling arrives first and survives
    assert nlog_components[0]['name'] == 'NLog'

    # repoB's dependency entry must reference the SURVIVING spelling, not the dropped one —
    # otherwise the fold reintroduces a dangling ref inside the BOM
    entries = {d['ref']: d['dependsOn'] for d in repo_a_sbom['dependencies']}
    assert entries[slugify_bom_ref('repoB')] == ['pkg:nuget/NLog@5.0.0']


# --- External-to-external closure tests ---
#
# The per-subtree walk collects the externals an internal element points AT. A package that only
# another package points at — the resolved closure a lockfile declares, already stored in every
# model the pip and NuGet analyzers produce — is invisible to that walk however many such edges
# the model holds. transitive_externals=True continues the walk from each external across
# External -> External associations, so that closure reaches the BOM.
#
# Opt-in, deliberately: the closure multiplies component counts on models that carry it, and
# every existing consumer of the default output must keep receiving exactly what it received
# before.


def npm_package(model, name, version):
    """A versioned NPM external in the shape the analyzers store it: NPM/<name>/<name> of version X.

    The versioned element is a CHILD of a package element rather than a direct child of the
    ecosystem root. That two-level shape is what makes the child-descent trap below reachable
    at all, so the tests here use it even where a flatter model would read more simply.
    """
    elem = model.createOrGetElementFromPath(
        f'/Org/External/NPM/{name}/{name} of version {version}')
    elem.attrs['version'] = version
    return elem


def nuget_package(model, name, version):
    """A versioned NuGet external in the shape the .NET analyzers store it, under 'Assemblies'.

    No element on that path names the ecosystem the way NPM/ and PIP/ do, so the purl type is
    resolved from the ancestor name instead. Kept faithful to the analyzers' path on purpose: a
    fixture that invented an ecosystem-named parent would exercise a shape no model holds.
    """
    elem = model.createOrGetElementFromPath(
        f'/Org/External/Assemblies/{name}/{name} of version {version}')
    elem.attrs['version'] = version
    return elem


def npm_chain_model(length, deptype='packagejson'):
    """A repo declaring pkg1 in its manifest, with pkg{n} -> pkg{n+1} inside External.

    'packagejson' because that is what the package-to-package edges on stored models actually
    carry: the npm audit analyzer writes it, and it accounts for every npm External -> External
    edge in the measured corpus. A fixture default is the easiest place for a coverage gap to
    hide — every test that inherits it pins one registry entry and none of the others — so the
    default is the deptype the data is in, and the deptypes that are NOT the common case are
    spelled out at their call sites.
    """
    model = SGraph(SElement(None, ''))
    app = model.createOrGetElementFromPath('/Org/repoA/src/app.js')
    packages = [npm_package(model, f'pkg{n}', f'{n}.0.0') for n in range(1, length + 1)]
    SElementAssociation(app, packages[0], 'packagejson').initElems()
    for user, used in zip(packages, packages[1:]):
        SElementAssociation(user, used, deptype).initElems()
    return model


def component_names(result, name):
    return sorted(c['name'] for c in sbom_of(result, name)['components'])


def test_external_to_external_edges_are_not_followed_by_default():
    """A package reachable only through another package stays out of the default BOM.

    The only test in this group that must pass BOTH before and after the closure exists: it
    pins the behaviour the opt-in flag is not allowed to change, so a regression in the default
    path surfaces here rather than in a consumer's pipeline.
    """
    model = npm_chain_model(2)
    result = generate_multi_from_sgraph(model, level=2)

    assert component_names(result, 'repoA') == ['pkg1']


def test_transitive_externals_pulls_an_indirectly_reachable_package():
    """With the flag, the package only pkg1 depends on becomes a component of its own."""
    model = npm_chain_model(2)
    result = generate_multi_from_sgraph(model, level=2, transitive_externals=True)

    assert component_names(result, 'repoA') == ['pkg1', 'pkg2']


def test_transitive_externals_tags_every_component_with_its_dependency_depth():
    """Each component reports how many package hops separate it from the analyzed code.

    Depth 1 carries the property too, so a consumer of an opt-in BOM reads one uniform field
    instead of treating an absent property as 'direct'. The property is absent altogether from
    a default-mode BOM, which is the coherent signal that the BOM makes no depth claim at all.
    """
    model = npm_chain_model(3)
    result = generate_multi_from_sgraph(model, level=2, transitive_externals=True)

    depths = {c['name']: find_property(c, 'dependencyDepth')
              for c in sbom_of(result, 'repoA')['components']}
    assert depths == {'pkg1': '1', 'pkg2': '2', 'pkg3': '3'}


def test_dependency_depth_is_absent_from_a_default_mode_bom():
    """Default output is byte-identical to what it was before the closure existed."""
    model = npm_chain_model(2)
    result = generate_multi_from_sgraph(model, level=2)

    assert all(find_property(c, 'dependencyDepth') is None
               for c in sbom_of(result, 'repoA')['components'])


def test_transitive_externals_terminates_on_an_external_dependency_cycle():
    """a -> b -> a resolves to two components instead of looping."""
    model = SGraph(SElement(None, ''))
    app = model.createOrGetElementFromPath('/Org/repoA/src/app.js')
    cyclic_a = npm_package(model, 'cyclic-a', '1.0.0')
    cyclic_b = npm_package(model, 'cyclic-b', '1.0.0')
    SElementAssociation(app, cyclic_a, 'packagejson').initElems()
    SElementAssociation(cyclic_a, cyclic_b, 'packagelock').initElems()
    SElementAssociation(cyclic_b, cyclic_a, 'packagelock').initElems()

    result = generate_multi_from_sgraph(model, level=2, transitive_externals=True)
    components = {c['name']: c for c in sbom_of(result, 'repoA')['components']}

    assert sorted(components) == ['cyclic-a', 'cyclic-b']
    # The edge back into a package already reached does not re-tag it at the deeper level:
    # the depth reported is the shortest route, the same first-wins rule deduplication uses.
    assert find_property(components['cyclic-a'], 'dependencyDepth') == '1'


def test_the_shortest_of_two_routes_is_the_depth_a_package_reports():
    """Two routes to one package, and the document publishes the shorter one.

    The walk is breadth-first exactly so that the first depth recorded for a package is its
    shortest route. A depth-first walk terminates on the same cycles, emits the same components
    and passes every other test in this file, the cycle one included — it differs only in the
    depth it publishes, which is the one thing a consumer reads to judge how far away a package
    is.

    Declaration order is load-bearing: 'far' is declared last, so it is what a stack-based walk
    pops first, and the long route then reaches 'target' before the short one does. Breadth-first
    reports 2 here, depth-first would report 3.
    """
    model = SGraph(SElement(None, ''))
    app = model.createOrGetElementFromPath('/Org/repoA/src/app.js')
    near = npm_package(model, 'near', '1.0.0')
    far = npm_package(model, 'far', '1.0.0')
    middle = npm_package(model, 'middle', '1.0.0')
    target = npm_package(model, 'target', '1.0.0')
    SElementAssociation(app, near, 'packagejson').initElems()
    SElementAssociation(app, far, 'packagejson').initElems()
    SElementAssociation(near, target, 'packagejson').initElems()
    SElementAssociation(far, middle, 'packagejson').initElems()
    SElementAssociation(middle, target, 'packagejson').initElems()

    result = generate_multi_from_sgraph(model, level=2, transitive_externals=True)
    components = {c['name']: c for c in sbom_of(result, 'repoA')['components']}

    assert find_property(components['target'], 'dependencyDepth') == '2'


def test_max_depth_caps_the_closure_at_the_requested_level():
    """A cap of 2 over a four-package chain yields exactly the first two levels."""
    model = npm_chain_model(4)
    result = generate_multi_from_sgraph(model, level=2, transitive_externals=True, max_depth=2)

    assert component_names(result, 'repoA') == ['pkg1', 'pkg2']


def test_a_max_depth_below_one_is_rejected_rather_than_silently_treated_as_one():
    """A cap of zero excludes every component the walk could emit, so it cannot be meant.

    Behaving as 1 instead answers a different question and says nothing about it, which is worse
    than refusing, because the caller reads a document that looks like the one it asked for. Both
    entry points check it — the caller that passes a cap read out of a request parameter is not
    the CLI.
    """
    model = npm_chain_model(2)
    for cap in (0, -1):
        with pytest.raises(ValueError):
            generate_multi_from_sgraph(model, level=2, transitive_externals=True, max_depth=cap)
        with pytest.raises(ValueError):
            generate_for_element_from_sgraph(model, '/Org/repoA', transitive_externals=True,
                                             max_depth=cap)


def test_a_finding_under_a_versioned_external_is_never_a_component():
    """Traversal follows associations only: the children of an external are not its dependencies.

    Vulnerability and deprecation findings are stored as CHILDREN of versioned external
    elements, and a versioned element is itself a child of its package element. A walk that
    descended into children would emit findings and unreferenced sibling versions as if they
    were packages.

    Both shapes are present here on purpose, and they fail two different wrong walks.

    The finding is given a 'version' attribute on top of the attributes the analyzers store, so
    that valid_for_bom ADMITS it. That is the discriminator, and it has to be stated rather than
    assumed: findings on stored models are rejected by valid_for_bom on their own attributes —
    'package_version' is not the 'version' key it reads, and across the models that carry
    findings not one of them passes. So against a faithful finding, valid_for_bom is what keeps
    a child-descending walk out of the BOM, the traversal rule is never consulted, and the test
    passes while proving nothing. Drop the attribute and this test stops discriminating,
    silently.

    The unreferenced sibling version covers the wider mistake instead: a walk that reached its
    element's PARENT's children — the 'elem.incoming + elem.parent.incoming' idiom this module
    uses elsewhere — inventories versions of a package that nothing references.
    """
    model = npm_chain_model(2)
    versioned = model.findElementFromPath('/Org/External/NPM/pkg2/pkg2 of version 2.0.0')
    finding = SElement(versioned, 'pkg2_GHSA-0000-0000-0000')
    finding.attrs['package_name'] = 'pkg2'
    finding.attrs['package_version'] = '2.0.0'
    finding.attrs['version'] = '2.0.0'
    finding.attrs['range'] = '<2.1.0'
    finding.setType('vulnerability')
    unreferenced_sibling = model.createOrGetElementFromPath(
        '/Org/External/NPM/pkg2/pkg2 of version 1.0.0')
    unreferenced_sibling.attrs['version'] = '1.0.0'

    result = generate_multi_from_sgraph(model, level=2, transitive_externals=True)
    components = sbom_of(result, 'repoA')['components']

    assert sorted(c['name'] for c in components) == ['pkg1', 'pkg2']
    assert [c['version'] for c in components if c['name'] == 'pkg2'] == ['2.0.0']


def test_a_dev_prefixed_deptype_traverses_exactly_like_its_base():
    """dev_packagelock is a packagelock edge declared in a development section.

    Scope handling — whether a development-only package should be marked 'optional' in the BOM
    — is a separate concern and deliberately not decided here. This pins only that the reserved
    prefix does not make the edge invisible to the closure.
    """
    model = npm_chain_model(2, deptype='dev_packagelock')
    result = generate_multi_from_sgraph(model, level=2, transitive_externals=True)

    assert component_names(result, 'repoA') == ['pkg1', 'pkg2']


def test_deptype_base_strips_only_the_reserved_development_prefix():
    """'development' is not a prefixed deptype: the separator is part of the convention."""
    assert deptype_base('dev_packagelock') == 'packagelock'
    assert deptype_base('packagelock') == 'packagelock'
    assert deptype_base('development') == 'development'


def test_an_edge_that_is_not_a_package_relation_is_not_followed():
    """Only deptypes meaning 'package depends on package' are traversed.

    External elements carry code-level edges too — a symbol in one external referencing a symbol
    in another — and following those would fill the BOM with packages the project never
    declared. That is why the registry is an allow-list rather than 'follow everything'.
    """
    model = npm_chain_model(2, deptype='inherits')
    result = generate_multi_from_sgraph(model, level=2, transitive_externals=True)

    assert component_names(result, 'repoA') == ['pkg1']


def test_an_empty_closure_names_the_deptypes_it_skipped(capsys):
    """An empty closure is otherwise indistinguishable from a model that holds no edges at all.

    Both produce a document identical to the default one, so someone who enabled the option and
    saw nothing change cannot tell "the analyzers stored no closure" from "the closure is stored
    under a deptype this converter does not recognise". The second is not hypothetical: the
    registry carries deptypes no analyzer emits.
    """
    model = npm_chain_model(2, deptype='inherits')
    generate_multi_from_sgraph(model, level=2, transitive_externals=True)

    err = capsys.readouterr().err
    assert '/Org/repoA' in err
    assert 'inherits' in err


def test_a_closure_that_followed_an_edge_reports_nothing(capsys):
    """Silence whenever the closure works, which is what keeps the report above worth reading.

    Code-level edges between externals are the ordinary case rather than an anomaly — the
    registry is an allow-list precisely because they exist — so reporting each skipped one would
    fire on nearly every model and train a reader to ignore the line.
    """
    model = npm_chain_model(2)
    code_level_target = npm_package(model, 'unrelated', '1.0.0')
    SElementAssociation(model.findElementFromPath('/Org/External/NPM/pkg2/pkg2 of version 2.0.0'),
                        code_level_target, 'inherits').initElems()

    generate_multi_from_sgraph(model, level=2, transitive_externals=True)

    assert capsys.readouterr().err == ''


def test_a_default_mode_document_reports_no_skipped_deptype(capsys):
    """A document that never walks those edges makes no claim about them either."""
    model = npm_chain_model(2, deptype='inherits')
    generate_multi_from_sgraph(model, level=2)

    assert capsys.readouterr().err == ''


def test_the_closure_is_ecosystem_independent_and_follows_pip_edges():
    """The same rule resolves a pip closure, which is the data stored models already hold."""
    model = SGraph(SElement(None, ''))
    app = model.createOrGetElementFromPath('/Org/repoA/src/app.py')
    requests = model.createOrGetElementFromPath(
        '/Org/External/PIP/requests/requests of version 2.31.0')
    requests.attrs['version'] = '2.31.0'
    urllib3 = model.createOrGetElementFromPath(
        '/Org/External/PIP/urllib3/urllib3 of version 2.2.1')
    urllib3.attrs['version'] = '2.2.1'
    SElementAssociation(app, requests, 'pip').initElems()
    SElementAssociation(requests, urllib3, 'pip').initElems()

    result = generate_multi_from_sgraph(model, level=2, transitive_externals=True)
    components = {c['name']: c for c in sbom_of(result, 'repoA')['components']}

    assert sorted(components) == ['requests', 'urllib3']
    assert components['urllib3']['purl'] == 'pkg:pypi/urllib3@2.2.1'
    assert find_property(components['urllib3'], 'dependencyDepth') == '2'


def test_the_closure_follows_a_lockfile_declared_edge():
    """The lockfile deptype is traversed too, ahead of the analyzer that emits it.

    No stored model carries a 'packagelock' edge yet: the analyzer that writes them ships
    alongside this converter. So this deptype is pinned by intent rather than by data, and it is
    stated at the call site rather than inherited from a fixture default — inheriting it is
    precisely how the deptypes that DO carry the data ended up pinned by nothing.
    """
    model = npm_chain_model(2, deptype='packagelock')
    result = generate_multi_from_sgraph(model, level=2, transitive_externals=True)

    assert component_names(result, 'repoA') == ['pkg1', 'pkg2']


def test_the_closure_follows_a_nuget_package_reference_edge():
    """The .NET analyzer's deptype, which carries every NuGet closure edge on stored models.

    Second in volume after the npm audit analyzer's, and pinned by nothing before this test: the
    registry entry could be deleted with the suite still green. It also exercises a subtree whose
    purl type resolves from an ancestor name rather than from an ecosystem-named root, which is
    the shape .NET externals are stored in.
    """
    model = SGraph(SElement(None, ''))
    project = model.createOrGetElementFromPath('/Org/repoA/src/App.csproj')
    serilog = nuget_package(model, 'Serilog', '3.1.1')
    sink = nuget_package(model, 'Serilog.Sinks.Console', '5.0.0')
    SElementAssociation(project, serilog, 'package_reference').initElems()
    SElementAssociation(serilog, sink, 'package_reference').initElems()

    result = generate_multi_from_sgraph(model, level=2, transitive_externals=True)
    components = {c['name']: c for c in sbom_of(result, 'repoA')['components']}

    assert sorted(components) == ['Serilog', 'Serilog.Sinks.Console']
    assert components['Serilog.Sinks.Console']['purl'] == 'pkg:nuget/Serilog.Sinks.Console@5.0.0'
    assert find_property(components['Serilog.Sinks.Console'], 'dependencyDepth') == '2'


def test_the_closure_composes_with_the_internal_transitive_mode():
    """Both flags together: the closure is collected for every element of the inlined chain."""
    model = SGraph(SElement(None, ''))
    a_file = model.createOrGetElementFromPath('/Org/repoA/src/a.js')
    b_file = model.createOrGetElementFromPath('/Org/repoB/src/b.js')
    direct = npm_package(model, 'direct-of-b', '1.0.0')
    indirect = npm_package(model, 'indirect-of-b', '1.0.0')
    SElementAssociation(a_file, b_file, 'use').initElems()
    SElementAssociation(b_file, direct, 'packagejson').initElems()
    SElementAssociation(direct, indirect, 'packagelock').initElems()

    result = generate_multi_from_sgraph(model, level=2, transitive=True,
                                        transitive_externals=True)
    components = {c['name']: c for c in sbom_of(result, 'repoA')['components']}

    assert find_property(components['indirect-of-b'], 'dependencyDepth') == '2'
    assert find_property(components['indirect-of-b'], 'softagram:via') == 'repoB'


def test_a_package_an_inlined_element_declares_reports_the_shorter_depth():
    """The depth a component publishes must agree with where this document's graph places it.

    Constructed from the two modes together: the root reaches 'shared' only at the end of its own
    package chain, while the inlined element declares it outright. The cross-element merge keeps
    the first component encountered, and traversal starts at the root, so on its own the root's
    longer route wins the depth property — while the attachment logic correctly keeps the package
    under the element that declares it. The same document would then say 'three hops away' and
    'directly depended upon' about the same package.

    The rule is the one already stated for a single walk: of several routes, the shortest is
    reported. Across the merge it has to be enforced rather than inherited, because there
    first-wins is traversal order between elements, not distance.
    """
    model = SGraph(SElement(None, ''))
    a_file = model.createOrGetElementFromPath('/Org/repoA/src/a.js')
    b_file = model.createOrGetElementFromPath('/Org/repoB/src/b.js')
    first = npm_package(model, 'first', '1.0.0')
    second = npm_package(model, 'second', '2.0.0')
    shared = npm_package(model, 'shared', '9.9.9')
    SElementAssociation(a_file, b_file, 'use').initElems()
    SElementAssociation(a_file, first, 'packagejson').initElems()
    SElementAssociation(first, second, 'packagejson').initElems()
    SElementAssociation(second, shared, 'packagejson').initElems()
    SElementAssociation(b_file, shared, 'packagejson').initElems()

    document = sbom_of(generate_multi_from_sgraph(model, level=2, transitive=True,
                                                  transitive_externals=True), 'repoA')
    components = {c['name']: c for c in document['components']}
    entries = {entry['ref']: entry['dependsOn'] for entry in document['dependencies']}

    assert 'pkg:npm/shared@9.9.9' in entries[slugify_bom_ref('repoB')]
    assert find_property(components['shared'], 'dependencyDepth') == '1'


# --- Dependency graph of the external closure ---
#
# Collecting the deeper packages is only half of what a consumer tracing an exposure path needs.
# Listed flat under the element, they say THAT a package is present but not WHICH package pulled
# it in, and they contradict the dependencyDepth published on the same component: a component
# reported at depth 2 cannot also be a direct dependency of the element. These tests pin the
# graph the collected hops are turned into.


def dependency_entries(result, name):
    """The dependencies section of one document, indexed by ref."""
    return {entry['ref']: entry['dependsOn'] for entry in sbom_of(result, name)['dependencies']}


def test_the_closure_emits_a_dependency_graph_entry_per_package_hop():
    """Each package-to-package hop becomes its own entry, and the element keeps only its own."""
    model = npm_chain_model(3)
    result = generate_multi_from_sgraph(model, level=2, transitive_externals=True)
    entries = dependency_entries(result, 'repoA')

    assert entries[slugify_bom_ref('repoA')] == ['pkg:npm/pkg1@1.0.0']
    assert entries['pkg:npm/pkg1@1.0.0'] == ['pkg:npm/pkg2@2.0.0']
    assert entries['pkg:npm/pkg2@2.0.0'] == ['pkg:npm/pkg3@3.0.0']


def test_a_package_both_declared_and_pulled_in_hangs_off_both():
    """Being reachable through another package does not stop a package being declared directly.

    The rule that moves a deeper package out of the element's dependsOn is 'attached elsewhere',
    which on its own would also move this one — and the document would then deny a dependency
    the manifest actually declares.
    """
    model = SGraph(SElement(None, ''))
    app = model.createOrGetElementFromPath('/Org/repoA/src/app.js')
    declared = npm_package(model, 'declared', '1.0.0')
    shared = npm_package(model, 'shared', '9.9.9')
    SElementAssociation(app, declared, 'packagejson').initElems()
    SElementAssociation(app, shared, 'packagejson').initElems()
    SElementAssociation(declared, shared, 'packagelock').initElems()

    result = generate_multi_from_sgraph(model, level=2, transitive_externals=True)
    entries = dependency_entries(result, 'repoA')

    assert entries[slugify_bom_ref('repoA')] == ['pkg:npm/declared@1.0.0', 'pkg:npm/shared@9.9.9']
    assert entries['pkg:npm/declared@1.0.0'] == ['pkg:npm/shared@9.9.9']


def test_a_hop_from_an_undescribed_package_still_leaves_its_target_in_the_graph():
    """A component no hop can name hangs off the element rather than dropping out of the graph.

    An unversioned package element describes no component of its own — valid_for_bom rejects it —
    yet it carries the edges to what it resolves to, so the hop is traversed and has no ref to be
    recorded under. Its target is a real component either way, and a component present in
    components[] but named by no entry is unreachable in a consumer's tree.

    Passes both before and after the graph exists: it locks the behaviour the change must not
    lose, which is exactly why it is written as a separate case rather than folded into one of
    the tests above.
    """
    model = SGraph(SElement(None, ''))
    app = model.createOrGetElementFromPath('/Org/repoA/src/app.js')
    undescribed = model.createOrGetElementFromPath('/Org/External/NPM/pkg1')
    resolved = npm_package(model, 'pkg2', '2.0.0')
    SElementAssociation(app, undescribed, 'packagejson').initElems()
    SElementAssociation(undescribed, resolved, 'packagelock').initElems()

    result = generate_multi_from_sgraph(model, level=2, transitive_externals=True)
    entries = dependency_entries(result, 'repoA')

    assert entries[slugify_bom_ref('repoA')] == ['pkg:npm/pkg2@2.0.0']


def test_the_dependency_graph_is_one_flat_entry_without_the_closure_flag():
    """The default document keeps the single entry it has always had."""
    model = npm_chain_model(3)
    result = generate_multi_from_sgraph(model, level=2)

    assert sbom_of(result, 'repoA')['dependencies'] == [{
        'ref': slugify_bom_ref('repoA'),
        'dependsOn': ['pkg:npm/pkg1@1.0.0']
    }]


def test_the_closure_graph_survives_the_internal_transitive_merge():
    """Package hops collected through an inlined internal element reach the graph too.

    The internal closure merges the components of several elements into one document and folds
    case-variant spellings while doing it. Both endpoints of a hop must be rewritten to the
    surviving spelling on the way through, or the graph names a component the merge removed.
    """
    model = SGraph(SElement(None, ''))
    a_file = model.createOrGetElementFromPath('/Org/repoA/src/a.js')
    b_file = model.createOrGetElementFromPath('/Org/repoB/src/b.js')
    direct = npm_package(model, 'direct-of-b', '1.0.0')
    indirect = npm_package(model, 'indirect-of-b', '1.0.0')
    SElementAssociation(a_file, b_file, 'use').initElems()
    SElementAssociation(b_file, direct, 'packagejson').initElems()
    SElementAssociation(direct, indirect, 'packagelock').initElems()

    result = generate_multi_from_sgraph(model, level=2, transitive=True,
                                        transitive_externals=True)
    entries = dependency_entries(result, 'repoA')

    assert entries[slugify_bom_ref('repoB')] == ['pkg:npm/direct-of-b@1.0.0']
    assert entries['pkg:npm/direct-of-b@1.0.0'] == ['pkg:npm/indirect-of-b@1.0.0']


# --- Declaring-scope provenance tests ---
#
# The External subtree is project-wide: every repository's resolved tree lands in the same
# External/<ecosystem> elements and shares the versioned ones. A package-to-package edge therefore
# says nothing about which repository's manifest declared it, and the closure of one repository
# follows a sibling's edges — reporting packages at versions it does not install, which is a false
# positive of exactly the kind the closure exists to remove.
#
# The analyzers now record the declaring scope on the edge. An edge is followed when that scope
# and the subtree being collected lie on the same root-to-leaf line: the scope IS the subtree, an
# ancestor of it, or a descendant of it. Not merely "under the subtree" — a directory-level export
# is rooted below the repository whose lockfile declared the edges, and a prefix test would empty
# its closure entirely.


def declare(user, used, deptype, *scopes):
    """A package-to-package edge whose declaring scopes are recorded on it."""
    assoc = SElementAssociation(user, used, deptype)
    assoc.initElems()
    assoc.attrs[DECLARING_SCOPE_ATTRIBUTE] = DECLARING_SCOPE_SEPARATOR.join(scopes)
    return assoc


def two_repository_model(deptype='packagelock', scope_a='/Org/repoA', scope_b='/Org/repoB'):
    """Two repositories sharing one package, each resolving it onto a different onward version.

    This is the measured defect in miniature: 'shared' is one element carrying both repositories'
    edges, so without provenance each repository's closure reaches the other's onward package.
    """
    model = SGraph(SElement(None, ''))
    a_file = model.createOrGetElementFromPath('/Org/repoA/src/a.js')
    b_file = model.createOrGetElementFromPath('/Org/repoB/src/b.js')
    shared = npm_package(model, 'shared', '1.0.0')
    onward_a = npm_package(model, 'onward', '1.0.0')
    onward_b = npm_package(model, 'onward', '2.0.0')
    SElementAssociation(a_file, shared, 'packagejson').initElems()
    SElementAssociation(b_file, shared, 'packagejson').initElems()
    declare(shared, onward_a, deptype, scope_a)
    declare(shared, onward_b, deptype, scope_b)
    return model


def component_versions(sbom, name):
    return sorted(c['version'] for c in sbom['components'] if c['name'] == name)


def test_an_edge_declared_only_by_another_repository_is_not_followed():
    """The whole point: repoA's closure stops at the version repoA's own manifest resolves."""
    result = generate_multi_from_sgraph(two_repository_model(), level=2,
                                        transitive_externals=True)

    assert component_versions(sbom_of(result, 'repoA'), 'onward') == ['1.0.0']
    assert component_versions(sbom_of(result, 'repoB'), 'onward') == ['2.0.0']


def test_an_edge_with_no_declaring_scope_is_followed():
    """Absence means unknown provenance, and unknown provenance keeps today's behaviour.

    Every model stored before the attribute existed carries no scope on any edge, and the pip and
    NuGet analyzers still record none. Reading absence as 'skip' would silently empty those
    closures — a far worse failure than the contamination being fixed here.
    """
    model = npm_chain_model(3)

    result = generate_multi_from_sgraph(model, level=2, transitive_externals=True)

    assert component_names(result, 'repoA') == ['pkg1', 'pkg2', 'pkg3']


def test_an_edge_declared_by_two_repositories_is_followed_from_both():
    """A shared edge is a fact about every repository that declared it, not about the last one."""
    model = two_repository_model(scope_a='/Org/repoA', scope_b='/Org/repoA')
    shared = model.findElementFromPath('/Org/External/NPM/shared/shared of version 1.0.0')
    for assoc in shared.outgoing:
        assoc.attrs[DECLARING_SCOPE_ATTRIBUTE] = DECLARING_SCOPE_SEPARATOR.join(
            ['/Org/repoA', '/Org/repoB'])

    result = generate_multi_from_sgraph(model, level=2, transitive_externals=True)

    assert component_versions(sbom_of(result, 'repoA'), 'onward') == ['1.0.0', '2.0.0']
    assert component_versions(sbom_of(result, 'repoB'), 'onward') == ['1.0.0', '2.0.0']


def test_a_directory_level_export_still_follows_its_repositorys_edges():
    """The scope is the repository root; the subtree is a directory inside it.

    A repository-level test passes under a prefix rule and under the correct one alike, so this
    is the case that tells them apart. A lockfile sits at the repository root, so under a prefix
    rule its scope is never 'under' a directory-level subtree and the closure would silently
    collapse to the packages the directory declares directly — the flag becoming a no-op at
    exactly the granularity that is otherwise the expensive one.
    """
    result = generate_multi_from_sgraph(two_repository_model(), level=3,
                                        transitive_externals=True)

    assert component_versions(sbom_of(result, 'src'), 'onward') == ['1.0.0']


def test_a_directory_level_export_still_excludes_a_sibling_repositorys_edges():
    """Reaching deeper must not mean reaching wider."""
    result = generate_multi_from_sgraph(two_repository_model(), level=3,
                                        transitive_externals=True)

    versions = {sbom['metadata']['component']['bom-ref']: component_versions(sbom, 'onward')
                for sbom in result}
    assert sorted(versions.values()) == [['1.0.0'], ['2.0.0']]


def test_a_selected_directory_element_follows_its_repositorys_edges_too():
    """The element-path entry point derives its level from the path, so it takes the same rule."""
    sbom = generate_for_element_from_sgraph(two_repository_model(), '/Org/repoA/src',
                                            transitive_externals=True)

    assert component_versions(sbom, 'onward') == ['1.0.0']


def test_a_scope_below_the_subtree_is_followed():
    """A subtree wide enough to contain the declaring scope contains its edges as well.

    The whole-project document is this case: every repository's lockfile lies within it, and
    nothing there is a sibling's.
    """
    model = two_repository_model(scope_a='/Org/repoA/frontend', scope_b='/Org/repoB')

    result = generate_multi_from_sgraph(model, level=2, transitive_externals=True)

    assert component_versions(sbom_of(result, 'repoA'), 'onward') == ['1.0.0']


def test_a_sibling_directory_scope_is_not_followed():
    """Two lockfiles in one repository govern their own directories, not each other's."""
    model = two_repository_model(scope_a='/Org/repoA/frontend', scope_b='/Org/repoB')
    result = generate_multi_from_sgraph(model, level=3, transitive_externals=True)

    assert component_versions(sbom_of(result, 'src'), 'onward') == []


def test_an_audit_declared_edge_takes_the_same_rule():
    """npm audit produces the package-to-package edges that exist on models today.

    Its deptype is 'packagejson' and its edges land on the same project-wide elements, so a
    filter that covered only the lockfile analyzer's deptype would leave the contamination in
    place on every model a customer already has.
    """
    result = generate_multi_from_sgraph(two_repository_model(deptype='packagejson'), level=2,
                                        transitive_externals=True)

    assert component_versions(sbom_of(result, 'repoA'), 'onward') == ['1.0.0']
    assert component_versions(sbom_of(result, 'repoB'), 'onward') == ['2.0.0']


def test_a_declaring_scope_changes_nothing_without_the_closure_flag():
    """The default document never walked package-to-package edges and still does not."""
    result = generate_multi_from_sgraph(two_repository_model(), level=2)

    assert component_names(result, 'repoA') == ['shared']


def test_cli_supports_the_external_closure_flags(tmp_path):
    """--transitive-externals and --max-depth reach the generator through the CLI.

    The multi fixture carries no External -> External package edges, so the flag adds no
    component here: what it does add is the depth property on every direct one, which is
    exactly the evidence that the option was wired through rather than silently dropped.

    Depth is a claim about the 3rd-party closure and is checked only there. An inlined internal
    component is an element of the estate, not a package hop away from it, so it carries no
    depth — asserted below rather than merely skipped, because silently excluding a component
    class from an invariant is how a real gap hides inside a passing test.
    """
    import json
    import subprocess
    import sys
    import os

    model_path = os.path.join(os.path.dirname(__file__), 'modelfile_for_sbom_multi_tests.xml')
    out_path = tmp_path / 'sboms.json'
    proc = subprocess.run(
        [sys.executable, '-m', 'sgraph.converters.sbom_cyclonedx_generator',
         model_path, str(out_path), '--level', '3', '--transitive-externals', '--max-depth', '2'],
        capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr

    result = json.loads(out_path.read_text())
    components = sbom_of(result, 'repoA')['components']
    third_party = [c for c in components if find_property(c, 'softagram:internal') is None]
    internal = [c for c in components if find_property(c, 'softagram:internal') == 'true']
    assert third_party
    assert all(find_property(c, 'dependencyDepth') == '1' for c in third_party)
    assert all(find_property(c, 'dependencyDepth') is None for c in internal)


def test_cli_rejects_a_max_depth_below_one(tmp_path):
    """The flag documents the deepest depth to emit, so a value below the shallowest is an error.

    Reported by the CLI in its own vocabulary — the flag as typed — rather than letting the
    generator's ValueError surface as a traceback.
    """
    import subprocess
    import sys
    import os

    model_path = os.path.join(os.path.dirname(__file__), 'modelfile_for_sbom_multi_tests.xml')
    for cap in ('0', '-1'):
        proc = subprocess.run(
            [sys.executable, '-m', 'sgraph.converters.sbom_cyclonedx_generator',
             model_path, str(tmp_path / 'out.json'), '--level', '3', '--transitive-externals',
             '--max-depth', cap],
            capture_output=True, text=True)
        assert proc.returncode != 0, cap
        assert '--max-depth must be 1 or greater' in proc.stderr


def test_cli_rejects_a_max_depth_without_the_closure_flag(tmp_path):
    """A cap on a walk the default mode never makes would be accepted and ignored.

    The guard is otherwise pinned by nothing: remove it and this test is the only one in the file
    that fails, so without it the option could start silently doing nothing unnoticed.
    """
    import subprocess
    import sys
    import os

    model_path = os.path.join(os.path.dirname(__file__), 'modelfile_for_sbom_multi_tests.xml')
    proc = subprocess.run(
        [sys.executable, '-m', 'sgraph.converters.sbom_cyclonedx_generator',
         model_path, str(tmp_path / 'out.json'), '--level', '3', '--max-depth', '2'],
        capture_output=True, text=True)

    assert proc.returncode != 0
    assert '--max-depth requires --transitive-externals' in proc.stderr


def test_cli_rejects_the_external_closure_flag_without_a_scope(tmp_path):
    """--transitive-externals is meaningless in the legacy single-SBOM mode, which ignores it."""
    import subprocess
    import sys
    import os

    model_path = os.path.join(os.path.dirname(__file__), 'modelfile_for_sbom_multi_tests.xml')
    proc = subprocess.run(
        [sys.executable, '-m', 'sgraph.converters.sbom_cyclonedx_generator',
         model_path, str(tmp_path / 'out.json'), '--transitive-externals'],
        capture_output=True, text=True)
    assert proc.returncode != 0
    assert '--transitive-externals requires --level' in proc.stderr


# --- Package identity of internal components ---
#
# A component describing an internal element used to be named after the ELEMENT — the repository
# or directory — with no version and no purl. A consumer then saw a row named after a repository
# where it expected the package that repository publishes, and had no identifier to resolve.
#
# The identity is read from an ecosystem-neutral triple stamped on the package element, never
# from the npm-specific file-level attribute: the same problem exists in pip, NuGet, Maven, Dart
# and Go, and one converter serves all of them.


def internal_package_element(model, path, name, version, ecosystem='npm'):
    """Stamp the identity triple the analyzers write onto a package element."""
    elem = model.createOrGetElementFromPath(path)
    elem.attrs['package_name'] = name
    elem.attrs['version'] = version
    if ecosystem is not None:
        elem.attrs['ecosystem'] = ecosystem
    return elem


def published_package_model(name='ui-lib', version='2.1.0', ecosystem='npm'):
    """repoA declaring a dependency on repoB, which publishes itself as an internal package."""
    model = SGraph(SElement(None, ''))
    model.createOrGetElementFromPath('/Org/repoB').attrs['repo_url'] = \
        'https://example.org/org/repoB.git'
    app = model.createOrGetElementFromPath('/Org/repoA/src/app.js')
    published = internal_package_element(
        model, f'/Org/repoB/package.json/{name}', name, version, ecosystem)
    SElementAssociation(app, published, 'packagejson').initElems()
    return model


def internal_components(sbom):
    return [c for c in sbom['components'] if find_property(c, 'softagram:internal') == 'true']


def the_internal_component(model, **kwargs):
    """The single inlined internal component of repoA's document."""
    result = generate_multi_from_sgraph(model, level=2, transitive=True, **kwargs)
    components = internal_components(sbom_of(result, 'repoA'))
    assert len(components) == 1, components
    return components[0]


def test_an_inlined_internal_component_carries_its_package_identity():
    """The component names the package the element publishes, not the element."""
    component = the_internal_component(published_package_model())

    assert component['name'] == 'ui-lib'
    assert component['version'] == '2.1.0'
    assert component['purl'] == 'pkg:generic/ui-lib@2.1.0'
    assert find_property(component, 'softagram:packageEcosystem') == 'npm'
    assert find_property(component, 'softagram:packageName') == 'ui-lib'


def test_publishing_an_identity_does_not_displace_what_the_component_already_said():
    """The element's own facts survive the identity: they answer a different question.

    The purl says which package this is; the location, the repository and the BOM-Link say where
    it lives and where its own document is. A consumer tracing an exposure path needs both, and
    the bom-ref must not move either — the dependency graph and the BOM-Links of every other
    document name the element by it.
    """
    component = the_internal_component(published_package_model())

    assert component['bom-ref'] == slugify_bom_ref('repoB')
    assert find_property(component, 'softagram:internal') == 'true'
    assert find_property(component, 'softagram:elementPath') == '/Org/repoB'
    assert component['externalReferences'] == [
        {'url': component['externalReferences'][0]['url'], 'type': 'bom'},
        {'url': 'https://example.org/org/repoB.git', 'type': 'vcs'},
    ]
    assert component['externalReferences'][0]['url'].startswith('urn:cdx:')


def test_an_internal_package_is_not_claimed_to_be_a_public_registry_package():
    """The purl type is 'generic', never the ecosystem's own type.

    pkg:npm/<name>@<v> asserts an identity in the public npm registry. Either the name is not
    published there, in which case the npm type buys nothing, or it is and belongs to someone
    else, in which case this component silently inherits a stranger's advisories — a
    dependency-confusion-shaped false positive. 'generic' is the purl type with no default
    package repository, which is what an internally published package is. The module already
    applies this reasoning to an in-house binary mistyped as a NuGet package.
    """
    component = the_internal_component(published_package_model())

    assert not component['purl'].startswith('pkg:npm/')
    assert component['purl'].startswith('pkg:generic/')


def test_the_identity_is_ecosystem_neutral():
    """A pip package resolves through exactly the same path, with no npm-shaped branch.

    The triple is read, not the ecosystem: the day an internal pip or NuGet package carries it,
    this works unchanged. The ecosystem is published as a property and never decides the purl
    type — which is why this component's purl is generic too, not pypi.
    """
    component = the_internal_component(
        published_package_model(name='shared-utils', version='0.4.1', ecosystem='pypi'))

    assert component['purl'] == 'pkg:generic/shared-utils@0.4.1'
    assert find_property(component, 'softagram:packageEcosystem') == 'pypi'


def test_an_element_that_publishes_no_package_keeps_the_element_name():
    """No identity in the subtree leaves the component exactly as it was."""
    model = SGraph(SElement(None, ''))
    app = model.createOrGetElementFromPath('/Org/repoA/src/app.js')
    used = model.createOrGetElementFromPath('/Org/repoB/src/util.js')
    SElementAssociation(app, used, 'use').initElems()

    component = the_internal_component(model)

    assert component['name'] == 'repoB'
    assert component['version'] == ''
    assert 'purl' not in component
    assert find_property(component, 'softagram:packageEcosystem') is None


def test_a_model_predating_the_identity_triple_is_untouched():
    """npm_package_name alone is an OLD model and must keep today's behaviour exactly.

    That attribute is a long-standing npm-only convention stamped on the package.json FILE
    element, with its own existing consumers. Every model stored before the analyzer half shipped
    carries it and carries no triple, so reading it would silently rewrite the output of every
    such model — the regression this lock exists to catch.
    """
    model = SGraph(SElement(None, ''))
    app = model.createOrGetElementFromPath('/Org/repoA/src/app.js')
    package_json = model.createOrGetElementFromPath('/Org/repoB/package.json')
    package_json.attrs['npm_package_name'] = 'ui-lib'
    legacy = model.createOrGetElementFromPath('/Org/repoB/package.json/ui-lib')
    SElementAssociation(app, legacy, 'packagejson').initElems()

    component = the_internal_component(model)

    assert component['name'] == 'repoB'
    assert component['version'] == ''
    assert 'purl' not in component


def test_an_ambiguous_multi_package_repository_falls_back_to_the_element_name():
    """Two published packages and nothing to choose between them: no identity is invented.

    A monorepo publishing several packages has no single identity, and picking one would
    attribute the whole element to an arbitrary member of the set. Saying nothing is the honest
    answer, and it is also the old behaviour, so ambiguity costs a consumer nothing it had.
    """
    model = SGraph(SElement(None, ''))
    app = model.createOrGetElementFromPath('/Org/repoA/src/app.js')
    used = model.createOrGetElementFromPath('/Org/repoB/src/util.js')
    SElementAssociation(app, used, 'use').initElems()
    internal_package_element(model, '/Org/repoB/packages/ui/package.json/ui-lib', 'ui-lib', '2.1.0')
    internal_package_element(model, '/Org/repoB/packages/api/package.json/api-lib', 'api-lib',
                             '1.0.0')

    component = the_internal_component(model)

    assert component['name'] == 'repoB'
    assert 'purl' not in component


def test_the_package_actually_depended_upon_resolves_the_ambiguity():
    """Among several published packages, the one something OUTSIDE the element points at wins.

    That is the package this dependency edge is about. An incoming association from inside the
    element is one sibling package using another and says nothing about which package the
    depending element resolved, so it deliberately does not count.
    """
    model = SGraph(SElement(None, ''))
    app = model.createOrGetElementFromPath('/Org/repoA/src/app.js')
    depended_upon = internal_package_element(
        model, '/Org/repoB/packages/ui/package.json/ui-lib', 'ui-lib', '2.1.0')
    internal_only = internal_package_element(
        model, '/Org/repoB/packages/tooling/package.json/build-tools', 'build-tools', '1.0.0')
    sibling = model.createOrGetElementFromPath('/Org/repoB/packages/ui/src/index.js')
    SElementAssociation(app, depended_upon, 'packagejson').initElems()
    SElementAssociation(sibling, internal_only, 'packagejson').initElems()

    component = the_internal_component(model)

    assert component['name'] == 'ui-lib'
    assert component['purl'] == 'pkg:generic/ui-lib@2.1.0'


def test_no_component_of_any_document_has_an_empty_purl():
    """Estate invariant: on a model that carries identity, every component is resolvable.

    An empty purl is not a harmless blank — it is a row a consumer cannot match against anything,
    which is what an internal dependency looked like before it had an identity. The metadata
    component is excluded on purpose: it describes the document's own subject rather than a
    dependency of it, and it carries no purl at all by its own separate rule.

    Absence and emptiness are different answers and only one of them is legal: CycloneDX types
    purl as an iri-reference, which the empty string is not, so a row with nothing to say omits
    the key. The disjunction is what makes this an invariant about EMPTINESS rather than about
    presence — a component may say nothing, but it may not say nothing badly.
    """
    model = published_package_model()
    third_party = model.createOrGetElementFromPath(
        '/Org/External/NPM/left-pad/left-pad of version 1.3.0')
    third_party.attrs['version'] = '1.3.0'
    SElementAssociation(model.findElementFromPath('/Org/repoA/src/app.js'), third_party,
                        'packagejson').initElems()

    for kwargs in (dict(), dict(transitive=True), dict(transitive=True,
                                                       transitive_externals=True)):
        for sbom in generate_multi_from_sgraph(model, level=2, **kwargs):
            for component in sbom['components']:
                assert 'purl' not in component or component['purl'], (kwargs,
                                                                      component['name'])


# --- Selected-element SBOM tests ---
#
# One SBOM for one chosen element (typically /Project/repo or /Project/repo/dir): the element
# is the metadata component, its descendants define the scope, and the peers at the same tree
# depth form the internal-dependency universe — the same universe the level-based multi mode
# uses, so a selected-element SBOM composes with the multi output instead of contradicting it.


def test_selected_element_sbom_names_the_element_and_keeps_the_deterministic_serial():
    """The chosen element becomes the metadata component of a single SBOM."""
    model, _ = get_model_and_model_api(MULTI_MODEL)
    sbom = generate_for_element_from_sgraph(model, '/OrgName/GroupA/repoA')

    assert isinstance(sbom, dict)
    assert sbom['metadata']['component']['name'] == 'repoA'
    assert sbom['serialNumber'] == deterministic_serial('/OrgName/GroupA/repoA')

    component_names = [c['name'] for c in sbom['components']]
    assert 'Newtonsoft.Json' in component_names
    assert not any('commons-lang3' in n for n in component_names)

    # Non-transitive keeps the multi-mode contract: internal deps stay BOM-Link URNs
    assert len(sbom['dependencies']) == 1
    repo_b_serial = deterministic_serial('/OrgName/GroupA/repoB').replace('urn:uuid:', '')
    assert any(ref.startswith('urn:cdx:') and repo_b_serial in ref
               for ref in sbom['dependencies'][0]['dependsOn'])


def test_selected_element_sbom_transitive_inlines_the_chain():
    """transitive=True gives the selected element the same inlined exposure chain as multi mode."""
    model, _ = get_model_and_model_api(MULTI_MODEL)
    sbom = generate_for_element_from_sgraph(model, '/OrgName/GroupA/repoA', transitive=True)

    components_by_name = {c['name']: c for c in sbom['components']}
    assert find_property(components_by_name['repoB'], 'softagram:internal') == 'true'
    commons = next(c for n, c in components_by_name.items() if 'commons-lang3' in n)
    assert find_property(commons, 'softagram:via') == 'repoB'

    entries = {d['ref']: d['dependsOn'] for d in sbom['dependencies']}
    root_ref = sbom['metadata']['component']['bom-ref']
    assert slugify_bom_ref('repoB') in entries[root_ref]
    assert any('commons-lang3' in ref for ref in entries[slugify_bom_ref('repoB')])

    known_refs = {c['bom-ref'] for c in sbom['components']} | {root_ref}
    for depends_on in entries.values():
        assert all(ref in known_refs for ref in depends_on)


def test_selected_element_accepts_a_deeper_directory_path():
    """A dir-level path works, and same-named peers at that depth get distinct bom-refs."""
    model, _ = get_model_and_model_api(MULTI_MODEL)
    sbom = generate_for_element_from_sgraph(model, '/OrgName/GroupA/repoA/src', transitive=True)

    assert sbom['metadata']['component']['name'] == 'src'
    assert sbom['serialNumber'] == deterministic_serial('/OrgName/GroupA/repoA/src')

    # repoB's src is reached through main.cs -> lib.cs and inlined as an internal component
    internal = [c for c in sbom['components']
                if find_property(c, 'softagram:internal') == 'true']
    assert len(internal) == 1
    assert internal[0]['name'] == 'src'
    # Both elements are named 'src'; the internal peer's ref must not collide with the root's
    root_ref = sbom['metadata']['component']['bom-ref']
    assert internal[0]['bom-ref'] != root_ref

    commons = next(c for c in sbom['components'] if 'commons-lang3' in c['name'])
    assert find_property(commons, 'softagram:via') == 'src'

    entries = {d['ref']: d['dependsOn'] for d in sbom['dependencies']}
    assert internal[0]['bom-ref'] in entries[root_ref]
    assert any('commons-lang3' in ref for ref in entries[internal[0]['bom-ref']])


def test_selected_element_unknown_path_raises():
    model, _ = get_model_and_model_api(MULTI_MODEL)
    try:
        generate_for_element_from_sgraph(model, '/OrgName/GroupA/nonexistent')
        assert False, 'expected ValueError'
    except ValueError as e:
        assert '/OrgName/GroupA/nonexistent' in str(e)


def test_selected_element_under_external_raises():
    """The External subtree holds 3rd-party components, not products — refuse to root there."""
    model, _ = get_model_and_model_api(MULTI_MODEL)
    try:
        generate_for_element_from_sgraph(model, '/OrgName/External/Maven')
        assert False, 'expected ValueError'
    except ValueError as e:
        assert 'External' in str(e)


def test_cli_exports_a_selected_element(tmp_path):
    """--element-path exports one SBOM for the chosen element, composable with --transitive."""
    import json
    import subprocess
    import sys
    import os

    model_path = os.path.join(os.path.dirname(__file__), 'modelfile_for_sbom_multi_tests.xml')
    out_path = tmp_path / 'sbom.json'
    proc = subprocess.run(
        [sys.executable, '-m', 'sgraph.converters.sbom_cyclonedx_generator',
         model_path, str(out_path), '--element-path', '/OrgName/GroupA/repoA', '--transitive'],
        capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr

    sbom = json.loads(out_path.read_text())
    assert isinstance(sbom, dict)
    assert sbom['metadata']['component']['name'] == 'repoA'
    assert any(find_property(c, 'softagram:internal') == 'true' for c in sbom['components'])


def test_cli_rejects_element_path_combined_with_level(tmp_path):
    import subprocess
    import sys
    import os

    model_path = os.path.join(os.path.dirname(__file__), 'modelfile_for_sbom_multi_tests.xml')
    proc = subprocess.run(
        [sys.executable, '-m', 'sgraph.converters.sbom_cyclonedx_generator',
         model_path, str(tmp_path / 'out.json'),
         '--element-path', '/OrgName/GroupA/repoA', '--level', '3'],
        capture_output=True, text=True)
    assert proc.returncode != 0
    assert 'not allowed with' in proc.stderr or 'mutually exclusive' in proc.stderr


def test_cli_supports_the_transitive_flag(tmp_path):
    """python -m ...sbom_cyclonedx_generator model out.json --level 3 --transitive works."""
    import json
    import subprocess
    import sys
    import os

    model_path = os.path.join(os.path.dirname(__file__), 'modelfile_for_sbom_multi_tests.xml')
    out_path = tmp_path / 'sboms.json'
    proc = subprocess.run(
        [sys.executable, '-m', 'sgraph.converters.sbom_cyclonedx_generator',
         model_path, str(out_path), '--level', '3', '--transitive'],
        capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr

    result = json.loads(out_path.read_text())
    repo_a_sbom = sbom_of(result, 'repoA')
    assert any(find_property(c, 'softagram:internal') == 'true'
               for c in repo_a_sbom['components'])


def test_cli_rejects_transitive_without_level(tmp_path):
    """--transitive is only meaningful with --level; without it the CLI refuses."""
    import subprocess
    import sys
    import os

    model_path = os.path.join(os.path.dirname(__file__), 'modelfile_for_sbom_multi_tests.xml')
    proc = subprocess.run(
        [sys.executable, '-m', 'sgraph.converters.sbom_cyclonedx_generator',
         model_path, str(tmp_path / 'out.json'), '--transitive'],
        capture_output=True, text=True)
    assert proc.returncode != 0
    assert '--transitive requires --level' in proc.stderr


# --- Element location tests ---
#
# The model position of an element is published two ways: the native CycloneDX 'group' field
# (the parent's full path) and a 'softagram:elementPath' property (the element's own path).
# The property is the exact string deterministic_serial() hashes, so it is verifiable.


def test_purl_and_version_stay_empty_on_the_metadata_component():
    """Characterization: the metadata component has no package identity, and must not gain one.

    Guards against a later 'fill the empty field' edit putting the element path into purl, where
    it would violate the purl grammar and be rejected by a purl-parsing consumer. The field is
    now omitted rather than emitted empty, so that edit has no empty field to find — but the
    guard still holds, because omission is not an invitation to populate it either.

    version stays empty and is deliberately NOT given the same treatment: CycloneDX constrains
    purl to an iri-reference and constrains version not at all, so the empty string is legal
    there and removing it would change output for no stated reason.
    """
    model, _ = get_model_and_model_api(MULTI_MODEL)
    result = generate_multi_from_sgraph(model, level=3)

    assert len(result) == 2
    for sbom in result:
        assert 'purl' not in sbom['metadata']['component']
        assert sbom['metadata']['component']['version'] == ''


def test_bom_ref_stays_the_slug_not_the_path():
    """Characterization: bom-ref is referenced from other SBOMs and must not become the path."""
    model, _ = get_model_and_model_api(MULTI_MODEL)
    result = generate_multi_from_sgraph(model, level=3)

    refs = sorted(sbom['metadata']['component']['bom-ref'] for sbom in result)
    assert refs == ['repoa', 'repob']


def test_serial_numbers_stay_derived_from_the_element_path():
    """Characterization: serialNumber == deterministic_serial(element_path), and stays that way.

    Re-ingesting a model must update the same projects rather than create new ones.
    """
    model, _ = get_model_and_model_api(MULTI_MODEL)
    result = generate_multi_from_sgraph(model, level=3)

    serials = {sbom['metadata']['component']['name']: sbom['serialNumber'] for sbom in result}
    assert serials['repoA'] == deterministic_serial('/OrgName/GroupA/repoA')
    assert serials['repoB'] == deterministic_serial('/OrgName/GroupA/repoB')


def test_metadata_component_carries_element_path():
    """The full model path is published as a property, because CycloneDX has no field for it."""
    model, _ = get_model_and_model_api(MULTI_MODEL)
    result = generate_multi_from_sgraph(model, level=3)

    component = sbom_of(result, 'repoA')['metadata']['component']
    assert find_property(component, 'softagram:elementPath') == '/OrgName/GroupA/repoA'


def test_metadata_component_carries_the_parent_path_as_group():
    """group holds the parent's full path, so two same-named groups stay distinguishable."""
    model, _ = get_model_and_model_api(MULTI_MODEL)
    result = generate_multi_from_sgraph(model, level=3)

    assert sbom_of(result, 'repoA')['metadata']['component']['group'] == '/OrgName/GroupA'
    assert sbom_of(result, 'repoB')['metadata']['component']['group'] == '/OrgName/GroupA'


def test_element_path_matches_the_serial_number_for_every_sbom():
    """The published path must be the same string the serial was derived from.

    This is the invariant that makes the property verifiable rather than decorative: it catches a
    future refactor that derives one from a normalised path and the other from the raw one.
    """
    model, _ = get_model_and_model_api(MULTI_MODEL)
    result = generate_multi_from_sgraph(model, level=3)

    assert len(result) == 2
    for sbom in result:
        path = find_property(sbom['metadata']['component'], 'softagram:elementPath')
        assert deterministic_serial(path) == sbom['serialNumber']


def test_element_location_is_level_agnostic():
    """At level 2 the element is the group itself, and its parent is the estate root."""
    model, _ = get_model_and_model_api(MULTI_MODEL)
    result = generate_multi_from_sgraph(model, level=2)

    component = sbom_of(result, 'GroupA')['metadata']['component']
    assert component['group'] == '/OrgName'
    assert find_property(component, 'softagram:elementPath') == '/OrgName/GroupA'


def test_group_is_absent_at_the_top_level():
    """A top-level element has no parent to name, so the key is omitted rather than emitted empty.

    An empty group cannot be told apart from 'the tool forgot to fill it in'; an absent one can.
    """
    model, _ = get_model_and_model_api(MULTI_MODEL)
    result = generate_multi_from_sgraph(model, level=1)

    component = sbom_of(result, 'OrgName')['metadata']['component']
    assert 'group' not in component
    assert find_property(component, 'softagram:elementPath') == '/OrgName'


def test_selected_element_sbom_also_carries_its_location():
    """--element-path routes through the same helper as --level, so it gets the same fields."""
    model, _ = get_model_and_model_api(MULTI_MODEL)
    sbom = generate_for_element_from_sgraph(model, '/OrgName/GroupA/repoA/src')

    component = sbom['metadata']['component']
    assert component['group'] == '/OrgName/GroupA/repoA'
    assert find_property(component, 'softagram:elementPath') == '/OrgName/GroupA/repoA/src'


MIRRORED_MODEL = 'converters/modelfile_for_sbom_mirrored_tests.xml'


def test_mirrored_repositories_are_distinguished_by_their_location():
    """One repository name under two groups: the only field that tells them apart is the path.

    'name' is identical. 'bom-ref' differs only through a traversal-order collision suffix, so it
    is not a stable identity: drop GroupA's copy and GroupB's silently becomes 'shared'.
    'serialNumber' differs but is an opaque hash. group and elementPath are the answer.
    """
    model, _ = get_model_and_model_api(MIRRORED_MODEL)
    result = generate_multi_from_sgraph(model, level=3)

    components = [sbom['metadata']['component'] for sbom in result]
    assert [c['name'] for c in components] == ['shared', 'shared']

    by_group = {c['group']: c for c in components}
    assert sorted(by_group) == ['/OrgName/GroupA', '/OrgName/GroupB']

    assert find_property(by_group['/OrgName/GroupA'], 'softagram:elementPath') \
        == '/OrgName/GroupA/shared'
    assert find_property(by_group['/OrgName/GroupB'], 'softagram:elementPath') \
        == '/OrgName/GroupB/shared'

    # The collision suffix keeps bom-refs unique within the set, but does not identify either one
    assert sorted(c['bom-ref'] for c in components) == ['shared', 'shared-2']

    # Mirror-specific: a serial derived from the NAME rather than the path would collide here,
    # where the names are identical. The generic path/serial invariant is pinned elsewhere.
    assert len({sbom['serialNumber'] for sbom in result}) == 2


def test_vcs_reference_comes_from_the_elements_own_repo_url():
    """The model already holds the repository URL; CycloneDX has a proper field for it."""
    model, _ = get_model_and_model_api(MULTI_MODEL)
    result = generate_multi_from_sgraph(model, level=3)

    component = sbom_of(result, 'repoA')['metadata']['component']
    vcs = [r['url'] for r in component['externalReferences'] if r['type'] == 'vcs']
    assert vcs == ['https://example.org/org/repoA.git']


def test_vcs_reference_is_inherited_from_the_nearest_ancestor():
    """A directory-level SBOM belongs to its repository's VCS, one level up."""
    model, _ = get_model_and_model_api(MULTI_MODEL)
    sbom = generate_for_element_from_sgraph(model, '/OrgName/GroupA/repoA/src')

    vcs = [r['url'] for r in sbom['metadata']['component']['externalReferences']
           if r['type'] == 'vcs']
    assert vcs == ['https://example.org/org/repoA.git']


def test_no_vcs_reference_when_no_ancestor_has_one():
    """Absent, never invented: a consumer cannot tell a fabricated URL from a real one."""
    model, _ = get_model_and_model_api(MULTI_MODEL)
    result = generate_multi_from_sgraph(model, level=3)

    component = sbom_of(result, 'repoB')['metadata']['component']
    assert [r for r in component['externalReferences'] if r['type'] == 'vcs'] == []


def test_mirrored_repositories_carry_their_own_distinct_repository_urls():
    """Two mirrors of one name are two different repositories, each with its own remote."""
    model, _ = get_model_and_model_api(MIRRORED_MODEL)
    result = generate_multi_from_sgraph(model, level=3)

    by_group = {sbom['metadata']['component']['group']: sbom['metadata']['component']
                for sbom in result}
    assert [r['url'] for r in by_group['/OrgName/GroupA']['externalReferences']
            if r['type'] == 'vcs'] == ['https://example.org/org/groupa-shared.git']
    assert [r['url'] for r in by_group['/OrgName/GroupB']['externalReferences']
            if r['type'] == 'vcs'] == ['https://example.org/org/groupb-shared.git']


def test_nearest_repo_url_wins_over_a_more_distant_ancestor():
    """A sub-repo's own remote describes it; its parent group's does not.

    Without this, a farthest-ancestor-wins regression passes the whole suite: no other fixture
    has two repo_url attributes on one chain, so nothing else can tell the two rules apart.
    """
    model, _ = get_model_and_model_api(MIRRORED_MODEL)
    result = generate_multi_from_sgraph(model, level=3)

    component = next(s['metadata']['component'] for s in result
                     if s['metadata']['component']['group'] == '/OrgName/GroupA')
    vcs = [r['url'] for r in component['externalReferences'] if r['type'] == 'vcs']
    assert vcs == ['https://example.org/org/groupa-shared.git']


def test_a_blank_repo_url_does_not_mask_a_real_one_further_up():
    """A blank attribute is not an answer. Publishing it would also hide a recoverable URL."""
    model = SGraph(SElement(None, ''))
    model.createOrGetElementFromPath('/Org/repo/sub')
    model.findElementFromPath('/Org/repo').attrs['repo_url'] = 'https://example.org/repo.git'
    model.findElementFromPath('/Org/repo/sub').attrs['repo_url'] = '   '

    component = {}
    sbom_cyclonedx_generator._add_vcs_reference(
        component, model.findElementFromPath('/Org/repo/sub'))

    assert component['externalReferences'] == [
        {'url': 'https://example.org/repo.git', 'type': 'vcs'}
    ]


def test_transitive_internal_components_carry_their_location():
    """Every link of the inlined exposure chain says where it lives, not just the chain's root."""
    model, _ = get_model_and_model_api(MULTI_MODEL)
    result = generate_multi_from_sgraph(model, level=3, transitive=True)

    repo_b = next(c for c in sbom_of(result, 'repoA')['components'] if c['name'] == 'repoB')
    assert repo_b['group'] == '/OrgName/GroupA'
    assert find_property(repo_b, 'softagram:elementPath') == '/OrgName/GroupA/repoB'
    # The pre-existing internal marker survives alongside the new property
    assert find_property(repo_b, 'softagram:internal') == 'true'
    # repoB has no repo_url in the fixture, so it gets no vcs reference
    assert [r for r in repo_b['externalReferences'] if r['type'] == 'vcs'] == []


def test_inlined_mirror_is_told_apart_from_its_host_by_its_published_location():
    """GroupA's transitive SBOM holds two components named 'shared' — one of them is itself.

    The two share a name, so a consumer reading names alone cannot tell which repository each
    component is. group, elementPath and the vcs URL answer that; the bom link then resolves
    the inlined one to its own standalone document. This is the case the feature exists for.
    """
    model, _ = get_model_and_model_api(MIRRORED_MODEL)
    result = generate_multi_from_sgraph(model, level=3, transitive=True)

    host = next(s for s in result if s['metadata']['component']['group'] == '/OrgName/GroupA')
    inlined = next(c for c in host['components']
                   if find_property(c, 'softagram:internal') == 'true')

    assert inlined['name'] == host['metadata']['component']['name'] == 'shared'
    assert inlined['group'] == '/OrgName/GroupB'
    assert find_property(inlined, 'softagram:elementPath') == '/OrgName/GroupB/shared'

    # List comprehensions rather than a {type: url} dict: these pin cardinality too, so a
    # regression emitting a second vcs entry cannot pass by last-wins.
    vcs = [r['url'] for r in inlined['externalReferences'] if r['type'] == 'vcs']
    assert vcs == ['https://example.org/org/groupb-shared.git']

    mirror = next(s for s in result if s['metadata']['component']['group'] == '/OrgName/GroupB')
    mirror_serial = mirror['serialNumber'].replace('urn:uuid:', '')
    bom_links = [r['url'] for r in inlined['externalReferences'] if r['type'] == 'bom']
    assert bom_links == [f'urn:cdx:{mirror_serial}/1']


def test_legacy_single_sbom_carries_the_element_path():
    """The legacy single-SBOM mode describes a model element too, so it publishes its path.

    Its element is at the top level, so group is omitted. Its bom-ref has always been the path;
    that is left alone, because other documents may already reference it.
    """
    model, _ = get_model_and_model_api('converters/modelfile_for_sbom_tests.xml')
    sbom = sbom_cyclonedx_generator.generate_from_sgraph(model)

    component = sbom['metadata']['component']
    assert component['name'] == 'nginx'
    assert find_property(component, 'softagram:elementPath') == '/nginx'
    assert 'group' not in component
    assert component['bom-ref'] == '/nginx'


# --- The model's element type ---
#
# A level-based export splits at a tree depth, and what sits at that depth is USUALLY a repository
# but not always: 9 of 689 documents in one reported export describe elements that are not
# t="repository" in the model, and all 9 emit zero components. A consumer reading only the
# document cannot tell those apart from a repository that genuinely has no dependencies, and the
# two mean very different things.
#
# component.type is a closed CycloneDX enum with no 'repository' value, so it cannot carry this;
# a softagram:-namespaced property is the schema-lawful place, the same reasoning that put
# elementPath there.
#
# Published only when the model actually carries a type. The alternative -- always emitting, with
# 'unknown' or '' where the attribute is absent -- was rejected, and the reason is written into
# _add_vcs_reference already: repo elements are NOT required to carry a 'type' attribute. So an
# absent attribute is not evidence of anything, and a sentinel would convert "the model did not
# say" into a positive claim that this is not a repository. That is the same false inference the
# request is trying to escape, moved one layer along. An absent property reads as "not stated",
# which is what is true.

ELEMENT_TYPE_PROPERTY = 'softagram:elementType'


def typed_estate_model():
    """Two elements at the same depth, one a repository and one not, as the split sees them.

    The shape the request is about: a level-3 export cannot assume what it split on, and the two
    kinds must be distinguishable in the document alone. 'plain' carries no type at all, which is
    the third case and the common one on stored models.
    """
    model = SGraph(SElement(None, ''))
    for name, elem_type in (('repoA', 'repository'), ('docsdir', 'dir'), ('plain', None)):
        elem = model.createOrGetElementFromPath(f'/OrgName/GroupA/{name}')
        if elem_type is not None:
            elem.attrs['type'] = elem_type
        model.createOrGetElementFromPath(f'/OrgName/GroupA/{name}/src/main.cs')
    return model


def test_a_repository_is_told_apart_from_a_non_repository_element():
    """The request itself: two documents at one level, describing different kinds of thing."""
    result = generate_multi_from_sgraph(typed_estate_model(), level=3)

    assert find_property(sbom_of(result, 'repoA')['metadata']['component'],
                         ELEMENT_TYPE_PROPERTY) == 'repository'
    assert find_property(sbom_of(result, 'docsdir')['metadata']['component'],
                         ELEMENT_TYPE_PROPERTY) == 'dir'


def test_an_untyped_element_publishes_no_type_rather_than_a_guess():
    """Absence of the attribute is not evidence, so nothing is claimed.

    A repository is not required to carry 'type', so emitting 'unknown' here would let a consumer
    filtering on elementType != 'repository' exclude a genuine repository on the strength of a
    value this code invented. Asserted as absence of the KEY rather than as an empty value: an
    empty string is still a property a consumer must interpret.
    """
    result = generate_multi_from_sgraph(typed_estate_model(), level=3)

    component = sbom_of(result, 'plain')['metadata']['component']
    assert find_property(component, ELEMENT_TYPE_PROPERTY) is None
    assert ELEMENT_TYPE_PROPERTY not in {p['name'] for p in component.get('properties', [])}


def test_every_stored_fixture_is_unchanged_because_none_carries_a_type():
    """The corpus-safety claim, stated as a test rather than left to the measurement.

    No committed fixture carries a 'type' attribute on a content element, so this property is
    emitted nowhere in them and every existing consumer of those documents receives exactly what
    it received. That is what makes the addition inert on stored models rather than merely small.
    """
    for model_file in (MULTI_MODEL, MIRRORED_MODEL, 'converters/modelfile_for_sbom_tests.xml'):
        model, _ = get_model_and_model_api(model_file)
        for document in generate_multi_from_sgraph(model, level=3):
            assert find_property(document['metadata']['component'],
                                 ELEMENT_TYPE_PROPERTY) is None, model_file


def test_the_type_reaches_the_legacy_and_inlined_components_too():
    """One assembly point, so all three components that describe an element get it.

    _add_element_location is called for the legacy single-document subject, for the per-element
    subject, and for an internal element inlined into another document. A per-call-site addition
    would have landed on one of the three, and the inlined component is the one that matters most
    here: it is where a consumer meets an element it did NOT ask for a document about.
    """
    model = SGraph(SElement(None, ''))
    top = model.createOrGetElementFromPath('/OrgName')
    top.attrs['type'] = 'estate'
    legacy = sbom_cyclonedx_generator.generate_from_sgraph(model)
    assert find_property(legacy['metadata']['component'], ELEMENT_TYPE_PROPERTY) == 'estate'

    model, _ = get_model_and_model_api(MIRRORED_MODEL)
    for path in ('/OrgName/GroupA/shared', '/OrgName/GroupB/shared'):
        model.findElementFromPath(path).attrs['type'] = 'repository'
    result = generate_multi_from_sgraph(model, level=3, transitive=True)

    inlined = [c for document in result for c in document['components']
               if find_property(c, 'softagram:internal') == 'true']
    assert inlined
    assert all(find_property(c, ELEMENT_TYPE_PROPERTY) == 'repository' for c in inlined)


def test_the_published_type_is_a_string_as_cyclonedx_requires():
    """properties[].value is typed as a string in every version, and a non-string voids the doc.

    The model stores attributes untyped, so a type attribute holding a non-string would otherwise
    reach the document unchanged and a validating consumer would discard the whole SBOM over it.
    """
    result = generate_multi_from_sgraph(typed_estate_model(), level=3)

    for document in result:
        for prop in document['metadata']['component'].get('properties', []):
            assert isinstance(prop['value'], str), prop


# --- purl type inference tests ---

BINARY_REFS_MODEL = 'converters/modelfile_for_sbom_binary_refs_tests.xml'

# The purl spec requires a type to start with a letter and to hold only [a-z0-9.-] in its
# canonical form. Only the type is anchored here: this pattern predates maven coordinates and
# still says nothing about namespace, name or version, which other assertions cover.
PURL_TYPE_PATTERN = re.compile(r'^pkg:[a-z][a-z0-9.-]*/')


def get_binary_refs_components():
    """Generate the binary-reference SBOM and index its components by component name."""
    model, _ = get_model_and_model_api(BINARY_REFS_MODEL)
    sbom = sbom_cyclonedx_generator.generate_from_sgraph(model)
    return {component['name']: component for component in sbom['components']}


def purl_type_resolution(component):
    """Return the purlTypeResolution property value of a component, or None when it has none."""
    for prop in component['properties']:
        if prop['name'] == 'purlTypeResolution':
            return prop['value']
    return None


def test_dll_referenced_binary_is_typed_as_nuget():
    """A binary referenced from a .dll gets the .NET ecosystem type instead of '???'."""
    component = get_binary_refs_components()['Ionic.Zip']
    assert component['purl'] == 'pkg:nuget/Ionic.Zip@1.9.1.8'
    assert component['bom-ref'] == component['purl']


def test_exe_referenced_binary_is_typed_as_nuget():
    """An .exe reference is the same .NET signal as a .dll reference."""
    assert get_binary_refs_components()['ExampleTool']['purl'] == 'pkg:nuget/ExampleTool@2.0.1'


def test_nupkg_referenced_binary_is_typed_as_nuget():
    """A .nupkg reference names the .NET package format directly."""
    component = get_binary_refs_components()['NupkgBinary']
    assert component['purl'] == 'pkg:nuget/NupkgBinary@3.1'
    assert purl_type_resolution(component) == 'inferred from referencing file extension: nupkg'


def test_wheel_and_egg_referenced_binary_is_typed_as_pypi():
    """.whl and .egg both name the Python ecosystem, whose purl type prohibits a namespace."""
    component = get_binary_refs_components()['PyBinary']
    # Folded by A4: pypi is case_sensitive false, so PyBinary and pybinary are one package and
    # the published spelling is the folded one. The element's name still reads PyBinary.
    assert component['purl'] == 'pkg:pypi/pybinary@1.2'
    assert purl_type_resolution(component) == 'inferred from referencing file extension: egg,whl'


def test_extension_matching_ignores_case_and_reports_every_winning_extension():
    """Helper.DLL and Legacy.exe both vote nuget; the provenance lists both, sorted."""
    component = get_binary_refs_components()['MultiRefBinary']
    assert component['purl'] == 'pkg:nuget/MultiRefBinary@6.1'
    assert purl_type_resolution(component) == 'inferred from referencing file extension: dll,exe'


def test_jar_referenced_binary_falls_back_to_generic():
    """jar/war/aar are deliberately unmapped: maven requires a groupId no extension can supply.

    This asserts its own premise, unlike the other guards. No assertion on the *output* can tell
    "referenced from a .jar" apart from "not referenced at all": both produce generic with
    'ecosystem unresolved'. Without the premise assertion below, removing the .jar reference would
    therefore leave this test passing while it proved only what
    test_binary_without_any_reference_falls_back_to_generic already proves. With it, that removal
    fails here. The extension is derived with plain string handling rather than the module's
    file_extension helper, so the premise does not depend on the code under test.
    """
    model, _ = get_model_and_model_api(BINARY_REFS_MODEL)
    elem = model.findElementFromPath(
        '/ExampleOrg/External/Unknown_Binary_Files/JvmBinary/JvmBinary of version 4.2')
    assert elem is not None
    voting_extensions = {association.fromElement.name.rsplit('.', 1)[-1].lower()
                         for association in elem.incoming + elem.parent.incoming}
    assert voting_extensions == {'jar'}

    component = get_binary_refs_components()['JvmBinary']
    assert component['purl'] == 'pkg:generic/JvmBinary@4.2'
    assert purl_type_resolution(component) == 'ecosystem unresolved'


def test_unknown_extension_falls_back_to_generic():
    """An extension with no registered purl type resolves honestly to generic."""
    component = get_binary_refs_components()['SampleExtension']
    assert component['purl'] == 'pkg:generic/SampleExtension@0.9'
    assert purl_type_resolution(component) == 'ecosystem unresolved'


def test_binary_without_any_reference_falls_back_to_generic():
    """With no referencing file there is no signal at all, so the fallback applies."""
    component = get_binary_refs_components()['OrphanBinary']
    assert component['purl'] == 'pkg:generic/OrphanBinary@7.7'
    assert purl_type_resolution(component) == 'ecosystem unresolved'


def test_reference_on_the_package_directory_types_its_versioned_child():
    """References often land on the package directory rather than on its versioned child."""
    component = get_binary_refs_components()['GroupedBinary']
    assert component['purl'] == 'pkg:nuget/GroupedBinary@3.3'
    assert purl_type_resolution(component) == 'inferred from referencing file extension: dll'


def test_element_under_a_java_parent_falls_back_to_generic():
    """A parent directory named Java no longer produces the syntactically invalid '??Java'."""
    component = get_binary_refs_components()['somelib']
    assert component['purl'] == 'pkg:generic/somelib@4.1'
    assert purl_type_resolution(component) == 'ecosystem unresolved'


def test_tie_between_candidate_types_is_broken_alphabetically():
    """One .gem and one .dll reference tie; gem wins by name so output cannot depend on order."""
    component = get_binary_refs_components()['MixedRefBinary']
    assert component['purl'] == 'pkg:gem/MixedRefBinary@5.0'
    assert purl_type_resolution(component) == 'inferred from referencing file extension: gem'


# --- purl provenance property tests ---


def test_provenance_cites_only_the_extensions_that_voted_for_the_winning_type():
    """Two .dll and one .whl: nuget wins 2-1, so the losing .whl is not cited as evidence.

    The .whl referencing MixedVoteBinary in the fixture is the deliberate losing vote and must
    not be removed: without it this guard cannot fail.
    """
    component = get_binary_refs_components()['MixedVoteBinary']
    assert component['purl'] == 'pkg:nuget/MixedVoteBinary@8.2'
    assert purl_type_resolution(component) == 'inferred from referencing file extension: dll'


def test_repotype_that_names_no_ecosystem_still_gets_provenance():
    """A repotype of 'Unknown_Binary_Files' resolves nothing, so the type is still a guess."""
    model, _ = get_model_and_model_api(BINARY_REFS_MODEL)
    elem = model.findElementFromPath(
        '/ExampleOrg/External/Unknown_Binary_Files/Ionic.Zip/Ionic.Zip of version 1.9.1.8')
    assert elem is not None
    assert elem.attrs['repotype'] == 'Unknown_Binary_Files'
    component = get_binary_refs_components()['Ionic.Zip']
    assert purl_type_resolution(component) == 'inferred from referencing file extension: dll'


def test_types_read_from_attributes_or_ancestors_carry_no_provenance():
    """A type resolved from an attribute naming an ecosystem is not a guess and is not labelled."""
    components = get_binary_refs_components()
    assert components['ExampleOrg.Common']['purl'] == 'pkg:nuget/ExampleOrg.Common@1.4.2'
    assert purl_type_resolution(components['ExampleOrg.Common']) is None
    maven_component = components['org.example.sample sample-lib']
    # This component is still looked up by a name that carries the space; only the purl stopped
    # carrying it. Maven ids cannot contain a space, so encoding it as %20 here would have been
    # spec-valid and still matched nothing.
    assert maven_component['purl'] == 'pkg:maven/org.example.sample/sample-lib@2.4.1'
    assert purl_type_resolution(maven_component) is None


# --- purl spec conformance guard tests ---


def test_every_generated_purl_has_a_spec_valid_type():
    """Regression guard: encode the purl-spec type invariant, not a list of expected values."""
    for model_file in (BINARY_REFS_MODEL, 'converters/modelfile_for_sbom_tests.xml'):
        model, _ = get_model_and_model_api(model_file)
        sbom = sbom_cyclonedx_generator.generate_from_sgraph(model)
        assert sbom['components']
        for component in sbom['components']:
            assert PURL_TYPE_PATTERN.match(component['purl']), component['purl']
            assert PURL_TYPE_PATTERN.match(component['bom-ref']), component['bom-ref']


def test_single_sbom_never_repeats_a_bom_ref():
    """CycloneDX requires bom-ref to be unique; the same package can be reached by two routes."""
    model, _ = get_model_and_model_api(BINARY_REFS_MODEL)
    sbom = sbom_cyclonedx_generator.generate_from_sgraph(model)
    bom_refs = [component['bom-ref'] for component in sbom['components']]
    assert bom_refs.count('pkg:nuget/DupPackage@2.5.0') == 1
    assert len(bom_refs) == len(set(bom_refs))


def test_infer_pkgtype_handles_element_without_a_parent():
    """The inference function is callable on a root element, which has no parent to consult."""
    model = SGraph(SElement(None, ''))
    assert infer_pkgtype_from_referencing_files(model.rootNode) == (None, [])


def test_bom_ref_still_returns_only_the_purl_string():
    """The public bom_ref signature and return type are unchanged by the provenance split."""
    model, _ = get_model_and_model_api(BINARY_REFS_MODEL)
    elem = model.findElementFromPath(
        '/ExampleOrg/External/Unknown_Binary_Files/Ionic.Zip/Ionic.Zip of version 1.9.1.8')
    assert elem is not None
    assert sbom_cyclonedx_generator.bom_ref(elem, '1.9.1.8') == 'pkg:nuget/Ionic.Zip@1.9.1.8'


# --- maven coordinate tests ---

MAVEN_COORDINATES_MODEL = 'converters/modelfile_for_sbom_maven_coordinates_tests.xml'


def get_maven_coordinate_components():
    """Generate the maven-coordinate SBOM and index its components by component name."""
    model, _ = get_model_and_model_api(MAVEN_COORDINATES_MODEL)
    sbom = sbom_cyclonedx_generator.generate_from_sgraph(model)
    return {component['name']: component for component in sbom['components']}


def test_maven_coordinates_supply_the_required_groupid_namespace():
    """The maven type requires a namespace, and the coordinates to build one were already there.

    Pinned as an exact set rather than per fixture: a missing purl and an unexpected extra one
    both fail, and an empty result cannot pass.
    """
    purls = set()
    for model_file in ('converters/modelfile_for_sbom_tests.xml',
                       'converters/modelfile_for_sbom_multi_tests.xml',
                       BINARY_REFS_MODEL):
        model, _ = get_model_and_model_api(model_file)
        sbom = sbom_cyclonedx_generator.generate_from_sgraph(model)
        purls.update(c['purl'] for c in sbom['components'] if c['purl'].startswith('pkg:maven/'))
    assert purls == {
        'pkg:maven/aopalliance/aopalliance@1.0',
        'pkg:maven/org.apache.commons/commons-lang3@3.12.0',
        'pkg:maven/org.example.sample/sample-lib@2.4.1',
    }


def test_multi_sbom_dependson_carries_a_well_formed_maven_reference():
    """A dependsOn entry is a bom-ref, and the maven one used to carry a raw space into it."""
    model, _ = get_model_and_model_api('converters/modelfile_for_sbom_multi_tests.xml')
    result = generate_multi_from_sgraph(model, level=3)
    repo_b_sbom = next(s for s in result if s['metadata']['component']['name'] == 'repoB')
    repo_b_ref = repo_b_sbom['metadata']['component']['bom-ref']
    depends_on = next(d for d in repo_b_sbom['dependencies']
                      if d['ref'] == repo_b_ref)['dependsOn']
    assert 'pkg:maven/org.apache.commons/commons-lang3@3.12.0' in depends_on
    assert not any(' ' in reference for reference in depends_on)


def test_partial_maven_coordinates_do_not_emit_half_an_identity():
    """Only one coordinate present must not produce a half-identity. With both coordinates absent,
    requiring both and requiring either behave identically, so no both-absent fixture can
    separate them. This element can, and under the relaxed rule it emits a namespace with an
    empty name.
    """
    component = get_maven_coordinate_components()['partial-lib']
    assert component['purl'] == 'pkg:generic/partial-lib@1.0'
    assert purl_type_resolution(component) == 'maven coordinates unavailable'


def test_maven_element_without_coordinates_takes_the_residual_and_is_not_inferred():
    """The Maven branch resolves its own fallback rather than falling through to inference.

    The fixture references this element from a .dll, which would vote nuget if the
    coordinate-less case reached infer_pkgtype_from_referencing_files. Both assertions below
    therefore separate an honest residual from a guess, which the type alone would not.
    """
    component = get_maven_coordinate_components()['coordinateless-lib']
    assert component['purl'] == 'pkg:generic/coordinateless-lib@2.0'
    assert purl_type_resolution(component) == 'maven coordinates unavailable'


def test_a_purl_legal_character_that_is_not_a_maven_id_takes_the_residual():
    """A colon is legal in a purl component and can never be a Maven id.

    A purl built from it would be canonical, would pass a conformance checker, and would match
    nothing. That is why the guard is the Maven id charset and not the purl charset.
    """
    component = get_maven_coordinate_components()['colon-lib']
    assert component['purl'] == 'pkg:generic/colon-lib@3.0'
    assert purl_type_resolution(component) == 'maven coordinates unavailable'


def test_the_residual_value_stays_distinct_from_an_unresolved_ecosystem():
    """A Maven element with no usable coordinates has a known ecosystem and an unusable name.

    Reusing 'ecosystem unresolved' here would mark as ecosystem-unknown a component whose
    ecosystem is known, blunting the discriminator the previous release told consumers to grep.
    """
    components = get_maven_coordinate_components()
    residuals = {purl_type_resolution(components[name])
                 for name in ('partial-lib', 'coordinateless-lib', 'colon-lib')}
    assert residuals == {'maven coordinates unavailable'}
    assert 'ecosystem unresolved' not in residuals


def test_maven_coordinate_case_is_preserved_in_both_components():
    """The maven type is case-sensitive in namespace and name, so neither may be lowercased.

    Asserts its own premise: the Maven bucket in this fixture sits under a JVM layer, as analyzer
    output does, and the branch matches the package element's parent so the extra layer makes no
    difference. Nothing in the output reveals the layer, so without the premise assertion,
    flattening the fixture would silently retire the only tracked evidence of that.
    """
    model, _ = get_model_and_model_api(MAVEN_COORDINATES_MODEL)
    elem = model.findElementFromPath(
        '/ExampleOrg/External/JVM/Maven/Org.Example.Mixed Mixed-Lib of version 4.0')
    assert elem is not None
    component = get_maven_coordinate_components()['Org.Example.Mixed Mixed-Lib']
    assert component['purl'] == 'pkg:maven/Org.Example.Mixed/Mixed-Lib@4.0'
    assert purl_type_resolution(component) is None


def test_an_unresolved_version_yields_a_versionless_purl():
    """A build-property expression names no published artifact, so the version is omitted.

    Omission is not a workaround: purl treats the version as optional, so the result is canonical
    and matches at package level, where the raw expression could only ever match nothing. The raw
    expression stays in the component's version field, so it is disclosed rather than dropped.
    """
    component = get_maven_coordinate_components()['org.example.unresolved unresolved-lib']
    assert component['purl'] == 'pkg:maven/org.example.unresolved/unresolved-lib'
    assert component['version'] == '${project.version}'
    assert purl_type_resolution(component) is None


def test_maven_coordinate_guard_accepts_real_coordinates():
    """Anti-vacuity for the guard: it must admit ordinary and uppercase coordinates."""
    for value in ('org.apache.commons', 'commons-lang3', 'aopalliance', 'HTTPClient'):
        assert sbom_cyclonedx_generator.is_maven_coordinate(value), value


def test_maven_coordinate_guard_does_more_than_reject_whitespace():
    """Control against simplifying the guard to a space check.

    Only three of the values below contain whitespace at all, asserted rather than claimed, so a
    guard reduced to a whitespace test would accept the other eight. Two of those eight,
    'org.example:lib' and 'org.example~lib', purl would leave unencoded: they are what
    distinguishes a Maven-charset guard from a purl-charset one. '.' and '..' are rejected by an
    explicit exclusion, since the pattern alone matches both. The trailing-newline value is there
    for a different reason from the rest: the pattern's '$' also matches just before a final
    newline, so match() accepts a coordinate that ends in one and would emit a purl with a line
    break inside the namespace. Only fullmatch's whole-string requirement refuses it.
    """
    not_maven_ids = ('org.example sample-lib', 'org.example\tlib', '', '.', '..',
                     'org/example', 'org.example:lib', 'org.example~lib',
                     '${project.version}', 'org.exämple', 'probe.group\n')
    for value in not_maven_ids:
        assert not sbom_cyclonedx_generator.is_maven_coordinate(value), value
    whitespace_bearing = [v for v in not_maven_ids if any(c.isspace() for c in v)]
    assert len(whitespace_bearing) == 3


def test_maven_coordinates_fixture_yields_eight_distinct_components():
    """Anti-vacuity for the fixture, and the collapse guard for version omission.

    A lookup above raises when an element vanishes, but an element added, or two bom-refs
    collapsed into one when a version is omitted, would otherwise go unnoticed. Eight, not
    ten: husk-lib and legacy-parent exist in the fixture and must not be counted here.
    """
    model, _ = get_model_and_model_api(MAVEN_COORDINATES_MODEL)
    sbom = sbom_cyclonedx_generator.generate_from_sgraph(model)
    assert len(sbom['components']) == 8
    assert len({component['bom-ref'] for component in sbom['components']}) == 8


# --- version-managed dependency tests ---


def test_a_referenced_versionless_dependency_is_still_a_component():
    """A dependency version-managed by an imported BOM has no version anywhere in the model.

    The version is real but lives inside an artifact the analyzer never parses, so requiring a
    version for inclusion drops exactly the dependencies modern Maven declares: the more a
    project centralizes versions in parents and BOMs, the emptier its SBOM. A versionless maven
    purl is canonical and still matches at package level — the same trade the
    unresolved-expression case above already accepted.
    """
    component = get_maven_coordinate_components()['org.example.managed managed-lib']
    assert component['purl'] == 'pkg:maven/org.example.managed/managed-lib'
    assert component['version'] == ''
    assert purl_type_resolution(component) is None


def test_an_unreferenced_versionless_element_is_not_swept_in():
    """The inclusion rule for versionless elements is incoming references, not existence.

    Version-management redirection re-points references at versioned elements and leaves the
    versionless originals behind with none. husk-lib is the control for managed-lib: identical
    shape, no incoming reference. Without it the rule could decay into plain coordinate
    presence and every other assertion would stay green.
    """
    assert 'org.example.husk husk-lib' not in get_maven_coordinate_components()


def test_parent_version_supplies_the_version_of_an_external_parent_pom():
    """A parent pom reference records its exact version under parent_version, not version.

    The analyzer read that version out of the <parent> block it parsed, so dropping the
    component, or emitting it versionless, discards information the model already holds.
    """
    component = get_maven_coordinate_components()['org.example.parentpom parent-pom']
    assert component['purl'] == 'pkg:maven/org.example.parentpom/parent-pom@7.1'
    assert component['version'] == '7.1'


def test_an_explicit_version_outranks_parent_version():
    """An element that is both a parent and an ordinary dependency keeps its own version.

    No fixture element carries both attributes, deliberately: this ordering is a property of
    extract_version alone, and a fixture pinning it would couple two orthogonal guards.
    """
    elem = SElement(None, 'org.example both')
    elem.attrs.update(version='1.0', parent_version='2.0')
    assert sbom_cyclonedx_generator.extract_version(elem) == '1.0'


def test_a_legacy_parent_without_coordinates_is_not_emitted():
    """Models persisted before the analyzer wrote coordinates onto parents must stay excluded.

    SBOMs are generated on demand from stored models with a multi-month lifetime, so the
    generator meets old shapes long after the analyzer moved on. A parent_version-only element
    has no coordinates to build a maven purl from; emitting it would splice the space-bearing
    element name into a generic purl — the exact class the maven-purl work eliminated. The
    fixture element is referenced, deliberately: exclusion must rest on the missing coordinates,
    not on a missing reference.
    """
    assert 'org.example.legacyparent legacy-parent' not in get_maven_coordinate_components()


def test_an_ambiguous_parent_version_stays_out_of_the_purl():
    """Two poms naming one parent at different versions collide on one versionless element.

    The attribute transfer joins their versions with a semicolon. A purl carrying the joined
    value asserts a version that exists nowhere and matches nothing; omitting it keeps the purl
    canonical and package-level matchable, while the raw value stays disclosed in the version
    field — the same split the unresolved-expression case established.
    """
    component = get_maven_coordinate_components()['org.example.multiparent multi-parent']
    assert component['purl'] == 'pkg:maven/org.example.multiparent/multi-parent'
    assert component['version'] == '4.1.0;3.2.0'


def test_versionless_inclusion_requires_usable_coordinates():
    """Charset-rejected coordinates plus no version leave nothing spec-clean to emit.

    A ${} groupId whose property lives in an external parent fails the coordinate guard, so no
    maven purl can be built; versionless, the element predates this feature in no BOM at all,
    and admitting it now would splice the space-bearing element name into a generic purl. A
    versioned element with the same broken coordinates still takes the generic residual as
    before — this rule is about what the versionless-inclusion branch may admit, not about
    tightening the residual.
    """
    assert 'org.example.propgroup prop-group-lib' not in get_maven_coordinate_components()


def test_the_generic_fallback_never_splices_an_empty_version():
    """The versionless-inclusion rule made an empty version reachable on the fallback path.

    Coordinates that fail the charset guard, such as an unresolved ${project.groupId}, drop the
    element to the generic branch, and a versionless element then reaches the final splice with
    an empty version. Appending it would emit a trailing '@' — not a canonical versionless purl
    but a malformed versioned one, the same shape maven_purl already refuses.
    """
    maven_bucket = SElement(None, 'Maven')
    elem = SElement(maven_bucket, 'caffeine')
    elem.attrs.update(groupId='${project.groupId}', artifactId='caffeine')
    purl, properties = sbom_cyclonedx_generator.purl_for(elem, '')
    assert purl == 'pkg:generic/caffeine'
    assert properties == [{'name': 'purlTypeResolution', 'value': 'maven coordinates unavailable'}]


def test_no_fixture_purl_carries_a_space_a_semicolon_or_a_trailing_at():
    """The cross-shape invariant the individual guards above defend, stated once directly.

    Findings against stored models all took one of these three shapes; asserting the invariant
    over every fixture generation catches a regression in any of them even if the targeted
    test for that shape is later weakened.
    """
    for model_file in (MAVEN_COORDINATES_MODEL, BINARY_REFS_MODEL,
                       'converters/modelfile_for_sbom_tests.xml',
                       'converters/modelfile_for_sbom_multi_tests.xml'):
        model, _ = get_model_and_model_api(model_file)
        sbom = sbom_cyclonedx_generator.generate_from_sgraph(model)
        for component in sbom['components']:
            for ref in (component['purl'], component['bom-ref']):
                assert ' ' not in ref, ref
                assert ';' not in ref, ref
                assert not ref.endswith('@'), ref


def test_a_partly_resolved_version_keeps_its_version():
    """Only a whole build-property expression is dropped, not a version that merely contains one.

    Nothing else can fail if UNRESOLVED_VERSION is widened from fullmatch to a substring search:
    no fixture carries a partly resolved version, so every other assertion stays green while
    '1.0-${suffix}' silently loses the resolved part it should have kept.
    """
    model = SGraph(SElement(None, ''))
    elem = model.createOrGetElementFromPath('/Proj/External/Maven/lib')
    elem.attrs.update({'groupId': 'org.example', 'artifactId': 'lib'})
    assert sbom_cyclonedx_generator.maven_purl(elem, '1.0-${suffix}') == \
        'pkg:maven/org.example/lib@1.0-${suffix}'
    assert sbom_cyclonedx_generator.maven_purl(elem, '${suffix}') == 'pkg:maven/org.example/lib'


def test_a_caret_prefixed_version_is_normalised_as_on_every_other_branch():
    """The maven path keeps the version handling the shared tail gives every other type.

    purl_for strips a leading caret before splicing the version in. The maven path returns
    early, so it has to apply that itself, and no fixture carries a caret version: dropping the
    call changes no other assertion in this file.
    """
    maven_bucket = SElement(None, 'Maven')
    elem = SElement(maven_bucket, 'org.example example-lib of version 1.0')
    elem.attrs.update(groupId='org.example', artifactId='example-lib')
    purl, properties = sbom_cyclonedx_generator.purl_for(elem, '^1.0')
    assert purl == 'pkg:maven/org.example/example-lib@1.0'
    assert properties == []


# --- component emission tests ---
#
# Five defects measured against the customer's 674 SBOMs, all local to this module: an image
# emitted as a library, a build-property version spliced into a purl on every non-maven type, an
# undecoded __slash__ in a version, one NuGet package inventoried twice under two spellings, and
# a committed binary asserted to be a published NuGet package.

EMISSION_MODEL = 'converters/modelfile_for_sbom_emission_tests.xml'


def get_emission_components():
    """Generate the emission SBOM and return its components as a list.

    A list rather than a by-name index: the case-differing spellings this fixture carries collide
    in a by-name dict until deduplication folds them together, and a dict would hide exactly the
    defect the fixture exists to pin.
    """
    model, _ = get_model_and_model_api(EMISSION_MODEL)
    return sbom_cyclonedx_generator.generate_from_sgraph(model)['components']


def find_property(component, name):
    """Return the value of a named CycloneDX property of a component, or None when absent.

    Distinct from purl_type_resolution above, which reads one fixed property name; this reads any
    of them, and the versionless-purl rules below each need a different one.
    """
    for prop in component.get('properties', []):
        if prop['name'] == name:
            return prop['value']
    return None


def emission_component(name):
    """Return the one component with this name, failing when it is absent or not unique."""
    matches = [component for component in get_emission_components() if component['name'] == name]
    assert len(matches) == 1, matches
    return matches[0]


def test_a_docker_image_is_emitted_as_a_container_not_a_library():
    """CycloneDX has a component type for an image, and the purl type already says it is one.

    'library' on an image is not a harmless default: consumers route components by type, and an
    image classified as a library is scanned as application code rather than as a base layer.
    """
    component = emission_component('nginx')
    assert component['purl'] == 'pkg:docker/nginx@1.25'
    assert component['type'] == 'container'


def test_a_package_that_is_not_an_image_stays_a_library():
    """Anti-vacuity for the mapping: it must retype images only, not everything."""
    assert emission_component('Ionic.Zip')['type'] == 'library'


def test_the_oci_purl_type_is_a_container_too():
    """oci names the same artifact class docker does, and no fixture can reach that branch.

    Nothing in this module emits pkg:oci today, so the mapping is asserted directly rather than
    through a model. The nuget case is the control: without it a mapping that answered
    'container' unconditionally would pass.
    """
    assert sbom_cyclonedx_generator.cyclonedx_component_type('pkg:oci/nginx@1.25') == 'container'
    assert sbom_cyclonedx_generator.cyclonedx_component_type('pkg:nuget/X@1.0') == 'library'


def test_an_msbuild_property_version_yields_a_versionless_purl():
    """$(...) is MSBuild's expression syntax and names no published version, exactly as ${...}.

    The rule already existed for maven and was applied nowhere else, so every other ecosystem
    kept splicing the unresolved expression into the purl.
    """
    component = emission_component('MsbuildLib')
    assert component['purl'] == 'pkg:nuget/MsbuildLib'
    assert component['version'] == '$(VersionPrefix)'


def test_an_unresolved_expression_is_unresolved_on_every_type_not_only_maven():
    """The same ${...} the maven branch already refused must not be spliced in on a nuget purl."""
    component = emission_component('MavenStyleLib')
    assert component['purl'] == 'pkg:nuget/MavenStyleLib'
    assert component['version'] == '${Version}'


def test_a_partly_resolved_msbuild_version_keeps_its_version():
    """The fullmatch discipline the maven branch established survives the widening.

    A version that merely contains an expression is partly known, and dropping the known part
    would change which components exist under a rule nobody has measured.
    """
    component = emission_component('PartlyResolvedLib')
    assert component['purl'] == 'pkg:nuget/PartlyResolvedLib@1.0-$(Suffix)'


def test_the_unresolved_version_guard_matches_both_expression_dialects():
    """Direct guard on the pattern, including the empty-expression and bare-dollar controls."""
    for value in ('${project.version}', '$(VersionPrefix)', '$(Ver)'):
        assert sbom_cyclonedx_generator.UNRESOLVED_VERSION.fullmatch(value), value
    for value in ('1.0', '1.0-${suffix}', '1.0-$(suffix)', '$', '${}', '$()', ''):
        assert not sbom_cyclonedx_generator.UNRESOLVED_VERSION.fullmatch(value), value


def test_a_slash_encoded_version_is_decoded_like_a_name():
    """__slash__ is sgraph's encoding of '/' and clean_name already decodes it out of names.

    A version carries the same encoding and was left raw, so both the disclosed version and the
    purl advertised a literal '__slash__' that matches nothing anywhere.
    """
    component = emission_component('BranchVersionLib')
    assert component['version'] == 'feature/1.0'
    assert component['purl'] == 'pkg:nuget/BranchVersionLib@feature/1.0'


def test_a_url_shaped_version_yields_a_versionless_purl_and_records_its_source():
    """A URL is a location, not a version: it names no release and matches no advisory.

    Omitting it keeps the purl canonical and package-level matchable, and the URL stays disclosed
    twice over — in the version field, and in a property saying why the purl has no version.
    """
    component = emission_component('UrlVersionLib')
    assert component['purl'] == 'pkg:nuget/UrlVersionLib'
    assert component['version'] == 'https://github.com/example/lib.git'
    assert find_property(component, 'versionSource') == 'https://github.com/example/lib.git'


def test_case_differing_nuget_spellings_are_one_package():
    """NuGet package ids are case-insensitive, so two spellings are one package, not two.

    Emitting both inflates the inventory and makes the same advisory arrive twice, once per
    spelling. The surviving spelling is the first in document order so output stays byte-stable.
    """
    nlog_components = [component for component in get_emission_components()
                       if component['name'].lower() == 'nlog']
    assert len(nlog_components) == 1
    assert nlog_components[0]['purl'] == 'pkg:nuget/NLog@5.0.0'


def test_case_differing_maven_artifacts_stay_two_packages():
    """Control against over-broad folding: Maven identity is case-sensitive in both coordinates.

    Folding every type would collapse these two real, distinct artifacts into one and lose a
    component outright — a strictly worse defect than the duplicate it set out to remove.
    """
    maven_purls = {component['purl'] for component in get_emission_components()
                   if component['purl'].startswith('pkg:maven/')}
    assert maven_purls == {'pkg:maven/org.example/CaseLib@1.0',
                           'pkg:maven/org.example/caselib@1.0'}


def test_case_differing_npm_names_stay_two_packages():
    """Control against widening the fold set: npm identity is case-sensitive by type definition.

    The 2015 rule that a new package name must not contain uppercase letters is about *new*
    names; mixed-case packages predating it were grandfathered in, which is why purl marks the
    npm type case-sensitive. This is the control most worth having, because every npm purl in the
    largest local model is already lowercase — no real-model measurement can catch this
    regression, so only this fixture stands between the fold set and a silent identity merge.
    """
    npm_purls = {component['purl'] for component in get_emission_components()
                 if component['purl'].startswith('pkg:npm/')}
    assert npm_purls == {'pkg:npm/JSONStream@1.3.5', 'pkg:npm/jsonstream@1.3.5'}


def test_a_binary_that_is_its_own_referencing_file_is_not_a_nuget_package():
    """An external whose name is the stem of the file referencing it IS that committed binary.

    pkg:nuget/<name> asserts a public NuGet package that does not exist — a
    dependency-confusion-shaped false positive for any consumer resolving purls. generic is the
    purl type with no default package repository, which is exactly what a committed binary is.
    """
    component = emission_component('softagram_windows-x64_1_93_1')
    assert component['purl'] == 'pkg:generic/softagram_windows-x64_1_93_1@1.95.0'
    assert purl_type_resolution(component) == \
        'referencing file is the binary itself: softagram_windows-x64_1_93_1.exe'


def test_the_self_reference_provenance_is_sorted_and_deduplicated():
    """Several referencing files must yield one deterministic citation, not a traversal-order one.

    The fixture references TwoRefBinary from two identically named .exe files in different
    directories and from one .dll. Citing names rather than paths collapses the two .exe rows to a
    single entry — the real acceptance data has exactly this shape, a binary referenced from both
    an installer output and an update directory — while the .dll stays a second entry. Sorting is
    what makes the pair's order independent of which association the walk reached first, which is
    the same byte-stability guarantee infer_pkgtype_from_referencing_files already provides.
    """
    component = emission_component('TwoRefBinary')
    assert component['purl'] == 'pkg:generic/TwoRefBinary@2.0'
    assert purl_type_resolution(component) == \
        'referencing file is the binary itself: TwoRefBinary.dll,TwoRefBinary.exe'


def test_folding_uses_ascii_lowercasing_not_unicode_casefolding():
    """Defends the documented choice of .lower() over .casefold() with the pair that separates them.

    'ß'.casefold() is 'ss', so casefolding would declare Straße and STRASSE the same NuGet package
    and drop one of them. .lower() leaves 'ß' alone and keeps them distinct. Every ASCII fixture
    passes under either function, so only a non-ASCII pair can fail if the two are swapped.
    """
    assert 'Straße'.casefold() == 'strasse'.casefold()  # the premise: casefold would merge these
    assert sbom_cyclonedx_generator.dedup_key('pkg:nuget/Straße@1.0') != \
        sbom_cyclonedx_generator.dedup_key('pkg:nuget/STRASSE@1.0')


def test_a_version_that_merely_contains_a_url_keeps_its_version():
    """Defends the URL rule's anchoring: it matches a version that IS a URL, not one holding one.

    The negative assertion uses search, not match, deliberately. re.match anchors at position 0 by
    definition, so a match-based assertion here would hold for any pattern that fails at position 0
    — including one with the '^' deleted — and would be true for the wrong reason, closing nothing.
    search is the only call that can distinguish an anchored pattern from an unanchored one, so
    this is the assertion that fails if the '^' is dropped and a partly known version such as
    '1.0+https://…' silently loses its version.

    Written against the pattern directly because no stored model carries such a version.
    """
    assert sbom_cyclonedx_generator.URL_SHAPED_VERSION.match('https://example.com/x.git')
    assert not sbom_cyclonedx_generator.URL_SHAPED_VERSION.search('1.0+https://example.com/x.git')


def test_a_package_referenced_by_a_differently_named_file_keeps_its_inferred_type():
    """Anti-vacuity for the rule above: a real package reference never shares the file's stem.

    Ionic.Zip is referenced from Consumer.dll, the ordinary shape, and must keep both its
    inferred type and the provenance that says the type was inferred.
    """
    component = emission_component('Ionic.Zip')
    assert component['purl'] == 'pkg:nuget/Ionic.Zip@1.9.1.8'
    assert purl_type_resolution(component) == 'inferred from referencing file extension: dll'


def test_the_emission_fixture_yields_fourteen_distinct_components():
    """Anti-vacuity for the fixture, and the collapse guard for the two versionless rules.

    Fourteen, not fifteen: the two NuGet spellings are one package, while the two npm spellings
    and the two Maven artifacts are four separate ones. A lookup above raises when an element
    vanishes, but an element added, or two bom-refs collapsed into one when a version is omitted,
    would otherwise go unnoticed — and omitting a version is exactly what two of these rules do.
    """
    components = get_emission_components()
    assert len(components) == 14
    assert len({component['bom-ref'] for component in components}) == 14


# CycloneDX defines properties[].value as a string in every spec version the generator can emit
# (verified against the 1.4, 1.5, 1.6 and 1.7 schemas, all of which declare {"type": "string"};
# 1.6 and 1.7 additionally set additionalProperties false on the property object, where 1.4 and
# 1.5 leave it open). A number there is not a lenient-consumer problem: a validating consumer
# rejects the entire document, so one mistyped property discards the whole SBOM. The selectable
# version does not soften this — the type is the same at the oldest version offered, so the rule
# holds whichever one a caller picks.


def model_with_indirect_exposure():
    """A package that is used directly AND reached through another package.

    That double role is what makes indirectExposureCount reachable in the DEFAULT export
    rather than only under the opt-in closure, so the fixture deliberately builds it: app.js
    imports lodash itself, while util.js reaches the same lodash through express.
    """
    model = SGraph(SElement(None, ''))
    app = model.createOrGetElementFromPath('/Org/repoA/src/app.js')
    util = model.createOrGetElementFromPath('/Org/repoA/src/util.js')
    express = model.createOrGetElementFromPath(
        '/Org/External/NPM/express/express of version 4.18.2')
    lodash = model.createOrGetElementFromPath(
        '/Org/External/NPM/lodash/lodash of version 4.17.21')
    express.attrs['version'] = '4.18.2'
    lodash.attrs['version'] = '4.17.21'

    for source, target, deptype in ((app, lodash, 'use'),
                                    (util, express, 'use'),
                                    (express, lodash, 'packagejson')):
        ea = SElementAssociation(source, target, deptype)
        ea.initElems()
    return model


def every_property_value(documents):
    """Yield (document name, component name, property name, value) across whole documents."""
    for doc in documents:
        doc_name = doc['metadata']['component']['name']
        for component in doc.get('components', []):
            for prop in component.get('properties', []):
                yield doc_name, component.get('name'), prop['name'], prop['value']


def test_indirect_exposure_count_is_a_string():
    """The count is published as a string, because CycloneDX has no numeric property value."""
    result = generate_multi_from_sgraph(model_with_indirect_exposure(), level=2)

    lodash = next(c for c in result[0]['components'] if c['name'] == 'lodash')
    count = find_property(lodash, 'indirectExposureCount')

    assert count == '1'
    assert isinstance(count, str)


def test_indirect_exposure_count_is_a_string_in_closure_mode_too():
    result = generate_multi_from_sgraph(model_with_indirect_exposure(), level=2,
                                        transitive_externals=True)

    lodash = next(c for c in result[0]['components'] if c['name'] == 'lodash')

    assert find_property(lodash, 'indirectExposureCount') == '1'


def test_the_count_still_carries_the_figure_it_always_did():
    """Stringifying must not cost the exposure figure - that is the valuable part.

    Two separate internal files reach lodash only through express, so the count is 2 and
    distinguishes this model from the single-exposure one above.
    """
    model = model_with_indirect_exposure()
    second = model.createOrGetElementFromPath('/Org/repoA/src/handler.js')
    express = model.createOrGetElementFromPath(
        '/Org/External/NPM/express/express of version 4.18.2')
    ea = SElementAssociation(second, express, 'use')
    ea.initElems()

    result = generate_multi_from_sgraph(model, level=2)
    lodash = next(c for c in result[0]['components'] if c['name'] == 'lodash')

    assert find_property(lodash, 'indirectExposureCount') == '2'


@pytest.mark.parametrize('kwargs', [
    {},
    {'transitive': True},
    {'transitive_externals': True},
    {'transitive': True, 'transitive_externals': True},
])
def test_no_property_value_is_ever_a_non_string(kwargs):
    """The invariant, across whole documents rather than one field.

    Pinning only indirectExposureCount would leave the next property free to repeat the
    mistake; this fails for any emission site that forgets to stringify.
    """
    documents = generate_multi_from_sgraph(model_with_indirect_exposure(), level=2, **kwargs)
    documents += generate_multi_from_sgraph(
        get_model_and_model_api(MULTI_MODEL)[0], level=3, **kwargs)

    offenders = [(doc, comp, name, type(value).__name__)
                 for doc, comp, name, value in every_property_value(documents)
                 if not isinstance(value, str)]

    assert offenders == []


# --- BOM admission tests ---
#
# What makes an external element a component at all. A licence, a hash and a URL are facts ABOUT
# a package; none of them is evidence that the element carrying it IS one. The distinction is
# invisible while no producer stamps those attributes on External elements — measured at zero on
# both the stored corpus and the current analyzer set — and becomes a silent emission the day one
# does, which is why it is pinned here rather than left to the first producer change to discover.


def admission_components(model):
    """The 3rd-party components of the legacy single-document mode.

    The legacy walk descends into children, so it reaches every element under External including
    a finding stored beneath a versioned package. That is what makes admission the only guard in
    these tests: the association-following walk used by the multi modes would keep a finding out
    by traversal alone, and a test written against it would pass while proving nothing.
    """
    return sbom_cyclonedx_generator.generate_from_sgraph(model)['components']


def referenced_external(model, path):
    """An external at path, referenced from the estate's own code so nothing else excludes it."""
    app = model.createOrGetElementFromPath('/Org/repoA/src/app.js')
    elem = model.createOrGetElementFromPath(path)
    SElementAssociation(app, elem, 'packagejson').initElems()
    return elem


def test_a_licence_alone_does_not_make_an_external_a_component():
    """A licence is a fact about a package, not evidence that something is one.

    The element here is what an analyzer records when it learns a licence but never resolves a
    version. Admitting it publishes 'pkg:npm/lodash' — an identifier with no version — for an
    element the model never claimed was an installed dependency.
    """
    model = SGraph(SElement(None, ''))
    elem = referenced_external(model, '/Org/External/NPM/lodash')
    elem.attrs['license'] = 'MIT'

    assert [component['name'] for component in admission_components(model)] == []


def test_a_licensed_versioned_external_still_carries_its_licence():
    """Anti-vacuity: the guard removes an admission rule, not licence reporting.

    Nothing else in this suite asserts the 'licenses' field at all, so without this test a change
    that silently stopped emitting licences would stay green. The element is admitted on its
    version, exactly as before, and its licence still reaches the document.
    """
    model = SGraph(SElement(None, ''))
    elem = referenced_external(model, '/Org/External/NPM/lodash/lodash of version 4.17.21')
    elem.attrs['version'] = '4.17.21'
    elem.attrs['license'] = 'MIT'

    components = admission_components(model)

    assert len(components) == 1
    assert components[0]['licenses'] == [{
        'license': {
            'id': 'MIT',
            'url': 'https://spdx.org/licenses/MIT.html'
        }
    }]


def test_a_licence_on_a_code_symbol_emits_nothing():
    """The shape a producer stamping licences on the import graph would trip.

    'Response' is a class reached through a 'ref' edge, not a package. Admitting it does not
    merely publish a versionless component: the purl type falls back to 'generic', so the
    document asserts a generic-ecosystem package named after a Python class.
    """
    model = SGraph(SElement(None, ''))
    app = model.createOrGetElementFromPath('/Org/repoA/src/app.py')
    symbol = model.createOrGetElementFromPath('/Org/External/Python/starlette/responses/Response')
    symbol.attrs['license'] = 'BSD-3-Clause'
    SElementAssociation(app, symbol, 'ref').initElems()

    assert [component['purl'] for component in admission_components(model)] == []


def test_a_hash_alone_does_not_admit_either():
    """The same rule stated for the attribute a lockfile producer reaches for next.

    An integrity hash identifies a file's contents, not a package. Neither name is read by
    admission today, and this fails if either becomes a way back into the hole the licence
    disjunct opened.
    """
    model = SGraph(SElement(None, ''))
    elem = referenced_external(model, '/Org/External/NPM/lodash')
    elem.attrs['hash'] = 'sha512-0000'
    elem.attrs['integrity'] = 'sha512-0000'

    assert [component['name'] for component in admission_components(model)] == []


def test_a_licence_on_a_finding_node_emits_nothing():
    """One guard, two hazards: the same rule keeps advisories out of the inventory.

    Findings are stored as children of a versioned external, so the legacy walk reaches them. The
    attributes here are the ones the npm audit analyzer actually writes, and none of them admits:
    'package_version' is not the 'version' key admission reads. The licence is therefore the only
    thing that could let this node through, which is what makes the test discriminate — drop it
    and the assertion holds for a reason that has nothing to do with the guard.

    Emitted, this node becomes a component named after the advisory itself, and an estate that
    depends on one package would report two.
    """
    model = SGraph(SElement(None, ''))
    versioned = referenced_external(model, '/Org/External/NPM/pkg2/pkg2 of version 2.0.0')
    versioned.attrs['version'] = '2.0.0'
    finding = SElement(versioned, 'pkg2_GHSA-0000-0000-0000')
    finding.setType('vulnerability')
    finding.attrs['package_name'] = 'pkg2'
    finding.attrs['package_version'] = '2.0.0'
    finding.attrs['range'] = '<2.1.0'
    finding.attrs['license'] = 'MIT'

    assert [component['name'] for component in admission_components(model)] == ['pkg2']


# --- npm install-path identity repair tests (A1) ---
#
# The npm lockfile analyzers record a nested install as ONE element whose name is the whole
# install path: 'wrap-ansi-cjs/strip-ansi'. Spliced into a purl unchanged that asserts a package
# published nowhere. The leading segments are the dependency chain that REQUIRED the package and
# the tail is the package itself, so the repair keeps the tail.
#
# Phase 0 refuted the opposite reading (repair to the leading @scope/pkg) on the version: across
# the 21 deep-scoped ids the version matched the prefix package in 0 cases and the leaf in 6.
# Repairing to the prefix would have kept the leaf's version against the prefix's name and
# fabricated a pair neither reading asserts.


def slash_named_external(model, root, raw_name, version=None, deptype='packagejson'):
    """An external whose entire id lives in ONE element name, separators included.

    SElement normalises '/' to '__slash__' on construction and clean_name decodes it back, so an
    install path is a single element with a slash-bearing name rather than a chain of elements.
    Built with SElement deliberately: createOrGetElementFromPath would split the id into a tree,
    the cleaned name would hold no slash, and the repair would never see the shape it exists for.
    """
    app = model.createOrGetElementFromPath('/Org/repoA/src/app.js')
    parent = model.createOrGetElementFromPath(f'/Org/External/{root}')
    elem = SElement(parent, raw_name)
    if version is not None:
        elem.attrs['version'] = version
    SElementAssociation(app, elem, deptype).initElems()
    return elem


def repair_components(model):
    """The 3rd-party components of the legacy single-document mode, in emission order."""
    return sbom_cyclonedx_generator.generate_from_sgraph(model)['components']


def one_component(root, raw_name, version):
    """Emit a single slash-named external and return the one component describing it."""
    model = SGraph(SElement(None, ''))
    slash_named_external(model, root, raw_name, version)
    components = repair_components(model)
    assert len(components) == 1, components
    return components[0]


def test_the_nested_install_path_identity_is_a_recorded_migration():
    """Records a published identifier that CHANGED, rather than pinning behaviour.

    Before this phase the same element emitted 'pkg:npm/wrap-ansi-cjs/strip-ansi@6.0.1'; it now
    emits 'pkg:npm/strip-ansi@6.0.1'. 87 refs across the 16 stored models move this way. The test
    was written asserting the old value and updated in the commit that landed the repair, so a
    consumer-visible migration appears in the diff of a test rather than only in a release note.

    It pins no behaviour of its own — the tests below do that — and it is the one place to look
    when asking what a resolver that cached the old identifier will no longer find.
    """
    assert one_component('NPM', 'wrap-ansi-cjs/strip-ansi',
                         '6.0.1')['purl'] == 'pkg:npm/strip-ansi@6.0.1'


def test_an_install_path_resolves_to_its_leaf_package():
    """'wrap-ansi-cjs/strip-ansi' is strip-ansi installed under wrap-ansi-cjs, not a package."""
    assert one_component('NPM', 'wrap-ansi-cjs/strip-ansi',
                         '6.0.1')['purl'] == 'pkg:npm/strip-ansi@6.0.1'


def test_a_deep_scoped_install_path_resolves_to_its_leaf():
    """A leading @scope belongs to the REQUIRER, so it does not move identity to the prefix.

    Phase 0 measured this one directly: the versions carried by these ids match the leaf package
    and never the scoped prefix.
    """
    assert one_component('NPM', '@eslint/eslintrc/minimatch',
                         '3.1.5')['purl'] == 'pkg:npm/minimatch@3.1.5'


def test_a_scoped_tail_keeps_both_of_its_segments():
    """When the tail is itself scoped, the package is the last TWO segments.

    This id settles the rule without reference to any version measurement: an import subpath
    cannot contain a second '@scope/' segment, so the string can only be an install path, and the
    installed package can only be '@rollup/pluginutils'.
    """
    component = one_component('NPM', '@rollup/plugin-node-resolve/@rollup/pluginutils', '5.3.0')
    assert component['purl'] == 'pkg:npm/%40rollup/pluginutils@5.3.0'


def test_a_deep_scoped_id_is_not_repaired_to_its_scope():
    """Tombstone for the reading Phase 0 refuted, kept because the refutation cost a full cycle.

    The original rule repaired '@eslint/eslintrc/minimatch' to its scoped prefix. The
    discriminator first used — 'is the prefix package emitted elsewhere?' — answered yes 21 times
    out of 21 and confirmed nothing, because a nested install path's prefix is itself a real
    installed package under BOTH readings. The version is what discriminates, and it matched the
    prefix in 0 of 21 cases. Asserting the positive value as well as the refuted one, because a
    bare inequality also passes for a third value that is wrong in some other way.
    """
    purl = one_component('NPM', '@eslint/eslintrc/minimatch', '3.1.5')['purl']
    assert purl == 'pkg:npm/minimatch@3.1.5'
    assert purl != 'pkg:npm/@eslint/eslintrc@3.1.5'


def test_a_canonical_scoped_name_is_left_alone():
    """'@babel/core' is a package name, not an install path: two segments and a leading @."""
    assert one_component('NPM', '@babel/core', '7.24.0')['purl'] == 'pkg:npm/%40babel/core@7.24.0'


def test_a_plain_package_name_is_left_alone():
    """No separator, nothing to repair — the overwhelming majority of npm ids."""
    assert one_component('NPM', 'lodash', '4.17.21')['purl'] == 'pkg:npm/lodash@4.17.21'


def test_a_golang_module_path_keeps_every_segment():
    """The control that matters most in this phase, and the only guard that can catch it.

    A golang module path legitimately contains separators — the purl in this module's own
    docstring is pkg:golang/github.com/0xAX/notificator — so a repair applied on the strength of
    a slash alone would destroy every golang identity. The 16 stored models contain ZERO
    slash-bearing external names outside npm, so a corpus sweep cannot detect that regression:
    no non-npm purl would change because none has a separator to lose. This test is the guard.

    Synthetic BY NECESSITY, not by convenience: no fixture drawn from a stored model can reach
    this shape, because no model holds one. The module already reasons this way where the oci
    purl type is asserted directly on cyclonedx_component_type rather than through a fixture, on
    the stated grounds that no model can reach a purl the generator never builds and a fixture
    that appeared to would be testing a hand-written string rather than this code.
    """
    component = one_component('Go', 'github.com/0xAX/notificator', '1.0.0')
    assert component['purl'] == 'pkg:golang/github.com/0xAX/notificator@1.0.0'


def test_a_pypi_name_containing_a_slash_is_not_repaired():
    """The repair is npm-only, asserted on a name that would otherwise match the shape.

    Written as ONE element named 'zope/interface' rather than as nested elements: nested elements
    leave no slash in the cleaned name, the predicate would fail for a reason unrelated to the
    ecosystem check, and the test would pass without exercising it.
    """
    assert one_component('PIP', 'zope/interface',
                         '5.4.0')['purl'] == 'pkg:pypi/zope/interface@5.4.0'


def test_a_versionless_npm_install_path_is_never_repaired():
    """The only guard on the repair itself, on a real unversioned install path.

    Not the only guard on emission: valid_for_bom blocks two further routes today, the
    parent_version-only route and the 'versions' plural route, both of which compute a repair
    that then emits nothing. That makes reason 3 below more important rather than less — the
    repair must be gated where it happens, not where the current call path happens to stop it.

    'wrap-ansi-cjs/strip-ansi' with no version is one of 363 unversioned slash-bearing npm ids
    in the 16 stored models — the same id also occurs versioned elsewhere, which is why it is the
    honest input here: the rule genuinely matches it, and only the gate stops the repair.

    Three reasons the gate exists, none of them "an unversioned id is an import subpath":
    1. Evidence. The tail-is-the-package rule was established by matching each element's version
       against the leaf's and against the prefix's, 6/21 versus 0/21. An unversioned element
       carries no such evidence, so a repair there asserts what cannot be falsified.
    2. Benefit. An unversioned element emits no component at all, so repairing its name can
       improve no purl. The gate is pure downside protection.
    3. Forward-looking, and why it is an explicit gate rather than an accident of the call path.
       If admission ever widens — a licence attribute, a stamped identity, any future criterion —
       an ungated repair would emit versionless rows for packages named only by a requirer chain,
       creating components from nothing. That is what invariant 2 forbids, enforced here.

    Checked two ways because neither alone is honest: a truly versionless element is not admitted
    to the BOM, so a document-level assertion about it would pass for reasons unrelated to this
    gate, while the empty-version element is the one shape carrying a versionless id all the way
    through emission.
    """
    # The rule WOULD repair this name. Without this line the assertions below could pass because
    # the input never matched, which is the failure mode this whole phase is about.
    assert sbom_cyclonedx_generator.repair_npm_package_name('wrap-ansi-cjs/strip-ansi') == (
        'strip-ansi', 'install-path')

    model = SGraph(SElement(None, ''))
    versionless = slash_named_external(model, 'NPM', 'wrap-ansi-cjs/strip-ansi')
    purl, repaired_name, _ = sbom_cyclonedx_generator.resolved_purl(versionless, '')
    assert purl == 'pkg:npm/wrap-ansi-cjs/strip-ansi'
    assert repaired_name is None

    empty_version = SGraph(SElement(None, ''))
    slash_named_external(empty_version, 'NPM', 'wrap-ansi-cjs/strip-ansi', '')
    component = repair_components(empty_version)[0]
    assert component['purl'] == 'pkg:npm/wrap-ansi-cjs/strip-ansi'
    assert component['name'] == 'wrap-ansi-cjs/strip-ansi'


def test_a_repaired_identity_records_its_provenance():
    """A rewritten name must disclose what the model said, since the purl no longer carries it.

    The property holds the original NAME rather than the original purl: the old purl is
    reconstructible from name, type and version, and republishing a pkg:npm/... string invites a
    consumer to resolve an identifier whose whole problem is that it denotes nothing.
    """
    component = one_component('NPM', 'wrap-ansi-cjs/strip-ansi', '6.0.1')
    assert find_property(component, 'packageNameResolution') == ('repaired from install path: '
                                                                 'wrap-ansi-cjs/strip-ansi')


def test_a_repaired_component_takes_the_repaired_name():
    """The name field follows the purl.

    A repaired purl beside the raw name would have the document name a package it does not
    identify, and the name is built outside resolved_purl, so it does not follow by itself.
    """
    assert one_component('NPM', 'wrap-ansi-cjs/strip-ansi', '6.0.1')['name'] == 'strip-ansi'


def test_a_repair_that_collides_with_an_emitted_package_merges_into_one_row():
    """Repairing to an identity already emitted folds the two rows, it does not duplicate them.

    dedup_key keys on the bom-ref, so the repaired ref meets the existing one and one row
    survives. This is why the phase pre-registers a DOCUMENT count that falls while the element
    count does not move.
    """
    model = SGraph(SElement(None, ''))
    slash_named_external(model, 'NPM', 'strip-ansi', '6.0.1')
    slash_named_external(model, 'NPM', 'wrap-ansi-cjs/strip-ansi', '6.0.1')

    components = repair_components(model)

    assert [component['purl'] for component in components] == ['pkg:npm/strip-ansi@6.0.1']


def test_the_repair_rule_as_a_unit_table():
    """The rule as a pure function, including the shapes no stored model happens to contain.

    'a/b/' is refused rather than normalised: an empty tail is a malformity the repair cannot
    reason about, and inventing a reading for it is the defect this item removes. A doubled
    separator with a usable tail is NOT refused — 'a//b' still installs 'b'.
    """
    repair = sbom_cyclonedx_generator.repair_npm_package_name
    assert repair('wrap-ansi-cjs/strip-ansi') == ('strip-ansi', 'install-path')
    assert repair('@scope/pkg/deep/path') == ('path', 'install-path')
    assert repair('a/@scope/b') == ('@scope/b', 'install-path-scoped-leaf')
    assert repair('a//b') == ('b', 'install-path')
    assert repair('a/b/') is None
    assert repair('a/@scope/') is None
    assert repair('@a/b') is None
    assert repair('@x') is None
    assert repair('lodash') is None
    assert repair('') is None


# --- merge evidence tests (P2b) ---
#
# When two elements describe one package, dedup keeps the component it met first and discards the
# other. The survivor is fixed by document order, which is a traversal artefact, so any rule
# phrased as "the correct row survives" is unsound in both directions: the corpus produced the
# repaired element as survivor, a code-built reproduction produced the plain one. The component
# must therefore be the UNION of what both elements know.
#
# The count forces the plumbing. indirectExposurePaths is truncated to four segments, so the raw
# elements cannot be recovered from the rendered string and no string-level merge can compute a
# correct count. Components carry _evidence while they are collected and the render boundary
# re-renders the three properties from it.


def folding_pair_model(indirect_for_install_path=False):
    """Two npm externals that emit one component: a package and an install path ending in it.

    a.js reaches the package by its own name, b.js through the install path, so each element
    holds a source reference the other lacks and the union is observable. With
    indirect_for_install_path the install path also carries indirect exposure the plain element
    has no route to, which is the shape that lost indirectExposureCount on the corpus.
    """
    model = SGraph(SElement(None, ''))
    a_file = model.createOrGetElementFromPath('/Org/repoA/src/a.js')
    b_file = model.createOrGetElementFromPath('/Org/repoA/src/b.js')
    npm = model.createOrGetElementFromPath('/Org/External/NPM')
    plain = SElement(npm, 'strip-ansi')
    plain.attrs['version'] = '6.0.1'
    install_path = SElement(npm, 'wrap-ansi-cjs/strip-ansi')
    install_path.attrs['version'] = '6.0.1'
    SElementAssociation(a_file, plain, 'packagejson').initElems()
    SElementAssociation(b_file, install_path, 'packagejson').initElems()
    if indirect_for_install_path:
        util = model.createOrGetElementFromPath('/Org/repoA/src/util.js')
        express = SElement(npm, 'express')
        express.attrs['version'] = '4.18.2'
        SElementAssociation(util, express, 'packagejson').initElems()
        SElementAssociation(express, install_path, 'packagejson').initElems()
    return model


def nuget_case_fold_model():
    """Two spellings of one case-insensitive NuGet id, each referenced by a different file.

    Code-built rather than fixture-based for two reasons: the tracked emission fixture's NLog and
    nlog elements carry no source references at all, so a test written against it would pass
    before and after while proving nothing; and
    test_the_emission_fixture_yields_fourteen_distinct_components pins that fixture's component
    count, which makes edits to it load-bearing for tests unrelated to this one.
    """
    model = SGraph(SElement(None, ''))
    a_file = model.createOrGetElementFromPath('/Org/repoA/src/a.cs')
    b_file = model.createOrGetElementFromPath('/Org/repoB/src/b.cs')
    assemblies = model.createOrGetElementFromPath('/Org/External/Assemblies')
    upper = SElement(assemblies, 'NLog')
    upper.attrs['version'] = '5.0.0'
    lower = SElement(assemblies, 'nlog')
    lower.attrs['version'] = '5.0.0'
    SElementAssociation(a_file, upper, 'assembly_ref').initElems()
    SElementAssociation(b_file, lower, 'assembly_ref').initElems()
    # a.cs -> b.cs is what pulls repoB's subtree into repoA's transitive document. Without it the
    # two spellings never meet and the cross-subtree fold this model exists for never happens.
    SElementAssociation(a_file, b_file, 'use').initElems()
    return model


def only_component(model):
    """The one 3rd-party component of the legacy document, failing if there is not exactly one."""
    components = sbom_cyclonedx_generator.generate_from_sgraph(model)['components']
    assert len(components) == 1, [c['purl'] for c in components]
    return components[0]


def test_a_merge_keeps_the_richer_exposure_data():
    """The defect this phase exists to remove: a fold that discards the duplicate's evidence.

    Measured on the corpus before the fix, seven of sixteen affected rows lost evidence, and on
    two of them sourceCodeReferences survived as a NAME while its VALUE was emptied — 223 and 458
    characters replaced by nothing. A check on property names alone would have called that a pass,
    which is why this asserts values.
    """
    components = sbom_cyclonedx_generator.generate_from_sgraph(
        folding_pair_model(indirect_for_install_path=True))['components']
    component = [c for c in components if c['purl'] == 'pkg:npm/strip-ansi@6.0.1'][0]

    assert find_property(component,
                         'sourceCodeReferences') == '/Org/repoA/src/a.js;/Org/repoA/src/b.js'
    assert find_property(component, 'indirectExposureCount') == '1'
    assert find_property(component, 'indirectExposurePaths') == '/Org/repoA/src'


def test_a_merge_unions_source_code_references():
    """Both elements' direct references reach the surviving row, sorted and deduplicated.

    The single-element path already deduplicates direct references by element, so the union
    reproduces that rule across elements rather than inventing one.
    """
    component = only_component(folding_pair_model())

    assert find_property(component,
                         'sourceCodeReferences') == '/Org/repoA/src/a.js;/Org/repoA/src/b.js'


def test_the_indirect_count_counts_distinct_exposed_elements_after_a_merge():
    """The count is the cardinality of the union, never the sum — the anti-sum test.

    produce_source_code_references builds indirect exposure as a set of ELEMENTS, so the number
    means distinct exposed elements. Summing two elements' counts double-counts every element
    exposed to both, and that overlap is largest exactly when a merge is most likely: the two
    rows describe one package, so the code reaching them is usually the same code.
    """
    model = SGraph(SElement(None, ''))
    util = model.createOrGetElementFromPath('/Org/repoA/src/util.js')
    npm = model.createOrGetElementFromPath('/Org/External/NPM')
    plain = SElement(npm, 'strip-ansi')
    plain.attrs['version'] = '6.0.1'
    install_path = SElement(npm, 'wrap-ansi-cjs/strip-ansi')
    install_path.attrs['version'] = '6.0.1'
    # util.js is exposed to BOTH elements, so a sum would count it twice; other.js reaches only
    # the install path, so the union is strictly larger than either element's own evidence and
    # the test fails both on a survivor-only implementation and on a summing one.
    other = model.createOrGetElementFromPath('/Org/repoA/src/other.js')
    for name, target in (('express', plain), ('chalk', install_path)):
        package = SElement(npm, name)
        package.attrs['version'] = '1.0.0'
        SElementAssociation(util, package, 'packagejson').initElems()
        SElementAssociation(package, target, 'packagejson').initElems()
    only_install_path = SElement(npm, 'only-install-path')
    only_install_path.attrs['version'] = '1.0.0'
    SElementAssociation(other, only_install_path, 'packagejson').initElems()
    SElementAssociation(only_install_path, install_path, 'packagejson').initElems()

    component = [
        c for c in sbom_cyclonedx_generator.generate_from_sgraph(model)['components']
        if c['purl'] == 'pkg:npm/strip-ansi@6.0.1'
    ][0]

    assert find_property(component, 'indirectExposureCount') == '2'


def test_a_merge_does_not_deduplicate_abstracted_exposure_paths():
    """The abstraction repeats a prefix reached twice, because the single-element path does.

    indirectExposurePaths abstracts AFTER deduplicating elements and does not deduplicate the
    abstracted strings, so two distinct exposed elements sharing a three-component prefix appear
    twice. Pinned against a plausible tidy-up: making the merge deduplicate here would make the
    merged row disagree with every unmerged one.
    """
    model = SGraph(SElement(None, ''))
    npm = model.createOrGetElementFromPath('/Org/External/NPM')
    plain = SElement(npm, 'strip-ansi')
    plain.attrs['version'] = '6.0.1'
    install_path = SElement(npm, 'wrap-ansi-cjs/strip-ansi')
    install_path.attrs['version'] = '6.0.1'
    for leaf, target in (('one.js', plain), ('two.js', install_path)):
        internal = model.createOrGetElementFromPath(f'/Org/repoA/src/{leaf}')
        package = SElement(npm, f'via-{leaf}')
        package.attrs['version'] = '1.0.0'
        SElementAssociation(internal, package, 'packagejson').initElems()
        SElementAssociation(package, target, 'packagejson').initElems()

    component = [
        c for c in sbom_cyclonedx_generator.generate_from_sgraph(model)['components']
        if c['purl'] == 'pkg:npm/strip-ansi@6.0.1'
    ][0]

    assert find_property(component, 'indirectExposureCount') == '2'
    assert find_property(component, 'indirectExposurePaths') == '/Org/repoA/src;/Org/repoA/src'


def test_unmerged_rows_are_byte_identical_after_the_render_moves():
    """The whole risk of moving the render: a row nothing merged must not shift by one byte.

    Every property, in order, with its exact value — not a subset check, because the failure this
    guards against is a re-render that reorders or reformats rather than one that drops a field.
    """
    model = model_with_indirect_exposure()

    components = sbom_cyclonedx_generator.generate_from_sgraph(model)['components']
    lodash = [c for c in components if c['name'] == 'lodash'][0]

    assert lodash['properties'] == [
        {
            'name': 'sourceCodeReferences',
            'value': '/Org/repoA/src/app.js'
        },
        {
            'name': 'indirectExposureCount',
            'value': '1'
        },
        {
            'name': 'indirectExposurePaths',
            'value': '/Org/repoA/src'
        },
    ]


@pytest.mark.parametrize('generate', [
    lambda model: [sbom_cyclonedx_generator.generate_from_sgraph(model)],
    lambda model: generate_multi_from_sgraph(model, level=2),
    lambda model: [generate_for_element_from_sgraph(model, '/Org/repoA')],
])
def test_no_emitted_component_carries_an_internal_key(generate):
    """_evidence is collection-time scaffolding and must never reach a document.

    Parametrised over every public generator, which under one-site placement is the executable
    form of the completeness argument: finalize sits at the render boundary, so a document that
    escaped it would have to escape rendering itself. The existing whole-document invariant walks
    properties only and cannot see a stray top-level key.
    """
    for document in generate(folding_pair_model(indirect_for_install_path=True)):
        for component in document['components']:
            internal = [key for key in component if key.startswith('_')]
            assert internal == [], (component.get('purl'), internal)


def test_a_merge_records_the_identifiers_it_superseded():
    """A consumer holding the folded-away identifier needs the map to the surviving one."""
    component = only_component(nuget_case_fold_model())

    assert component['purl'] == 'pkg:nuget/NLog@5.0.0'
    assert find_property(component, 'supersededIdentifiers') == 'pkg:nuget/nlog@5.0.0'


def test_a_merge_of_identical_refs_records_no_supersession():
    """Anti-vacuity: a repaired install path merges into the SAME identifier, superseding nothing.

    Without this the property could be emitted on every merge and still pass the test above, which
    would publish a migration map naming the identifier it maps to.
    """
    component = only_component(folding_pair_model())

    assert component['purl'] == 'pkg:npm/strip-ansi@6.0.1'
    assert find_property(component, 'supersededIdentifiers') is None


def test_repair_provenance_survives_only_when_every_merged_element_was_repaired():
    """packageNameResolution asserts how THIS row's identity was derived, so a merge can retract it.

    Kept only when every merged element was repaired; otherwise the row would claim its identity
    came from a repair while another element published the same identity outright.
    """
    mixed = only_component(folding_pair_model())
    assert find_property(mixed, 'packageNameResolution') is None

    model = SGraph(SElement(None, ''))
    npm = model.createOrGetElementFromPath('/Org/External/NPM')
    for requirer in ('wrap-ansi-cjs', 'string-width-cjs'):
        internal = model.createOrGetElementFromPath(f'/Org/repoA/src/{requirer}.js')
        element = SElement(npm, f'{requirer}/strip-ansi')
        element.attrs['version'] = '6.0.1'
        SElementAssociation(internal, element, 'packagejson').initElems()

    both_repaired = only_component(model)
    assert both_repaired['purl'] == 'pkg:npm/strip-ansi@6.0.1'
    assert find_property(both_repaired, 'packageNameResolution') is not None


@pytest.mark.parametrize('label,build,generate', [
    ('legacy', folding_pair_model,
     lambda model: [sbom_cyclonedx_generator.generate_from_sgraph(model)]),
    ('level', folding_pair_model, lambda model: generate_multi_from_sgraph(model, level=2)),
    ('transitive', nuget_case_fold_model,
     lambda model: generate_multi_from_sgraph(model, level=2, transitive=True)),
])
def test_every_fold_site_merges(label, build, generate):
    """All three fold sites, because a fix at one leaves the other two losing data silently.

    Three independent implementations of "drop the duplicate" grew separately and only one ever
    noticed it was discarding information. The transitive case uses the two-repository model
    because that site folds ACROSS subtrees — within one subtree the earlier site has already
    folded, and the parametrisation would test the same code path three times.
    """
    merged = [
        component for document in generate(build()) for component in document['components']
        if component.get('purl') in ('pkg:npm/strip-ansi@6.0.1', 'pkg:nuget/NLog@5.0.0')
    ]

    assert merged, label
    for component in merged:
        references = find_property(component, 'sourceCodeReferences') or ''
        assert len(references.split(';')) == 2, (label, references)


def test_a_nuget_case_fold_keeps_both_elements_evidence():
    """The instance of this defect that was already shipping before P2 made it common.

    P2 did not introduce evidence loss; it made it measurable. This fold has been discarding one
    spelling's references for as long as the case fold has existed, and it is the reason the fix
    is a general primitive rather than a repair-specific patch.
    """
    component = only_component(nuget_case_fold_model())

    assert find_property(component,
                         'sourceCodeReferences') == '/Org/repoA/src/a.cs;/Org/repoB/src/b.cs'


def test_a_duplicate_carries_a_depth_to_compare_at_every_fold_site():
    """The component is complete before the fold decides, so the primitive always has both sides.

    Previously the duplicate was discarded BEFORE dependencyDepth was attached, so a depth merge
    received nothing to compare and silently did nothing. Legacy mode is absent from this test on
    purpose: it publishes no depth at all, which
    test_dependency_depth_is_absent_from_a_default_mode_bom pins.
    """
    documents = generate_multi_from_sgraph(nuget_case_fold_model(), level=2, transitive=True,
                                           transitive_externals=True)
    for document in documents:
        for component in document['components']:
            if component.get('purl') == 'pkg:nuget/NLog@5.0.0':
                assert find_property(component, 'dependencyDepth') is not None


def test_two_elements_folding_to_one_key_report_the_shorter_depth_within_one_subtree():
    """Two readings of emit() disagreed on whether it shares the cross-subtree depth defect.

    Written to fail if the per-subtree walk can record the longer route: NLog is reached directly
    by a.cs at depth 1 and nlog through a package chain at depth 3, both inside ONE subtree. If
    this passes unchanged then breadth-first ordering guarantees the shorter route arrives first
    and the exposure never existed at this site; if it fails, the site needed the same primitive
    the cross-subtree merge needed.
    """
    model = SGraph(SElement(None, ''))
    a_file = model.createOrGetElementFromPath('/Org/repoA/src/a.cs')
    assemblies = model.createOrGetElementFromPath('/Org/External/Assemblies')
    lower = SElement(assemblies, 'nlog')
    lower.attrs['version'] = '5.0.0'
    upper = SElement(assemblies, 'NLog')
    upper.attrs['version'] = '5.0.0'
    hop_one = SElement(assemblies, 'first-hop')
    hop_one.attrs['version'] = '1.0.0'
    hop_two = SElement(assemblies, 'second-hop')
    hop_two.attrs['version'] = '1.0.0'
    # depth 3 route recorded first, then the direct one
    SElementAssociation(a_file, hop_one, 'assembly_ref').initElems()
    SElementAssociation(hop_one, hop_two, 'assembly_ref').initElems()
    SElementAssociation(hop_two, lower, 'assembly_ref').initElems()
    SElementAssociation(a_file, upper, 'assembly_ref').initElems()

    documents = generate_multi_from_sgraph(model, level=2, transitive_externals=True)
    nlog = [
        component for document in documents for component in document['components']
        if component['name'].lower() == 'nlog'
    ]

    assert nlog, [c['purl'] for d in documents for c in d['components']]
    assert find_property(nlog[0], 'dependencyDepth') == '1'


def test_finalize_is_idempotent_and_leaves_internal_components_alone():
    """Called twice it changes nothing, and a component it does not own it does not touch.

    Idempotence matters because the render boundary is reachable more than once for one SBOM
    object, and an internal component carries no evidence at all — it must emerge byte-identical
    rather than gaining an empty rendering of properties it never had.
    """
    third_party = {
        'name': 'strip-ansi',
        'purl': 'pkg:npm/strip-ansi@6.0.1',
        'properties': [{
            'name': 'sourceCodeReferences',
            'value': '/Org/repoA/src/a.js'
        }],
        '_evidence': {
            'direct': ['/Org/repoA/src/a.js'],
            'indirect': [],
            'superseded': []
        },
    }
    internal = {
        'name': 'repoB',
        'bom-ref': 'repoB',
        'properties': [{
            'name': 'softagram:internal',
            'value': 'true'
        }]
    }
    components = [third_party, internal]
    internal_before = copy.deepcopy(internal)

    sbom_cyclonedx_generator.finalize_components(components)
    once = copy.deepcopy(components)
    sbom_cyclonedx_generator.finalize_components(components)

    assert components == once
    assert internal == internal_before
    assert '_evidence' not in third_party


# --- reporting channel tests (P3) ---
#
# The generator's only reporting channel is stderr, and one loop writes on it unconditionally.
# A2 takes ownership of reporting, so the guard is fixed here rather than left for whoever next
# notices their sweep output streaming element paths.


def test_the_generator_is_silent_without_the_noisy_flag(capsys):
    """Default output belongs to the caller, and today one loop writes to stderr on every run.

    The `for e in other_excluding_parent` loop in elem_as_bom_data sits OUTSIDE the `noisy` guard
    that its own header line respects, so any model carrying three externals of one name prints
    paths during a perfectly ordinary export. Reproduced here with exactly that shape.
    """
    model = SGraph(SElement(None, ''))
    referrer = model.createOrGetElementFromPath('/Org/repoA/src/app.js')
    for root in ('NPM', 'PIP', 'APT'):
        parent = model.createOrGetElementFromPath(f'/Org/External/{root}')
        elem = SElement(parent, 'lodash')
        SElementAssociation(referrer, elem, 'use').initElems()

    sbom_cyclonedx_generator.generate_from_sgraph(model)

    assert capsys.readouterr().err == ''


def test_source_code_references_contain_no_duplicate_paths():
    """The premise two renderers depend on, asserted where it is ESTABLISHED.

    produce_source_code_references deduplicates direct references by element and builds indirect
    exposure as a set of elements, so its lists carry no repeats. The single-element renderer
    counts the raw list while the merge counts the cardinality of a set: they agree only because
    of that. If this function ever returned duplicates, unmerged rows would report a sum and
    merged rows a cardinality — the divergence the merge rules explicitly forbid — silently.

    Asserted here rather than commented at either renderer, because a guard at the consumer sits
    where the breakage would not originate and a comment cannot fail.
    """
    model = SGraph(SElement(None, ''))
    app = model.createOrGetElementFromPath('/Org/repoA/src/app.js')
    npm = model.createOrGetElementFromPath('/Org/External/NPM')
    lodash = SElement(npm, 'lodash')
    lodash.attrs['version'] = '4.17.21'
    express = SElement(npm, 'express')
    express.attrs['version'] = '4.18.2'
    # two routes from one file to one package, direct and through express
    SElementAssociation(app, lodash, 'use').initElems()
    SElementAssociation(app, express, 'use').initElems()
    SElementAssociation(express, lodash, 'packagejson').initElems()

    direct, indirect = sbom_cyclonedx_generator.produce_source_code_references(
        lodash, model.findElementFromPath('/Org/External'))

    assert len(direct) == len(set(direct))
    assert len(indirect) == len(set(indirect))


# --- purl canonicalization tests (A4) ---
#
# Narrowed against the primary source, types/*-definition.json, rather than against PURL-TYPES.rst
# which it supersedes. npm says case_sensitive true and "the npm scope @ sign prefix is always
# percent encoded"; pypi says case_sensitive false with underscore-to-dash, and scopes its dot rule
# to distribution FILE names rather than to the name component; nuget says case_sensitive true, so
# its 300 uppercase ids are spec-conforming and are left alone.
#
# A4 canonicalises the PURL only. The disclosed name keeps whatever the model said — the opposite
# of A1, which rewrites the name because the name denoted nothing.


def canonical_component(root, raw_name, version, attrs=None):
    """Emit one external under a root and return the single component describing it."""
    model = SGraph(SElement(None, ''))
    app = model.createOrGetElementFromPath('/Org/repoA/src/app.txt')
    parent = model.createOrGetElementFromPath(f'/Org/External/{root}')
    elem = SElement(parent, raw_name)
    elem.attrs['version'] = version
    for key, value in (attrs or {}).items():
        elem.attrs[key] = value
    SElementAssociation(app, elem, 'use').initElems()
    components = sbom_cyclonedx_generator.generate_from_sgraph(model)['components']
    assert len(components) == 1, components
    return components[0]


def test_the_canonicalization_is_a_recorded_migration():
    """Records the published identifiers that CHANGE, in one place a reviewer can find.

    1 224 refs move: 1 053 npm scopes gaining %40 and 171 pypi names folded. Written asserting the
    values shipping today and updated in the commit that lands the change, so a consumer-visible
    migration appears in the diff of a test rather than only in a release note.

    The third line is the scope rule reaching a type other than npm. It moves ZERO refs in the 20
    local models — every one of the 2 171 scoped purls there is npm and was already encoded — so
    unlike the two above it is recorded from a fixture rather than from the corpus. That is the
    honest shape of this one: the population it repairs is a scoped package whose ecosystem did
    not resolve, which the local models happen not to contain and a reported export contained 90
    of. A migration measured at zero locally is still a migration for whoever has the rows.
    """
    assert canonical_component('NPM', '@angular/animation',
                               '12.3.1')['purl'] == 'pkg:npm/%40angular/animation@12.3.1'
    assert canonical_component('PIP', 'zope_interface',
                               '5.4.0')['purl'] == 'pkg:pypi/zope-interface@5.4.0'
    assert canonical_component('UnknownRegistry', '@example/pkg',
                               '1.0.0')['purl'] == 'pkg:generic/%40example/pkg@1.0.0'


def test_an_npm_scope_is_percent_encoded():
    """The npm definition states the scope's @ prefix is always percent encoded."""
    component = canonical_component('NPM', '@angular/animation', '12.3.1')

    assert component['purl'] == 'pkg:npm/%40angular/animation@12.3.1'


def test_only_a_leading_at_is_encoded():
    """A yarn protocol alias puts an @ inside the VERSION, and encoding there would corrupt it.

    'string-width-cjs': 'npm:string-width@^4.2.0' produces a version carrying both @ and a colon.
    Nine components in the stored models look like this. The name is what A4 canonicalises, so the
    rule is anchored to the name's leading character rather than to any @ in the string.
    """
    component = canonical_component('NPM', 'string-width-cjs', 'npm:string-width@^4.2.0')

    assert component['purl'] == 'pkg:npm/string-width-cjs@npm:string-width@^4.2.0'


def test_the_version_separator_is_never_encoded():
    """The @ that separates a version is punctuation, not part of any name."""
    component = canonical_component('NPM', '@babel/core', '7.24.0')

    assert component['purl'].endswith('@7.24.0')
    assert component['purl'].count('%40') == 1


def test_a_pypi_name_is_lowercased_and_underscores_become_dashes():
    """pypi is case_sensitive false and replaces underscore with dash."""
    component = canonical_component('PIP', 'Zope_Interface', '5.4.0')

    assert component['purl'] == 'pkg:pypi/zope-interface@5.4.0'


def test_a_pypi_name_keeps_its_dots():
    """The control on the ruling: purl scopes its dot rule to distribution FILE names.

    PEP 503 collapses dots for internal matching and match_key applies that, so zope.interface
    still matches zope-interface where matching is what is wanted. Publishing is the other
    operation, and it keeps the dots.
    """
    component = canonical_component('PIP', 'zope.interface', '5.4.0')

    assert component['purl'] == 'pkg:pypi/zope.interface@5.4.0'


def test_an_npm_name_keeps_its_case():
    """npm is case_sensitive true: old mixed-case packages were grandfathered in."""
    component = canonical_component('NPM', 'JSONStream', '1.3.5')

    assert component['purl'] == 'pkg:npm/JSONStream@1.3.5'


def test_a_nuget_name_keeps_its_case():
    """nuget is case_sensitive true, so the 300 uppercase ids in the corpus are conforming."""
    component = canonical_component('Assemblies', 'Newtonsoft.Json', '13.0.3')

    assert component['purl'] == 'pkg:nuget/Newtonsoft.Json@13.0.3'


def test_a_scoped_name_whose_ecosystem_did_not_resolve_is_still_encoded():
    """The reported residue: a scoped npm package that fell through to the generic type.

    The encoding was keyed on the resolved ecosystem, so an element the type inference could not
    place never reached it and was published with a raw '@'. That is not a cosmetic difference.
    '@' is the version separator in a purl, so 'pkg:generic/@example/accounting-codes@100.4.0'
    is ambiguous to a parser in a way the encoded spelling is not — the name component has to be
    unambiguous whatever the ecosystem turned out to be.

    The root here is one purl_for cannot type, which is what puts the element on the fallback
    branch: the defect is reachable only through a type resolution FAILURE, so a fixture naming a
    known root would test the path that already worked.
    """
    component = canonical_component('UnknownRegistry', '@example/accounting-codes', '100.4.0')

    assert component['purl'] == 'pkg:generic/%40example/accounting-codes@100.4.0'
    assert purl_type_resolution(component) == 'ecosystem unresolved'


def test_the_generic_encoding_does_not_touch_the_disclosed_name():
    """Widening the encoding must not widen what it applies TO.

    A4's split is that the purl is canonicalised and the component's name keeps the model's
    spelling. Extending the scope rule beyond npm changes which purls are rewritten; it must not
    start rewriting names, or the document would stop disclosing the id the model actually held.
    """
    component = canonical_component('UnknownRegistry', '@example/accounting-codes', '100.4.0')

    assert component['name'] == '@example/accounting-codes'


def test_a_generic_name_without_a_scope_is_untouched():
    """The control: widening the rule must not start encoding names that carry no scope.

    Without this, a rule that encoded the whole name, or that matched an '@' anywhere, would pass
    every other assertion in this group — they all use scoped inputs.
    """
    component = canonical_component('UnknownRegistry', 'accounting-codes', '100.4.0')

    assert component['purl'] == 'pkg:generic/accounting-codes@100.4.0'


def test_the_disclosed_name_stays_raw_and_carries_no_provenance():
    """A4 canonicalises the purl only, and the raw spelling is already disclosed in name.

    The opposite of A1, which rewrites the name because the name denoted nothing and therefore
    owes a provenance property. Here the model's spelling is still true, so a property on 1 224
    rows would duplicate the name field for zero information.
    """
    component = canonical_component('PIP', 'Zope_Interface', '5.4.0')

    assert component['name'] == 'Zope_Interface'
    assert find_property(component, 'packageNameResolution') is None


def test_two_pypi_spellings_become_one_component():
    """Folding the published name makes two spellings of one package one row."""
    model = SGraph(SElement(None, ''))
    app = model.createOrGetElementFromPath('/Org/repoA/src/app.py')
    parent = model.createOrGetElementFromPath('/Org/External/PIP')
    for spelling in ('zope_interface', 'Zope_Interface'):
        elem = SElement(parent, spelling)
        elem.attrs['version'] = '5.4.0'
        SElementAssociation(app, elem, 'use').initElems()

    components = sbom_cyclonedx_generator.generate_from_sgraph(model)['components']

    assert [component['purl'] for component in components] == ['pkg:pypi/zope-interface@5.4.0']


def test_a_golang_purl_is_untouched():
    """golang ids contain separators and case that the definition does not license changing."""
    component = canonical_component('Go', 'github.com/0xAX/notificator', '1.0.0')

    assert component['purl'] == 'pkg:golang/github.com/0xAX/notificator@1.0.0'


# --- purl key omission tests (A6) ---
#
# CycloneDX types 'purl' as a string with format 'iri-reference'. The empty string is not one, so
# a strict validator may reject a document that carries it — the field said nothing, in a way that
# was not legal. Omitting the key says the same nothing legally.
#
# Scoped to purl alone: 'version' has no format constraint, so an empty version is valid and stays
# exactly as it is. Emptiness is not the defect; emptiness in a FORMATTED field is.


def test_an_internal_component_with_an_identity_still_publishes_its_purl():
    """The guard on over-deletion: omission is for rows with nothing to say, not for every row.

    Removing an empty field and removing the field are one edit away from each other, and the
    inlined-internal path is the one place that computes a purl conditionally — it starts from
    the no-identity default and overwrites it when the subtree names a package. An edit that
    dropped the key instead of the empty value would silently unpublish every identity this
    sprint added.
    """
    component = the_internal_component(published_package_model())

    assert component['purl'] == 'pkg:generic/ui-lib@2.1.0'


def test_the_single_document_metadata_component_omits_its_purl():
    """The third emission site, which no other test reaches.

    generate_from_sgraph builds its metadata component in analyze_component_section rather than
    in the multi-document path, so the two named metadata tests do not cover it and it kept its
    empty purl through every earlier phase.
    """
    model, _ = get_model_and_model_api(MULTI_MODEL)

    sbom = sbom_cyclonedx_generator.generate_from_sgraph(model)

    assert 'purl' not in sbom['metadata']['component']
    assert sbom['metadata']['component']['version'] == ''


def test_no_purl_key_anywhere_in_any_fixture_is_empty():
    """Estate invariant over every fixture and every mode, metadata components included.

    The narrower invariant above reads one model's components in three modes. This one reads
    every stored fixture in every generation mode and both positions a purl can occupy, because
    the defect was three separate literals in three functions and a check that visited only one
    of them is what let the other two survive this long.
    """
    fixtures = ('converters/modelfile_for_sbom_tests.xml', MULTI_MODEL, MIRRORED_MODEL,
                BINARY_REFS_MODEL, MAVEN_COORDINATES_MODEL, EMISSION_MODEL)
    modes = (dict(), dict(transitive=True), dict(transitive=True, transitive_externals=True))

    checked = 0
    for model_file in fixtures:
        model, _ = get_model_and_model_api(model_file)
        documents = [sbom_cyclonedx_generator.generate_from_sgraph(model)]
        for kwargs in modes:
            documents.extend(generate_multi_from_sgraph(model, level=2, **kwargs))
        for document in documents:
            for component in document['components'] + [document['metadata']['component']]:
                assert component.get('purl', 'nonempty') != '', (model_file, component['name'])
                checked += 1

    assert checked > 0


@pytest.mark.parametrize('fixture,subject,aggregate', [
    ('modelfile_for_sbom_tests.xml', '/nginx', 'unknown'),
    ('modelfile_for_sbom_maven_coordinates_tests.xml', '/ExampleOrg', 'incomplete'),
])
def test_cli_coverage_flag_adds_the_completeness_claim(tmp_path, fixture, subject, aggregate):
    """--coverage reaches the document through the CLI, in CycloneDX's own slot.

    Both reachable outcomes are exercised, on fixtures measured to produce them: one whose
    externals are all identified and one carrying an external that is not. A single fixture would
    have pinned whichever state it happened to be in, and this one was in the quiet state -- the
    flag could have been wired to a constant and still passed.

    The 'incomplete' side moved from the emission fixture to the maven-coordinates one, and the
    reason is worth recording. The emission fixture's entire claim to incompleteness was ONE
    element: /ExampleOrg/External/Unknown_Binary_Files, the root bucket itself, which the old
    is_root_node did not recognise as a root because it was absent from the ecosystem table, and
    which was therefore reported as a package the BOM had failed to identify. With that repaired
    the fixture has nothing unidentified left, and 'unknown' is the true claim for it. The
    maven-coordinates fixture carries three externals that genuinely cannot be identified, so it
    exercises 'incomplete' for the reason the test means to exercise it.

    The subject is pinned rather than only compared against the document, because reading it out
    of the same document it is asserted against cannot fail.
    """
    import json
    import subprocess
    import sys
    import os

    model_path = os.path.join(os.path.dirname(__file__), fixture)
    out_path = tmp_path / 'sbom.json'
    proc = subprocess.run([
        sys.executable, '-m', 'sgraph.converters.sbom_cyclonedx_generator', model_path,
        str(out_path), '--coverage'
    ], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr

    document = json.loads(out_path.read_text())
    assert document['metadata']['component']['bom-ref'] == subject
    assert document['compositions'] == [{'aggregate': aggregate, 'assemblies': [subject]}]
    from sgraph.converters.external_identification import SUMMARY_PROPERTIES
    summary = {prop['name'] for prop in document['metadata']['properties']}
    assert summary == set(SUMMARY_PROPERTIES)


def test_cli_without_the_coverage_flag_adds_no_composition(tmp_path):
    """Default-off through the CLI too, asserted rather than assumed.

    The flag is the whole opt-in: a document produced without it must be what 1.13.0 produced,
    so a consumer diffing two releases sees nothing they did not ask for.
    """
    import json
    import subprocess
    import sys
    import os

    model_path = os.path.join(os.path.dirname(__file__), 'modelfile_for_sbom_tests.xml')
    out_path = tmp_path / 'sbom.json'
    proc = subprocess.run([
        sys.executable, '-m', 'sgraph.converters.sbom_cyclonedx_generator', model_path,
        str(out_path)
    ], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr

    document = json.loads(out_path.read_text())
    assert 'compositions' not in document
    assert 'properties' not in document['metadata']


@pytest.mark.parametrize('scope', [['--level', '3'], ['--element-path', '/Project/repoA']])
def test_cli_rejects_coverage_with_a_multi_document_scope(tmp_path, scope):
    """The coverage report is model-wide, so it cannot describe one document's assembly.

    Attaching it to a per-element SBOM would claim that repoA's third-party assembly is
    incomplete because repoB's is, which is a statement about a document that does not contain
    the evidence for it. Rejected at the CLI the way every other unsupported combination is,
    rather than emitted with a caveat nobody reads.
    """
    import subprocess
    import sys
    import os

    model_path = os.path.join(os.path.dirname(__file__), 'modelfile_for_sbom_multi_tests.xml')
    out_path = tmp_path / 'sboms.json'
    proc = subprocess.run([
        sys.executable, '-m', 'sgraph.converters.sbom_cyclonedx_generator', model_path,
        str(out_path), '--coverage'
    ] + scope, capture_output=True, text=True)

    assert proc.returncode != 0
    # The exact message, not merely the flag name: before the flag existed these assertions
    # passed on argparse's "unrecognized arguments: --coverage", which is a pass for the wrong
    # reason and would have survived the flag being wired to nothing.
    assert '--coverage cannot be combined with --level or --element-path' in proc.stderr


def advisory_materialised(model, path):
    """A version element the producer invented so a finding would have a parent.

    softagram-live stamps version_kind='advisory_range' on these: the version segment of the name
    holds an advisory's affected RANGE, and nothing is installed at it. Built here rather than
    taken from a fixture because no stored model carries the attribute yet -- it is stamped by an
    analyzer change that ships separately, which is exactly why absence must keep meaning
    "installed".
    """
    elem = referenced_external(model, path)
    elem.attrs['version_kind'] = 'advisory_range'
    return elem


def test_an_advisory_materialised_version_is_not_a_component():
    """A range nothing is installed at is not inventory, so it must not be published as stock.

    Emitting it asserts that the estate depends on `ws` at version '>=8.0.0 <8.21.0' -- a version
    that exists in no registry and was never installed anywhere. The producer now says so; this
    is the consumer honouring it.
    """
    model = SGraph(SElement(None, ''))
    advisory_materialised(model, '/Org/External/NPM/ws/ws of version >=8.0.0 <8.21.0')

    assert [component['name'] for component in admission_components(model)] == []


def test_the_installed_version_beside_it_still_emits():
    """Anti-vacuity, and the failure this guards is the expensive one.

    A rule that suppressed the real release alongside the invented one would delete genuine
    inventory from the document, and the deletion would look like an improvement because the
    phantom count went to zero at the same time.
    """
    model = SGraph(SElement(None, ''))
    advisory_materialised(model, '/Org/External/NPM/ws/ws of version >=8.0.0 <8.21.0')
    referenced_external(model, '/Org/External/NPM/ws/ws of version 8.11.0')

    assert [component['version'] for component in admission_components(model)] == ['8.11.0']


def test_an_unrecognised_version_kind_still_emits():
    """Only the value this rule reasoned about suppresses. Every other one is left alone.

    'declared_range' is the intended next value, and it names a DIFFERENT population -- one
    element per declaring dependent, every one of them carrying incoming edges. Suppressing on the
    mere presence of the attribute would silently delete those the day the producer starts
    stamping them, which is a behaviour change nobody asked for arriving through the back door.
    """
    model = SGraph(SElement(None, ''))
    elem = referenced_external(model, '/Org/External/NPM/thenify/thenify of version >= 3.1.0 < 4')
    elem.attrs['version_kind'] = 'declared_range'

    assert [component['name'] for component in admission_components(model)] == ['thenify']


def test_a_suppressed_advisory_row_is_referenced_nowhere_in_the_document():
    """Removing a component must not leave a ref pointing at something no longer there.

    Checked over the whole serialised document rather than over the component list, because a
    dangling reference would sit in some other section -- dependencies, compositions, or an
    externalReference -- and a component-list assertion would never see it.
    """
    import json

    model = SGraph(SElement(None, ''))
    advisory_materialised(model, '/Org/External/NPM/ws/ws of version >=8.0.0 <8.21.0')
    referenced_external(model, '/Org/External/NPM/ws/ws of version 8.11.0')

    document = json.dumps(sbom_cyclonedx_generator.generate_from_sgraph(model))

    assert '>=8.0.0' not in document


# --- Selectable CycloneDX specification version ---
#
# The generator declared 1.7 and nothing else. CycloneDX 1.7 was published in October 2025, so a
# consumer built against a library released before that cannot parse the document at all — it is
# rejected on the version string, before any of its content is read. A measured instance runs
# Dependency-Track 4.12.0 on cyclonedx-core-java 9.0.5, which is exactly that case, and the whole
# export is unusable there.
#
# Nothing in the output needs 1.7. Every document this generator can produce — 912 of them, from
# 20 real models, in single, per-level and coverage modes — validates against the official
# bom-1.4, bom-1.5 and bom-1.6 schemas with only the version string swapped, and those schemas set
# additionalProperties:false at both the document root and the component, so the result is a
# statement about the content rather than a permissive schema declining to look. bom-1.3 is
# permissive and is deliberately NOT offered.
#
# So the default moved to 1.6: identical information, readable by the deployed estate. 1.7 remains
# available to a caller that asks for it by name.

SUPPORTED_SPEC_VERSIONS = ('1.4', '1.5', '1.6', '1.7')

DEFAULT_SPEC_VERSION = '1.6'


def test_the_default_spec_version_is_one_the_deployed_estate_can_read():
    """1.6 rather than 1.7, on every public entry point.

    Pinned as a literal in all three places rather than read from the module constant. A test
    that compares the output against the same constant the output is built from passes whatever
    that constant says, which is precisely the change this asserts against.
    """
    model, _ = get_model_and_model_api(MULTI_MODEL)

    assert sbom_cyclonedx_generator.generate_from_sgraph(model)['specVersion'] == '1.6'
    assert all(document['specVersion'] == '1.6'
               for document in generate_multi_from_sgraph(model, level=3))
    assert generate_for_element_from_sgraph(model, '/OrgName/GroupA/repoA')['specVersion'] == '1.6'


def test_each_supported_spec_version_reaches_every_entry_point():
    """The requested version is what the document declares, on all three generators.

    Asserted per entry point rather than once, because each threads the value through a different
    call path: the legacy generator builds one SBOM directly, while the level and element modes
    both go through the shared per-element builder.
    """
    model, _ = get_model_and_model_api(MULTI_MODEL)

    for version in SUPPORTED_SPEC_VERSIONS:
        single = sbom_cyclonedx_generator.generate_from_sgraph(model, spec_version=version)
        assert single['specVersion'] == version

        multi = generate_multi_from_sgraph(model, level=3, spec_version=version)
        assert [document['specVersion'] for document in multi] == [version] * len(multi)

        one = generate_for_element_from_sgraph(model, '/OrgName/GroupA/repoA',
                                               spec_version=version)
        assert one['specVersion'] == version


def test_an_unsupported_spec_version_is_refused_naming_the_ones_that_work():
    """Refused rather than passed through, and the message has to carry the way out.

    A version string reaches the document untouched, so an unchecked value would produce a
    document declaring a specification it does not conform to — invalid in a way no consumer can
    diagnose, since the only evidence is a version number that looks deliberate. 1.3 is in the
    sample deliberately: it is a real CycloneDX version, and a caller reaching for an older one
    still has to be told where the floor is.
    """
    model, _ = get_model_and_model_api(MULTI_MODEL)

    for rejected in ('1.3', '1.8', '1.6.0', 'latest', ''):
        for call in (lambda v: sbom_cyclonedx_generator.generate_from_sgraph(model,
                                                                             spec_version=v),
                     lambda v: generate_multi_from_sgraph(model, level=3, spec_version=v),
                     lambda v: generate_for_element_from_sgraph(model, '/OrgName/GroupA/repoA',
                                                                spec_version=v)):
            with pytest.raises(ValueError) as excinfo:
                call(rejected)
            message = str(excinfo.value)
            assert all(supported in message for supported in SUPPORTED_SPEC_VERSIONS), message


def test_a_requested_spec_version_cannot_leak_into_the_next_call():
    """BASIC_INFO is class-level and mutable, so a per-call value written into it would persist.

    The failure this forecloses is not a wrong document but a wrong LATER document: one export
    asks for 1.4, and every subsequent export in the same process silently declares 1.4 as well.
    In a long-lived server that is the normal case rather than the exceptional one, and it is
    invisible from the call that caused it. Both halves are asserted — the next call's output,
    and the class attribute itself — because the second is what makes the first true, and a fix
    that only defends the observable half would leave the shared dict poisoned for anything else
    that reads it.
    """
    model, _ = get_model_and_model_api(MULTI_MODEL)

    sbom_cyclonedx_generator.generate_from_sgraph(model, spec_version='1.4')

    assert sbom_cyclonedx_generator.generate_from_sgraph(model)['specVersion'] == '1.6'
    assert sbom_cyclonedx_generator.SBOM.BASIC_INFO['specVersion'] == '1.6'


def without_the_fields_allowed_to_move(document):
    """The document minus the three fields that legitimately differ between two generations.

    specVersion is the subject of the comparison. metadata.timestamp is the generation time, and
    serialNumber is minted from uuid4 by the legacy single-document mode, so both differ between
    any two calls whatever else is held fixed. Everything else must be identical, and stating the
    exclusions here rather than inside each assertion keeps the list of what is forgiven short
    enough to read.
    """
    stripped = copy.deepcopy(document)
    stripped.pop('specVersion', None)
    stripped.pop('serialNumber', None)
    stripped.get('metadata', {}).pop('timestamp', None)
    return stripped


def test_the_spec_version_is_the_only_thing_the_spec_version_changes():
    """Selecting a version must relabel the document, not reshape it.

    This is the claim the default change rests on: the content is identical across the supported
    range, so moving the default loses a consumer nothing. Asserted by generating the same model
    at every supported version and comparing whole documents, which catches a conditional emitted
    per version far more reliably than checking the fields anyone thought to name.
    """
    model, _ = get_model_and_model_api(MULTI_MODEL)

    reference = without_the_fields_allowed_to_move(
        sbom_cyclonedx_generator.generate_from_sgraph(model, spec_version=DEFAULT_SPEC_VERSION))

    for version in SUPPORTED_SPEC_VERSIONS:
        document = sbom_cyclonedx_generator.generate_from_sgraph(model, spec_version=version)
        assert without_the_fields_allowed_to_move(document) == reference, version


# Enumerated from bom-1.6.schema.json (http://cyclonedx.org/schema/bom-1.6.schema.json), the
# default specVersion, at the object levels this generator actually emits. The schema sets
# additionalProperties:false at every one of them, so a key outside these sets does not merely
# read oddly — it makes the whole document invalid, and a validating consumer discards the entire
# SBOM rather than the offending field.
#
# Held as key sets here rather than by validating against a vendored copy of the schema, for
# three reasons. The schema does not constrain specVersion at all (it is {"type": "string"} with
# no enum, in 1.4, 1.5 and 1.6 alike), so validating against it cannot test the selection this
# section is about; what rejects 1.7 is the consumer's own version dispatch, which no schema
# reproduces. bom-1.6 is 262 KB and $refs spdx.schema.json and jsf-0.82.schema.json, so vendoring
# it means committing 332 KB of third-party JSON. And it would add jsonschema as a test
# dependency to a library that declares three runtime ones. What a vendored schema would really
# buy is this additionalProperties check, and this states it in a form a reviewer can read.
#
# CycloneDX adds members across versions and does not remove them, so drift in these sets makes
# the test permissive rather than falsely red.
CYCLONEDX_1_6_KEYS = {
    'bom': {'$schema', 'annotations', 'bomFormat', 'components', 'compositions', 'declarations',
            'definitions', 'dependencies', 'externalReferences', 'formulation', 'metadata',
            'properties', 'serialNumber', 'services', 'signature', 'specVersion', 'version',
            'vulnerabilities'},
    'metadata': {'authors', 'component', 'licenses', 'lifecycles', 'manufacture', 'manufacturer',
                 'properties', 'supplier', 'timestamp', 'tools'},
    'tool': {'externalReferences', 'hashes', 'name', 'vendor', 'version'},
    'component': {'author', 'authors', 'bom-ref', 'components', 'copyright', 'cpe',
                  'cryptoProperties', 'data', 'description', 'evidence', 'externalReferences',
                  'group', 'hashes', 'licenses', 'manufacturer', 'mime-type', 'modelCard',
                  'modified', 'name', 'omniborId', 'pedigree', 'properties', 'publisher', 'purl',
                  'releaseNotes', 'scope', 'signature', 'supplier', 'swhid', 'swid', 'tags',
                  'type', 'version'},
    'externalReference': {'comment', 'hashes', 'type', 'url'},
    'property': {'name', 'value'},
    'dependency': {'dependsOn', 'provides', 'ref'},
    'composition': {'aggregate', 'assemblies', 'bom-ref', 'dependencies', 'signature',
                    'vulnerabilities'},
}


def objects_by_cyclonedx_kind(document):
    """Yield (kind, object) for every schema-governed object in a document.

    Components nest, and the nested ones are governed by the same definition as the outermost,
    so the walk recurses rather than reading one level. A caller gets every object the schema has
    an opinion about, which is what makes the assertion over it exhaustive instead of a sample.
    """
    yield 'bom', document

    metadata = document.get('metadata', {})
    if metadata:
        yield 'metadata', metadata
    for tool in metadata.get('tools', []):
        yield 'tool', tool

    def walk_component(component):
        yield 'component', component
        for reference in component.get('externalReferences', []):
            yield 'externalReference', reference
        for prop in component.get('properties', []):
            yield 'property', prop
        for nested in component.get('components', []):
            yield from walk_component(nested)

    if metadata.get('component'):
        yield from walk_component(metadata['component'])
    for component in document.get('components', []):
        yield from walk_component(component)

    for dependency in document.get('dependencies', []):
        yield 'dependency', dependency
    for composition in document.get('compositions', []):
        yield 'composition', composition


def test_every_key_the_default_document_carries_is_one_the_default_version_defines():
    """The document declares 1.6, so every key in it has to be a key 1.6 defines.

    Offline and dependency-free by construction: the claim is checked against the enumerated key
    sets above, so it runs anywhere pytest runs. Run over the coverage document as well as the
    plain one, because compositions is reachable no other way and is the one section whose
    membership genuinely differs between 1.4 and 1.5.
    """
    from sgraph.converters.external_identification import (attach_coverage_compositions,
                                                           attach_coverage_summary,
                                                           external_coverage_report)

    for model_file in (MULTI_MODEL, EMISSION_MODEL, MAVEN_COORDINATES_MODEL, BINARY_REFS_MODEL,
                       'converters/modelfile_for_sbom_tests.xml'):
        model, _ = get_model_and_model_api(model_file)

        plain = sbom_cyclonedx_generator.generate_from_sgraph(model)
        report = external_coverage_report(model)
        covered = attach_coverage_compositions(
            attach_coverage_summary(sbom_cyclonedx_generator.generate_from_sgraph(model), report),
            report)

        for document in (plain, covered, *generate_multi_from_sgraph(model, level=3)):
            assert document['specVersion'] == DEFAULT_SPEC_VERSION, model_file
            for kind, obj in objects_by_cyclonedx_kind(document):
                unexpected = set(obj) - CYCLONEDX_1_6_KEYS[kind]
                assert not unexpected, (model_file, kind, sorted(unexpected))


def test_the_oldest_stored_fixture_takes_the_new_default_like_every_other():
    """A model shaped by an analyzer three years older than this change, exported at the default.

    modelfile_for_sbom_tests.xml has been in the tree since April 2023 and carries none of the
    attributes the later fixtures were written around — no version_kind, no declaring scope, no
    package coordinates. SBOMs are generated on demand from stored models with a multi-month
    lifetime, so the generator meets shapes like this one long after the analyzer moved on, and a
    version default proven only on fixtures written in lockstep with today's analyzer is proven
    on the easy half of the corpus.

    Six components, deliberately restated from test_filter_model: the point is that changing the
    declared version changed the inventory not at all, and an assertion on the version alone
    would hold just as well if every component had vanished.
    """
    model, _ = get_model_and_model_api('converters/modelfile_for_sbom_tests.xml')

    document = sbom_cyclonedx_generator.generate_from_sgraph(model)

    assert document['specVersion'] == DEFAULT_SPEC_VERSION
    assert document['bomFormat'] == 'CycloneDX'
    assert len(document['components']) == 6

    for version in SUPPORTED_SPEC_VERSIONS:
        older = sbom_cyclonedx_generator.generate_from_sgraph(model, spec_version=version)
        assert older['specVersion'] == version
        assert without_the_fields_allowed_to_move(older) == \
            without_the_fields_allowed_to_move(document)


def test_cli_selects_the_spec_version(tmp_path):
    """--spec-version reaches the generator, and without it the CLI emits the default."""
    import json
    import subprocess
    import sys
    import os

    model_path = os.path.join(os.path.dirname(__file__), 'modelfile_for_sbom_multi_tests.xml')

    for flag, expected in (([], DEFAULT_SPEC_VERSION), (['--spec-version', '1.7'], '1.7'),
                           (['--spec-version', '1.4'], '1.4')):
        out_path = tmp_path / f'sboms{expected}.json'
        proc = subprocess.run(
            [sys.executable, '-m', 'sgraph.converters.sbom_cyclonedx_generator',
             model_path, str(out_path), '--level', '3', *flag],
            capture_output=True, text=True)
        assert proc.returncode == 0, proc.stderr

        result = json.loads(out_path.read_text())
        assert [document['specVersion'] for document in result] == [expected] * len(result)


def test_cli_selects_the_spec_version_in_the_legacy_single_document_mode(tmp_path):
    """The legacy mode takes the flag too, unlike the closure flags which it rejects.

    Asserted separately because that asymmetry is deliberate and easy to get wrong in either
    direction: --transitive-externals is refused there since the single-document walk would
    ignore it, while a version selection is honoured by every mode and refusing it would strand
    the one export shape that has no --level.
    """
    import json
    import subprocess
    import sys
    import os

    model_path = os.path.join(os.path.dirname(__file__), 'modelfile_for_sbom_multi_tests.xml')
    out_path = tmp_path / 'single.json'
    proc = subprocess.run(
        [sys.executable, '-m', 'sgraph.converters.sbom_cyclonedx_generator',
         model_path, str(out_path), '--spec-version', '1.5'],
        capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr

    assert json.loads(out_path.read_text())['specVersion'] == '1.5'


def test_cli_rejects_an_unsupported_spec_version(tmp_path):
    """Rejected before the model is parsed, with the supported versions in the message.

    Reported the way every other CLI misuse in this module is reported — a non-zero exit and a
    message on stderr naming the flag as typed — rather than as a traceback from the generator.
    """
    import subprocess
    import sys
    import os

    model_path = os.path.join(os.path.dirname(__file__), 'modelfile_for_sbom_multi_tests.xml')
    proc = subprocess.run(
        [sys.executable, '-m', 'sgraph.converters.sbom_cyclonedx_generator',
         model_path, str(tmp_path / 'out.json'), '--level', '3', '--spec-version', '1.3'],
        capture_output=True, text=True)

    assert proc.returncode != 0
    assert '--spec-version' in proc.stderr
    for supported in SUPPORTED_SPEC_VERSIONS:
        assert supported in proc.stderr, proc.stderr
