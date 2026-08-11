import re

from sgraph import SElement, SElementAssociation, SGraph
from sgraph.converters import sbom_cyclonedx_generator
from sgraph.converters.sbom_cyclonedx_generator import (
    deterministic_serial, slugify_bom_ref, generate_multi_from_sgraph,
    generate_for_element_from_sgraph, infer_pkgtype_from_referencing_files
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

    # Each SBOM should have specVersion 1.7
    for sbom in result:
        assert sbom['specVersion'] == '1.7'
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


def test_transitive_mode_dependson_refs_all_resolve_within_the_bom():
    """Every ref and dependsOn entry points at a component of the same BOM (DT-import safety)."""
    model, _ = get_model_and_model_api(MULTI_MODEL)
    result = generate_multi_from_sgraph(model, level=3, transitive=True)

    for sbom in result:
        known_refs = {c['bom-ref'] for c in sbom['components']}
        known_refs.add(sbom['metadata']['component']['bom-ref'])
        for entry in sbom['dependencies']:
            assert entry['ref'] in known_refs
            for ref in entry['dependsOn']:
                assert ref in known_refs


def test_default_mode_is_unchanged_by_the_transitive_feature():
    """Without transitive=True there are no inlined internal components and BOM-Links remain."""
    model, _ = get_model_and_model_api(MULTI_MODEL)
    result = generate_multi_from_sgraph(model, level=3)

    repo_a_sbom = sbom_of(result, 'repoA')
    assert all(find_property(c, 'softagram:internal') is None
               for c in repo_a_sbom['components'])
    assert len(repo_a_sbom['dependencies']) == 1
    assert any(ref.startswith('urn:cdx:')
               for ref in repo_a_sbom['dependencies'][0]['dependsOn'])


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
    it would violate the purl grammar and be rejected by a purl-parsing consumer.
    """
    model, _ = get_model_and_model_api(MULTI_MODEL)
    result = generate_multi_from_sgraph(model, level=3)

    assert len(result) == 2
    for sbom in result:
        assert sbom['metadata']['component']['purl'] == ''
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
    assert component['purl'] == 'pkg:pypi/PyBinary@1.2'
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
