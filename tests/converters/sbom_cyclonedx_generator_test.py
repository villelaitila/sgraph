import re

from sgraph import SElement, SGraph
from sgraph.converters import sbom_cyclonedx_generator
from sgraph.converters.sbom_cyclonedx_generator import (
    deterministic_serial, slugify_bom_ref, generate_multi_from_sgraph,
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


# --- purl type inference tests ---

BINARY_REFS_MODEL = 'converters/modelfile_for_sbom_binary_refs_tests.xml'

# The purl spec requires a type to start with a letter and to hold only [a-z0-9.-] in its
# canonical form. Only the type is anchored on purpose: name encoding is a separate, pre-existing
# concern (existing fixtures legitimately produce maven names that contain a space).
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
    # Characterization of known-nonconforming output: the name keeps its literal space (names
    # are emitted unencoded — see the type-only caveat in the generator). A name-encoding fix
    # should update this expected string, not relax the assertion.
    assert maven_component['purl'] == 'pkg:maven/org.example.sample sample-lib@2.4.1'
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
