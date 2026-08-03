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

    Only two of the values below contain whitespace at all, asserted rather than claimed, so a
    guard reduced to a whitespace test would accept the other eight. Two of those eight,
    'org.example:lib' and 'org.example~lib', purl would leave unencoded: they are what
    distinguishes a Maven-charset guard from a purl-charset one. '.' and '..' are rejected by an
    explicit exclusion, since the pattern alone matches both.
    """
    not_maven_ids = ('org.example sample-lib', 'org.example\tlib', '', '.', '..',
                     'org/example', 'org.example:lib', 'org.example~lib',
                     '${project.version}', 'org.exämple')
    for value in not_maven_ids:
        assert not sbom_cyclonedx_generator.is_maven_coordinate(value), value
    whitespace_bearing = [v for v in not_maven_ids if any(c.isspace() for c in v)]
    assert len(whitespace_bearing) == 2


def test_maven_coordinates_fixture_yields_five_distinct_components():
    """Anti-vacuity for the fixture, and the collapse guard for version omission.

    A lookup above raises when an element vanishes, but an element added, or two bom-refs
    collapsed into one when a version is omitted, would otherwise go unnoticed.
    """
    model, _ = get_model_and_model_api(MAVEN_COORDINATES_MODEL)
    sbom = sbom_cyclonedx_generator.generate_from_sgraph(model)
    assert len(sbom['components']) == 5
    assert len({component['bom-ref'] for component in sbom['components']}) == 5


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
