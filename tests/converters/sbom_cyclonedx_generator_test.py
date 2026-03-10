from sgraph.converters import sbom_cyclonedx_generator
from sgraph.converters.sbom_cyclonedx_generator import (
    deterministic_serial, slugify_bom_ref, generate_multi_from_sgraph
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