# Multi-SBOM Generator Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the CycloneDX SBOM generator to produce per-repository SBOMs with inter-repo dependency tracking via BOM-Link.

**Architecture:** Add `--level N` CLI parameter to existing generator. When specified, use `generalizer.py` to flatten dependencies to level N, then iterate level-N elements producing one SBOM each with BOM-Link cross-references. Output is a JSON array of SBOM objects.

**Tech Stack:** Python, CycloneDX 1.7, existing sgraph model/generalizer.

**Spec:** `docs/superpowers/specs/2026-03-10-multi-sbom-generator-design.md`

---

## File Structure

| File | Responsibility |
|------|---------------|
| `src/sgraph/converters/sbom_cyclonedx_generator.py` (modify) | Add `generate_multi_from_sgraph()`, `deterministic_serial()`, `slugify_bom_ref()`, BOM-Link logic, update spec to 1.7, add `--level` CLI param |
| `tests/converters/sbom_cyclonedx_generator_test.py` (modify) | Add multi-SBOM tests |
| `tests/converters/modelfile_for_sbom_multi_tests.xml` (create) | Test model with 3+ levels and cross-repo dependencies |

---

## Chunk 1: Test Model and Core Multi-SBOM Generation

### Task 1: Create multi-level test model XML

**Files:**
- Create: `tests/converters/modelfile_for_sbom_multi_tests.xml`

This model simulates: `root -> OrgName -> GroupA -> [repoA, repoB] + GroupA/External/...`
repoA has a file that depends on something in repoB's External, and repoB has its own External deps.
After generalization to level 3, repoA should have an outgoing dependency to repoB.

- [ ] **Step 1: Create the test model file**

```xml
<model version="2.1">
  <elements>
    <e n="OrgName">
      <e n="GroupA">
        <e n="repoA">
          <e n="src">
            <e i="10" n="main.cs">
              <!-- depends on repoB's lib.cs and an external NuGet package -->
              <r r="20" t="use" />
              <r r="30" t="assembly_ref" />
            </e>
          </e>
        </e>
        <e n="repoB">
          <e n="src">
            <e i="20" n="lib.cs">
              <!-- depends on an external Maven package -->
              <r r="40" t="use" />
            </e>
          </e>
        </e>
      </e>
      <e n="External">
        <e n="Assemblies">
          <e n="Newtonsoft.Json">
            <e i="30" n="Newtonsoft.Json" version="13.0.1" />
          </e>
        </e>
        <e n="Maven">
          <e i="40" n="org.apache.commons commons-lang3 of version 3.12.0"
            artifactId="commons-lang3" groupId="org.apache.commons"
            repotype="Maven" version="3.12.0" />
        </e>
      </e>
    </e>
  </elements>
</model>
```

Key properties:
- Level 1: `OrgName`
- Level 2: `GroupA`, `External`
- Level 3: `repoA`, `repoB` (under GroupA), `Assemblies`, `Maven` (under External)
- `repoA/src/main.cs` -> `repoB/src/lib.cs` (internal cross-repo dep, type `use`)
- `repoA/src/main.cs` -> `External/Assemblies/.../Newtonsoft.Json` (3rd party, type `assembly_ref`)
- `repoB/src/lib.cs` -> `External/Maven/.../commons-lang3` (3rd party, type `use`)

- [ ] **Step 2: Verify model loads**

Run: `python -c "from sgraph import SGraph; g = SGraph.parse_xml_or_zipped_xml('tests/converters/modelfile_for_sbom_multi_tests.xml'); print('root children:', [c.name for c in g.rootNode.children])"`

Expected output: `root children: ['OrgName']`

- [ ] **Step 3: Commit**

```bash
git add tests/converters/modelfile_for_sbom_multi_tests.xml
git commit -m "Add multi-level test model for multi-SBOM generation"
```

---

### Task 2: Write failing test for `deterministic_serial()`

**Files:**
- Modify: `tests/converters/sbom_cyclonedx_generator_test.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/converters/sbom_cyclonedx_generator_test.py`:

```python
from sgraph.converters.sbom_cyclonedx_generator import deterministic_serial


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/converters/sbom_cyclonedx_generator_test.py::test_deterministic_serial_is_stable -v`

Expected: FAIL with `ImportError: cannot import name 'deterministic_serial'`

- [ ] **Step 3: Implement `deterministic_serial()`**

Add to `src/sgraph/converters/sbom_cyclonedx_generator.py` (near top, after imports):

```python
# Fixed namespace for deterministic UUID v5 generation of SBOM serial numbers.
# Using the URL namespace as base since element paths are path-like identifiers.
SGRAPH_SBOM_NS = uuid.uuid5(uuid.NAMESPACE_URL, "https://softagram.com/sgraph/sbom")


def deterministic_serial(element_path: str) -> str:
    """Generate a deterministic urn:uuid: serial number from an element path.
    Same path always yields the same UUID (v5, namespace-based)."""
    return f"urn:uuid:{uuid.uuid5(SGRAPH_SBOM_NS, element_path)}"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/converters/sbom_cyclonedx_generator_test.py::test_deterministic_serial_is_stable tests/converters/sbom_cyclonedx_generator_test.py::test_deterministic_serial_differs_per_path -v`

Expected: both PASS

- [ ] **Step 5: Commit**

```bash
git add src/sgraph/converters/sbom_cyclonedx_generator.py tests/converters/sbom_cyclonedx_generator_test.py
git commit -m "Add deterministic_serial() for stable SBOM serial numbers"
```

---

### Task 3: Write failing test for `slugify_bom_ref()`

**Files:**
- Modify: `tests/converters/sbom_cyclonedx_generator_test.py`
- Modify: `src/sgraph/converters/sbom_cyclonedx_generator.py`

- [ ] **Step 1: Write the failing test**

```python
from sgraph.converters.sbom_cyclonedx_generator import slugify_bom_ref


def test_slugify_bom_ref():
    assert slugify_bom_ref("online3_invoicepayment") == "online3-invoicepayment"
    assert slugify_bom_ref("my repo name") == "my-repo-name"
    assert slugify_bom_ref("UPPERCASE") == "uppercase"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/converters/sbom_cyclonedx_generator_test.py::test_slugify_bom_ref -v`

Expected: FAIL with `ImportError`

- [ ] **Step 3: Implement `slugify_bom_ref()`**

Add to `src/sgraph/converters/sbom_cyclonedx_generator.py`:

```python
import re


def slugify_bom_ref(name: str) -> str:
    """Convert element name to a URL-safe bom-ref slug."""
    slug = name.lower().replace('_', '-').replace(' ', '-')
    slug = re.sub(r'[^a-z0-9-]', '', slug)
    slug = re.sub(r'-+', '-', slug).strip('-')
    return slug
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/converters/sbom_cyclonedx_generator_test.py::test_slugify_bom_ref -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/sgraph/converters/sbom_cyclonedx_generator.py tests/converters/sbom_cyclonedx_generator_test.py
git commit -m "Add slugify_bom_ref() for URL-safe component identifiers"
```

---

### Task 4: Write failing test for `generate_multi_from_sgraph()`

**Files:**
- Modify: `tests/converters/sbom_cyclonedx_generator_test.py`

- [ ] **Step 1: Write the failing test**

```python
from sgraph.converters.sbom_cyclonedx_generator import generate_multi_from_sgraph
from ..modelapi_test import get_model_and_model_api


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/converters/sbom_cyclonedx_generator_test.py::test_generate_multi_sboms_at_level_3 -v`

Expected: FAIL with `ImportError: cannot import name 'generate_multi_from_sgraph'`

- [ ] **Step 3: Commit failing tests**

```bash
git add tests/converters/sbom_cyclonedx_generator_test.py
git commit -m "Add failing tests for multi-SBOM generation"
```

---

### Task 5: Implement `generate_multi_from_sgraph()`

**Files:**
- Modify: `src/sgraph/converters/sbom_cyclonedx_generator.py`

This is the core implementation. It does:
1. Generalizes model to target level
2. Identifies "content" elements (non-External) at target level
3. For each content element, finds its External subtree and generates 3rd-party components
4. For each content element, finds outgoing dependencies to other content elements and generates BOM-Link references
5. Packages each as a CycloneDX 1.7 SBOM

- [ ] **Step 1: Update SBOM class spec version to 1.7**

In `src/sgraph/converters/sbom_cyclonedx_generator.py`, change the `BASIC_INFO` dict in the `SBOM` class:

```python
# Change line: 'specVersion': '1.6',
# To:
'specVersion': '1.7',
```

- [ ] **Step 2: Implement `generate_multi_from_sgraph()`**

Add the following function to `src/sgraph/converters/sbom_cyclonedx_generator.py` (after `generate_from_sgraph()`):

```python
def _find_external_root(elem):
    """Find the External element that is a sibling or ancestor-sibling of elem in the original model.
    In the generalized model, External is a sibling of the groups at the same level."""
    # Walk up to find the level-1 element (org root), then look for External child
    ancestor = elem
    while ancestor.parent and ancestor.parent.parent:
        ancestor = ancestor.parent
    return ancestor.getChildByName('External')


def _collect_repo_externals(repo_elem, external_root):
    """Collect External elements that repo_elem has outgoing dependencies to."""
    if external_root is None:
        return []
    external_targets = []
    for assoc in repo_elem.outgoing:
        if assoc.toElement.isDescendantOf(external_root) or assoc.toElement == external_root:
            external_targets.append(assoc.toElement)
    return external_targets


def generate_multi_from_sgraph(sgraph: SGraph, level: int = 3) -> list[dict]:
    """Generate one CycloneDX 1.7 SBOM per element at the given level.

    Uses generalizer to flatten dependencies to target level, then produces
    per-element SBOMs with BOM-Link cross-references for internal dependencies.

    :param sgraph: The loaded SGraph model
    :param level: Tree depth at which to split into separate SBOMs
    :return: List of CycloneDX SBOM dicts
    """
    from sgraph.algorithms.generalizer import generalize_model

    generalized = generalize_model(sgraph, level_to_generalize=level)

    # Collect all elements at target level, separating content from External
    content_elements = []  # repos/components
    external_root = None

    def collect_at_level(elem, current_level):
        nonlocal external_root
        if current_level == level:
            if elem.name == 'External' and elem.parent and not elem.typeEquals('dir') and not elem.typeEquals('repo'):
                pass  # Skip External subtrees at this level
            else:
                content_elements.append(elem)
            return
        if current_level < level:
            if elem.name == 'External' and not elem.typeEquals('dir') and not elem.typeEquals('repo'):
                external_root = elem
                return
            for child in elem.children:
                collect_at_level(child, current_level + 1)

    for root_child in generalized.rootNode.children:
        collect_at_level(root_child, 1)

    # Build path -> element lookup and serial numbers for all content elements
    elem_serials = {}
    elem_bom_refs = {}
    for elem in content_elements:
        path = elem.getPath()
        elem_serials[elem] = deterministic_serial(path)
        elem_bom_refs[elem] = slugify_bom_ref(elem.name)

    sboms = []
    for elem in content_elements:
        sbom = SBOM()
        serial = elem_serials[elem]
        ref = elem_bom_refs[elem]

        # Metadata component
        sbom.metadata_component = {
            'bom-ref': ref,
            'type': 'application',
            'name': elem.name,
            'version': '',
            'purl': '',
            'externalReferences': []
        }

        # 3rd party components: find External deps for this element
        if external_root is not None:
            repo_external_targets = _collect_repo_externals(elem, external_root)
            other_externals_by_name = {}
            stack = list(external_root.children)
            while stack:
                e = stack.pop(0)
                other_externals_by_name.setdefault(clean_name(e.name), []).append(e)
                stack += e.children

            for ext_target in repo_external_targets:
                for component in elem_as_bom_data(ext_target, other_externals_by_name, external_root):
                    # Avoid duplicate components
                    existing_refs = {c['bom-ref'] for c in sbom.components}
                    if component['bom-ref'] not in existing_refs:
                        sbom.components.append(component)

        # Dependencies section
        depends_on = []

        # 3rd party purl refs
        for component in sbom.components:
            depends_on.append(component['bom-ref'])

        # Internal cross-repo dependencies (BOM-Link URNs)
        for assoc in elem.outgoing:
            target = assoc.toElement
            if target in elem_serials and target != elem:
                target_serial_uuid = elem_serials[target].replace('urn:uuid:', '')
                target_ref = elem_bom_refs[target]
                bom_link = f"urn:cdx:{target_serial_uuid}/1#{target_ref}"
                if bom_link not in depends_on:
                    depends_on.append(bom_link)

        dependencies = [{'ref': ref, 'dependsOn': depends_on}]

        # Serialize
        data = sbom.as_cyclonedx_json()
        data['serialNumber'] = serial  # Override random UUID with deterministic one
        data['dependencies'] = dependencies
        sboms.append(data)

    return sboms
```

- [ ] **Step 3: Run all multi-SBOM tests**

Run: `python -m pytest tests/converters/sbom_cyclonedx_generator_test.py -v`

Expected: All tests PASS (both old `test_filter_model` and new multi-SBOM tests)

- [ ] **Step 4: Commit**

```bash
git add src/sgraph/converters/sbom_cyclonedx_generator.py
git commit -m "Implement generate_multi_from_sgraph() with BOM-Link cross-references"
```

---

## Chunk 2: CLI and Existing Test Compatibility

### Task 6: Update CLI with --level parameter

**Files:**
- Modify: `src/sgraph/converters/sbom_cyclonedx_generator.py`

- [ ] **Step 1: Update the `__main__` block**

Replace the current `__main__` block (lines 458-463) with:

```python
if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Generate CycloneDX SBOM from sgraph model')
    parser.add_argument('model', help='Path to model XML file')
    parser.add_argument('output', help='Path to output SBOM JSON file')
    parser.add_argument('--level', type=int, default=None,
                        help='Generate one SBOM per element at this tree depth. '
                             'Without this flag, generates a single SBOM (legacy behavior).')
    args = parser.parse_args()

    g = SGraph.parse_xml_or_zipped_xml(args.model)

    if args.level is not None:
        result = generate_multi_from_sgraph(g, level=args.level)
    else:
        result = generate_from_sgraph(g)

    with open(args.output, 'w') as f:
        json.dump(result, f, indent=4)
```

- [ ] **Step 2: Test CLI help works**

Run: `python -m sgraph.converters.sbom_cyclonedx_generator --help`

Expected: Shows help with `--level` option described.

- [ ] **Step 3: Verify existing test still passes**

Run: `python -m pytest tests/converters/sbom_cyclonedx_generator_test.py::test_filter_model -v`

Expected: PASS (6 components, unchanged)

- [ ] **Step 4: Commit**

```bash
git add src/sgraph/converters/sbom_cyclonedx_generator.py
git commit -m "Add --level CLI parameter for multi-SBOM generation"
```

---

### Task 7: Verify with real model (manual, optional)

This is a manual verification step using the large Talenom model if available.

- [ ] **Step 1: Run multi-SBOM generation on real model**

Run: `python -m sgraph.converters.sbom_cyclonedx_generator model.xml sbom_multi.json --level 3`

- [ ] **Step 2: Inspect output**

Run: `python -c "import json; data=json.load(open('sbom_multi.json')); print(f'{len(data)} SBOMs'); print([s['metadata']['component']['name'] for s in data[:5]])"`

Expected: List of repo names, count should match number of repositories in the model.

- [ ] **Step 3: Spot-check one SBOM for dependencies section**

Run: `python -c "import json; data=json.load(open('sbom_multi.json')); sbom=[s for s in data if s['metadata']['component']['name']=='online3_invoicepayment'][0] if any(s['metadata']['component']['name']=='online3_invoicepayment' for s in data) else None; print(json.dumps(sbom.get('dependencies',[])[:3], indent=2) if sbom else 'not found')"`

Expected: Should see both `pkg:nuget/...` and `urn:cdx:...` entries in `dependsOn`.
