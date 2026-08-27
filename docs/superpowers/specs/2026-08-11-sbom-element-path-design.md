# SBOM: expose the element's model path

Design for a change to `src/sgraph/converters/sbom_cyclonedx_generator.py`.

Baseline: sgraph **1.9.0** (`upstream/main` @ `fb65e0d`), 237 tests green.

> **Partly superseded in 1.17.0.** This document specifies `group` as the parent element's
> *full path*. That was changed to the parent's *bare name*: the path put the unstable estate
> root inside an identity field, and CycloneDX defines `group` as a single name rather than a
> location. The rest of the design — `softagram:elementPath`, the derived serial, the vcs
> ancestor walk — is unchanged. See "Caveats" in `docs/data-formats.md`. This file is kept as
> the record of the original decision.

---

## 1. The problem

At `--level 3` the per-repository SBOM identifies the repository by name only:

```json
{ "bom-ref": "repoa",
  "name": "repoA",
  "type": "application", "version": "", "purl": "", "externalReferences": [] }
```

Nothing says the element lives under `/OrgName/GroupA`. The bulk export is the only endpoint
usable at scale, so a consumer that needs the parent group has to download the whole model XML
— hundreds of megabytes on a large estate — purely to rebuild a tree the SBOM set already
implicitly contains.

Two independent consumers pay this cost today:

- A reporting tool infers the group **heuristically**, from the `sourceCodeReferences` paths of
  the components. That is not merely inelegant, it is ambiguous: `sourceCodeReferences` is
  collected model-wide, so a package in repo A lists files in repo B, and the group has to be
  recovered by majority vote over path segments. For a repository mirrored into two groups the
  vote is **unresolvable** — both SBOMs vote for the same winner and the two locations cannot be
  told apart.
- A downstream integration downloads the model for nothing else.

The path is not expensive to publish. The generator already computes it and already depends on
it — the serial number is derived from it.

### The identity that is missing is the only stable one

Mirrored repositories do not share a `bom-ref`, as an earlier draft of this design assumed. The
collision suffix in `_multi_sbom_context` gives them distinct refs:

```
shared | bom-ref: shared    | serial: urn:uuid:905b7d45...
shared | bom-ref: shared-2  | serial: urn:uuid:71368b41...
```

That suffix is assigned in **traversal order**. Delete `GroupA`'s copy and `GroupB`'s silently
becomes `shared`. So `bom-ref` distinguishes the two documents but does not identify either one
across time, `name` identifies neither, and `serialNumber` is an opaque hash. After this change
`softagram:elementPath` is the only stable, human-legible per-element identity in the document.

---

## 2. Spec

### Target output

```json
{ "bom-ref": "repoa",
  "name": "repoA",
  "group": "/OrgName/GroupA",
  "type": "application",
  "version": "",
  "purl": "",
  "externalReferences": [
    { "url": "https://example.org/org/repoA.git", "type": "vcs" }
  ],
  "properties": [
    { "name": "softagram:elementPath", "value": "/OrgName/GroupA/repoA" }
  ] }
```

### Field by field

| Field | Value | Why |
|---|---|---|
| `group` | the parent element's **full path**, omitted when that path is empty | Native CycloneDX field, so no custom-property parsing is needed for the common case. Holding the full parent path rather than the bare parent name keeps two identically named groups under different roots distinguishable, and hands the consumer the estate root without a second lookup. |
| `properties[softagram:elementPath]` | full path from the model root | Exact and lossless: works at any `--level`, survives deeper nesting, and is the single value from which the whole tree can be rebuilt. |
| `externalReferences[type=vcs]` | `repo_url` of the element, or of the nearest ancestor that has one; absent when none does | CycloneDX has a proper field for the repository URL, and the model already carries it. Removes another reason to fetch the model. |
| `purl` | stays empty | See below. |
| `bom-ref` | **unchanged** | See non-goals. |

`group` and `elementPath` are strictly redundant of each other — `group` is `elementPath` minus
its last segment. That is accepted deliberately: `group` is the field a stock CycloneDX consumer
reads with no custom-property support, and `elementPath` is the exact string
`deterministic_serial()` hashes, so it must be published verbatim rather than reconstructed.

### Why the path must not go into `purl`

purl has a grammar: `pkg:type/namespace/name@version`, where the type must start with a letter
and hold only `[a-zA-Z0-9.+-]`. `/OrgName/GroupA/repoA` is not a purl and cannot be made into one
by placing it in that field. A purl-parsing consumer would reject or mis-parse the component —
the same failure class as the historical `pkg:???` placeholder that 1.7.1 removed for exactly
this reason.

So `purl` stays empty until there is a real package identity to put there.

### Why a property rather than a new top-level field

The CycloneDX 1.7 component schema sets **`additionalProperties: false`**. A field such as
`elementPath` on the component would make the document schema-invalid. `properties` is the
schema's own extension point and therefore the only lawful place for the full path.

`group`, by contrast, is a native field and needs no extension point. It is currently unused
anywhere in the module — Maven `groupId` goes into the purl namespace, not into `group` — so
there is no collision with an existing meaning.

### Naming

`softagram:elementPath` follows the namespace the module's two newest extensions use —
`softagram:via` and `softagram:internal`. The module is not consistent here: `purlTypeResolution`,
`versionSource` and `sourceCodeReferences` carry no prefix. New names take the prefix; renaming
the existing ones is a separate, breaking decision.

### Invariants worth asserting

1. `deterministic_serial(elementPath) == serialNumber` — the published path must be the same
   string the serial was derived from. This turns the property from decoration into something
   verifiable, and would catch a future refactor that computes one from a normalised path and the
   other from the raw one.
2. `group + '/' + name == elementPath` at every level below the top, and `group` is absent at the
   top level.
3. Two SBOMs for one mirrored repository share `name`, carry **distinct** `bom-ref`s (via the
   traversal-order collision suffix) and distinct `serialNumber`s, and are told apart
   unambiguously by `group` and `elementPath`.
4. A vcs reference is present exactly when the element or one of its ancestors carries a
   **non-blank** `repo_url`, and carries the value of the **nearest** such ancestor. A blank
   attribute is walked past rather than published: stopping on it would emit an empty url and
   suppress a real remote further up. No fabricated URL is ever emitted on the new code paths.

### A caveat for consumers

The first path segment is the model's estate root and **is not stable** — it changes when the
estate is renamed or restructured. Consumers should read it from the path rather than hardcode
it. `group` moves with it, so a consumer comparing `group` across model generations must expect
the same.

---

## 3. Non-goals

- **Do not change `bom-ref`.** It is referenced from `dependencies[].dependsOn` and from BOM-Link
  URNs in other SBOMs. Changing it breaks cross-SBOM resolution for every already-ingested
  document. (`analyze_component_section` already uses a path-valued `bom-ref`; that is not a
  reason to change this one.)
- **Do not change `serialNumber`.** It is already derived from the path and must stay stable so
  re-ingesting a model updates projects rather than creating new ones.
- **Do not fill `version`.** A repository has no version; a commit hash is not one either.
- **Do not touch the `UNKNOWN-REPOSITORY_LOCATION` fallback** in `analyze_component_section`.
  Fabricating a URL for a repository whose remote is unknown is a defect, but removing it changes
  existing output and is its own decision. The new code paths never fabricate.
- **Do not remove the model download from every workflow.** This change removes it for tree
  reconstruction. Measuring which repositories the analyzer failed to read still requires the
  model, because that fact is absent from the SBOMs by construction.

---

## 4. Implementation

### Two helpers

Both mutate an already-built component dict, matching the idiom already used for
`softagram:via`:

```python
ELEMENT_PATH_PROPERTY = 'softagram:elementPath'


def _add_element_location(component, elem):
    """Publish where elem sits in the model, on a component that describes elem.

    'group' carries the parent's full path rather than its bare name so two identically named
    groups under different roots stay distinguishable, and is omitted for a top-level element,
    whose parent is the model root and has no path of its own. The element's own path goes into
    a property because CycloneDX sets additionalProperties: false on component; it is also the
    exact string deterministic_serial() hashes, so a consumer can verify the identity without
    the model.

    Call once per component: this overwrites 'group' and appends to 'properties'. elem must be
    attached to a model. A detached element is not merely unsupported here, it is dangerous:
    getPath() would return a bare name with no leading slash, and publishing that as an
    elementPath yields a document a consumer cannot resolve and cannot detect as broken.
    Raising at the call site is the better failure.
    """
    parent_path = elem.parent.getPath()
    if parent_path:
        component['group'] = parent_path
    component.setdefault('properties', []).append({
        'name': ELEMENT_PATH_PROPERTY,
        'value': elem.getPath()
    })


def _add_vcs_reference(component, elem):
    """Publish the repository URL of elem, or of the nearest ancestor carrying one.

    The walk upwards is what makes the field correct rather than merely absent on a
    directory-level SBOM: the directory has no remote of its own, but the repository it lives
    in does, and that is the VCS location of its contents. The NEAREST carrier wins, because a
    sub-repo's own remote describes it better than its estate's does.

    A blank attribute is not an answer, so the walk continues past it. Stopping there would
    publish an empty url and, worse, suppress a real remote one level further up.

    Nothing is emitted when no ancestor carries a usable repo_url. An invented URL is worse
    than a missing one, because a consumer cannot tell it from a real one.

    Call this only for components describing INTERNAL model elements. Were it run against a
    3rd-party component in the External subtree, the walk would climb out to the estate root
    and attribute that package to the analyzed organisation's own repository.
    """
    ancestor = elem
    while ancestor is not None:
        repo_url = ancestor.attrs.get('repo_url', '').strip()
        if repo_url:
            component.setdefault('externalReferences', []).append({'url': repo_url, 'type': 'vcs'})
            return
        ancestor = ancestor.parent
```

`getPath()` returns `''` for the model root, which is a level-1 element's parent, so
`if parent_path:` is the entire top-level guard. There is deliberately **no** `parent is None`
fallback: it is unreachable from every call site, and where it would fire it would emit
`elementPath` as a bare name with no leading slash — a value that looks like a path but resolves
to nothing. Raising beats publishing that.

### Three call sites

`metadata_component` is assembled in more than one place, and a third site describes model
elements without being a metadata component. Every site that describes a **model element** gets
both fields; a site that describes something without a model path gets neither.

| Site | What it describes | Gets |
|---|---|---|
| `_sbom_for_content_element` (~:1045) | the metadata component of a `--level` or `--element-path` SBOM | location + vcs |
| transitive internal components (~:939) | reachable internal elements inlined into one BOM | location + vcs |
| `analyze_component_section` (~:820) | the level-1 element of the legacy single SBOM | location only; `group` self-omits |

Both public entry points — `generate_multi_from_sgraph` and `generate_for_element_from_sgraph` —
route through `_sbom_for_content_element`, so one edit there covers both. The legacy path keeps
its own existing vcs logic, including the fabricated-URL fallback, per non-goals.

3rd-party components from the External subtree get neither field: they describe packages, not
model elements, and already carry `sourceCodeReferences`.

### Tests

TDD order: characterization tests pinning current output first, then the feature. All 19 live in
one `# --- Element location tests ---` section of
`tests/converters/sbom_cyclonedx_generator_test.py`, using the `find_property` helper already in
that module. Names below are the shipped ones.

Characterization — pin what must NOT change:

| Test | Asserts |
|---|---|
| `test_purl_and_version_stay_empty_on_the_metadata_component` | both still `''` — guards against a later "fill the empty field" edit |
| `test_bom_ref_stays_the_slug_not_the_path` | still `repoa`/`repob`, not the path |
| `test_serial_numbers_stay_derived_from_the_element_path` | `serialNumber == deterministic_serial(element_path)` |

Location, against `modelfile_for_sbom_multi_tests.xml` (`/OrgName/GroupA/repoA`, `.../repoB`):

| Test | Asserts |
|---|---|
| `test_metadata_component_carries_element_path` | property equals `/OrgName/GroupA/repoA` |
| `test_metadata_component_carries_the_parent_path_as_group` | `group` equals `/OrgName/GroupA` |
| `test_element_path_matches_the_serial_number_for_every_sbom` | `deterministic_serial(path) == serialNumber`, for every SBOM |
| `test_element_location_is_level_agnostic` | at `--level 2` the group is `/OrgName` |
| `test_group_is_absent_at_the_top_level` | at `--level 1` no `group` key is emitted |
| `test_selected_element_sbom_also_carries_its_location` | `--element-path` gets the same fields, since it shares the helper |
| `test_legacy_single_sbom_carries_the_element_path` | `analyze_component_section` publishes the path and omits `group` |

Repository URL:

| Test | Asserts |
|---|---|
| `test_vcs_reference_comes_from_the_elements_own_repo_url` | `repoA`'s SBOM carries its `repo_url` as a vcs reference |
| `test_vcs_reference_is_inherited_from_the_nearest_ancestor` | a dir-level `--element-path` SBOM inherits the repo's URL |
| `test_no_vcs_reference_when_no_ancestor_has_one` | absent, not fabricated |
| `test_nearest_repo_url_wins_over_a_more_distant_ancestor` | the nearest carrier wins — the only test that can tell nearest from farthest |
| `test_a_blank_repo_url_does_not_mask_a_real_one_further_up` | a blank value is walked past, not published |

Transitive mode:

| Test | Asserts |
|---|---|
| `test_transitive_internal_components_carry_their_location` | the inlined `repoB` component carries `group` and `elementPath`, and keeps `softagram:internal` |
| `test_inlined_mirror_is_told_apart_from_its_host_by_its_published_location` | a component and its host share a name; location and the vcs URL separate them |

`repo_url` is added to `repoA` in the existing multi fixture. This is safe: the one existing test
asserting on those `externalReferences` filters `type == 'bom'` first. `repoB` deliberately keeps
none, so it can serve as the absence case.

A new fixture `modelfile_for_sbom_mirrored_tests.xml` carries one repository name under two
groups — the case the feature exists to disambiguate, which no existing fixture covers. `GroupA`
also carries a `repo_url` of its own, which is what makes the nearest-wins rule testable: it is
the only ancestor chain in the suite with two carriers on it.

| Test | Asserts |
|---|---|
| `test_mirrored_repositories_are_distinguished_by_their_location` | same `name`, distinct `group`, `elementPath` and `serialNumber` |
| `test_mirrored_repositories_carry_their_own_distinct_repository_urls` | each mirror publishes its own remote, not its neighbour's |

### Verification against a real model

```bash
.venv/bin/python -m sgraph.converters.sbom_cyclonedx_generator \
  model.xml sboms_level3.json --level 3
```

then check the invariants hold across every SBOM:

```python
import json
from sgraph.converters.sbom_cyclonedx_generator import deterministic_serial

sboms = json.load(open('sboms_level3.json'))
for s in sboms:
    c = s['metadata']['component']
    path = next(p['value'] for p in c['properties']
                if p['name'] == 'softagram:elementPath')
    assert deterministic_serial(path) == s['serialNumber'], c['name']
    assert path == c['group'] + '/' + c['name'], c['name']
print(len(sboms), 'SBOMs: elementPath consistent with serial and group')
```

Expected cost: additive fields only, so component counts, purls and serials must be
**byte-identical** to the previous run apart from the new fields and the timestamp. Any other
difference means something unintended moved.

---

## 5. Consumer impact

- **Additive.** No existing field changes value, so nothing already ingested breaks.
- The integration that motivated this drops the model download entirely.
- The reporting tool can delete its group-inference heuristic and read `group` and the estate
  straight from the metadata component — which also fixes the mirrored-repository ambiguity it
  currently cannot resolve.
- Transitive-mode consumers gain the location of every link in the exposure chain, not just its
  root.
