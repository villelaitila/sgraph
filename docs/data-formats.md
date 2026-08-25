---
layout: page
title: Data Formats
permalink: /data-formats/
---

# Data Formats

sgraph supports multiple data formats, each optimized for different use cases. This guide explains when and how to use each format.

## Overview

| Format | Use Case | File Size | Performance | Human Readable |
|--------|----------|-----------|-------------|----------------|
| **XML** | Large models, production | Compact | Very Fast | Moderate |
| **Deps** | Scripting, simple analysis | Small | Fast | Very High |
| **JSON** | Web applications | Medium | Moderate | High |
| **GraphML** | Graph visualization tools | Large | Moderate | Low |

## XML Format

The XML format is the primary format for sgraph, designed for performance and scalability.

### Structure

```xml
<model version="2.1">
  <elements t="architecture">
    <e n="root_element">
      <e n="child_element" i="2">
        <r r="3" t="relationship_type" />
      </e>
      <e i="3" n="target_element">
      </e>
    </e>
  </elements>
</model>
```

### Key Features

- **Integer References**: Elements use integer IDs (`i` attribute) for efficient relationships
- **Compact Representation**: Minimal XML overhead
- **Hierarchical Structure**: Nested elements represent containment
- **Relationships**: `<r>` tags define associations between elements
- **Attributes**: Custom attributes stored as XML attributes

### Attributes Reference

#### Element Attributes (`<e>`)
- `n` - Name of the element
- `i` - Unique integer identifier  
- `t` - Type of the element
- Custom attributes as needed

#### Relationship Attributes (`<r>`)
- `r` - Reference to target element ID
- `t` - Type of relationship
- Custom attributes for relationship metadata

### Example: C Project Structure

```xml
<model version="2.1">
  <elements t="c_project">
    <e n="nginx">
      <e n="src">
        <e n="core">
          <e n="nginx.c" t="source_file">
            <r r="2" t="includes" />
            <r r="3" t="includes" />
          </e>
          <e i="2" n="nginx.h" t="header_file">
          </e>
          <e i="3" n="config.h" t="header_file">
          </e>
        </e>
      </e>
    </e>
  </elements>
</model>
```

### Working with XML

```python
from sgraph import SGraph
from sgraph.modelapi import ModelApi

# Create and export to XML
model = SGraph(SElement(None, ''))
# ... build your model ...
model.to_xml('output.xml')

# Load from XML
api = ModelApi(filepath='model.xml')
elements = api.getAllElements()
```

## Deps Format

The Deps format is a simple, line-based text format perfect for scripting and quick analysis.

### Structure

```
source_path:target_path:relationship_type
source_path:target_path:relationship_type:attribute1=value1,attribute2=value2
```

### Examples

#### Basic Dependencies
```
/nginx/src/core/nginx.c:/nginx/src/core/nginx.h:includes
/nginx/src/core/nginx.c:/nginx/src/core/config.h:includes
/myapp/views.py:/myapp/models.py:imports
/myapp/views.py:/myapp/utils.py:imports
```

#### With Attributes
```
/api/user.py:/api/auth.py:imports:frequency=high,critical=true
/frontend/login.js:/api/auth.py:calls:method=POST,async=true
```

#### Hierarchical Elements Only
When no relationships exist, the format shows the hierarchical structure:
```
/nginx
/nginx/src
/nginx/src/core
/nginx/src/core/nginx.c
/nginx/src/core/nginx.h
```

### Working with Deps Format

```python
from sgraph import SGraph
from sgraph.converters.deps_to_xml import DepsToXml
from sgraph.converters.xml_to_deps import XmlToDeps

# Export to Deps
model.to_deps('dependencies.txt')

# Convert between formats
deps_to_xml = DepsToXml()
deps_to_xml.convert('dependencies.txt', 'model.xml')

xml_to_deps = XmlToDeps()
xml_to_deps.convert('model.xml', 'dependencies.txt')
```

### Command Line Usage

```bash
# Convert XML to Deps
python -m sgraph.converters.xml_to_deps model.xml output.deps

# Convert Deps to XML  
python -m sgraph.converters.deps_to_xml dependencies.txt model.xml

# Filter deps files
grep "\.py:" dependencies.txt > python_deps.txt
```

## JSON Format

JSON format provides a web-friendly representation of sgraph models.

### Structure

```json
{
  "model_version": "2.1",
  "root": {
    "name": "root",
    "type": "root",
    "children": [
      {
        "name": "module1",
        "type": "module",
        "attributes": {
          "language": "python",
          "lines": 150
        },
        "children": [],
        "relationships": [
          {
            "target_path": "/module2",
            "type": "imports",
            "attributes": {}
          }
        ]
      }
    ]
  }
}
```

### Working with JSON

```python
from sgraph.converters.sgraph_json import SGraphJson
from sgraph.converters.xml_to_json import XmlToJson

# Convert to JSON
converter = XmlToJson()
converter.convert('model.xml', 'model.json')

# Load JSON in web applications
import json
with open('model.json', 'r') as f:
    model_data = json.load(f)
```

## GraphML Format

GraphML is a standard XML format for graphs, supported by many visualization tools.

### Features

- Compatible with Gephi, yEd, Cytoscape
- Rich metadata support
- Standard format for graph exchange

### Working with GraphML

```python
from sgraph.converters.xml_to_graphml import XmlToGraphMl

# Convert to GraphML
converter = XmlToGraphMl()
converter.convert('model.xml', 'graph.graphml')

# Import into visualization tools:
# - Gephi: File > Open > graph.graphml
# - yEd: File > Open > graph.graphml  
# - Cytoscape: File > Import > Network from File
```

## CycloneDX SBOM Format

`sgraph.converters.sbom_cyclonedx_generator` emits CycloneDX documents. It can produce a
single SBOM for the whole model, one SBOM per element at a chosen tree depth (`--level`), or one
for a named element (`--element-path`).

```bash
# One SBOM per repository, for a model whose repositories sit at depth 3
python -m sgraph.converters.sbom_cyclonedx_generator model.xml sboms.json --level 3
```

### The declared specification version

Documents declare **CycloneDX 1.6** by default. `--spec-version` selects another of `1.4`, `1.5`,
`1.6` and `1.7`; anything else is refused rather than passed through to `specVersion`.

The document content is identical across that whole range — only the declared version differs.
Every document the generator can produce validates against the official bom-1.4, bom-1.5 and
bom-1.6 schemas with nothing but the version string swapped, and those schemas set
`additionalProperties: false` at both the document root and the component, so nothing in the
output requires the newest specification.

What the version does decide is whether a consumer will read the document at all. CycloneDX 1.7
was published in October 2025, and a tool built against an earlier library rejects a 1.7 document
on the version string alone, before reading any of its content. Hence the default: 1.6 carries
the same information to a far larger installed base. Ask for 1.7 when the consuming tool is known
to support it.

```bash
# For a consumer that supports the newest specification
python -m sgraph.converters.sbom_cyclonedx_generator model.xml sboms.json \
    --level 3 --spec-version 1.7
```

`--spec-version` works in **every** mode, including the single-SBOM mode that rejects the closure
flags below. The asymmetry is deliberate: the closure flags would be silently ignored there,
whereas refusing a version selection would strand the one export shape that has no `--level`
behind a version its consumer cannot read.

The same selection is available on `generate_from_sgraph`, `generate_multi_from_sgraph` and
`generate_for_element_from_sgraph` as a `spec_version` keyword. 1.3 is deliberately not offered:
it is permissive where the later schemas are strict, so conformance to it could not be checked.

### The transitive dependency closure

By default a document lists the 3rd-party packages the analyzed code itself declares. A package
that only *another package* depends on — the resolved closure a lockfile records — is left out,
even when the model holds those package-to-package edges.

`--transitive-externals` follows them, so the whole closure reaches the document. It is opt-in:
the closure multiplies component counts, and every existing consumer of the default output keeps
receiving exactly what it received before. `--max-depth N` caps how deep the walk goes.

```bash
# Direct dependencies plus everything they pull in, no deeper than two hops
python -m sgraph.converters.sbom_cyclonedx_generator model.xml sboms.json \
    --level 3 --transitive-externals --max-depth 2
```

Both options require `--level` or `--element-path`; the single-SBOM mode does not accept them.
`--max-depth` requires `--transitive-externals`, and must be 1 or greater: a smaller cap excludes
every component the walk could emit, so it is refused rather than rounded up to the shallowest
level.

| Field | Meaning |
|-------|---------|
| `properties[dependencyDepth]` | Package hops between the component and the analyzed code: `1` for a package the code declares, `2` for one that package pulls in, and so on. When a package is reachable by several routes, the **shortest** is reported — including routes through the internal elements a `--transitive` document inlines, so the depth a component publishes always agrees with where the `dependencies` section of the same document places it. |

- The property is present on **every** 3rd-party component of a `--transitive-externals`
  document, depth 1 included, and **absent from every component** of a default one. So an absent
  property means the document makes no depth claim — never "this package is direct".
- Only edges that mean *package depends on package* are followed (the manifest and lockfile
  deptypes). Code-level edges between externals are not: they describe how code is written, not
  what a manifest declares, and following them would list packages the project never depends on.
- A development-section declaration is followed exactly like a production one. Whether such a
  package should be scoped differently in the document is a separate question this option does
  not answer.
- The option is **inert on a model that holds no package-to-package edges the converter
  recognises**: the components are the same, only the depth property is added. What a document
  contains depends on what the analyzers stored, not on the flag alone. The recognised deptypes
  are the manifest and lockfile ones — `packagejson`, `packagelock`, `pip`, `package_reference`,
  `nuget` and `pubspec`, each also in its `dev_`-prefixed form. Anything else between two
  externals is skipped.
- **An empty closure says so.** When a document follows no package-to-package edge at all while
  edges between external elements were skipped for their deptype, one line naming those deptypes
  is written to stderr. Otherwise an unrecognised deptype and a model with no closure at all
  produce the same document, and nothing distinguishes them.

#### Which repository's edges a document follows

The `External` subtree is project-wide: every repository's resolved tree lands in the same
`External/<ecosystem>` elements and shares the versioned ones. A package-to-package edge on its
own therefore says nothing about which repository's manifest declared it, and a naive closure
walks a sibling's edges — putting packages in a document at versions that repository does not
install. Measured on two real repositories in one estate, 6 % and 4 % of the closure was another
repository's.

The analyzers record the declaring scope on each such edge, as the model path of the directory
whose manifest declared it (the repository root for the ordinary lockfile that sits there). Where
several manifests declare the same edge, every scope is recorded — the paths joined by `//`,
a sequence that cannot occur inside a single model path.

An edge is followed when its declaring scope and the element the document is rooted at lie on the
**same root-to-leaf line**: the scope is that element, an ancestor of it, or a descendant of it.
Not merely "inside it" — a lockfile sits at a repository root while a directory-level document is
rooted below it, so an "inside" test would empty the closure of every directory-level document.

**An edge with no declaring scope is followed.** Every model stored before the attribute existed
carries none, and the pip and NuGet analyzers record none today. Absence means unknown
provenance, and unknown provenance keeps the behaviour that was there before; reading it as
"skip" would silently empty those closures.

With the closure, `dependencies` becomes a graph rather than a flat list: every package that
pulls in another gets an entry of its own, so a consumer can trace *which* package introduced an
exposure instead of only learning that it is present.

```json
"dependencies": [
  { "ref": "repoa", "dependsOn": ["pkg:npm/express@4.18.2"] },
  { "ref": "pkg:npm/express@4.18.2", "dependsOn": ["pkg:npm/body-parser@1.20.1"] },
  { "ref": "pkg:npm/body-parser@1.20.1", "dependsOn": ["pkg:npm/qs@6.11.0"] }
]
```

- A package reached **only** through another one is listed under that package, not under the
  element. Listing it under the element would assert a direct dependency no manifest declares,
  and contradict the `dependencyDepth` the same document publishes for it.
- A package that is **both** declared and pulled in appears under both.
- Every ref resolves within the document, except `urn:cdx:` BOM-Links, which name another
  document by design.
- Without `--transitive-externals` there are no package-to-package hops, so the section keeps the
  single flat entry it has always had.

### Internal packages

A dependency that resolves to **another element of the same estate** is a third category: not the
document's own subject, and not a 3rd-party package. It appears as a component marked
`softagram:internal`, alongside the `urn:cdx:` BOM-Link that has always been in `dependsOn`.

```json
{ "bom-ref": "repob",
  "type": "library",
  "name": "ui-lib",
  "version": "2.1.0",
  "purl": "pkg:generic/ui-lib@2.1.0",
  "group": "/OrgName/GroupA",
  "properties": [
    { "name": "softagram:internal", "value": "true" },
    { "name": "softagram:packageName", "value": "ui-lib" },
    { "name": "softagram:packageEcosystem", "value": "npm" },
    { "name": "softagram:elementPath", "value": "/OrgName/GroupA/repoB" }
  ],
  "externalReferences": [
    { "url": "urn:cdx:b02cf884-4fe6-5d96-8bab-a649ae9844b2/1", "type": "bom" },
    { "url": "https://example.org/org/repoB.git", "type": "vcs" }
  ] }
```

| Field | Meaning |
|-------|---------|
| `name` / `version` / `purl` | The package the element publishes, when the model says unambiguously which one that is. Otherwise the element's own name, an empty version and an empty purl. |
| `properties[softagram:internal]` | Always `"true"` on these components. |
| `properties[softagram:packageName]` | The published package name, the same one spliced into the purl. |
| `properties[softagram:packageEcosystem]` | The ecosystem the package is published in (`npm`, `pypi`, ...). Absent when the model does not name one; it decides no part of the purl. |
| `externalReferences[type=bom]` | BOM-Link to that element's own standalone document. |

- **The purl type is `generic`, never the ecosystem's own type.** `pkg:npm/<name>@<version>` would
  assert an identity in the public npm registry. Either the name is not published there, in which
  case the npm type buys nothing, or it is and belongs to someone else, in which case the
  component silently inherits a stranger's advisories. The ecosystem is published as a property
  instead, so nothing is lost but the false claim.
- The dependency is emitted **both** as this component and as a `urn:cdx:` BOM-Link in
  `dependsOn`. The link federates to the element's own document for a consumer that follows
  links across uploads; the component is what a consumer that does not follow them can see at
  all.
- Only **direct** internal dependencies are inlined into a default document. `--transitive`
  inlines the whole chain of them, together with the 3rd-party components of every link.
- **In a default document the component appears only when the element publishes a package
  identity**; without one, `dependsOn` carries the BOM-Link alone, exactly as before. A component
  named after a repository or a directory, with no version and no purl, is the very shape the
  missing-identifier problem is about, and until an analyzer stamps the identity attributes every
  such component on an existing model would come out that way. So the default document changes
  for a consumer only once the row can carry real coordinates.
- **`--transitive` deliberately does not take that rule.** Inlining internal elements is what
  that option has always done and its consumers already receive those rows; identity improves
  them where it exists, but its absence must not delete a dependency a consumer can see today.
  The asymmetry is intentional, not an inconsistency.
- **How many of these a document holds scales with the granularity you select.** They are not a
  fixed overhead: they are one component per element the chosen element directly depends on, so
  the count follows the `--level` (or `--element-path`) you pass. A repository-level export
  usually gains a handful. A directory-level export splits the same estate into far more, and
  finer, elements, so dependencies that were internal to one repository become cross-element
  ones — on a large repository a single directory-level document has been measured gaining
  several hundred. That is the number of dependencies that directory genuinely has, not a
  closure being walked; if it is more than you want, export at a coarser level.
- An element that publishes **several** packages with nothing to choose between them is given no
  identity at all: it keeps the element name and carries **no `purl` key**. No coordinates are
  invented. (Before 1.13.0 the key was present and empty, which CycloneDX types as an
  iri-reference and the empty string is not one.)
- Components describing internal packages carry **no** `dependencyDepth`. That property counts
  package hops through the 3rd-party closure, and an element of the estate is not one.

### What the document does not cover

A component list cannot say what is missing from it. An external the analyzer saw and the
generator could not identify leaves no trace, so a consumer cannot tell "this estate depends on
nothing else" from "we could not identify the rest".

`--coverage` says it, in single-SBOM mode:

```bash
python -m sgraph.converters.sbom_cyclonedx_generator model.xml sbom.json --coverage
```

It adds two things. Five `metadata.properties` counting what was and was not identified under
`External` — components emitted, not a package, version unknown by design, could not identify,
unknown root kind — and one `compositions` entry stating whether the third-party assembly is
complete:

```json
"compositions": [{ "aggregate": "incomplete", "assemblies": ["/Org"] }]
```

| `aggregate` | When |
|-------------|------|
| `incomplete` | Externals were seen that could not be identified, or that sit under a root with no rule. |
| `unknown` | Everything seen was explained. Whether everything was *seen* is a different question. |
| `not_specified` | No `External` subtree at all, so there is no basis for a claim. |

#### `coverageUnknownRootKind`, and why it is not part of `coverageCouldNotIdentify`

`couldNotIdentify` means an identification was attempted and failed. It is only a meaningful
number if everything counted into it actually claimed to be a third-party package.

An element under a root this library has no rule for makes no such claim. The `External` subtree
is organised into roots — `NPM`, `PIP`, `Maven`, and so on — and the converter carries a table of
what each root *is*: a package registry, an import graph, a standard library, a filesystem
namespace. A model can carry roots absent from that table, and they are common: `TypeScript`,
`JavaScript`, `Node`, `DotNet`, `Rust`, the `Odoo*` roots, Java and Android package namespaces.
Under such a root nothing is known about what its members are, so neither "we failed to identify
a package" nor "this is not a package" is supported.

Those elements are counted separately, under a name that says what is true. The difference is
large: across a 20-model corpus this split moved 78,877 of 80,971 elements out of
`couldNotIdentify`, leaving 1,991 that are genuine identification failures.

Nothing is hidden — a consumer wanting the old total adds the two. What changes is that the two
numbers call for different responses: `couldNotIdentify` is identification work, while
`unknownRootKind` is answered by classifying a handful of roots.

**What this is not.** A root's absence from the table does not make its contents non-packages.
An unmapped `JavaScript` or `TypeScript` root holds real npm packages beside code symbols, and
depth does not separate them either — `java/util` at package depth is the standard library while
`TypeScript/vue-router` at the same depth is a real package. No shape rule is guessed at; the gap
is reported instead. A root that is *in* the table and asserts no ecosystem (`Docker`, `JVM`,
`Java`) is a different case and is not counted here.

- **`complete` is never emitted.** CycloneDX defines it as "no further relationships ... are
  KNOWN to exist". The report proves only that every element the walk *saw* was classified, never
  that the analyzer saw everything — an analyzer that was not run leaves no evidence that it was
  missing. Claiming completeness makes a consumer stop looking, so the strongest honest claim is
  `unknown`, which the specification defines as a best-effort whose completeness is inconclusive.
- **Single-SBOM mode only.** The report is model-wide, so attaching it to a `--level` or
  `--element-path` document would claim that *that* document's assembly is incomplete because some
  other subtree's is. `--coverage` combined with either is refused rather than emitted with a
  caveat.
- **Opt-in.** Without the flag the document is exactly what earlier releases produced.
- The five counts are properties rather than part of the composition because a composition holds
  `aggregate`, `assemblies`, `dependencies` and `vulnerabilities` and nothing else. Completeness
  fits the standard; a ten-category taxonomy with counts and samples does not.
- Combines with `--spec-version`; the counts and the composition are valid at every supported
  version, since the three `aggregate` values used are defined from 1.4 onward.


### Where an element lives

Every component that describes a **model element** — the metadata component of each document,
and every internal component — publishes its position in the model:

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
    { "name": "softagram:elementPath", "value": "/OrgName/GroupA/repoA" },
    { "name": "softagram:elementType", "value": "repository" }
  ] }
```

| Field | Meaning |
|-------|---------|
| `group` | The **full path of the parent element**, not just its name. Omitted for a top-level element, which has no parent path. |
| `properties[softagram:elementPath]` | The element's own full path. A property rather than a field because the CycloneDX component schema sets `additionalProperties: false`. |
| `properties[softagram:elementType]` | What the **model** calls this element — `repository`, `dir`, `file`, and so on. **Present only when the model carries a type**; see below. |
| `externalReferences[type=vcs]` | The `repo_url` of the element, or of the **nearest ancestor** carrying a non-blank one. Absent when no ancestor has one — never a placeholder. |

#### `softagram:elementType`

A `--level` export splits at a tree depth, and what sits at that depth is usually a repository but
not always. A document describing a directory, or a file, that emits no components is
indistinguishable from a repository that genuinely has no dependencies — and those mean opposite
things: "nothing to report" versus "not the kind of thing that reports". `component.type` cannot
carry the distinction, because CycloneDX closes that enum and has no `repository` value.

**The property is absent when the model carries no type, and absence means "not stated" — never
"not a repository".** Repository elements are not required to carry a `type` attribute, so a
missing one is evidence of nothing. Emitting `unknown` or `""` there would turn silence into a
positive claim, and a consumer filtering on `elementType != "repository"` would then exclude
genuine repositories on the strength of an invented value. Filter on the property's *presence*
before filtering on its value.

Expect more values than `repository` and `dir`. A level split on a small single-repository model
reaches file and function elements, so `file`, `function`, `variable`, `class` and `page` all
occur. The property states what the model says in every case.

Components describing **3rd-party packages** carry none of these. Their identity is the `purl`.

### Guarantees

- **Every `properties[].value` is a JSON string**, including the ones that carry a number.
  CycloneDX types the field as a string in every spec version this converter emits, and sets
  `additionalProperties: false`, so a numeric value is not merely untidy: a validating consumer
  rejects the whole document rather than the one field. Counts such as `indirectExposureCount`
  are therefore published as `"3"`, not `3`, and a consumer reading them numerically has to
  parse them — the same as for `dependencyDepth`.
- `deterministic_serial(elementPath) == serialNumber` **in `--level` and `--element-path` mode**.
  The published path is the exact string the serial is derived from, so a consumer can verify a
  document's identity without the model.

  **This does not hold in single-SBOM mode**, where `serialNumber` is a random UUID v4 minted per
  call: two runs over an unchanged model produce different serials, and neither is derived from
  the element path the document publishes. A consumer must not apply the check above to a
  single-SBOM document. This is long-standing behaviour rather than a recent change, and altering
  it would change the identity every existing single-SBOM consumer files the document under, so it
  is documented here rather than quietly repaired.
- `group + '/' + name == elementPath` below the top level.
- Two repositories that share a name under different groups are distinguished by `group` and
  `elementPath`. They are *not* reliably distinguished by `bom-ref`, whose collision suffix
  (`repoa`, `repoa-2`) depends on traversal order and can change between model generations.

### Caveats

- **The first path segment is the estate root and is not stable.** It changes when the estate is
  renamed or restructured. Read it from the path rather than hardcoding it.
- **`group` holds a path, not a package namespace.** The CycloneDX specification suggests
  avoiding special characters in `group` and shows package coordinates such as
  `org.apache.commons`. A model group is a tree location, so this converter puts the parent's
  full path there. Tools that render `group` as a package coordinate will show the path.

  **What the path buys, stated accurately.** It distinguishes two *groups* that share a name under
  different parents — `/Estate/TeamA/tools` and `/Estate/TeamB/tools` — *in a model that has such
  a pair*. Many models have none. Measured across three real single-root estates at both level 2
  and level 3, every full-path `group` value mapped one-to-one onto its bare name (73 → 73, 78 →
  78, 11 → 11), so the prefix disambiguated nothing in any of them.

  So the path is a guarantee that holds for *every* model, not a fix for a collision every model
  has, and a reader should not infer that their own `group` values would collide without it. Note
  the collision it guards against is between **groups**; two repositories sharing a name under
  *differently* named groups are already distinguished by the group name alone.

  **If you want the bare name, take it from the path**; the last segment is the parent's name.
  And if you want an unambiguous identifier for the element itself, use
  `properties[softagram:elementPath]`, which is unique across all documents from one model and is
  the string the serial number is derived from — `group` is not the field to reach for. Note the
  first path segment is the estate root and changes when the estate is renamed, so anything
  derived from `group` inherits that instability.
- **`purl` and `version` are empty on the metadata component**, and on an internal component
  whose element publishes no unambiguous package. A repository has no package identity and no
  version of its own; a path is not a valid purl and is deliberately not placed there. An
  internal component whose element *does* publish one carries that package's coordinates — see
  [Internal packages](#internal-packages).
- The vcs reference is inherited by proximity. A repository with no remote of its own, under a
  group that has one, reports the group's URL.

## Format Comparison

### Performance Benchmarks

| Format | 1K Elements | 100K Elements | 1M Elements |
|--------|-------------|---------------|-------------|
| XML Load | 10ms | 500ms | 5s |
| Deps Load | 5ms | 200ms | 2s |
| JSON Load | 15ms | 800ms | 8s |
| GraphML Load | 20ms | 1.2s | 12s |

### File Size Comparison

For a typical software project with 10K elements:

| Format | File Size | Compression Ratio |
|--------|-----------|-------------------|
| XML | 2.5 MB | 1.0x (baseline) |
| Deps | 800 KB | 3.1x smaller |
| JSON | 4.2 MB | 1.7x larger |
| GraphML | 8.1 MB | 3.2x larger |

## Best Practices

### Choosing the Right Format

**Use XML when:**
- Working with large models (>10K elements)
- Need maximum performance
- Building production systems
- Preserving all metadata and attributes

**Use Deps when:**
- Simple dependency analysis
- Scripting and automation
- Human-readable output needed
- Working with shell tools (grep, awk, etc.)

**Use JSON when:**
- Building web applications
- Need JavaScript compatibility
- Creating REST APIs
- Moderate-sized models (<50K elements)

**Use GraphML when:**
- Importing into visualization tools
- Sharing with researchers
- Need standards compliance
- One-time analysis tasks

### Performance Optimization

#### For Large Models
```python
# Use XML format for storage
model.to_xml('large_model.xml')

# Load with ModelApi for efficient querying
api = ModelApi(filepath='large_model.xml')

# Use specific queries instead of loading all elements
functions = api.getElementsByType('function')
specific_elements = api.getElementsByName('main')
```

#### For Streaming Processing
```python
# Process deps format line by line for very large files
def process_large_deps_file(filepath):
    with open(filepath, 'r') as f:
        for line in f:
            if ':' in line:
                parts = line.strip().split(':')
                source, target, rel_type = parts[:3]
                # Process dependency
                yield source, target, rel_type
```

### Memory Management

```python
# For very large models, use streaming
from sgraph.loader.modelloader import ModelLoader

# Load incrementally
loader = ModelLoader()
for element_batch in loader.load_streaming('huge_model.xml', batch_size=1000):
    # Process batch
    process_elements(element_batch)
```

## Migration Between Formats

### Preserving Metadata

When converting between formats, be aware of metadata preservation:

| From → To | Elements | Relationships | Attributes | Performance |
|-----------|----------|---------------|------------|-------------|
| XML → Deps | ✅ Paths only | ✅ | ⚠️ Limited | Fast |
| XML → JSON | ✅ | ✅ | ✅ | Medium |
| XML → GraphML | ✅ | ✅ | ✅ | Slow |
| Deps → XML | ✅ | ✅ | ⚠️ Limited | Fast |

### Batch Conversion

```python
import os
from sgraph.converters.xml_to_deps import XmlToDeps

def convert_project_models(input_dir, output_dir):
    """Convert all XML models to Deps format"""
    converter = XmlToDeps()
    
    for filename in os.listdir(input_dir):
        if filename.endswith('.xml'):
            input_path = os.path.join(input_dir, filename)
            output_path = os.path.join(output_dir, filename.replace('.xml', '.deps'))
            
            print(f"Converting {filename}...")
            converter.convert(input_path, output_path)

# Usage
convert_project_models('models/', 'deps_output/')
```

## Advanced Features

### Custom Attributes in XML

```xml
<e n="MyClass" t="class" visibility="public" complexity="high" loc="250">
  <r r="2" t="inherits" strength="strong" />
</e>
```

### Relationship Attributes in Deps

```
/src/main.py:/src/utils.py:imports:frequency=10,last_used=2023-12-01
```

### Nested Attributes in JSON

```json
{
  "name": "MyFunction",
  "attributes": {
    "metrics": {
      "complexity": 15,
      "lines": 45,
      "parameters": 3
    },
    "metadata": {
      "author": "developer",
      "last_modified": "2023-12-01"
    }
  }
}
```

Understanding these formats allows you to choose the right tool for each task and integrate sgraph into your development workflow effectively!

