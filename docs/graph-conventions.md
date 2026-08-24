---
layout: page
title: Graph Conventions
permalink: /graph-conventions/
---

# Graph Conventions

sgraph is a generic hierarchical graph library. The data model itself is convention-agnostic: elements form a tree, associations form directed edges, and both carry arbitrary key-value attributes. The **convention** defines how these primitives are used to represent a specific domain.

This document describes the known conventions. Understanding the active convention is essential for writing meaningful queries, building correct tooling, and (in the future) mapping sgraph structures to query languages like Cypher.

## Convention: Software Architecture

Used by Softagram analyzers and the sgraph-mcp-server to represent analyzed codebases.

### Top-Level Structure

Every software architecture model has a single **project element** (P) directly under the root. This element represents the analysis target — it may be a single project, a mono-repo, or an umbrella node covering an entire organization's codebases.

```
root (unnamed)
└── P (project element — exactly one)
    ├── External/          (3rd-party dependencies)
    ├── repo-a/            (git repository, type="repo")
    ├── repo-b/            (git repository, type="repo")
    └── ...
```

**Key rules:**

- There is exactly **one** project element P under the root.
- P's name is typically the project or organization name.
- In a **multi-repo** analysis, P's children include multiple git repositories (type `repo`) plus the `External` subtree.
- In a **single-repo / local** analysis, P itself represents the sole git repository. Its children (besides `External`) are directories and files directly. Nested git submodules may still appear with type `repo` deeper in the tree.

### The External Subtree

The child of P named **`External`** is the ancestor of all identified third-party dependencies. Its internal structure is organized by package ecosystem:

```
P/
└── External/
    ├── Python/
    │   ├── requests/
    │   ├── flask/
    │   └── ...
    ├── NPM/
    │   ├── react/
    │   ├── lodash/
    │   └── ...
    ├── Docker/
    │   └── Image/
    │       ├── nginx:latest/
    │       └── ...
    ├── Go/
    ├── Maven/
    ├── Java/
    ├── Assemblies/      (.NET)
    └── APT/
```

External elements may carry a `repotype` attribute indicating the package manager (e.g., `NPM`, `PIP`, `APT`). The `version` attribute stores the resolved version when available.

An element can be tested for externality by checking whether any of its ancestors is named `External`. The library provides `isExternalElement()` for this purpose.

#### Root semantics: registries, import graphs and stdlib namespaces

The children of `External` are **not** interchangeable. Three distinct kinds share the level, and confusing them is the single largest source of misidentification:

| Root | purl type | Kind | Depth semantics | Written by |
|---|---|---|---|---|
| `PIP` | `pypi` | registry | depth 1 = package, depth 2 = versioned instance | pip / requirements analyzer |
| `Python` | `pypi` | **import graph** | depth 1 = imported module, deeper = subpath or code symbol | Python import analyzer |
| `PythonLibs` | — | **stdlib namespace** | the standard library, never a dependency | structure analytics |
| `NPM` | `npm` | registry **and** import graph | depth 1 = package; deeper = import subpath. A name may itself contain `/` (encoded `__slash__`) when it came from an install path | npm audit / lockfile / JS import analyzers |
| `Go` | `golang` | import graph; `Go/Standard_Go` is stdlib | module paths contain `/` legitimately | Go analyzer |
| `Maven` | `maven` | registry | identity is the `groupId`+`artifactId` attributes, not the name | Maven analyzer |
| `Assemblies` | `nuget` | registry | depth 1 = assembly | .NET analyzer |
| `APT` | `deb` | registry | depth 1 = package | Dockerfile analyzer |
| `Docker/Image` | `docker` | image identity | name carries ` of tag <tag>` | Dockerfile analyzer |
| `Docker/FilesysReference` | — | **filesystem paths** | `COPY` sources; not packages at all | Dockerfile analyzer |
| `Java` | — | unclassified | — | — |

An element under an import-graph root carrying **no version** is normally a module reference, not a missing dependency: the same package usually appears under the corresponding registry root with its version. An element whose incoming associations are all of deptype `ref` is an unresolved code symbol, not a package.

`PythonLibs` and `Go/Standard_Go` deliberately assert **no** purl type. The standard library is not a dependency, and giving it an ecosystem would make a stdlib module name match a real published package — `dataclasses` is both a Python 3.7+ stdlib module and a real PyPI backport package.

**The two npm shapes, which look alike and mean opposite things.** A slash in a *single element's name* (stored `__slash__`) is an **install path** written by the lockfile or audit analyzer: `wrap-ansi-cjs/strip-ansi` is `strip-ansi` as installed underneath `wrap-ansi-cjs`. Nested parent/child elements are an **import subpath** written by the JS import analyzer: `NPM/react-dom` with a child `server` is `react-dom/server`. In an install-path name the leading segments are the packages that **required** the package — they are requirers, not containers — and the final segment, or the final two when the package is scoped, is the installed package itself. The version on such an element belongs to that leaf, not to any prefix: a nested install exists precisely because the required version differs from the one hoisted to the top level, so the leaf at that exact version often appears nowhere else in the model.

This documents the *convention*. sgraph itself remains convention-agnostic; the registry encoding this table lives in `sgraph/converters/external_root_semantics.py`.

### Element Types

Element types are stored in the `type` attribute (`attrs['type']`). Types are free-form strings — the library does not enforce an enum. The following types are conventional:

#### Structural Types

| Type | Meaning |
|------|---------|
| `repo` | Git repository root |
| `dir` | Directory / folder |
| `file` | Source file (generic) |

#### Language-Specific File Types

| Type | Meaning |
|------|---------|
| `c_source` | C source file (.c) |
| `c_header` | C header file (.h) |
| `python_module` | Python module (.py) |

#### Code-Level Types

| Type | Meaning |
|------|---------|
| `class` | Class definition |
| `function` | Function or method |
| `interface` | Interface definition |
| `property` | Property or field |
| `package` | Package / namespace |

**Notes:**
- The `repo` type is preserved and never overwritten by directory-type inference.
- Composite types (e.g., `file_class`) can arise during element merging when two elements with different types are combined.
- Not all elements have a type — `getType()` returns an empty string when unset.

### Association Types (Dependency Types)

Associations represent directed dependencies between elements. The type is stored in the `deptype` field of `SElementAssociation`.

| deptype | Meaning |
|---------|---------|
| `inc` | Include directive (C/C++ `#include`) |
| `imports` | Import statement |
| `function_ref` | Function call / reference |
| `inherits` | Class inheritance |
| `implements` | Interface implementation |
| `use` | General dependency (unclassified) |
| `calls` | Function/method invocation |
| `assembly_ref` | .NET assembly reference |

**Dynamic (inferred) dependencies** are prefixed with `dynamic_` (e.g., `dynamic_function_ref`). These are generated by `SGraphAnalysis.generate_dynamic_dependencies()` for cases like polymorphic method dispatch where the static call target differs from the runtime target.

### Common Element Attributes

| Attribute | Type | Meaning |
|-----------|------|---------|
| `type` | str | Element type (see above) |
| `loc` | int | Lines of code |
| `visibility` | str | Access modifier (public, private, ...) |
| `complexity` | int | Cyclomatic complexity |
| `repo_url` | str | Git remote URL (on repo elements) |
| `version` | str | Version string (on External dependencies) |
| `repotype` | str | Package ecosystem (NPM, PIP, APT, ...) |

### Association Attributes

| Attribute | Type | Meaning |
|-----------|------|---------|
| `compare` | str | Change status: `added`, `removed`, `changed` (in diff models) |

### Hierarchy Semantics

In the software convention, the hierarchy represents **structural containment**:

- A directory *contains* its files
- A file *contains* its classes, functions, and other declarations
- A class *contains* its methods and properties
- A repository *contains* its directory tree

This containment relationship is implicit in the parent-child tree. Associations (edges) represent **semantic dependencies** that cross the containment boundary — a function calling another function, a file importing another file, a class inheriting from another class.

### Path Format

Element paths use `/` as separator and start from the project element:

```
/my-project/src/main/java/com/example/App.java/App/main
 ^project   ^directories                ^file  ^class ^method
```

External dependency paths:

```
/my-project/External/Python/requests
/my-project/External/NPM/react
/my-project/External/Docker/Image/nginx:latest
```

---

## Convention: Genealogy

Used by the sgraph-genealogy-mcp-server to represent family trees.

### Top-Level Structure

All persons are placed as **direct children of the root element** — the hierarchy is flat.

```
root (unnamed)
├── Matti Leppanen 1804 Taipale, Kivijarvi K. 1860 Kivijarvi
├── Johan Leppanen 1770 Kivijarvi K. 1850
├── Hilda Sofia Storck (Hanninen) 1906 K. 1976
└── ...
```

### Element Naming Convention

Each person's name encodes structured biographical data in a single string:

```
FirstName [Patronym] LastName [(FormerName)] BirthYear BirthPlace K. DeathYear DeathPlace
```

| Component | Example | Required |
|-----------|---------|----------|
| First name(s) | `Matti`, `Hilda Sofia` | Yes |
| Patronymic | `Iisakinpoika`, `Matintytär` | No |
| Last name(s) | `Leppanen`, `Storck` | Yes |
| Former/maiden name | `(Hanninen)`, `(Rintala)` | No |
| Birth year | `1804` | Yes |
| Birth place(s) | `Taipale, Kivijarvi` | No |
| Death marker | `K.` (Kuollut) | Only if deceased |
| Death year | `1860` | Only if deceased |
| Death place(s) | `Kivijarvi` | No |

Approximate dates are prefixed with `noin` (approximately), `ennen vuotta` (before year), or `arviolta` (estimated). Negative years represent BC dates.

### Association Types

| deptype | Meaning | Direction |
|---------|---------|-----------|
| `parent` | Parent relationship | child → parent |

This is the only association type. A person has outgoing `parent` associations pointing to their parents. Incoming `parent` associations come from their children.

### Hierarchy Semantics

In the genealogy convention, the hierarchy is **not semantically meaningful** — it serves only as a flat container. All family relationships are expressed through associations, not through parent-child tree nesting.

---

## Defining New Conventions

When creating a new sgraph convention for a domain, document the following:

1. **Top-level structure**: How many elements under root? What do they represent?
2. **Hierarchy semantics**: Does the tree represent containment, categorization, or is it flat?
3. **Element types**: What values does the `type` attribute take? What do they mean?
4. **Naming convention**: Is the element name a simple identifier or does it encode structured data?
5. **Association types**: What `deptype` values exist and what relationships do they represent?
6. **Direction convention**: For each association type, what does the direction (from → to) mean?
7. **Standard attributes**: What attributes are expected on elements and associations?

These definitions form the **schema** that enables meaningful queries, whether through the ModelApi, MCP tools, or query languages like Cypher.

---

## Implications for Query Languages

The convention determines how sgraph maps to external query models:

| Concept | Software Convention | Genealogy Convention |
|---------|-------------------|---------------------|
| **Node labels** (Cypher) | Element type: `:File`, `:Class`, `:Function` | All nodes are `:Person` |
| **Relationship types** (Cypher) | deptype: `:IMPORTS`, `:CALLS`, `:INHERITS` | `:PARENT_OF` |
| **Hierarchy** | Explicit `:CONTAINS` relationships or path property | Not applicable (flat) |
| **Properties** | Attributes from `attrs` dict | Parsed from element name |
