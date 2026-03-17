---
layout: page
title: Cypher Query Support
permalink: /cypher/
---

# Cypher Query Support

sgraph provides built-in support for querying models using the [openCypher](https://opencypher.org/) query language. This is powered by [sPyCy](https://github.com/aneeshdurg/spycy), a Python implementation of openCypher with a pluggable graph backend.

## Installation

Cypher support requires sPyCy as an optional dependency:

```bash
pip install spycy-aneeshdurg
```

## How It Works

sgraph's data model is a **hierarchical graph** — elements form a tree, and associations form directed edges between elements. Cypher operates on **labeled property graphs** (flat nodes with labels, typed relationships with properties). The `SGraphCypherBackend` bridges these two models:

| sgraph concept | Cypher concept |
|---|---|
| SElement | Node |
| Element `type` attribute | Node label (e.g., `:file`, `:class`) |
| Element `attrs` + name/path | Node properties |
| SElementAssociation | Relationship |
| Association `deptype` | Relationship type (e.g., `:imports`, `:function_ref`) |
| Parent-child hierarchy | `:CONTAINS` relationships (optional) |

Elements without a `type` attribute have no labels. The `name` and `path` properties are always available on every node.

## Python API

```python
from sgraph import SGraph
from sgraph.cypher import cypher_query

model = SGraph.parse_xml_or_zipped_xml('model.xml.zip')

# Returns a pandas DataFrame
results = cypher_query(model, '''
    MATCH (f:file)-[:imports]->(dep)
    RETURN f.name, dep.name
''')
print(results)
```

For more control over the backend (e.g., disabling hierarchy edges):

```python
from sgraph.cypher import SGraphCypherBackend, SGraphCypherExecutor

backend = SGraphCypherBackend(root=model.rootNode, include_hierarchy=False)
executor = SGraphCypherExecutor(graph=backend)
result = executor.exec('MATCH (n) RETURN count(n)')
```

## Command-Line Interface

Query models directly from the terminal:

```bash
# Single query
python -m sgraph.cypher model.xml.zip 'MATCH (n:file) RETURN n.name LIMIT 5'

# Interactive REPL
python -m sgraph.cypher model.xml.zip

# Without hierarchy edges
python -m sgraph.cypher --no-hierarchy model.xml.zip
```

In interactive mode, type Cypher queries at the `cypher>` prompt. Multi-line queries are supported — the query is executed when a line ends with a semicolon or when a blank line is entered after the query. Type `quit` or `exit` to leave, or press Ctrl+D. Use `\format <name>` to switch output format mid-session.

### Output Formats

The `-f` / `--format` flag controls the output format. Use `-o` to write to a file instead of stdout.

**Tabular formats** — render the query result DataFrame:

| Format | Flag | Description |
|---|---|---|
| `table` | `-f table` | Aligned columns (default) |
| `csv` | `-f csv` | Comma-separated values |
| `tsv` | `-f tsv` | Tab-separated values |
| `json` | `-f json` | JSON array of objects |
| `jsonl` | `-f jsonl` | One JSON object per line |

**Graph formats** — extract a subgraph from `Node`/`Edge` objects in the result and export using sgraph converters. The query must return node and edge variables (e.g., `RETURN a, r, b`, not `RETURN a.name`):

| Format | Flag | Description |
|---|---|---|
| `xml` | `-f xml` | sgraph XML format |
| `deps` | `-f deps` | Line-based deps format |
| `dot` | `-f dot` | Graphviz DOT |
| `plantuml` | `-f plantuml` | PlantUML component diagram |
| `graphml` | `-f graphml` | GraphML (yFiles compatible) |
| `cytoscape` | `-f cytoscape` | CytoscapeJS JSON |

**Examples:**

```bash
# Export query results as CSV for further processing
python -m sgraph.cypher model.xml.zip -f csv \
  'MATCH (a:file)-[r:imports]->(b) RETURN a.name, b.name' > imports.csv

# Extract a subgraph as Graphviz DOT
python -m sgraph.cypher model.xml.zip -f dot \
  'MATCH (a)-[r:inc]->(b) RETURN a, r, b' | dot -Tpng -o graph.png

# Export matched subgraph as PlantUML
python -m sgraph.cypher model.xml.zip -f plantuml \
  'MATCH (a)-[r]->(b) WHERE a.name = "main.py" RETURN a, r, b' > deps.puml

# Save subgraph as GraphML for yEd
python -m sgraph.cypher model.xml.zip -f graphml -o subgraph.graphml \
  'MATCH (a)-[r:imports]->(b) RETURN a, r, b'

# JSON Lines for streaming/piping
python -m sgraph.cypher model.xml.zip -f jsonl \
  'MATCH (n:file) RETURN n.name, n.path' | jq .
```

## Query Examples

### Software Architecture Convention

**Find all import dependencies between files:**
```cypher
MATCH (a:file)-[r:imports]->(b:file)
RETURN a.name, b.name
```

**What does a specific file depend on?**
```cypher
MATCH (a)-[r]->(b)
WHERE a.name = 'main.py' AND type(r) <> 'CONTAINS'
RETURN a.name, type(r), b.name
```

**Transitive dependencies (up to 3 hops):**
```cypher
MATCH (a:file)-[:imports|function_ref*1..3]->(b)
RETURN DISTINCT a.name, b.name
```

**Count dependencies per file, sorted:**
```cypher
MATCH (a:file)-[r]->(b)
WHERE type(r) <> 'CONTAINS'
RETURN a.name, count(r) AS deps
ORDER BY deps DESC
```

**Files importing external packages:**
```cypher
MATCH (dir)-[:CONTAINS]->(f:file)-[:imports]->(ext:package)
RETURN dir.name, f.name, ext.name
```

**Find elements under External:**
```cypher
MATCH (n)
WHERE n.path CONTAINS 'External'
RETURN n.name, n.path
```

**Containment hierarchy:**
```cypher
MATCH (parent)-[:CONTAINS]->(child:file)
RETURN parent.name, child.name
```

**Navigate hierarchy with depth:**
```cypher
MATCH (root)-[:CONTAINS*1..3]->(deep)
WHERE root.name = 'src'
RETURN deep.name, deep.path
```

### Genealogy Convention

**Find a person's parents:**
```cypher
MATCH (child)-[:parent]->(parent)
WHERE child.name CONTAINS 'Matti'
RETURN child.name, parent.name
```

**Find a person's children (reverse direction):**
```cypher
MATCH (child)-[:parent]->(parent)
WHERE parent.name CONTAINS 'Matti'
RETURN child.name
```

**Ancestors up to 3 generations:**
```cypher
MATCH (person)-[:parent*1..3]->(ancestor)
WHERE person.name CONTAINS 'Pekka'
RETURN ancestor.name
```

## Supported Cypher Features

| Feature | Supported |
|---|---|
| `MATCH` with node labels and properties | Yes |
| `WHERE` with comparisons, `CONTAINS`, `AND`/`OR` | Yes |
| `RETURN` with aliases | Yes |
| `DISTINCT` | Yes |
| `ORDER BY`, `LIMIT`, `SKIP` | Yes |
| `count()`, `sum()`, `avg()`, `min()`, `max()` | Yes |
| `type(r)`, `labels(n)`, `id(n)` | Yes |
| Variable-length paths `*1..N` | Yes |
| `WITH` (intermediate results) | Yes |
| `UNION` / `UNION ALL` | Yes |
| `UNWIND` | Yes |
| `OPTIONAL MATCH` | Yes |
| `CREATE`, `DELETE`, `SET` | No (read-only) |
| `MERGE` | No |
| `CALL` subqueries | No |

## Performance Notes

The backend builds an in-memory index of all elements and associations on first use. For typical software projects (up to hundreds of thousands of elements) this is fast. For very large models (millions of elements), the initial indexing may take a few seconds.

The `:CONTAINS` hierarchy edges roughly double the edge count. Use `include_hierarchy=False` (or `--no-hierarchy` on the CLI) if you only need association queries and want faster indexing.
