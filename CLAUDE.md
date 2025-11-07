# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

sgraph is a Python library for working with hierarchic graph structures, typically used for representing software architectures. It provides data formats, structures, and algorithms for analyzing and manipulating software dependency graphs.

The library is maintained by Softagram and is used for building information models about analyzed software. See also [sgraph-mcp-server](https://github.com/softagram/sgraph-mcp-server) for AI agent integration.

## Development Commands

### Environment Setup
```bash
# Install dependencies
pip install -r requirements.txt

# Install dev dependencies (includes yapf, flake8)
pip install -r requirements-dev.txt

# Install package in development mode
pip install -e .
```

### Testing
```bash
# Run all tests
pytest

# Run specific test file
pytest tests/sgraph_test.py

# Run specific test
pytest tests/sgraph_test.py::test_deepcopy
```

### Linting
```bash
# Run flake8 (max line length: 100)
flake8 src/

# Format code with yapf (config in .style.yapf)
yapf -r -i src/
```

### Building
```bash
# Build distribution packages
python3 setup.py sdist bdist_wheel
```

### Releasing

The project uses an automated release script to streamline the release process:

```bash
# Auto-bump patch version (1.1.1 -> 1.1.2)
python scripts/release.py --bump patch

# Auto-bump minor version (1.1.1 -> 1.2.0)
python scripts/release.py --bump minor

# Auto-bump major version (1.1.1 -> 2.0.0)
python scripts/release.py --bump major

# Release specific version
python scripts/release.py --version 1.2.0

# Dry run to preview changes
python scripts/release.py --bump patch --dry-run
```

The script automates the full release workflow: version bumping, branch creation, PR creation (requires `gh` CLI), tagging, building, PyPI upload (requires `twine`), and GitHub release creation with auto-generated release notes from merged PRs. See `scripts/README.md` for setup instructions.

## Core Architecture

### Data Model

The sgraph data model consists of three primary classes:

1. **SGraph** (`sgraph.py`): The top-level model container
   - Contains a root `SElement`
   - Manages model-level attributes via `modelAttrs` and `metaAttrs`
   - Provides serialization to XML, deps, and other formats
   - Entry point for parsing models from files

2. **SElement** (`selement.py`): Hierarchical graph nodes
   - Represents elements in a tree structure (like directories/files)
   - Each element has a name, parent, children (stored in both list and dict)
   - Contains `incoming` and `outgoing` lists of associations (edges)
   - Stores attributes as key-value pairs in `attrs` dict
   - Uses `__slots__` for memory efficiency

3. **SElementAssociation** (`selementassociation.py`): Edges between elements
   - Represents directed relationships between elements
   - Has `fromElement`, `toElement`, and `deptype` (dependency type)
   - Stores additional attributes in `attrs` dict
   - Must call `initElems()` to register with connected elements
   - Use `create_unique_element_association()` to avoid duplicates

### High-Level APIs

- **ModelApi** (`modelapi.py`): Query and traverse models
  - `getElementByPath()`: Find elements by path
  - `getElementsByName()`: Find all elements by name
  - `getCalledFunctions()`: Get function call relationships
  - Various filtering and traversal utilities

- **MetricsApi** (`metricsapi.py`): Extract metrics from models
  - `get_total_loc_metrics()`: Lines of code metrics
  - `get_total_tech_debt_metrics()`: Tech debt analysis

### Module Structure

- **algorithms/**: Graph algorithms (metrics, filtering, generalization, analysis)
- **converters/**: Format converters (XML, deps, GraphML, JSON, PlantUML, DOT, CytoscapeJS, SBOM)
- **compare/**: Model comparison and diff functionality (rename detection, similarity analysis)
- **loader/**: Model loading utilities
- **cli/**: Command-line interface utilities
- **attributes/**: Attribute query and management

### Data Formats

The library supports multiple serialization formats:

1. **XML Format**: High-performance format for large models (10M+ elements)
   - Uses integer IDs for element references
   - Minimalist syntax: `<e n="name">` for elements, `<r r="id" t="type">` for relationships
   - Model version 2.1

2. **Deps Format**: Line-based text format for simple scripting
   - Format: `/path/to/from:/path/to/to:dependency_type`
   - Easy to read and script, but not recommended for very large models

3. **Other formats**: GraphML, JSON, PlantUML, DOT, CytoscapeJS

### Key Patterns

- **Path-based element access**: Elements are identified by hierarchical paths (e.g., `/nginx/src/core/nginx.c`)
- **Lazy element creation**: `createOrGetElementFromPath()` creates elements on-demand
- **Element merging**: Duplicate elements under the same parent are merged
- **Association initialization**: Associations must call `initElems()` to register with their connected elements
- **Type-based filtering**: Elements and associations support type attributes for categorization

## Common Workflows

### Creating a Model
```python
from sgraph import SGraph, SElement, SElementAssociation

# Create empty model
model = SGraph(SElement(None, ''))

# Create elements from paths
e1 = model.createOrGetElementFromPath('/path/to/file.x')
e2 = model.createOrGetElementFromPath('/path/to/file.y')

# Create association
ea = SElementAssociation(e1, e2, 'use')
ea.initElems()  # Must call to register association

# Serialize
model.to_xml('output.xml')
model.to_deps('output.txt')
```

### Loading and Querying
```python
from sgraph import SGraph, ModelApi

# Load model
model = SGraph.parse_xml_or_zipped_xml('model.xml')

# Query with ModelApi
api = ModelApi(model=model)
element = api.getElementByPath('/some/path')
elements = api.getElementsByName('nginx.c')
```

## File Locations

- Source code: `src/sgraph/`
- Tests: `tests/`
- Automation scripts: `scripts/` (includes `release.py`)
- Package metadata: `setup.cfg`, `setup.py`
- Documentation: `README.md`, `releasing.md`, `CLAUDE.md`
