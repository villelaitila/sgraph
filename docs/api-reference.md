---
layout: page
title: API Reference
permalink: /api-reference/
---

# API Reference

Complete reference for the sgraph Python API.

## Core Classes

### SGraph

The main graph container class that holds the entire model.

```python
from sgraph import SGraph, SElement

# Create a new graph
root_element = SElement(None, 'root')
graph = SGraph(root_element)
```

#### Methods

##### `createOrGetElementFromPath(path: str) -> SElement`
Creates or retrieves an element at the specified path.

```python
element = graph.createOrGetElementFromPath('/project/src/main.py')
```

##### `getAllElements() -> List[SElement]`
Returns all elements in the graph.

```python
all_elements = graph.getAllElements()
print(f"Total elements: {len(all_elements)}")
```

##### `getElementsByName(name: str) -> List[SElement]`
Finds all elements with the specified name.

```python
main_files = graph.getElementsByName('main.py')
```

##### `to_xml(fname: str = None) -> str`
Exports the graph to sgraph XML format.

```python
# Return as string
xml_content = graph.to_xml()

# Save to file
graph.to_xml('model.xml')
```

##### `to_deps(fname: str = None) -> str`
Exports the graph to Deps format.

```python
# Return as string
deps_content = graph.to_deps()

# Save to file
graph.to_deps('dependencies.txt')
```

### SElement

Represents a single element (node) in the graph.

```python
from sgraph import SElement

# Create an element
parent = SElement(None, 'parent')
child = SElement(parent, 'child')
```

#### Properties

- `name: str` - The element's name
- `parent: SElement` - Parent element (None for root)
- `id: int` - Unique identifier

#### Methods

##### `getPath() -> str`
Returns the full path from root to this element.

```python
path = element.getPath()
# Example: '/project/src/main.py'
```

##### `getChildElements() -> List[SElement]`
Returns direct children of this element.

```python
children = element.getChildElements()
for child in children:
    print(child.name)
```

##### `addAttribute(key: str, value: str)`
Adds a custom attribute.

```python
element.addAttribute('type', 'file')
element.addAttribute('loc', '150')
```

##### `getAttribute(key: str, default_value: str = None) -> str`
Retrieves an attribute value.

```python
file_type = element.getAttribute('type', 'unknown')
lines = int(element.getAttribute('loc', '0'))
```

##### `getAssociationsFrom() -> List[SElementAssociation]`
Returns all outgoing associations.

```python
dependencies = element.getAssociationsFrom()
for dep in dependencies:
    print(f"Depends on: {dep.toElement.getPath()}")
```

##### `getAssociationsTo() -> List[SElementAssociation]`
Returns all incoming associations.

```python
dependents = element.getAssociationsTo()
for dep in dependents:
    print(f"Used by: {dep.fromElement.getPath()}")
```

### SElementAssociation

Represents a relationship between two elements.

```python
from sgraph import SElementAssociation

# Create an association
association = SElementAssociation(from_element, to_element, 'import')
association.initElems()  # Must call this to activate the association
```

#### Properties

- `fromElement: SElement` - Source element
- `toElement: SElement` - Target element  
- `type: str` - Relationship type

#### Methods

##### `initElems()`
Activates the association by adding it to both elements.

```python
association.initElems()
```

##### `addAttribute(key: str, value: str)`
Adds metadata to the relationship.

```python
association.addAttribute('frequency', 'high')
association.addAttribute('conditional', 'true')
```

##### `getAttribute(key: str, default_value: str = None) -> str`
Retrieves relationship metadata.

```python
frequency = association.getAttribute('frequency', 'unknown')
```

## High-Level APIs

### ModelApi

Provides convenient methods for querying and analyzing models.

```python
from sgraph.modelapi import ModelApi

# Load a model
api = ModelApi(filepath='model.xml')
```

#### Methods

##### `getAllElements() -> List[SElement]`
Returns all elements in the model.

##### `getElementsByName(name: str) -> List[SElement]`
Finds elements by name.

##### `getElementsByType(element_type: str) -> List[SElement]`
Finds elements by type attribute.

```python
functions = api.getElementsByType('function')
classes = api.getElementsByType('class')
```

##### `getCalledFunctions(element: SElement) -> List[SElement]`
For a function element, returns all functions it calls.

```python
called = api.getCalledFunctions(main_function)
print(f"Calls {len(called)} functions")
```

##### `getCallingFunctions(element: SElement) -> List[SElement]`
For a function element, returns all functions that call it.

```python
callers = api.getCallingFunctions(utility_function)
print(f"Called by {len(callers)} functions")
```

### MetricsApi

Provides methods for calculating architecture metrics.

```python
from sgraph.metricsapi import MetricsApi

metrics = MetricsApi(filepath='model.xml')
```

#### Methods

##### `calculateComplexityMetrics() -> Dict`
Calculates various complexity metrics.

##### `calculateCouplingMetrics() -> Dict`
Calculates coupling and cohesion metrics.

## Converters

### XML Converters

#### XmlToDeps

```python
from sgraph.converters.xml_to_deps import XmlToDeps

converter = XmlToDeps()
converter.convert('model.xml', 'dependencies.txt')
```

#### XmlToJson

```python
from sgraph.converters.xml_to_json import XmlToJson

converter = XmlToJson()
converter.convert('model.xml', 'model.json')
```

#### XmlToGraphMl

```python
from sgraph.converters.xml_to_graphml import XmlToGraphMl

converter = XmlToGraphMl()
converter.convert('model.xml', 'graph.graphml')
```

#### XmlToPlantUml

```python
from sgraph.converters.xml_to_plantuml import XmlToPlantUml

converter = XmlToPlantUml()
converter.convert('model.xml', 'diagram.puml')
```

### Format Converters

#### DepsToXml

```python
from sgraph.converters.deps_to_xml import DepsToXml

converter = DepsToXml()
converter.convert('dependencies.txt', 'model.xml')
```

#### GraphMlToXml

```python
from sgraph.converters.graphml_to_xml import GraphMlToXml

converter = GraphMlToXml()
converter.convert('graph.graphml', 'model.xml')
```

### Visualization Converters

#### SGraphToCytoscape

```python
from sgraph.converters.sgraph_to_cytoscape import SGraphToCytoscape

converter = SGraphToCytoscape()
converter.convert('model.xml', 'cytoscape.html')
```

#### XmlTo3DForceGraph

```python
from sgraph.converters.xml_to_3dforcegraph import XmlTo3DForceGraph

converter = XmlTo3DForceGraph()
converter.convert('model.xml', 'force_graph.html')
```

## Algorithms

### Graph Analysis

#### SGraphAnalysis

```python
from sgraph.algorithms.sgraphanalysis import SGraphAnalysis

analysis = SGraphAnalysis(model)
```

##### Methods

- `findCycles() -> List[List[SElement]]` - Detect circular dependencies
- `calculateDepth(element: SElement) -> int` - Calculate element depth
- `findRoots() -> List[SElement]` - Find root elements

#### SGraphMetrics

```python
from sgraph.algorithms.sgraphmetrics import SGraphMetrics

metrics = SGraphMetrics(model)
```

##### Methods

- `calculateFanIn(element: SElement) -> int` - Count incoming dependencies
- `calculateFanOut(element: SElement) -> int` - Count outgoing dependencies
- `calculateInstability(element: SElement) -> float` - Calculate instability metric

### Filtering

#### SGraphFiltering

```python
from sgraph.algorithms.sgraphfiltering import SGraphFiltering

filtering = SGraphFiltering(model)
```

##### Methods

- `filterByType(element_type: str) -> SGraph` - Filter by element type
- `filterByPath(path_pattern: str) -> SGraph` - Filter by path pattern
- `removeIsolatedElements() -> SGraph` - Remove elements with no relationships

## Comparison

### ModelCompare

```python
from sgraph.compare.modelcompare import ModelCompare

comparer = ModelCompare()
result = comparer.compare('old_model.xml', 'new_model.xml')
```

#### Methods

##### `compare(old_model: str, new_model: str) -> Dict`
Compares two models and returns differences.

##### `calculateSimilarity(old_model: str, new_model: str) -> float`
Calculates similarity score between models.

## CLI Tools

### show_model

Display model information.

```bash
python -m sgraph.cli.show_model model.xml
```

Options:
- `--stats` - Show statistics
- `--elements` - List all elements
- `--relationships` - Show relationships

### filter

Filter model content.

```bash
python -m sgraph.cli.filter model.xml --output filtered.xml --include "*.py"
```

Options:
- `--include PATTERN` - Include elements matching pattern
- `--exclude PATTERN` - Exclude elements matching pattern
- `--type TYPE` - Filter by element type
- `--output FILE` - Output file path

## Exceptions

### SElementMergedException

Raised when attempting to merge elements incorrectly.

```python
from sgraph.exceptions import SElementMergedException

try:
    # Some operation that might fail
    element.merge(other_element)
except SElementMergedException as e:
    print(f"Merge failed: {e}")
```

### ModelNotFoundException

Raised when a model file cannot be found.

```python
from sgraph.exceptions import ModelNotFoundException

try:
    api = ModelApi(filepath='nonexistent.xml')
except ModelNotFoundException as e:
    print(f"Model not found: {e}")
```

## Utilities

### Graph Utilities

```python
from sgraph.algorithms.graphutils import GraphUtils

# Find shortest path
path = GraphUtils.findShortestPath(from_element, to_element)

# Calculate graph diameter
diameter = GraphUtils.calculateDiameter(model)

# Find strongly connected components
components = GraphUtils.findStronglyConnectedComponents(model)
```

### Element Utilities

```python
from sgraph.algorithms.selementutils import SElementUtils

# Get all descendants
descendants = SElementUtils.getAllDescendants(element)

# Check if element is ancestor
is_ancestor = SElementUtils.isAncestor(parent, child)

# Calculate element size (including children)
size = SElementUtils.calculateSubtreeSize(element)
```

## Configuration

### Loading Configuration

```python
from sgraph.loader.modelloader import ModelLoader

# Configure loader
loader = ModelLoader()
loader.configure({
    'batch_size': 1000,
    'validate': True,
    'encoding': 'utf-8'
})

# Load with configuration
model = loader.load('large_model.xml')
```

## Best Practices

### Performance Optimization

```python
# Use ModelApi for large models
api = ModelApi(filepath='large_model.xml')

# Query specific elements instead of loading all
specific_elements = api.getElementsByName('target_name')

# Use batch operations
elements_to_analyze = api.getElementsByType('function')
```

### Memory Management

```python
# For very large models, process incrementally
def process_large_model(filepath):
    api = ModelApi(filepath=filepath)
    
    # Process in chunks
    all_functions = api.getElementsByType('function')
    chunk_size = 1000
    
    for i in range(0, len(all_functions), chunk_size):
        chunk = all_functions[i:i + chunk_size]
        process_function_chunk(chunk)
        # Optionally clear processed data
```

### Error Handling

```python
from sgraph.exceptions import SElementMergedException, ModelNotFoundException

def safe_model_operation(filepath):
    try:
        api = ModelApi(filepath=filepath)
        # Perform operations
        return api.getAllElements()
        
    except ModelNotFoundException:
        print("Model file not found")
        return []
        
    except SElementMergedException:
        print("Element merge conflict")
        return []
        
    except Exception as e:
        print(f"Unexpected error: {e}")
        return []
```

This API reference covers the essential classes and methods you'll need to work with sgraph effectively. For the most up-to-date information, refer to the source code and docstrings.
