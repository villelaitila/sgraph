---
layout: page
title: Getting Started
permalink: /getting-started/
---

# Getting Started with sgraph

This guide will help you get up and running with sgraph in just a few minutes.

## Installation

sgraph requires Python 3.8 or higher. Install it using pip:

```bash
pip install sgraph
```

For development dependencies:

```bash
pip install sgraph[dev]
```

## Your First Model

Let's create a simple model representing a basic software project structure:

```python
from sgraph import SGraph, SElement, SElementAssociation

# Create a new model with an empty root element
model = SGraph(SElement(None, ''))

# Create elements representing files in a project
main_py = model.createOrGetElementFromPath('/myproject/src/main.py')
utils_py = model.createOrGetElementFromPath('/myproject/src/utils.py')
config_py = model.createOrGetElementFromPath('/myproject/config/settings.py')

# Create relationships between files
# main.py imports utils.py
import_utils = SElementAssociation(main_py, utils_py, 'import')
import_utils.initElems()

# main.py imports config/settings.py
import_config = SElementAssociation(main_py, config_py, 'import')
import_config.initElems()

# View the model structure
print("=== Model Structure ===")
print(model.to_deps())
```

Output:
```
/myproject/src/main.py:/myproject/src/utils.py:imports
/myproject/src/main.py:/myproject/config/settings.py:imports
/myproject
/myproject/src
/myproject/config
```

## Working with Elements

### Creating Elements

There are several ways to create elements:

```python
# Method 1: Create from path (recommended)
element = model.createOrGetElementFromPath('/project/module/file.py')

# Method 2: Create manually
parent = model.createOrGetElementFromPath('/project/module')
element = SElement(parent, 'file.py')
```

### Adding Attributes

Elements can have custom attributes:

```python
# Add type information
element.addAttribute('type', 'file')
element.addAttribute('loc', 150)  # loc: lines of code metric
element.addAttribute('complexity', 'medium')

# Access attributes
print(f"Type: {element.getAttribute('type')}")
print(f"LOC: {element.getAttribute('loc')}")
```

### Navigating the Hierarchy

```python
# Get parent and children
parent = element.parent
children = element.getChildElements()

# Get the full path
full_path = element.getPath()
print(f"Element path: {full_path}")

# Find elements by name
elements = model.getElementsByName('__init__.py')
for elem in elements:
    print(f"Found: {elem.getPath()}")
```

## Working with Associations

Associations represent relationships between elements:

```python
# Create different types of relationships
includes = SElementAssociation(file1, file2, 'includes')
calls = SElementAssociation(func1, func2, 'calls')
inherits = SElementAssociation(class1, class2, 'inherits')

# Don't forget to initialize!
includes.initElems()
calls.initElems()
inherits.initElems()

# Add attributes to relationships
calls.addAttribute('frequency', 'high')
calls.addAttribute('conditional', 'true')
```

## Data Export Formats

### Deps Format (Simple Text)

Perfect for scripting and simple analysis:

```python
# Export to string
deps_content = model.to_deps()
print(deps_content)

# Save to file
model.to_deps(fname='dependencies.txt')
```

Format: `source:target:relationship_type`

### XML Format (Rich Data)

Ideal for large models and complex analysis:

```python
# Export to string
xml_content = model.to_xml()
print(xml_content)

# Save to file
model.to_xml(fname='model.xml')
```

The XML format includes:
- Hierarchical structure
- Integer-based references for performance
- All attributes and metadata

## Loading Existing Models

### From XML

```python
from sgraph.modelapi import ModelApi

# Load and analyze an existing model
api = ModelApi(filepath='existing_model.xml')

# Find specific elements
functions = api.getElementsByName('authenticate')
print(f"Found {len(functions)} functions named 'authenticate'")

# Analyze a specific function
if functions:
    func = functions[0]
    called = api.getCalledFunctions(func)
    callers = api.getCallingFunctions(func)
    
    print(f"Function {func.name}:")
    print(f"  Calls {len(called)} other functions")
    print(f"  Called by {len(callers)} functions")
```

### From Deps Format

```python
from sgraph.converters.deps_to_xml import DepsToXml

# Convert deps file to XML format
converter = DepsToXml()
converter.convert('dependencies.txt', 'model.xml')

# Now load with ModelApi
api = ModelApi(filepath='model.xml')
```

## Command Line Tools

sgraph includes several CLI tools:

```bash
# View model information
python -m sgraph.cli.show_model model.xml

# Filter models
python -m sgraph.cli.filter model.xml --output filtered.xml --include "*.py"

# Convert between formats
python -m sgraph.converters.xml_to_deps model.xml output.deps
```

## Next Steps

Now that you know the basics, explore:

- [**Examples**](examples.html) - Real-world usage patterns
- [**API Reference**](api-reference.html) - Complete API documentation
- [**Data Formats**](data-formats.html) - Deep dive into XML and Deps formats
- [**Visualization**](visualization.html) - Creating diagrams and visualizations

## Common Patterns

### Building Models from Source Code

```python
import os
from sgraph import SGraph, SElement, SElementAssociation

def analyze_python_project(project_path):
    model = SGraph(SElement(None, ''))
    
    # Walk through Python files
    for root, dirs, files in os.walk(project_path):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                # Create relative path for model
                rel_path = os.path.relpath(file_path, project_path)
                element = model.createOrGetElementFromPath(f'/{rel_path}')
                
                # Add file metadata
                stat = os.stat(file_path)
                element.addAttribute('size', stat.st_size)
                element.addAttribute('type', 'file')
    
    return model

# Use it
model = analyze_python_project('/path/to/your/project')
model.to_xml(fname='project_structure.xml')
```

### Filtering and Querying

```python
# Find all Python files
python_files = [elem for elem in model.getAllElements() 
                if elem.getAttribute('type') == 'file' and elen.name.endswith('.py')]

# Find large files
large_files = [elem for elem in python_files 
               if int(elem.getAttribute('size', 0)) > 10000]

# Find files with many dependencies
files_with_deps = []
for elem in python_files:
    deps = elem.getAssociationsFrom()
    if len(deps) > 5:
        files_with_deps.append(elem)
```

Happy modeling! 🚀
