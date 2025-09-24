---
layout: default
title: "sgraph - Hierarchical Graph Data Structures for Software Analysis"
description: "A powerful Python library for representing and analyzing software architectures through hierarchical graphs"
---

# sgraph
## Hierarchical Graph Data Structures for Software Analysis

[![PyPI version](https://badge.fury.io/py/sgraph.svg)](https://badge.fury.io/py/sgraph)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/release/python-380/)

**sgraph** is a powerful Python library that provides data formats, structures, and algorithms for working with hierarchical graph structures. It's particularly suited for representing and analyzing software architectures, dependencies, and complex system relationships.

## 🚀 Quick Start

```bash
pip install sgraph
```

```python
from sgraph import SGraph, SElement, SElementAssociation

# Create a model
model = SGraph(SElement(None, ''))

# Add elements
file1 = model.createOrGetElementFromPath('/project/src/main.py')
file2 = model.createOrGetElementFromPath('/project/src/utils.py')

# Create relationships
dependency = SElementAssociation(file1, file2, 'imports')
dependency.initElems()

# Export to various formats
print(model.to_deps())  # Simple text format
print(model.to_xml())   # Rich XML format
```

## ✨ Key Features

### 🏗️ **Flexible Data Structures**
- **Hierarchical Elements**: Represent complex nested structures like file systems, modules, and packages
- **Rich Associations**: Model relationships with custom types and attributes
- **Scalable Design**: Handle models with millions of elements efficiently

### 📊 **Multiple Data Formats**
- **XML Format**: Rich, performant format with integer references for large models
- **Deps Format**: Simple line-based format perfect for scripting
- **GraphML Export**: Compatible with graph visualization tools
- **JSON Export**: Web-friendly format for modern applications

### 🔍 **Powerful Analysis Tools**
- **Dependency Analysis**: Find calling/called relationships
- **Metrics Calculation**: Compute complexity and coupling metrics
- **Graph Algorithms**: Built-in algorithms for graph analysis
- **Model Comparison**: Compare different versions of your architecture

### 🛠️ **Rich Ecosystem**
- **CLI Tools**: Command-line utilities for model processing
- **Converters**: Transform between different graph formats
- **Visualization**: Export to various visualization formats (PlantUML, Cytoscape, 3D Force Graph)

## 🎯 Use Cases

### Software Architecture Analysis
Analyze codebases to understand:
- Module dependencies and coupling
- Call graphs and function relationships  
- Package structure and organization
- Technical debt and complexity metrics

### System Documentation
Generate up-to-date documentation:
- Dependency diagrams
- Architecture overviews
- Module relationship maps
- API interaction flows

### Code Quality Assessment
Track and improve:
- Circular dependencies
- Coupling and cohesion metrics
- Architectural violations
- Evolution over time

## 📖 Documentation

- [**Getting Started Guide**](getting-started.html) - Your first steps with sgraph
- [**API Reference**](api-reference.html) - Complete API documentation  
- [**Examples & Tutorials**](examples.html) - Real-world usage examples
- [**Data Formats**](data-formats.html) - Understanding XML and Deps formats
- [**Visualization Guide**](visualization.html) - Creating beautiful diagrams

## 🌟 Example: Analyzing a Real Project

```python
from sgraph.modelapi import ModelApi

# Load a model from XML
api = ModelApi(filepath='project_model.xml')

# Find specific elements
functions = api.getElementsByName('authenticate')
for func in functions:
    print(f"Function: {func.name} at {func.getPath()}")

# Analyze dependencies
main_func = functions[0]
called = api.getCalledFunctions(main_func)
callers = api.getCallingFunctions(main_func)

print(f"Calls {len(called)} functions")
print(f"Called by {len(callers)} functions")
```

## 🏢 Production Usage

sgraph powers [Softagram](https://github.com/softagram), a software analytics platform used by development teams worldwide to:
- Visualize software architecture
- Track technical debt
- Monitor code quality trends
- Understand system complexity

## 🤝 Contributing

We welcome contributions! Whether you're:
- 🐛 Reporting bugs
- 💡 Suggesting features  
- 📝 Improving documentation
- 🔧 Submitting code changes

Check out our [contribution guidelines](https://github.com/softagram/sgraph/blob/main/CONTRIBUTING.md) to get started.

## 📊 Performance

sgraph is designed for performance:
- ✅ Handle models with **10+ million elements**
- ✅ Efficient integer-based referencing system
- ✅ Memory-optimized data structures
- ✅ Fast XML parsing and generation

## 🤖 AI-Powered Analysis

**[sgraph-mcp-server](https://softagram.github.io/sgraph-mcp-server/)** - Analyze large codebases using sgraph over the Model Context Protocol (MCP). Enable AI agents to understand your software architecture with high-performance search, dependency analysis, and intelligent refactoring capabilities.

## 🔗 Links

- [🤖 SGraph MCP Server](https://softagram.github.io/sgraph-mcp-server/) - AI-powered code analysis
- [📦 PyPI Package](https://pypi.org/project/sgraph/)
- [📚 GitHub Repository](https://github.com/softagram/sgraph)
- [🐛 Issue Tracker](https://github.com/softagram/sgraph/issues)
- [📧 Contact](mailto:ville.laitila@softagram.com)

---

<div style="text-align: center; margin-top: 2rem; padding: 1rem; background-color: #f8f9fa; border-radius: 8px;">
  <strong>Ready to start analyzing your software architecture?</strong><br>
  <code>pip install sgraph</code>
</div>
