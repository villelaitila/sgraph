---
layout: page
title: Examples & Tutorials
permalink: /examples/
---

# Examples & Tutorials

Learn sgraph through practical examples and real-world use cases.

## Table of Contents
- [Basic Usage Examples](#basic-usage-examples)
- [Software Architecture Analysis](#software-architecture-analysis)
- [Dependency Analysis](#dependency-analysis)
- [Visualization Examples](#visualization-examples)
- [Advanced Patterns](#advanced-patterns)

## Basic Usage Examples

### Example 1: Modeling a Simple C Project

```python
from sgraph import SGraph, SElement, SElementAssociation

# Create model for nginx-like structure
model = SGraph(SElement(None, ''))

# Create the directory structure
nginx_root = model.createOrGetElementFromPath('/nginx')
src = model.createOrGetElementFromPath('/nginx/src')
core = model.createOrGetElementFromPath('/nginx/src/core')

# Create source files
nginx_c = model.createOrGetElementFromPath('/nginx/src/core/nginx.c')
nginx_h = model.createOrGetElementFromPath('/nginx/src/core/nginx.h')
config_h = model.createOrGetElementFromPath('/nginx/src/core/config.h')

# Add file types
nginx_c.addAttribute('type', 'c_source')
nginx_h.addAttribute('type', 'c_header')
config_h.addAttribute('type', 'c_header')

# Model #include relationships
include_nginx_h = SElementAssociation(nginx_c, nginx_h, 'includes')
include_config_h = SElementAssociation(nginx_c, config_h, 'includes')

include_nginx_h.initElems()
include_config_h.initElems()

# Export to see the structure
print("=== Dependencies ===")
print(model.to_deps())

print("\n=== XML Structure ===")
print(model.to_xml())
```

### Example 2: Python Module Dependencies

```python
from sgraph import SGraph, SElement, SElementAssociation

# Model a Python package
model = SGraph(SElement(None, ''))

# Create package structure
package = model.createOrGetElementFromPath('/myapp')
models = model.createOrGetElementFromPath('/myapp/models.py')
views = model.createOrGetElementFromPath('/myapp/views.py')
utils = model.createOrGetElementFromPath('/myapp/utils.py')
tests = model.createOrGetElementFromPath('/myapp/tests.py')

# Add metadata
models.addAttribute('type', 'python_module')
models.addAttribute('lines', 250)
views.addAttribute('type', 'python_module')
views.addAttribute('lines', 180)
utils.addAttribute('type', 'python_module')
utils.addAttribute('lines', 95)

# Model import relationships
views_imports_models = SElementAssociation(views, models, 'imports')
views_imports_utils = SElementAssociation(views, utils, 'imports')
tests_imports_models = SElementAssociation(tests, models, 'imports')
tests_imports_views = SElementAssociation(tests, views, 'imports')

# Initialize all relationships
for assoc in [views_imports_models, views_imports_utils, 
              tests_imports_models, tests_imports_views]:
    assoc.initElems()

# Analyze the structure
print("=== Module Dependencies ===")
deps_output = model.to_deps()
print(deps_output)

# Find modules with most dependencies
all_elements = model.getAllElements()
modules = [e for e in all_elements if e.getAttribute('type') == 'python_module']

for module in modules:
    imports = len(module.getAssociationsFrom())
    imported_by = len(module.getAssociationsTo())
    print(f"{module.name}: imports {imports}, imported by {imported_by}")
```

## Software Architecture Analysis

### Example 3: Analyzing Function Call Graphs

```python
from sgraph.modelapi import ModelApi

# This example assumes you have a model file with function call data
# You can create such models using static analysis tools

def analyze_function_complexity(model_path):
    api = ModelApi(filepath=model_path)
    
    # Find all function elements
    functions = api.getElementsByType('function')
    
    complexity_data = []
    
    for func in functions:
        # Count incoming and outgoing calls
        called_functions = api.getCalledFunctions(func)
        calling_functions = api.getCallingFunctions(func)
        
        # Calculate complexity metrics
        fan_out = len(called_functions)  # Functions this calls
        fan_in = len(calling_functions)  # Functions calling this
        complexity_score = fan_out + fan_in
        
        complexity_data.append({
            'name': func.name,
            'path': func.getPath(),
            'fan_out': fan_out,
            'fan_in': fan_in,
            'complexity': complexity_score
        })
    
    # Sort by complexity
    complexity_data.sort(key=lambda x: x['complexity'], reverse=True)
    
    print("=== Top 10 Most Complex Functions ===")
    for i, func_data in enumerate(complexity_data[:10]):
        print(f"{i+1:2d}. {func_data['name']} (score: {func_data['complexity']})")
        print(f"     Fan-out: {func_data['fan_out']}, Fan-in: {func_data['fan_in']}")
        print(f"     Path: {func_data['path']}\n")
    
    return complexity_data

# Usage (requires a model file with function data)
# complexity_analysis = analyze_function_complexity('codebase_model.xml')
```

### Example 4: Finding Circular Dependencies

```python
from sgraph.modelapi import ModelApi
from collections import defaultdict, deque

def find_circular_dependencies(model_path):
    api = ModelApi(filepath=model_path)
    
    # Build adjacency list of dependencies
    dependencies = defaultdict(set)
    all_elements = api.getAllElements()
    
    for element in all_elements:
        element_path = element.getPath()
        for assoc in element.getAssociationsFrom():
            if assoc.type in ['imports', 'includes', 'depends_on']:
                target_path = assoc.toElement.getPath()
                dependencies[element_path].add(target_path)
    
    def has_cycle_from(start, visited, rec_stack):
        visited.add(start)
        rec_stack.add(start)
        
        for neighbor in dependencies[start]:
            if neighbor not in visited:
                if has_cycle_from(neighbor, visited, rec_stack):
                    return True
            elif neighbor in rec_stack:
                return True
        
        rec_stack.remove(start)
        return False
    
    # Find cycles
    cycles = []
    visited = set()
    
    for node in dependencies:
        if node not in visited:
            rec_stack = set()
            if has_cycle_from(node, visited, rec_stack):
                cycles.append(node)
    
    if cycles:
        print("=== Circular Dependencies Found ===")
        for cycle_node in cycles:
            print(f"Cycle involving: {cycle_node}")
    else:
        print("No circular dependencies found!")
    
    return cycles

# Usage
# circular_deps = find_circular_dependencies('project_model.xml')
```

## Dependency Analysis

### Example 5: Dependency Impact Analysis

```python
from sgraph.modelapi import ModelApi

def analyze_dependency_impact(model_path, target_element_name):
    """
    Analyze what would be affected if we changed a specific element
    """
    api = ModelApi(filepath=model_path)
    
    # Find the target element
    targets = api.getElementsByName(target_element_name)
    if not targets:
        print(f"Element '{target_element_name}' not found!")
        return
    
    target = targets[0]
    print(f"Analyzing impact of changes to: {target.getPath()}")
    print("=" * 50)
    
    # Direct dependencies (what uses this element)
    direct_dependents = api.getCallingFunctions(target)
    print(f"\nDirect Dependents ({len(direct_dependents)}):")
    for dep in direct_dependents[:10]:  # Show first 10
        print(f"  - {dep.getPath()}")
    if len(direct_dependents) > 10:
        print(f"  ... and {len(direct_dependents) - 10} more")
    
    # Transitive dependencies (what this element uses)
    dependencies = api.getCalledFunctions(target)
    print(f"\nDirect Dependencies ({len(dependencies)}):")
    for dep in dependencies[:10]:
        print(f"  - {dep.getPath()}")
    if len(dependencies) > 10:
        print(f"  ... and {len(dependencies) - 10} more")
    
    # Calculate impact score
    impact_score = len(direct_dependents) * 2 + len(dependencies)
    print(f"\nImpact Score: {impact_score}")
    print("(High score = high impact if changed)")
    
    return {
        'target': target,
        'direct_dependents': direct_dependents,
        'dependencies': dependencies,
        'impact_score': impact_score
    }

# Usage
# impact = analyze_dependency_impact('model.xml', 'authentication_module')
```

### Example 6: Layer Violation Detection

```python
from sgraph.modelapi import ModelApi

def detect_layer_violations(model_path):
    """
    Detect architectural layer violations in a layered system
    """
    api = ModelApi(filepath=model_path)
    
    # Define architectural layers (customize for your project)
    layers = {
        'presentation': ['view', 'controller', 'ui'],
        'business': ['service', 'domain', 'business'],
        'data': ['repository', 'dao', 'database', 'persistence']
    }
    
    layer_order = ['presentation', 'business', 'data']
    violations = []
    
    all_elements = api.getAllElements()
    
    for element in all_elements:
        element_path = element.getPath().lower()
        element_layer = None
        
        # Determine element's layer
        for layer_name, keywords in layers.items():
            if any(keyword in element_path for keyword in keywords):
                element_layer = layer_name
                break
        
        if element_layer:
            # Check dependencies
            for assoc in element.getAssociationsFrom():
                target_path = assoc.toElement.getPath().lower()
                target_layer = None
                
                for layer_name, keywords in layers.items():
                    if any(keyword in target_path for keyword in keywords):
                        target_layer = layer_name
                        break
                
                if target_layer:
                    element_idx = layer_order.index(element_layer)
                    target_idx = layer_order.index(target_layer)
                    
                    # Violation: higher layer depending on lower layer
                    if element_idx > target_idx:
                        violations.append({
                            'from': element.getPath(),
                            'from_layer': element_layer,
                            'to': assoc.toElement.getPath(),
                            'to_layer': target_layer,
                            'type': assoc.type
                        })
    
    if violations:
        print("=== Layer Violations Detected ===")
        for v in violations:
            print(f"VIOLATION: {v['from_layer']} -> {v['to_layer']}")
            print(f"  From: {v['from']}")
            print(f"  To: {v['to']}")
            print(f"  Type: {v['type']}\n")
    else:
        print("No layer violations found!")
    
    return violations

# Usage
# violations = detect_layer_violations('architecture_model.xml')
```

## Visualization Examples

### Example 7: Generate PlantUML Diagrams

```python
from sgraph.modelapi import ModelApi
from sgraph.converters.xml_to_plantuml import XmlToPlantUml

def create_architecture_diagram(model_path, output_path):
    """
    Generate a PlantUML architecture diagram
    """
    # Convert model to PlantUML
    converter = XmlToPlantUml()
    converter.convert(model_path, output_path)
    
    print(f"PlantUML diagram generated: {output_path}")
    print("To generate PNG:")
    print(f"plantuml {output_path}")
    
    # You can also customize the PlantUML output
    with open(output_path, 'r') as f:
        content = f.read()
    
    # Add styling
    styled_content = """@startuml
!theme vibrant
skinparam backgroundColor #FAFAFA
skinparam class {
    BackgroundColor #E8F4FD
    BorderColor #1565C0
    ArrowColor #1976D2
}

""" + content.replace("@startuml", "").replace("@enduml", "") + "\n@enduml"
    
    styled_output = output_path.replace('.puml', '_styled.puml')
    with open(styled_output, 'w') as f:
        f.write(styled_content)
    
    print(f"Styled PlantUML diagram: {styled_output}")

# Usage
# create_architecture_diagram('model.xml', 'architecture.puml')
```

### Example 8: Create Interactive Web Visualization

```python
from sgraph.converters.xml_to_3dforcegraph import XmlTo3DForceGraph
from sgraph.converters.sgraph_to_cytoscape import SGraphToCytoscape

def create_interactive_visualization(model_path):
    """
    Create interactive web-based visualizations
    """
    # 3D Force Graph (for large graphs)
    force_converter = XmlTo3DForceGraph()
    force_converter.convert(model_path, 'force_graph.html')
    print("3D Force Graph created: force_graph.html")
    
    # Cytoscape.js (for detailed analysis)
    cyto_converter = SGraphToCytoscape()
    cyto_converter.convert(model_path, 'cytoscape.html')
    print("Cytoscape visualization created: cytoscape.html")
    
    # Create a simple dashboard HTML
    dashboard_html = """
<!DOCTYPE html>
<html>
<head>
    <title>Project Architecture Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .viz-link { 
            display: inline-block; 
            margin: 10px; 
            padding: 15px 25px; 
            background: #007bff; 
            color: white; 
            text-decoration: none; 
            border-radius: 5px; 
        }
        .viz-link:hover { background: #0056b3; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Project Architecture Visualizations</h1>
        <p>Explore your project's architecture through interactive visualizations:</p>
        
        <a href="force_graph.html" class="viz-link">🌐 3D Force Graph</a>
        <a href="cytoscape.html" class="viz-link">🔍 Detailed Network</a>
        
        <h2>About Your Architecture</h2>
        <p>This dashboard provides different views of your software architecture:</p>
        <ul>
            <li><strong>3D Force Graph:</strong> Great for exploring large codebases and finding clusters</li>
            <li><strong>Detailed Network:</strong> Perfect for analyzing specific components and relationships</li>
        </ul>
    </div>
</body>
</html>
"""
    
    with open('dashboard.html', 'w') as f:
        f.write(dashboard_html)
    
    print("Dashboard created: dashboard.html")
    print("\nOpen dashboard.html in your browser to explore!")

# Usage
# create_interactive_visualization('large_project_model.xml')
```

## Advanced Patterns

### Example 9: Model Comparison and Evolution Tracking

```python
from sgraph.compare.modelcompare import ModelCompare
from sgraph.modelapi import ModelApi

def compare_model_versions(old_model_path, new_model_path):
    """
    Compare two versions of a model to track changes
    """
    comparer = ModelCompare()
    comparison = comparer.compare(old_model_path, new_model_path)
    
    print("=== Model Evolution Analysis ===")
    print(f"Old model: {old_model_path}")
    print(f"New model: {new_model_path}")
    print("=" * 40)
    
    # Analyze changes
    added_elements = comparison.get('added_elements', [])
    removed_elements = comparison.get('removed_elements', [])
    modified_elements = comparison.get('modified_elements', [])
    
    print(f"📈 Added elements: {len(added_elements)}")
    for elem in added_elements[:5]:
        print(f"   + {elem}")
    if len(added_elements) > 5:
        print(f"   ... and {len(added_elements) - 5} more")
    
    print(f"\n📉 Removed elements: {len(removed_elements)}")
    for elem in removed_elements[:5]:
        print(f"   - {elem}")
    if len(removed_elements) > 5:
        print(f"   ... and {len(removed_elements) - 5} more")
    
    print(f"\n🔄 Modified elements: {len(modified_elements)}")
    for elem in modified_elements[:5]:
        print(f"   ~ {elem}")
    if len(modified_elements) > 5:
        print(f"   ... and {len(modified_elements) - 5} more")
    
    return comparison

# Usage
# evolution = compare_model_versions('v1.0_model.xml', 'v2.0_model.xml')
```

### Example 10: Custom Metrics Calculation

```python
from sgraph.modelapi import ModelApi
from sgraph.metricsapi import MetricsApi

def calculate_custom_metrics(model_path):
    """
    Calculate custom architecture quality metrics
    """
    api = ModelApi(filepath=model_path)
    metrics = MetricsApi(model_path)
    
    all_elements = api.getAllElements()
    modules = [e for e in all_elements if 'module' in e.getPath()]
    
    print("=== Custom Architecture Metrics ===")
    
    # 1. Coupling Metrics
    coupling_scores = []
    for module in modules:
        # Efferent coupling (outgoing dependencies)
        outgoing = len(module.getAssociationsFrom())
        # Afferent coupling (incoming dependencies)
        incoming = len(module.getAssociationsTo())
        
        # Instability = Outgoing / (Incoming + Outgoing)
        total_coupling = incoming + outgoing
        instability = outgoing / total_coupling if total_coupling > 0 else 0
        
        coupling_scores.append({
            'module': module.name,
            'path': module.getPath(),
            'efferent': outgoing,
            'afferent': incoming,
            'instability': instability
        })
    
    # Sort by instability (most unstable first)
    coupling_scores.sort(key=lambda x: x['instability'], reverse=True)
    
    print(f"\n📊 Coupling Analysis ({len(modules)} modules):")
    print("Most Unstable Modules (high outgoing dependencies):")
    for score in coupling_scores[:5]:
        print(f"  {score['module']:20} | "
              f"Out: {score['efferent']:3} | "
              f"In: {score['afferent']:3} | "
              f"Instability: {score['instability']:.2f}")
    
    # 2. Abstractness (if you have interface/abstract class info)
    abstractness_scores = []
    for module in modules:
        # Count abstract elements (interfaces, abstract classes)
        abstract_count = 0
        concrete_count = 0
        
        for child in module.getChildElements():
            if child.getAttribute('type') in ['interface', 'abstract_class']:
                abstract_count += 1
            elif child.getAttribute('type') in ['class', 'function']:
                concrete_count += 1
        
        total = abstract_count + concrete_count
        abstractness = abstract_count / total if total > 0 else 0
        
        abstractness_scores.append({
            'module': module.name,
            'abstractness': abstractness,
            'abstract_count': abstract_count,
            'concrete_count': concrete_count
        })
    
    print(f"\n🎯 Abstractness Analysis:")
    abstractness_scores.sort(key=lambda x: x['abstractness'], reverse=True)
    for score in abstractness_scores[:5]:
        print(f"  {score['module']:20} | "
              f"Abstract: {score['abstract_count']:2} | "
              f"Concrete: {score['concrete_count']:2} | "
              f"Abstractness: {score['abstractness']:.2f}")
    
    # 3. Distance from Main Sequence (D = |A + I - 1|)
    print(f"\n📏 Distance from Main Sequence:")
    for i, coupling in enumerate(coupling_scores):
        if i < len(abstractness_scores):
            abstract = abstractness_scores[i]['abstractness']
            instability = coupling['instability']
            distance = abs(abstract + instability - 1)
            
            print(f"  {coupling['module']:20} | Distance: {distance:.2f}")
    
    return {
        'coupling': coupling_scores,
        'abstractness': abstractness_scores
    }

# Usage
# metrics = calculate_custom_metrics('enterprise_model.xml')
```

These examples show the power and flexibility of sgraph for analyzing software architectures. Each example can be adapted and extended for your specific use case!

## Next Steps

- Try these examples with your own code models
- Combine multiple analyses for comprehensive insights
- Create custom visualizations for your specific needs
- Build automated architecture quality checks into your CI/CD pipeline

Happy analyzing! 🔍📊

