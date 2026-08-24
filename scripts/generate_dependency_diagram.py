#!/usr/bin/env python3
"""
Generate detailed dependency diagram in PlantUML format.

Shows all files/modules and their dependencies at the most detailed level.

Usage:
    python scripts/generate_dependency_diagram.py [path] [--output file.pu]

Examples:
    # Analyze sgraph itself
    python scripts/generate_dependency_diagram.py ./src/sgraph

    # Analyze any Python project
    python scripts/generate_dependency_diagram.py /path/to/project --output deps.pu

    # Print to stdout only
    python scripts/generate_dependency_diagram.py ./src/sgraph --stdout

    # Include classes and functions
    python scripts/generate_dependency_diagram.py ./src/sgraph --level functions
"""
from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path

# Add src/ to path when running directly from repo
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from sgraph.analyzers import analyze_python, AnalysisLevel


def get_element_path(elem) -> str:
    """Return element's full path."""
    parts = []
    current = elem
    while current is not None and current.name:
        parts.insert(0, current.name)
        current = current.parent
    return ".".join(parts)


def get_top_package(elem) -> str:
    """Return element's top-level package."""
    parts = []
    current = elem
    while current is not None and current.name:
        parts.insert(0, current.name)
        current = current.parent
    return parts[0] if parts else ""


def collect_all_dependencies(result) -> list[tuple[str, str, str, str]]:
    """
    Collect all dependencies from analysis result.

    Returns:
        list of (from_path, to_path, dep_type, from_package)
    """
    deps = []

    def traverse(elem):
        from_path = get_element_path(elem)
        from_pkg = get_top_package(elem)

        for ea in elem.outgoing:
            to_path = get_element_path(ea.toElement)
            dep_type = ea.deptype or "depends"
            deps.append((from_path, to_path, dep_type, from_pkg))

        for child in elem.children:
            traverse(child)

    traverse(result.graph.rootNode)
    return deps


def collect_all_elements(result) -> dict[str, list[str]]:
    """
    Collect all elements grouped by package.

    Returns:
        dict: {package_name: [element_path1, element_path2, ...]}
    """
    elements: dict[str, list[str]] = defaultdict(list)

    def traverse(elem):
        path = get_element_path(elem)
        pkg = get_top_package(elem)

        if path and pkg:
            elements[pkg].append(path)

        for child in elem.children:
            traverse(child)

    traverse(result.graph.rootNode)
    return dict(elements)


def sanitize_name(name: str) -> str:
    """Convert name to PlantUML-compatible format."""
    return name.replace(".", "_").replace("-", "_")


def generate_detailed_plantuml(
    result,
    title: str = "Dependencies",
    group_by_package: bool = True,
) -> str:
    """
    Generate detailed PlantUML diagram.

    Args:
        result: AnalysisResult object
        title: Diagram title
        group_by_package: Whether to group by package

    Returns:
        PlantUML string
    """
    deps = collect_all_dependencies(result)
    elements = collect_all_elements(result)

    lines = [
        "@startuml",
        "!theme plain",
        "skinparam linetype ortho",
        "skinparam packageStyle rectangle",
        "skinparam shadowing false",
        "skinparam defaultFontName monospace",
        "skinparam nodesep 10",
        "skinparam ranksep 20",
        "left to right direction",
        "",
        f"title {title}",
        "",
    ]

    # Collect all elements that have dependencies
    elements_with_deps = set()
    for from_path, to_path, _, _ in deps:
        elements_with_deps.add(from_path)
        elements_with_deps.add(to_path)

    if group_by_package:
        # Group by package
        for pkg in sorted(elements.keys()):
            pkg_elements = [e for e in elements[pkg] if e in elements_with_deps]
            if not pkg_elements:
                continue

            lines.append(f'package "{pkg}" {{')
            for elem_path in sorted(pkg_elements):
                safe_name = sanitize_name(elem_path)
                # Show only module name, not full path
                display_name = elem_path.split(".")[-1]
                lines.append(f'  [{display_name}] as {safe_name}')
            lines.append("}")
            lines.append("")
    else:
        # All elements at same level
        for elem_path in sorted(elements_with_deps):
            safe_name = sanitize_name(elem_path)
            lines.append(f'[{elem_path}] as {safe_name}')
        lines.append("")

    # Add dependencies
    lines.append("' Dependencies")
    seen_deps = set()
    for from_path, to_path, dep_type, _ in sorted(deps):
        if from_path == to_path:
            continue

        dep_key = (from_path, to_path)
        if dep_key in seen_deps:
            continue
        seen_deps.add(dep_key)

        from_safe = sanitize_name(from_path)
        to_safe = sanitize_name(to_path)

        # Use different arrow styles for different dependency types
        if dep_type == "import":
            arrow = "-->"
        elif dep_type == "from_import":
            arrow = "..>"
        else:
            arrow = "-->"

        lines.append(f"{from_safe} {arrow} {to_safe}")

    lines.append("")
    lines.append("@enduml")
    lines.append("")

    return "\n".join(lines)


def generate_simple_plantuml(
    result,
    title: str = "Dependencies",
) -> str:
    """
    Generate simpler PlantUML without package groups.
    Suitable for smaller projects.
    """
    deps = collect_all_dependencies(result)

    lines = [
        "@startuml",
        "!theme plain",
        "skinparam linetype polyline",
        "skinparam shadowing false",
        "skinparam defaultFontName monospace",
        "",
        f"title {title}",
        "",
    ]

    # Collect unique elements
    elements_with_deps = set()
    for from_path, to_path, _, _ in deps:
        elements_with_deps.add(from_path)
        elements_with_deps.add(to_path)

    # Add elements
    for elem_path in sorted(elements_with_deps):
        safe_name = sanitize_name(elem_path)
        lines.append(f'rectangle "{elem_path}" as {safe_name}')

    lines.append("")

    # Add dependencies
    seen_deps = set()
    for from_path, to_path, dep_type, _ in sorted(deps):
        if from_path == to_path:
            continue

        dep_key = (from_path, to_path)
        if dep_key in seen_deps:
            continue
        seen_deps.add(dep_key)

        from_safe = sanitize_name(from_path)
        to_safe = sanitize_name(to_path)
        lines.append(f"{from_safe} --> {to_safe}")

    lines.append("")
    lines.append("@enduml")
    lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Generate detailed dependency diagram from a Python project",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "path",
        nargs="?",
        default="./src/sgraph",
        help="Path to project to analyze (default: ./src/sgraph)",
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file (default: <project_name>_dependencies.pu)",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Print to stdout only, don't save to file",
    )
    parser.add_argument(
        "--level",
        choices=["files", "classes", "functions", "full"],
        default="files",
        help="Analysis detail level (default: files)",
    )
    parser.add_argument(
        "--title",
        help="Diagram title (default: project name + Dependencies)",
    )
    parser.add_argument(
        "--no-group",
        action="store_true",
        help="Don't group by package",
    )
    parser.add_argument(
        "--simple",
        action="store_true",
        help="Use simpler format (rectangles)",
    )
    parser.add_argument(
        "--xml",
        metavar="FILE",
        help="Save model in sgraph XML format",
    )
    parser.add_argument(
        "--deps",
        metavar="FILE",
        help="Save model in sgraph deps txt format",
    )

    args = parser.parse_args()

    # Set level
    level_map = {
        "files": AnalysisLevel.FILES,
        "classes": AnalysisLevel.CLASSES,
        "functions": AnalysisLevel.FUNCTIONS,
        "full": AnalysisLevel.FULL,
    }
    level = level_map[args.level]

    # Analyze
    path = Path(args.path)
    if not path.exists():
        print(f"Error: Path '{path}' not found", file=sys.stderr)
        sys.exit(1)

    print(f"Analyzing: {path}", file=sys.stderr)
    print(f"Level: {args.level}", file=sys.stderr)
    result = analyze_python(str(path), level=level)

    if not result.success:
        print("Error: Analysis failed", file=sys.stderr)
        for error in result.errors:
            print(f"  {error}", file=sys.stderr)
        sys.exit(1)

    print(f"  Files: {result.file_count}", file=sys.stderr)
    print(f"  Packages: {result.stats.get('packages', 0)}", file=sys.stderr)
    print(f"  Modules: {result.stats.get('modules', 0)}", file=sys.stderr)
    print(f"  Classes: {result.stats.get('classes', 0)}", file=sys.stderr)
    print(f"  Functions: {result.stats.get('functions', 0)}", file=sys.stderr)
    print(f"  Dependencies: {result.stats.get('dependencies', 0)}", file=sys.stderr)

    # Generate PlantUML
    title = args.title or f"{path.name} Dependencies"

    if args.simple:
        plantuml = generate_simple_plantuml(result, title=title)
    else:
        plantuml = generate_detailed_plantuml(
            result,
            title=title,
            group_by_package=not args.no_group,
        )

    if args.stdout:
        print(plantuml)
    else:
        output = args.output or f"{path.name}_dependencies.pu"
        Path(output).write_text(plantuml)
        print(f"\nSaved: {output}", file=sys.stderr)
        print("\nRender image:", file=sys.stderr)
        print(f"  plantuml {output}", file=sys.stderr)
        print("  # SVG (better for large diagrams):", file=sys.stderr)
        print(f"  plantuml -tsvg {output}", file=sys.stderr)

    # Save in XML format
    if args.xml:
        result.graph.to_xml(args.xml)
        print(f"\nXML model saved: {args.xml}", file=sys.stderr)

    # Save in deps txt format
    if args.deps:
        result.graph.to_deps(args.deps)
        print(f"\nDeps model saved: {args.deps}", file=sys.stderr)


if __name__ == "__main__":
    main()
