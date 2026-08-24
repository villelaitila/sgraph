#!/usr/bin/env python3
"""
Generate architecture diagram for a Python project in PlantUML format.

Usage:
    python scripts/generate_architecture_diagram.py [path] [--output file.pu]

Examples:
    # Analyze sgraph itself
    python scripts/generate_architecture_diagram.py ./src/sgraph

    # Analyze any Python project
    python scripts/generate_architecture_diagram.py /path/to/project --output arch.pu

    # Print to stdout only
    python scripts/generate_architecture_diagram.py ./src/sgraph --stdout
"""
from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path

# Add src/ to path when running directly from repo
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from sgraph.analyzers import analyze_python, AnalysisLevel


def collect_package_dependencies(result) -> dict[str, set[str]]:
    """
    Collect package-level dependencies from analysis result.

    Returns:
        dict: {from_package: {to_package1, to_package2, ...}}
    """
    deps: dict[str, set[str]] = defaultdict(set)

    def get_package_name(elem) -> str:
        """Return element's package (top-level directory)."""
        parts = []
        current = elem
        while current is not None and current.name:
            parts.insert(0, current.name)
            current = current.parent

        if not parts:
            return ""

        # Return top-level package
        return parts[0]

    def traverse(elem):
        pkg = get_package_name(elem)
        for ea in elem.outgoing:
            to_pkg = get_package_name(ea.toElement)
            if pkg and to_pkg and pkg != to_pkg:
                deps[pkg].add(to_pkg)

        for child in elem.children:
            traverse(child)

    traverse(result.graph.rootNode)
    return dict(deps)


def generate_plantuml(
    result,
    title: str = "Architecture",
    show_classes: bool = False,
) -> str:
    """
    Generate PlantUML diagram from analysis result.

    Args:
        result: AnalysisResult object
        title: Diagram title
        show_classes: Whether to show classes

    Returns:
        PlantUML string
    """
    deps = collect_package_dependencies(result)

    # Collect all packages
    all_packages = set(deps.keys())
    for targets in deps.values():
        all_packages.update(targets)

    # Categorize packages (sgraph-specific)
    core_packages = {"sgraph", "selement", "selementassociation", "sgraph_utils",
                     "exceptions", "definitions"}
    api_packages = {"modelapi", "metricsapi", "graphdataservice"}
    analyzer_packages = {p for p in all_packages if p.startswith("analyzers")}
    other_packages = all_packages - core_packages - api_packages - analyzer_packages

    lines = [
        "@startuml",
        "!theme plain",
        "skinparam linetype ortho",
        "skinparam packageStyle rectangle",
        "skinparam shadowing false",
        "skinparam defaultFontName monospace",
        "",
        f"title {title}",
        "",
    ]

    # Add packages grouped
    def add_package_group(name: str, packages: set[str], color: str = ""):
        if not packages:
            return
        color_str = f" {color}" if color else ""
        lines.append(f'package "{name}"{color_str} {{')
        for pkg in sorted(packages):
            lines.append(f"  [{pkg}]")
        lines.append("}")
        lines.append("")

    if core_packages & all_packages:
        add_package_group("Core", core_packages & all_packages)

    if api_packages & all_packages:
        add_package_group("APIs", api_packages & all_packages)

    if analyzer_packages:
        add_package_group("Analyzers", analyzer_packages, "#LightGreen")

    # Other packages in their own groups
    known_groups = {
        "algorithms": "Algorithms",
        "converters": "Converters",
        "loader": "Loader",
        "compare": "Compare",
        "cli": "CLI",
        "attributes": "Attributes",
    }

    for pkg, group_name in known_groups.items():
        if pkg in other_packages:
            add_package_group(group_name, {pkg})
            other_packages.discard(pkg)

    if other_packages:
        add_package_group("Other", other_packages)

    # Add dependencies
    lines.append("' Dependencies")
    for from_pkg, to_pkgs in sorted(deps.items()):
        for to_pkg in sorted(to_pkgs):
            lines.append(f"[{from_pkg}] --> [{to_pkg}]")

    lines.append("")
    lines.append("@enduml")
    lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Generate architecture diagram from a Python project",
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
        help="Output file (default: <project_name>_architecture.pu)",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Print to stdout only, don't save to file",
    )
    parser.add_argument(
        "--level",
        choices=["files", "classes", "functions"],
        default="files",
        help="Analysis detail level (default: files)",
    )
    parser.add_argument(
        "--title",
        help="Diagram title (default: project name)",
    )

    args = parser.parse_args()

    # Set level
    level_map = {
        "files": AnalysisLevel.FILES,
        "classes": AnalysisLevel.CLASSES,
        "functions": AnalysisLevel.FUNCTIONS,
    }
    level = level_map[args.level]

    # Analyze
    path = Path(args.path)
    if not path.exists():
        print(f"Error: Path '{path}' not found", file=sys.stderr)
        sys.exit(1)

    print(f"Analyzing: {path}", file=sys.stderr)
    result = analyze_python(str(path), level=level)

    if not result.success:
        print("Error: Analysis failed", file=sys.stderr)
        for error in result.errors:
            print(f"  {error}", file=sys.stderr)
        sys.exit(1)

    print(f"  Files: {result.file_count}", file=sys.stderr)
    print(f"  Dependencies: {result.stats.get('dependencies', 0)}", file=sys.stderr)

    # Generate PlantUML
    title = args.title or f"{path.name} Architecture"
    plantuml = generate_plantuml(result, title=title)

    if args.stdout:
        print(plantuml)
    else:
        output = args.output or f"{path.name}_architecture.pu"
        Path(output).write_text(plantuml)
        print(f"Saved: {output}", file=sys.stderr)
        print("\nRender image:", file=sys.stderr)
        print(f"  plantuml {output}", file=sys.stderr)
        png = output.replace('.pu', '.png')
        print(f"  # or: cat {output} | curl -s -d @- "
              f"http://www.plantuml.com/plantuml/png/ > {png}", file=sys.stderr)


if __name__ == "__main__":
    main()
