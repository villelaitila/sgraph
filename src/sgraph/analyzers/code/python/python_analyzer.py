"""Python source code analyzer."""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from sgraph import SGraph, SElement, SElementAssociation

from ...base import (
    AnalyzerConfig,
    AnalysisResult,
    AnalysisError,
    AnalysisLevel,
)
from ..base import SourceFile, discover_source_files, read_source_file
from .ast_visitor import visit_module
from .import_resolver import resolve_import, get_dependency_type


def analyze_python_project(config: AnalyzerConfig) -> AnalysisResult:
    """
    Analyze a Python project and produce an SGraph model.

    Args:
        config: Analyzer configuration

    Returns:
        AnalysisResult containing the graph, errors and statistics

    Example:
        >>> config = AnalyzerConfig(root_path=Path("./src"))
        >>> result = analyze_python_project(config)
        >>> print(f"Analyzed {result.file_count} files")
        >>> result.graph.to_xml("model.xml")
    """
    graph = SGraph(SElement(None, ''))
    errors: list[AnalysisError] = []
    stats: dict[str, int] = {
        "files_analyzed": 0,
        "files_skipped": 0,
        "packages": 0,
        "modules": 0,
        "classes": 0,
        "functions": 0,
        "dependencies": 0,
    }

    # Module registry for import resolution
    module_registry: dict[str, SElement] = {}

    # Collect pending imports from all files
    all_pending_imports: list[tuple[SElement, list[dict[str, Any]]]] = []

    # Phase 1: Discover and analyze files
    source_files = list(discover_source_files(
        config.root_path,
        tuple(config.include_patterns),
        tuple(config.exclude_patterns),
    ))

    for source in source_files:
        try:
            source_with_content = read_source_file(source)
            file_element, pending_imports = _analyze_file(
                graph=graph,
                source=source_with_content,
                config=config,
                stats=stats,
                module_registry=module_registry,
            )
            if pending_imports:
                all_pending_imports.append((file_element, pending_imports))

        except SyntaxError as e:
            errors.append(AnalysisError(
                file=source.path,
                message=f"Syntax error: {e.msg}",
                line=e.lineno,
                exception=e,
            ))
            stats["files_skipped"] += 1

        except Exception as e:
            errors.append(AnalysisError(
                file=source.path,
                message=str(e),
                exception=e,
            ))
            stats["files_skipped"] += 1

    # Phase 2: Resolve imports into dependencies
    _resolve_all_imports(
        all_pending_imports=all_pending_imports,
        module_registry=module_registry,
        config=config,
        stats=stats,
    )

    return AnalysisResult(
        graph=graph,
        config=config,
        errors=errors,
        stats=stats,
    )


def _analyze_file(
    graph: SGraph,
    source: SourceFile,
    config: AnalyzerConfig,
    stats: dict[str, int],
    module_registry: dict[str, SElement],
) -> tuple[SElement, list[dict[str, Any]]]:
    """
    Analyze a single Python file.

    Returns:
        tuple[SElement, list]: (created element, pending imports)
    """
    if source.content is None:
        raise ValueError(f"Source content is None for {source.path}")

    # Parse the AST
    tree = ast.parse(source.content, filename=str(source.path))

    # Build the element path
    path_parts = list(source.relative_path.parts)

    # Handle __init__.py specially (it represents a package)
    is_package_init = source.is_package_init

    if is_package_init:
        path_parts = path_parts[:-1]  # Drop __init__.py
        element_type = "package"
    else:
        # Strip the .py suffix from the file name
        if path_parts:
            path_parts[-1] = path_parts[-1].removesuffix('.py')
        element_type = "file"

    # Create or get the element
    if path_parts:
        element_path = "/" + "/".join(path_parts)
        file_element = graph.createOrGetElementFromPath(element_path)
    else:
        # Empty path = root (e.g. a lone __init__.py)
        file_element = graph.rootNode

    file_element.setType(element_type)
    file_element.addAttribute("source_path", str(source.path))

    # Register the module
    module_path = source.module_path
    if module_path:
        module_registry[module_path] = file_element

    # Update statistics
    stats["files_analyzed"] += 1
    if is_package_init:
        stats["packages"] += 1
    else:
        stats["modules"] += 1

    # Collect content from the AST (classes, functions, imports)
    pending_imports: list[dict[str, Any]] = []
    if config.level.value >= AnalysisLevel.FILES.value:
        pending_imports = visit_module(
            tree=tree,
            file_element=file_element,
            source=source,
            config=config,
            stats=stats,
        )

    return file_element, pending_imports


def _resolve_all_imports(
    all_pending_imports: list[tuple[SElement, list[dict[str, Any]]]],
    module_registry: dict[str, SElement],
    config: AnalyzerConfig,
    stats: dict[str, int],
) -> None:
    """Resolve all imports into dependencies."""
    for from_element, pending_imports in all_pending_imports:
        for import_info in pending_imports:
            targets = resolve_import(
                import_info=import_info,
                from_element=from_element,
                module_registry=module_registry,
                config=config,
            )
            for target in targets:
                _create_import_dependency(
                    from_elem=from_element,
                    to_elem=target.element,
                    import_info=import_info,
                    stats=stats,
                )


def _create_import_dependency(
    from_elem: SElement,
    to_elem: SElement,
    import_info: dict[str, Any],
    stats: dict[str, int],
) -> None:
    """Create an import dependency between elements."""
    # Avoid self-references
    if from_elem is to_elem:
        return

    dep_type = get_dependency_type(import_info)

    # Collect attributes
    attrs: dict[str, str | int | list[str]] = {}
    if "line" in import_info:
        attrs["line"] = import_info["line"]
    if "names" in import_info:
        attrs["imported_names"] = import_info["names"]

    # Check whether the same dependency already exists
    for existing in from_elem.outgoing:
        if existing.toElement is to_elem and existing.deptype == dep_type:
            return  # Duplicate, skip

    # Create the association
    ea = SElementAssociation(from_elem, to_elem, dep_type, attrs)
    ea.initElems()
    stats["dependencies"] += 1


def analyze_python(
    path: str | Path,
    level: AnalysisLevel = AnalysisLevel.FUNCTIONS,
    **kwargs: Any,
) -> AnalysisResult:
    """
    Convenient entry point for Python analysis.

    Args:
        path: Root directory of the project
        level: Analysis detail level
        **kwargs: Other AnalyzerConfig parameters

    Returns:
        AnalysisResult

    Example:
        >>> result = analyze_python("./src/sgraph")
        >>> print(result.graph.rootNode.getNodeCount())
        >>> result.graph.to_xml("model.xml")
    """
    config = AnalyzerConfig(
        root_path=Path(path) if isinstance(path, str) else path,
        level=level,
        **kwargs,
    )
    return analyze_python_project(config)
