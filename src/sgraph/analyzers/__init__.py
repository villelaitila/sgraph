"""
Analyzers for modeling various sources into SGraph structures.

This module provides tools for analyzing source code, databases and other
structures into hierarchic graph models.

Usage examples:

    # Simple Python analysis
    >>> from sgraph.analyzers import analyze_python
    >>> result = analyze_python("./src")
    >>> result.graph.to_xml("model.xml")

    # Finer control
    >>> from sgraph.analyzers import AnalyzerConfig, AnalysisLevel
    >>> from sgraph.analyzers.code.python import analyze_python_project
    >>> config = AnalyzerConfig(
    ...     root_path="./src",
    ...     level=AnalysisLevel.FULL,
    ...     exclude_patterns=("**/test/**",),
    ... )
    >>> result = analyze_python_project(config)
"""
from sgraph.analyzers.base import (
    AnalyzerConfig,
    AnalysisResult,
    AnalysisError,
    AnalysisLevel,
    DependencyKind,
    SourceLocation,
)


# Lazy import to avoid circular dependencies during package init
def analyze_python(
    path: str,
    level: "AnalysisLevel" = AnalysisLevel.FUNCTIONS,
    **kwargs,
) -> "AnalysisResult":
    """
    Analyze a Python project and produce an SGraph model.

    Args:
        path: Root directory of the project
        level: Analysis detail level
        **kwargs: Other AnalyzerConfig parameters

    Returns:
        AnalysisResult containing the graph, errors and statistics

    Example:
        >>> result = analyze_python("./src/sgraph")
        >>> print(result.graph.rootNode.getNodeCount())
    """
    from sgraph.analyzers.code.python.python_analyzer import analyze_python as _analyze
    return _analyze(path, level, **kwargs)


__all__ = [
    # Main functions
    "analyze_python",
    # Configuration
    "AnalyzerConfig",
    "AnalysisLevel",
    # Results
    "AnalysisResult",
    "AnalysisError",
    # Types
    "DependencyKind",
    "SourceLocation",
]
