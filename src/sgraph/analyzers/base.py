"""Shared types and helper functions for the analyzer architecture."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import TYPE_CHECKING
from collections.abc import Sequence

if TYPE_CHECKING:
    from sgraph import SGraph


class AnalysisLevel(Enum):
    """Analysis detail level."""
    PACKAGES_ONLY = auto()  # Packages/directories only
    FILES = auto()          # + files
    CLASSES = auto()        # + classes
    FUNCTIONS = auto()      # + functions/methods
    FULL = auto()           # + attributes, parameters, decorators


class DependencyKind(Enum):
    """Dependency types."""
    IMPORT = "import"
    FROM_IMPORT = "from_import"
    INHERITS = "inherits"
    IMPLEMENTS = "implements"
    CALLS = "calls"
    TYPE_REF = "type_ref"


@dataclass(frozen=True, slots=True)
class SourceLocation:
    """Source code reference."""
    file: Path
    line: int
    column: int = 0
    end_line: int | None = None
    end_column: int | None = None


@dataclass
class AnalyzerConfig:
    """
    Analyzer configuration.

    Attributes:
        root_path: Root directory of the project to analyze
        level: Analysis detail level
        include_patterns: Glob patterns for files to include
        exclude_patterns: Glob patterns for files/directories to skip
        follow_external_imports: Whether to follow external dependencies
        include_stdlib: Whether to include standard-library modules
    """
    root_path: Path
    level: AnalysisLevel = AnalysisLevel.FUNCTIONS
    include_patterns: Sequence[str] = ("**/*.py",)
    exclude_patterns: Sequence[str] = (
        "**/__pycache__/**",
        "**/.*",
        "**/venv/**",
        "**/.venv/**",
        "**/env/**",
        "**/node_modules/**",
        "**/*.egg-info/**",
        "**/build/**",
        "**/dist/**",
    )
    follow_external_imports: bool = False
    include_stdlib: bool = False

    def __post_init__(self):
        # Convert string to Path
        if isinstance(self.root_path, str):
            object.__setattr__(self, 'root_path', Path(self.root_path))


@dataclass
class AnalysisError:
    """A single error during analysis."""
    file: Path
    message: str
    line: int | None = None
    exception: Exception | None = None

    def __str__(self) -> str:
        loc = f":{self.line}" if self.line else ""
        return f"{self.file}{loc}: {self.message}"


@dataclass
class AnalysisResult:
    """
    Analysis result.

    Attributes:
        graph: The produced SGraph model
        config: The configuration that was used
        errors: List of errors encountered during analysis
        stats: Statistics (files analyzed, elements, etc.)
    """
    graph: "SGraph"
    config: AnalyzerConfig
    errors: list[AnalysisError] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)

    @property
    def success(self) -> bool:
        """Whether the analysis succeeded (at least one element)."""
        return self.graph.rootNode.getNodeCount() > 0

    @property
    def file_count(self) -> int:
        """Number of files analyzed."""
        return self.stats.get("files_analyzed", 0)

    @property
    def error_count(self) -> int:
        """Number of errors."""
        return len(self.errors)

    def summary(self) -> str:
        """Return a summary of the analysis."""
        lines = [
            f"Files analyzed: {self.file_count}",
            f"Packages: {self.stats.get('packages', 0)}",
            f"Modules: {self.stats.get('modules', 0)}",
            f"Classes: {self.stats.get('classes', 0)}",
            f"Functions: {self.stats.get('functions', 0)}",
            f"Dependencies: {self.stats.get('dependencies', 0)}",
            f"Errors: {self.error_count}",
        ]
        return "\n".join(lines)
