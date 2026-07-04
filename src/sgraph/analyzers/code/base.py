"""Shared structures for code analysis."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator
import fnmatch


@dataclass(frozen=True, slots=True)
class SourceFile:
    """
    Metadata for a source file.

    Attributes:
        path: Absolute path to the file
        relative_path: Path relative to the root directory
        content: File contents (loaded separately)
    """
    path: Path
    relative_path: Path
    content: str | None = None

    @property
    def module_path(self) -> str:
        """
        Convert a file path into a Python module path.

        E.g. src/sgraph/analyzers/__init__.py -> src.sgraph.analyzers
        """
        parts = list(self.relative_path.with_suffix('').parts)
        if parts and parts[-1] == '__init__':
            parts = parts[:-1]
        return '.'.join(parts)

    @property
    def is_package_init(self) -> bool:
        """Whether the file is a package __init__.py."""
        return self.relative_path.name == '__init__.py'


def discover_source_files(
    root: Path,
    include_patterns: tuple[str, ...],
    exclude_patterns: tuple[str, ...],
) -> Iterator[SourceFile]:
    """
    Find source files in a directory.

    Args:
        root: Root directory
        include_patterns: Glob patterns for files to include
        exclude_patterns: Glob patterns for files to skip

    Yields:
        SourceFile objects for the files found
    """
    root = root.resolve()

    def is_excluded(path: Path) -> bool:
        rel_path = path.relative_to(root)
        rel_str = str(rel_path)
        rel_parts = rel_path.parts

        for pat in exclude_patterns:
            # Check whether the pattern is a simple directory name (e.g. "__pycache__")
            # or of the form **/name/** or **/name/*
            clean_pat = pat.strip("*").strip("/")
            if not clean_pat:
                continue

            # If the pattern is "**/__pycache__/**", check whether "__pycache__" is in the path
            if pat.startswith("**/") and (pat.endswith("/**") or pat.endswith("/*")):
                dir_name = clean_pat.rstrip("/*")
                if dir_name in rel_parts:
                    return True

            # Simple fnmatch without ** support
            if fnmatch.fnmatch(rel_str, pat):
                return True

        return False

    for pattern in include_patterns:
        for file_path in root.glob(pattern):
            if file_path.is_file() and not is_excluded(file_path):
                yield SourceFile(
                    path=file_path,
                    relative_path=file_path.relative_to(root),
                )


def read_source_file(source: SourceFile, encoding: str = 'utf-8') -> SourceFile:
    """
    Read a file's contents into a SourceFile object.

    Args:
        source: SourceFile that is missing its content
        encoding: Character encoding (default: utf-8)

    Returns:
        A new SourceFile with content filled in
    """
    try:
        content = source.path.read_text(encoding=encoding)
    except UnicodeDecodeError:
        # Fall back to latin-1
        content = source.path.read_text(encoding='latin-1')
    return SourceFile(
        path=source.path,
        relative_path=source.relative_path,
        content=content
    )
