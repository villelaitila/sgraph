"""Python import resolution for creating dependencies."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sgraph import SElement

from ...base import AnalyzerConfig


@dataclass(slots=True)
class ImportTarget:
    """A resolved import target."""
    element: SElement
    module_path: str
    is_external: bool = False


def resolve_import(
    import_info: dict[str, Any],
    from_element: SElement,
    module_registry: dict[str, SElement],
    config: AnalyzerConfig,
) -> list[ImportTarget]:
    """
    Resolve an import statement into target elements.

    Args:
        import_info: Import information (from ast_visitor)
        from_element: The element the import is made from
        module_registry: Registered modules (module_path -> SElement)
        config: Analyzer configuration

    Returns:
        List of ImportTarget objects (may be empty if nothing is found)
    """
    results: list[ImportTarget] = []
    module_name = import_info.get("module", "")
    level = import_info.get("level", 0)
    names = import_info.get("names", [])

    # Handle relative imports
    if level > 0:
        base_path = _resolve_relative_import_base(
            level=level,
            from_element=from_element,
        )
        if base_path is None:
            return []

        if module_name:
            # "from .subpkg import x" -> base_path.module_name
            full_module = f"{base_path}.{module_name}" if base_path else module_name
            target = _find_module(full_module, module_registry, config)
            if target:
                results.append(target)
        elif names:
            # "from . import x, y" -> resolve each name separately
            for name in names:
                full_module = f"{base_path}.{name}" if base_path else name
                target = _find_module(full_module, module_registry, config)
                if target:
                    results.append(target)
        else:
            # Plain package import
            target = _find_module(base_path, module_registry, config)
            if target:
                results.append(target)
    else:
        # Absolute import
        if module_name:
            target = _find_module(module_name, module_registry, config)
            if target:
                results.append(target)

    return results


def _find_module(
    module_name: str,
    module_registry: dict[str, SElement],
    config: AnalyzerConfig,
) -> ImportTarget | None:
    """Find a module in the registry."""
    if not module_name:
        return None

    # Check for a direct match
    if module_name in module_registry:
        return ImportTarget(
            element=module_registry[module_name],
            module_path=module_name,
            is_external=False,
        )

    # Try to find a parent module
    parts = module_name.split(".")
    for i in range(len(parts), 0, -1):
        partial = ".".join(parts[:i])
        if partial in module_registry:
            return ImportTarget(
                element=module_registry[partial],
                module_path=module_name,
                is_external=False,
            )

    # External module - skipped unless we follow them
    if not config.follow_external_imports:
        return None

    return None


def _resolve_relative_import_base(
    level: int,
    from_element: SElement,
) -> str | None:
    """
    Resolve the base path for a relative import.

    Args:
        level: Number of dots (1 = ".", 2 = "..", etc.)
        from_element: The element the import is made from

    Returns:
        Base path (e.g. "pkg" when in pkg/main.py) or None

    Example:
        # If we are in pkg/sub/module.py
        # level=1 -> "pkg.sub"
        # level=2 -> "pkg"
    """
    # Collect the element's path from the root
    path_parts: list[str] = []
    current = from_element
    while current is not None and current.name != '':
        path_parts.insert(0, current.name)
        current = current.parent

    # If a file (not __init__.py), drop the file name
    # __init__.py represents the package; other files are modules within the package
    if from_element.getType() == "file":
        if path_parts:
            path_parts = path_parts[:-1]

    # Move up level-1 levels
    # level=1 (from . import x) = same package
    # level=2 (from .. import x) = parent package
    if level > 1:
        steps_up = level - 1
        if steps_up >= len(path_parts):
            return None  # Too many levels up
        path_parts = path_parts[:-steps_up]

    if not path_parts:
        # We are at the root; a relative import cannot work
        return ""

    return ".".join(path_parts)


def get_dependency_type(import_info: dict[str, Any]) -> str:
    """Return the dependency type based on the import information."""
    if import_info.get("is_from"):
        return "from_import"
    return "import"
