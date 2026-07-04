"""Python AST processing for building the element structure."""
from __future__ import annotations

import ast
from typing import Any

from sgraph import SElement

from ...base import AnalyzerConfig, AnalysisLevel
from ..base import SourceFile


def visit_module(
    tree: ast.Module,
    file_element: SElement,
    source: SourceFile,
    config: AnalyzerConfig,
    stats: dict[str, int],
) -> list[dict[str, Any]]:
    """
    Walk the AST and create elements under file_element.

    Args:
        tree: Parsed AST tree
        file_element: SElement representing the file/package
        source: Source file information
        config: Analyzer configuration
        stats: Statistics (mutated in place)

    Returns:
        List of collected import information for later resolution
    """
    visitor = _ModuleVisitor(
        file_element=file_element,
        source=source,
        config=config,
        stats=stats,
    )
    visitor.visit(tree)
    return visitor.pending_imports


class _ModuleVisitor(ast.NodeVisitor):
    """AST visitor that builds the SElement structure."""

    def __init__(
        self,
        file_element: SElement,
        source: SourceFile,
        config: AnalyzerConfig,
        stats: dict[str, int],
    ):
        self.file_element = file_element
        self.source = source
        self.config = config
        self.stats = stats
        self.current_scope: SElement = file_element
        self.pending_imports: list[dict[str, Any]] = []

    def visit_Module(self, node: ast.Module) -> None:
        """Handle the module top level."""
        for child in node.body:
            self.visit(child)

    def visit_Import(self, node: ast.Import) -> None:
        """Handle 'import x' and 'import x as y' statements."""
        for alias in node.names:
            self.pending_imports.append({
                "module": alias.name,
                "alias": alias.asname,
                "is_from": False,
                "line": node.lineno,
            })

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Handle 'from x import y' statements."""
        if node.module is None and node.level == 0:
            return  # Invalid import

        names = [alias.name for alias in node.names]
        self.pending_imports.append({
            "module": node.module or "",
            "names": names,
            "level": node.level,  # Relative import level (0 = absolute)
            "is_from": True,
            "line": node.lineno,
        })

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Handle class definitions."""
        if self.config.level.value < AnalysisLevel.CLASSES.value:
            return

        class_elem = SElement(self.current_scope, node.name)
        class_elem.setType("class")
        class_elem.addAttribute("line", node.lineno)

        # Decorators
        if node.decorator_list and self.config.level == AnalysisLevel.FULL:
            decorators = [_get_decorator_name(d) for d in node.decorator_list]
            class_elem.addAttribute("decorators", ";".join(filter(None, decorators)))

        # Inheritance - store for later resolution
        if node.bases:
            base_names = [_get_name_from_node(b) for b in node.bases]
            base_names = [b for b in base_names if b]  # Filter out empties
            if base_names:
                class_elem.addAttribute("_pending_bases", base_names)

        self.stats["classes"] = self.stats.get("classes", 0) + 1

        # Process the class body
        if self.config.level.value >= AnalysisLevel.FUNCTIONS.value:
            old_scope = self.current_scope
            self.current_scope = class_elem
            for child in node.body:
                self.visit(child)
            self.current_scope = old_scope

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Handle function/method definitions."""
        self._handle_function(node, is_async=False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Handle async functions."""
        self._handle_function(node, is_async=True)

    def _handle_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        is_async: bool = False,
    ) -> None:
        """Shared handling for functions and methods."""
        if self.config.level.value < AnalysisLevel.FUNCTIONS.value:
            return

        func_elem = SElement(self.current_scope, node.name)

        # Determine type: method vs function
        is_method = self.current_scope.getType() == "class"
        func_elem.setType("method" if is_method else "function")
        func_elem.addAttribute("line", node.lineno)

        if is_async:
            func_elem.addAttribute("async", "true")

        # Decorators at FULL level
        if node.decorator_list and self.config.level == AnalysisLevel.FULL:
            decorators = [_get_decorator_name(d) for d in node.decorator_list]
            decorators = [d for d in decorators if d]
            if decorators:
                func_elem.addAttribute("decorators", ";".join(decorators))

        # Parameters at FULL level
        if self.config.level == AnalysisLevel.FULL:
            params = _extract_parameters(node.args)
            if params:
                func_elem.addAttribute("parameters", ";".join(params))

            # Return type annotation
            if node.returns:
                return_type = _get_name_from_node(node.returns)
                if return_type:
                    func_elem.addAttribute("return_type", return_type)

        self.stats["functions"] = self.stats.get("functions", 0) + 1


def _get_decorator_name(node: ast.expr) -> str:
    """Extract the decorator name from an AST node."""
    match node:
        case ast.Name(id=name):
            return name
        case ast.Attribute(attr=attr):
            return attr
        case ast.Call(func=func):
            return _get_decorator_name(func)
        case _:
            return ""


def _get_name_from_node(node: ast.expr) -> str:
    """Extract a name from an AST expression (type annotations, base classes, etc.)."""
    match node:
        case ast.Name(id=name):
            return name
        case ast.Attribute(value=value, attr=attr):
            prefix = _get_name_from_node(value)
            return f"{prefix}.{attr}" if prefix else attr
        case ast.Subscript(value=value):
            # E.g. list[str] -> list
            return _get_name_from_node(value)
        case ast.Constant(value=value):
            # String annotation "SomeType"
            return str(value) if isinstance(value, str) else ""
        case ast.BinOp():
            # Union type X | Y (Python 3.10+)
            return ""
        case _:
            return ""


def _extract_parameters(args: ast.arguments) -> list[str]:
    """Extract function parameters."""
    params: list[str] = []

    # Positional-only parameters (Python 3.8+)
    for arg in args.posonlyargs:
        params.append(arg.arg)

    # Regular positional/keyword parameters
    for arg in args.args:
        params.append(arg.arg)

    # *args
    if args.vararg:
        params.append(f"*{args.vararg.arg}")

    # Keyword-only parameters
    for arg in args.kwonlyargs:
        params.append(arg.arg)

    # **kwargs
    if args.kwarg:
        params.append(f"**{args.kwarg.arg}")

    return params
