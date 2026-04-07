"""Evaluator — turns a parsed Expression into a filtered SGraph.

## View Model Design

All result SGraph instances use a consistent **ghost-parent** structure:

1. ``result.rootNode.children`` contains ONLY the explicitly matched top-level
   elements — no ancestor-only structural nodes.

2. Each element in the result is a shallow copy:
   - **Top-level elements**: ``parent`` is set to the ORIGINAL model's parent
     (a "ghost" ancestor chain).  This makes ``getPath()`` return the correct
     full path, while ``traverseElements`` from ``result.rootNode`` does NOT
     visit the ghost ancestors (they are not in any result node's children
     list).
   - **Nested elements** (children within a subtree copy): ``parent`` points to
     their copy parent within the result subtree, providing correct paths for
     all descendants.

3. Associations in the result graph reference result elements (not originals).

## Operator semantics

- AND: sequential filter — apply right to result of left
- OR:  union — evaluate both on original model, merge top-level elements
- NOT: subtract — evaluate inner on total, prune those paths from current view
"""
from __future__ import annotations

import re
from typing import Optional

from sgraph import SElement, SElementAssociation, SGraph
from sgraph.query.expressions import (
    AndExpr,
    AttrEqualsExpr,
    AttrGtExpr,
    AttrLtExpr,
    AttrNotEqualsExpr,
    AttrRegexExpr,
    ChainSearchExpr,
    DepSearchExpr,
    Expression,
    HasAttrExpr,
    KeywordExpr,
    NotExpr,
    OrExpr,
    ParenExpr,
    ShortestPathExpr,
)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def evaluate(
    expr: Expression,
    model: SGraph,
    total_model: Optional[SGraph] = None,
    max_depth: int = 20,
    chain_collector: Optional[list] = None,
) -> SGraph:
    """Evaluate *expr* against *model* and return a new filtered SGraph.

    Args:
        expr: Parsed AST node.
        model: Model to filter (accumulates through AND chains).
        total_model: Original unfiltered model for NOT complement. Defaults to *model*.
        max_depth: Maximum hop count for chain search (``--->``). Defaults to 20.
        chain_collector: Optional list that receives one ordered tuple of
            :class:`SElement` instances per discovered chain when the
            expression contains a chain search (``--->``). Pass ``None``
            to skip path tracking. Chains discovered inside a NOT branch
            are NOT collected (they would be the *excluded* set, not the
            user-visible result).

    Returns:
        A new :class:`~sgraph.SGraph` with only matching elements.
    """
    total = total_model if total_model is not None else model

    if isinstance(expr, (HasAttrExpr, AttrEqualsExpr, AttrNotEqualsExpr,
                         AttrGtExpr, AttrLtExpr, AttrRegexExpr)):
        return _eval_predicate(expr, model)
    if isinstance(expr, KeywordExpr):
        return _eval_keyword(expr, model)
    if isinstance(expr, AndExpr):
        left = evaluate(expr.left, model, total, max_depth=max_depth,
                        chain_collector=chain_collector)
        return evaluate(expr.right, left, total, max_depth=max_depth,
                        chain_collector=chain_collector)
    if isinstance(expr, OrExpr):
        left = evaluate(expr.left, model, total, max_depth=max_depth,
                        chain_collector=chain_collector)
        right = evaluate(expr.right, model, total, max_depth=max_depth,
                         chain_collector=chain_collector)
        return _union(left, right)
    if isinstance(expr, NotExpr):
        # Chains inside a NOT are the EXCLUDED set; don't surface them.
        return _eval_not(expr, model, total)
    if isinstance(expr, ParenExpr):
        return evaluate(expr.inner, model, total, max_depth=max_depth,
                        chain_collector=chain_collector)
    if isinstance(expr, DepSearchExpr):
        return _eval_dep_search(expr, model, total)
    if isinstance(expr, ChainSearchExpr):
        return _eval_chain_search(
            expr, model, total, max_depth=max_depth,
            chain_collector=chain_collector,
        )
    if isinstance(expr, ShortestPathExpr):
        return _eval_shortest_path(expr, model, total)

    raise ValueError(f"Unknown expression type: {type(expr)}")


# ---------------------------------------------------------------------------
# Element copy helpers
# ---------------------------------------------------------------------------

def _make_copy(src: SElement, parent: Optional[SElement]) -> SElement:
    """Create a shallow copy of *src* with the given *parent*."""
    copy: SElement = object.__new__(SElement)
    copy.name = src.name
    copy.parent = parent
    copy.children = []
    copy.childrenDict = {}
    copy.outgoing = []
    copy.incoming = []
    copy._incoming_index = {}
    copy.attrs = dict(src.attrs)
    copy.human_readable_name = src.human_readable_name
    return copy


def _subtree_copy(src: SElement, parent: Optional[SElement]) -> SElement:
    """Recursively copy *src* and all its descendants.

    The returned copy has ``parent = parent`` and its children are copies
    of *src*'s children (with correct parent pointers).
    """
    copy = _make_copy(src, parent)
    for child in src.children:
        child_copy = _subtree_copy(child, copy)
        copy.children.append(child_copy)
        copy.childrenDict[child_copy.name] = child_copy
    return copy


def _new_result() -> SGraph:
    return SGraph(SElement(None, ''))


def _all_paths(graph: SGraph) -> set[str]:
    paths: set[str] = set()
    graph.rootNode.traverseElements(lambda e: paths.add(e.getPath()))
    return paths


def _all_elements(graph: SGraph) -> list[SElement]:
    elems: list[SElement] = []

    def visit(e: SElement) -> None:
        if e.parent is not None:
            elems.append(e)

    graph.rootNode.traverseElements(visit)
    return elems


def _add_subtree(result: SGraph, src_elem: SElement) -> None:
    """Add *src_elem* and its full subtree as a top-level entry in *result*.

    Uses *src_elem*'s original parent as a ghost for path resolution:
    the copy's parent is set to ``src_elem.parent`` (not ``result.rootNode``),
    so ``getPath()`` returns the full original path.  The copy IS in
    ``result.rootNode.children`` for traversal.
    """
    top = _subtree_copy(src_elem, src_elem.parent)  # ghost parent = original parent
    result.rootNode.children.append(top)


def _add_flat(result: SGraph, src_elem: SElement) -> None:
    """Add a single element (no children) to *result* as a flat ghost copy.

    The copy's parent is ``src_elem.parent`` (ghost), so ``getPath()`` works.
    The copy's children list is empty — ``traverseElements`` does NOT recurse.
    """
    copy = _make_copy(src_elem, src_elem.parent)
    result.rootNode.children.append(copy)


def _is_flat_model(model: SGraph) -> bool:
    """True if the model was produced by an attribute predicate (flat output).

    A flat model's top-level elements have ghost parents AND no children in
    the result graph (they were added via ``_add_flat`` which creates empty
    children lists).  Subtree results ALSO use ghost parents but DO have
    children in the result.
    """
    for child in model.rootNode.children:
        if child.children:
            return False  # has children → not flat
    # If ALL top-level elements have no children, treat as flat
    # (even a subtree of leaf elements would work correctly as flat)
    return True


# ---------------------------------------------------------------------------
# Attribute filters — flat results
# ---------------------------------------------------------------------------

def _attr_value(elem: SElement, attr_name: str) -> Optional[str]:
    if attr_name == 'name':
        return elem.name
    if attr_name == 'type':
        t = elem.getType()
        return t if t else None
    raw = elem.attrs.get(attr_name)
    if raw is None:
        return None
    return ';'.join(str(v) for v in raw) if isinstance(raw, list) else str(raw)


def _matches(expr: Expression, elem: SElement) -> bool:
    if isinstance(expr, HasAttrExpr):
        if expr.attr_name == 'name':
            return True
        if expr.attr_name == 'type':
            return bool(elem.getType())
        return expr.attr_name in elem.attrs

    attr_name: str = getattr(expr, 'attr_name', '')
    val = _attr_value(elem, attr_name)

    if val is None:
        return isinstance(expr, AttrNotEqualsExpr)  # absent → trivially "not equals"

    if isinstance(expr, AttrEqualsExpr):
        return val == expr.value if expr.exact else expr.value.lower() in val.lower()
    if isinstance(expr, AttrNotEqualsExpr):
        return val != expr.value if expr.exact else expr.value.lower() not in val.lower()
    if isinstance(expr, AttrGtExpr):
        try:
            return float(val) > expr.value
        except (ValueError, TypeError):
            return False
    if isinstance(expr, AttrLtExpr):
        try:
            return float(val) < expr.value
        except (ValueError, TypeError):
            return False
    if isinstance(expr, AttrRegexExpr):
        return bool(re.search(expr.pattern, val))

    raise ValueError(f"Not a predicate expression: {type(expr)}")


def _eval_predicate(expr: Expression, model: SGraph) -> SGraph:
    """Return a flat result: one ghost copy per matched element, no ancestors."""
    result = _new_result()
    seen: set[str] = set()

    def visit(elem: SElement) -> None:
        if elem.parent is None:
            return
        if _matches(expr, elem):
            path = elem.getPath()
            if path not in seen:
                seen.add(path)
                _add_flat(result, elem)

    model.rootNode.traverseElements(visit)
    return result


# ---------------------------------------------------------------------------
# Keyword / path — subtree results
# ---------------------------------------------------------------------------

def _eval_keyword(expr: KeywordExpr, model: SGraph) -> SGraph:
    result = _new_result()
    kw = expr.keyword
    seen: set[str] = set()

    if expr.exact:
        if kw == '/':
            for child in model.rootNode.children:
                if child.getPath() not in seen:
                    seen.add(child.getPath())
                    _add_subtree(result, child)
            return result

        if kw.endswith('/**'):
            base = model.findElementFromPath(kw[:-3])
            if base is not None:
                for child in base.children:
                    if child.getPath() not in seen:
                        seen.add(child.getPath())
                        _add_subtree(result, child)
            return result

        if kw.endswith('/*'):
            base = model.findElementFromPath(kw[:-2])
            if base is not None:
                for child in base.children:
                    if child.getPath() not in seen:
                        seen.add(child.getPath())
                        # Single-level: just the element (no children)
                        copy = _make_copy(child, child.parent)
                        result.rootNode.children.append(copy)
            return result

        elem = model.findElementFromPath(kw)
        if elem is not None:
            _add_subtree(result, elem)
        return result

    # Keyword search
    ends_with = kw.endswith('$')
    term = kw[:-1].lower() if ends_with else kw.lower()

    def visit(elem: SElement) -> None:
        if elem.parent is None:
            return
        n = elem.name.lower()
        if n.endswith(term) if ends_with else term in n:
            path = elem.getPath()
            if path not in seen:
                seen.add(path)
                _add_subtree(result, elem)

    model.rootNode.traverseElements(visit)
    return result


# ---------------------------------------------------------------------------
# Logical operators
# ---------------------------------------------------------------------------

def _union(a: SGraph, b: SGraph) -> SGraph:
    """Merge two results, deduplicating by top-level path."""
    result = _new_result()
    seen: set[str] = set()
    a_flat = _is_flat_model(a)
    b_flat = _is_flat_model(b)

    if a_flat or b_flat:
        # Flat union: preserve ghost parents
        for src in (a, b):
            for elem in src.rootNode.children:
                path = elem.getPath()
                if path not in seen:
                    seen.add(path)
                    _add_flat(result, elem)
    else:
        # Hierarchical union: preserve subtrees with ghost parents
        for src in (a, b):
            for top_elem in src.rootNode.children:
                path = top_elem.getPath()
                if path not in seen:
                    seen.add(path)
                    _add_subtree(result, _find_original_top(top_elem))

    return result


def _find_original_top(elem: SElement) -> SElement:
    """Return the original-model element corresponding to this result element.

    For subtree results, the copy's ghost parent chain leads back to the
    original parent.  We reconstruct the original element by finding the
    element whose name matches in the parent's childrenDict.
    """
    if elem.parent is None:
        return elem
    original_parent = elem.parent
    if elem.name in original_parent.childrenDict:
        return original_parent.childrenDict[elem.name]
    # Fallback: elem itself (may be a copy)
    return elem


def _eval_not(expr: NotExpr, model: SGraph, total: SGraph) -> SGraph:
    """NOT: subtract inner-matched paths from current model view."""
    inner = evaluate(expr.inner, total, total)
    # Collect excluded paths from the actual matched subtrees (not ancestors)
    excluded: set[str] = set()
    for top_elem in inner.rootNode.children:
        top_elem.traverseElements(lambda e: excluded.add(e.getPath()))

    result = _new_result()
    is_flat = _is_flat_model(model)

    if is_flat:
        seen: set[str] = set()
        for elem in model.rootNode.children:
            path = elem.getPath()
            if path not in excluded and path not in seen:
                seen.add(path)
                _add_flat(result, elem)
    else:
        for top_elem in model.rootNode.children:
            _prune_into(top_elem, result.rootNode, excluded,
                        ghost_parent=top_elem.parent)

    return result


def _prune_into(
    src: SElement,
    dst_parent: SElement,
    excluded: set[str],
    ghost_parent: Optional[SElement] = None,
) -> None:
    """Recursively copy *src* into *dst_parent*, skipping excluded paths."""
    if src.getPath() in excluded:
        return

    copy = _make_copy(src, ghost_parent if ghost_parent is not None else dst_parent)
    dst_parent.children.append(copy)
    if copy.name not in dst_parent.childrenDict:
        dst_parent.childrenDict[copy.name] = copy

    for child in src.children:
        # Children use copy as parent (proper hierarchy within result subtree)
        _prune_into(child, copy, excluded)


# ---------------------------------------------------------------------------
# Dependency search
# ---------------------------------------------------------------------------

def _eval_dep_search(expr: DepSearchExpr, model: SGraph, total: SGraph) -> SGraph:
    """Find direct dependencies FROM → TO in *total*."""
    from_originals = _resolve_endpoint(expr.from_expr, total)
    to_originals = _resolve_endpoint(expr.to_expr, total)

    from_set = _descendants(from_originals)
    to_set = _descendants(to_originals)
    to_paths: set[str] = {e.getPath() for e in to_set}

    def assoc_ok(a: SElementAssociation) -> bool:
        if a.toElement.getPath() not in to_paths:
            return False
        if expr.dep_type is not None and a.deptype != expr.dep_type:
            return False
        if expr.dep_attr_name is not None:
            av = a.attrs.get(expr.dep_attr_name)
            if av is None and expr.dep_attr_name == 'type':
                av = a.deptype
            if av is None:
                return False
            if expr.dep_attr_value is not None and str(av) != expr.dep_attr_value:
                return False
        return True

    matched: list[SElementAssociation] = []
    for fe in from_set:
        for a in fe.outgoing:
            if assoc_ok(a):
                matched.append(a)

    if not expr.directed:
        from_paths: set[str] = {e.getPath() for e in from_set}

        def rev_ok(a: SElementAssociation) -> bool:
            if a.toElement.getPath() not in from_paths:
                return False
            if expr.dep_type is not None and a.deptype != expr.dep_type:
                return False
            if expr.dep_attr_name is not None:
                av = a.attrs.get(expr.dep_attr_name)
                if av is None and expr.dep_attr_name == 'type':
                    av = a.deptype
                if av is None:
                    return False
                if expr.dep_attr_value is not None and str(av) != expr.dep_attr_value:
                    return False
            return True

        for te in to_set:
            for a in te.outgoing:
                if rev_ok(a):
                    matched.append(a)

    # Build result: shallow copies of matched endpoints + new associations
    result = _new_result()
    elem_map: dict[str, SElement] = {}

    def get_copy(original: SElement) -> SElement:
        path = original.getPath()
        if path in elem_map:
            return elem_map[path]
        copy = _make_copy(original, original.parent)  # ghost parent for path
        elem_map[path] = copy
        result.rootNode.children.append(copy)
        return copy

    for assoc in matched:
        from_copy = get_copy(assoc.fromElement)
        to_copy = get_copy(assoc.toElement)
        key = (id(from_copy), assoc.deptype)
        if key not in to_copy._incoming_index:
            new_assoc = SElementAssociation(from_copy, to_copy, assoc.deptype, dict(assoc.attrs))
            new_assoc.initElems()

    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve_endpoint(
    endpoint_expr: Optional[Expression],
    total: SGraph,
) -> list[SElement]:
    """Evaluate endpoint expression; return ORIGINAL model elements.

    Maps result elements back to originals so outgoing associations are intact.
    None means wildcard — return all children of total.rootNode.
    """
    if endpoint_expr is None:
        return list(total.rootNode.children)

    filtered = evaluate(endpoint_expr, total, total)
    result = []
    for elem in filtered.rootNode.children:
        original = total.findElementFromPath(elem.getPath())
        if original is not None:
            result.append(original)
        else:
            # Fallback: the element IS from the original (flat copy uses ghost parent)
            # Reconstruct original via ghost parent chain
            if elem.parent is not None and elem.name in elem.parent.childrenDict:
                result.append(elem.parent.childrenDict[elem.name])
    return result


def _descendants(elements: list[SElement]) -> set[SElement]:
    """Return *elements* and all descendants (from original model traversal)."""
    result: set[SElement] = set()
    for e in elements:
        e.traverseElements(lambda x: result.add(x))
    return result


# ---------------------------------------------------------------------------
# Chain search  ( ---> )
# ---------------------------------------------------------------------------

def _eval_chain_search(
    expr: ChainSearchExpr,
    model: SGraph,
    total: SGraph,
    max_depth: int = 20,
    chain_collector: Optional[list] = None,
) -> SGraph:
    """Find all directed multi-hop chains FROM → ... → TO via DFS.

    *max_depth* caps the number of hops the DFS will follow from each
    starting element. Defaults to 20.

    *chain_collector*, when provided, receives one entry per discovered
    chain. Each entry is a tuple of original-model :class:`SElement`
    instances in start-to-end order. Callers that want only the
    sub-graph (no path enumeration) pass ``None``.
    """
    from_originals = _resolve_endpoint(expr.from_expr, total)
    to_originals = _resolve_endpoint(expr.to_expr, total)
    is_wildcard_to = expr.to_expr is None

    from_set = _descendants(from_originals)
    to_set = _descendants(to_originals) if not is_wildcard_to else set()
    to_paths: set[str] = {e.getPath() for e in to_set} if not is_wildcard_to else set()

    def edge_ok(a: SElementAssociation) -> bool:
        if expr.dep_type is not None and a.deptype != expr.dep_type:
            return False
        if expr.dep_attr_name is not None:
            av = a.attrs.get(expr.dep_attr_name)
            if av is None and expr.dep_attr_name == 'type':
                av = a.deptype
            if av is None:
                return False
            if expr.dep_attr_value is not None and str(av) != expr.dep_attr_value:
                return False
        return True

    # DFS to find all chains. Collect all associations on any chain.
    chain_assocs: list[SElementAssociation] = []
    found_assoc_ids: set[int] = set()

    def is_target(path: str) -> bool:
        if is_wildcard_to:
            return path not in {e.getPath() for e in from_set}
        return path in to_paths

    def dfs(elem: SElement, visited: set[str], chain: list[SElementAssociation], depth: int) -> None:
        if depth > max_depth:
            return
        for a in elem.outgoing:
            if not edge_ok(a):
                continue
            target = a.toElement
            target_path = target.getPath()
            if target_path in visited:
                continue  # cycle prevention

            if is_target(target_path):
                # Found a chain — record all associations on this path
                for ca in chain:
                    aid = id(ca)
                    if aid not in found_assoc_ids:
                        found_assoc_ids.add(aid)
                        chain_assocs.append(ca)
                aid = id(a)
                if aid not in found_assoc_ids:
                    found_assoc_ids.add(aid)
                    chain_assocs.append(a)

                # Record the ordered element tuple for this chain when
                # the caller asked for it. The chain starts at the DFS
                # root (``fe``) and ends at the matched ``target``.
                if chain_collector is not None:
                    ordered = (
                        (chain[0].fromElement,) if chain
                        else (a.fromElement,)
                    )
                    ordered = ordered + tuple(c.toElement for c in chain)
                    ordered = ordered + (target,)
                    chain_collector.append(ordered)

                # Continue DFS through this node too (more chains possible)
                new_visited = visited | {target_path}
                dfs(target, new_visited, chain + [a], depth + 1)
            else:
                # Continue DFS
                new_visited = visited | {target_path}
                dfs(target, new_visited, chain + [a], depth + 1)

    for fe in from_set:
        dfs(fe, {fe.getPath()}, [], 0)

    # Build result graph from collected associations
    result = _new_result()
    elem_map: dict[str, SElement] = {}

    def get_copy(original: SElement) -> SElement:
        path = original.getPath()
        if path in elem_map:
            return elem_map[path]
        copy = _make_copy(original, original.parent)
        elem_map[path] = copy
        result.rootNode.children.append(copy)
        return copy

    for assoc in chain_assocs:
        from_copy = get_copy(assoc.fromElement)
        to_copy = get_copy(assoc.toElement)
        new_assoc = SElementAssociation(from_copy, to_copy, assoc.deptype, dict(assoc.attrs))
        new_assoc.initElems()

    return result


# ---------------------------------------------------------------------------
# Shortest path  ( --- )
# ---------------------------------------------------------------------------

def _eval_shortest_path(expr: ShortestPathExpr, model: SGraph, total: SGraph) -> SGraph:
    """Find shortest undirected path FROM → ... → TO via BFS."""
    from_originals = _resolve_endpoint(expr.from_expr, total)
    to_originals = _resolve_endpoint(expr.to_expr, total)

    if not from_originals or not to_originals:
        return _new_result()

    from_set = _descendants(from_originals)
    to_paths: set[str] = {e.getPath() for e in _descendants(to_originals)}

    # BFS from each from-element, treating graph as undirected
    # Returns the first (shortest) path found as a list of (element, association) pairs
    from collections import deque

    best_path: Optional[list[tuple[SElement, Optional[SElementAssociation]]]] = None

    for start in from_set:
        start_path = start.getPath()
        if start_path in to_paths:
            # Trivial case: start is already in to-set
            best_path = [(start, None)]
            break

        queue: deque[tuple[SElement, list[tuple[SElement, Optional[SElementAssociation]]]]] = deque()
        queue.append((start, [(start, None)]))
        visited: set[str] = {start_path}

        while queue:
            current, path = queue.popleft()
            if best_path is not None and len(path) >= len(best_path):
                break  # can't beat the best already found

            # Explore outgoing
            for a in current.outgoing:
                neighbor = a.toElement
                npath = neighbor.getPath()
                if npath in visited:
                    continue
                new_path = path + [(neighbor, a)]
                if npath in to_paths:
                    if best_path is None or len(new_path) < len(best_path):
                        best_path = new_path
                    break
                visited.add(npath)
                queue.append((neighbor, new_path))

            # Explore incoming (undirected)
            for a in current.incoming:
                neighbor = a.fromElement
                npath = neighbor.getPath()
                if npath in visited:
                    continue
                new_path = path + [(neighbor, a)]
                if npath in to_paths:
                    if best_path is None or len(new_path) < len(best_path):
                        best_path = new_path
                    break
                visited.add(npath)
                queue.append((neighbor, new_path))

        if best_path is not None and len(best_path) <= 2:
            break  # optimal: direct neighbor

    if best_path is None:
        return _new_result()

    # Build result graph from the path
    result = _new_result()
    elem_map: dict[str, SElement] = {}

    def get_copy(original: SElement) -> SElement:
        path = original.getPath()
        if path in elem_map:
            return elem_map[path]
        copy = _make_copy(original, original.parent)
        elem_map[path] = copy
        result.rootNode.children.append(copy)
        return copy

    for elem, assoc in best_path:
        get_copy(elem)
        if assoc is not None:
            from_copy = get_copy(assoc.fromElement)
            to_copy = get_copy(assoc.toElement)
            new_assoc = SElementAssociation(from_copy, to_copy, assoc.deptype, dict(assoc.attrs))
            new_assoc.initElems()

    return result
