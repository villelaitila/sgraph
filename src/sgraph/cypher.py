"""Cypher query support for sgraph via sPyCy.

Provides a read-only sPyCy Graph backend that maps sgraph elements and
associations to the labeled property graph model expected by Cypher.

Mapping (software convention):
    SElement        -> Node with labels from element type, properties from attrs
    SElementAssociation -> Relationship with type from deptype
    Parent-child    -> :CONTAINS relationships (hierarchy as explicit edges)

Usage:
    from sgraph import SGraph
    from sgraph.cypher import cypher_query

    model = SGraph.parse_xml_or_zipped_xml('model.xml')
    results = cypher_query(model, '''
        MATCH (f:file)-[r:function_ref]->(g:file)
        RETURN f.name, g.name, r
    ''')
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

import pandas as pd

from sgraph.selement import SElement
from sgraph.selementassociation import SElementAssociation

try:
    from spycy.graph import Graph
    from spycy.spycy import CypherExecutorBase
except ImportError:
    raise ImportError(
        "spycy is required for Cypher support. "
        "Install it with: pip install spycy-aneeshdurg"
    )


class _DictMapping(Mapping):
    """Thin Mapping wrapper over a dict."""

    def __init__(self, data: dict):
        self._data = data

    def __getitem__(self, key):
        return self._data[key]

    def __iter__(self):
        return iter(self._data)

    def __len__(self):
        return len(self._data)


@dataclass
class SGraphCypherBackend(Graph[int, int]):
    """Read-only sPyCy Graph backend wrapping an sgraph model.

    Builds an index of all elements and associations on construction,
    mapping them to the labeled property graph model.

    Args:
        root: Root SElement of the sgraph model.
        include_hierarchy: If True, add :CONTAINS edges for parent-child
            relationships. Default True.
    """

    root: SElement
    include_hierarchy: bool = True

    _node_data: Dict[int, dict] = field(default_factory=dict, init=False)
    _edge_data: Dict[int, dict] = field(default_factory=dict, init=False)
    _elem_to_node: Dict[int, int] = field(default_factory=dict, init=False)
    _node_out: Dict[int, List[int]] = field(default_factory=dict, init=False)
    _node_in: Dict[int, List[int]] = field(default_factory=dict, init=False)
    _edge_src: Dict[int, int] = field(default_factory=dict, init=False)
    _edge_dst: Dict[int, int] = field(default_factory=dict, init=False)
    # Reverse mappings for subgraph extraction
    _node_to_elem: Dict[int, SElement] = field(
        default_factory=dict, init=False)
    _edge_to_assoc: Dict[int, Optional[SElementAssociation]] = field(
        default_factory=dict, init=False)

    def __post_init__(self):
        self._build_index()

    def _collect_elements(self) -> List[SElement]:
        # TODO: Collecting all elements into a list may be problematic for
        # very large models (10M+ elements). Consider a stack-based iterative
        # traversal with a while-loop to avoid both list materialization and
        # Python's recursion limit. Fine for typical project sizes.
        elements: List[SElement] = []
        self.root.traverseElements(lambda e: elements.append(e))
        return elements

    def _build_index(self):
        node_id = 0
        edge_id = 0
        all_elements = self._collect_elements()

        # Pass 1: create nodes for all elements
        for elem in all_elements:
            nid = node_id
            node_id += 1
            self._elem_to_node[id(elem)] = nid
            self._node_to_elem[nid] = elem
            self._node_out[nid] = []
            self._node_in[nid] = []

            labels = set()
            elem_type = elem.getType()
            if elem_type:
                labels.add(elem_type)

            props = dict(elem.attrs) if elem.attrs else {}
            props['name'] = elem.name
            props['path'] = elem.getPath()
            # Remove 'type' from properties since it's a label
            props.pop('type', None)

            self._node_data[nid] = {
                'labels': labels,
                'properties': props,
            }

        # Pass 2: create edges for associations
        seen_assocs = set()
        for elem in all_elements:
            for assoc in elem.outgoing:
                assoc_id = id(assoc)
                if assoc_id in seen_assocs:
                    continue
                seen_assocs.add(assoc_id)

                from_nid = self._elem_to_node.get(id(assoc.fromElement))
                to_nid = self._elem_to_node.get(id(assoc.toElement))
                if from_nid is None or to_nid is None:
                    continue

                eid = edge_id
                edge_id += 1

                edge_props = dict(assoc.attrs) if assoc.attrs else {}
                self._edge_data[eid] = {
                    'type': assoc.deptype or 'unknown',
                    'properties': edge_props,
                }
                self._node_out[from_nid].append(eid)
                self._node_in[to_nid].append(eid)
                self._edge_src[eid] = from_nid
                self._edge_dst[eid] = to_nid
                self._edge_to_assoc[eid] = assoc

        # Pass 3: create CONTAINS edges for hierarchy
        if self.include_hierarchy:
            for elem in all_elements:
                parent_nid = self._elem_to_node.get(id(elem))
                if parent_nid is None:
                    continue
                for child in elem.children:
                    child_nid = self._elem_to_node.get(id(child))
                    if child_nid is None:
                        continue
                    eid = edge_id
                    edge_id += 1
                    self._edge_data[eid] = {
                        'type': 'CONTAINS',
                        'properties': {},
                    }
                    self._node_out[parent_nid].append(eid)
                    self._node_in[child_nid].append(eid)
                    self._edge_src[eid] = parent_nid
                    self._edge_dst[eid] = child_nid
                    # CONTAINS edges have no SElementAssociation
                    self._edge_to_assoc[eid] = None

    @property
    def nodes(self) -> Mapping[int, Any]:
        return _DictMapping(self._node_data)

    @property
    def edges(self) -> Mapping[int, Any]:
        return _DictMapping(self._edge_data)

    def add_node(self, data: Dict[str, Any]) -> int:
        raise NotImplementedError("SGraphCypherBackend is read-only")

    def add_edge(self, start: int, end: int, data: Dict[str, Any]) -> int:
        raise NotImplementedError("SGraphCypherBackend is read-only")

    def out_edges(self, node: int) -> List[int]:
        return self._node_out.get(node, [])

    def in_edges(self, node: int) -> List[int]:
        return self._node_in.get(node, [])

    def remove_node(self, node: int):
        raise NotImplementedError("SGraphCypherBackend is read-only")

    def remove_edge(self, edge: int):
        raise NotImplementedError("SGraphCypherBackend is read-only")

    def src(self, edge: int) -> int:
        return self._edge_src[edge]

    def dst(self, edge: int) -> int:
        return self._edge_dst[edge]


@dataclass
class SGraphCypherExecutor(CypherExecutorBase[int, int]):
    """Cypher executor for sgraph models."""
    graph: SGraphCypherBackend = field(
        default_factory=lambda: SGraphCypherBackend(SElement(None, ''))
    )


def cypher_query(model, query: str,
                 include_hierarchy: bool = True) -> pd.DataFrame:
    """Execute a Cypher query against an sgraph model.

    Args:
        model: An SGraph instance or the root SElement.
        query: A Cypher query string.
        include_hierarchy: If True, add :CONTAINS edges for the element
            tree. Default True.

    Returns:
        pandas DataFrame with query results.
    """
    from sgraph.sgraph import SGraph

    if isinstance(model, SGraph):
        root = model.rootNode
    else:
        root = model

    backend = SGraphCypherBackend(root=root,
                                 include_hierarchy=include_hierarchy)
    executor = SGraphCypherExecutor(graph=backend)
    return executor.exec(query)


def _extract_subgraph(result: pd.DataFrame,
                      backend: SGraphCypherBackend):
    """Build an SGraph subgraph from Cypher query results.

    Scans the result DataFrame for Node and Edge objects returned by
    sPyCy, maps them back to the original SElements and
    SElementAssociations, and assembles a new SGraph containing only
    those elements and associations.
    """
    from spycy.types import Node, Edge
    from sgraph.sgraph import SGraph

    node_ids = set()
    edge_ids = set()

    for col in result.columns:
        for val in result[col]:
            if val is pd.NA:
                continue
            if isinstance(val, Node):
                node_ids.add(val.id_)
            elif isinstance(val, Edge):
                if isinstance(val.id_, list):
                    edge_ids.update(val.id_)
                else:
                    edge_ids.add(val.id_)
            elif isinstance(val, list):
                for v in val:
                    if isinstance(v, Node):
                        node_ids.add(v.id_)
                    elif isinstance(v, Edge):
                        edge_ids.add(v.id_)

    # Also include source/target nodes of matched edges
    for eid in list(edge_ids):
        node_ids.add(backend.src(eid))
        node_ids.add(backend.dst(eid))

    if not node_ids:
        return SGraph(SElement(None, ''))

    # Build new graph: recreate element paths and associations
    new_graph = SGraph(SElement(None, ''))
    path_to_new_elem = {}

    for nid in sorted(node_ids):
        elem = backend._node_to_elem[nid]
        path = elem.getPath()
        if not path:
            continue
        new_elem = new_graph.createOrGetElementFromPath(path)
        # Copy type
        orig_type = elem.getType()
        if orig_type:
            new_elem.setType(orig_type)
        # Copy attributes (except type which is already set)
        if elem.attrs:
            for k, v in elem.attrs.items():
                if k != 'type':
                    new_elem.addAttribute(k, v)
        path_to_new_elem[path] = new_elem

    for eid in sorted(edge_ids):
        assoc = backend._edge_to_assoc.get(eid)
        if assoc is None:
            # CONTAINS edge — hierarchy is implicit in the tree
            continue
        from_path = assoc.fromElement.getPath()
        to_path = assoc.toElement.getPath()
        from_elem = path_to_new_elem.get(from_path)
        to_elem = path_to_new_elem.get(to_path)
        if from_elem is None:
            from_elem = new_graph.createOrGetElementFromPath(from_path)
            path_to_new_elem[from_path] = from_elem
        if to_elem is None:
            to_elem = new_graph.createOrGetElementFromPath(to_path)
            path_to_new_elem[to_path] = to_elem
        new_assoc = SElementAssociation(from_elem, to_elem, assoc.deptype)
        if assoc.attrs:
            for k, v in assoc.attrs.items():
                new_assoc.addAttribute(k, v)
        new_assoc.initElems()

    return new_graph


# ── Output formatters ──────────────────────────────────────────────

TABULAR_FORMATS = ('table', 'csv', 'tsv', 'json', 'jsonl')
GRAPH_FORMATS = ('xml', 'deps', 'dot', 'plantuml', 'graphml', 'cytoscape')
ALL_FORMATS = TABULAR_FORMATS + GRAPH_FORMATS


def _output_tabular(result: pd.DataFrame, fmt: str):
    """Write DataFrame in a tabular format to stdout."""
    import json as json_mod
    import sys

    if fmt == 'table':
        if len(result):
            print(result.to_string(index=False), flush=True)
    elif fmt == 'csv':
        print(result.to_csv(index=False), end='')
    elif fmt == 'tsv':
        print(result.to_csv(index=False, sep='\t'), end='')
    elif fmt == 'json':
        records = _dataframe_to_serializable(result)
        print(json_mod.dumps(records, ensure_ascii=False, indent=2))
    elif fmt == 'jsonl':
        records = _dataframe_to_serializable(result)
        for rec in records:
            print(json_mod.dumps(rec, ensure_ascii=False))


def _dataframe_to_serializable(df: pd.DataFrame) -> list:
    """Convert DataFrame to a JSON-serializable list of dicts."""
    from spycy.types import Node, Edge

    records = df.to_dict('records')
    for rec in records:
        for k, v in list(rec.items()):
            if v is pd.NA:
                rec[k] = None
            elif isinstance(v, Node):
                rec[k] = f'Node({v.id_})'
            elif isinstance(v, Edge):
                rec[k] = f'Edge({v.id_})'
            elif isinstance(v, (set, frozenset)):
                rec[k] = list(v)
    return records


def _output_graph(result: pd.DataFrame, fmt: str,
                  backend: SGraphCypherBackend, outfile: Optional[str]):
    """Extract subgraph from results and output in a graph format."""
    import json as json_mod
    import sys

    subgraph = _extract_subgraph(result, backend)

    if fmt == 'xml':
        subgraph.to_xml(outfile)
    elif fmt == 'deps':
        subgraph.to_deps(outfile)
    elif fmt == 'plantuml':
        subgraph.to_plantuml(outfile)
    elif fmt == 'dot':
        from sgraph.converters.xml_to_dot import graph_to_dot
        graph_to_dot(subgraph)
    elif fmt == 'graphml':
        if outfile:
            from sgraph.converters.graphml import sgraph_to_graphml_file
            sgraph_to_graphml_file(subgraph, outfile)
        else:
            # graphml requires a file; write to stdout via temp
            import tempfile
            import os
            from sgraph.converters.graphml import sgraph_to_graphml_file
            with tempfile.NamedTemporaryFile(
                    mode='w', suffix='.graphml',
                    delete=False) as tmp:
                tmp_path = tmp.name
            try:
                sgraph_to_graphml_file(subgraph, tmp_path)
                with open(tmp_path, 'r') as f:
                    sys.stdout.write(f.read())
            finally:
                os.unlink(tmp_path)
    elif fmt == 'cytoscape':
        from sgraph.converters.sgraph_to_cytoscape import graph_to_cyto
        data = graph_to_cyto(subgraph)
        print(json_mod.dumps(data, ensure_ascii=False, indent=2))


# ── CLI ─────────────────────────────────────────────────────────────

def main():
    """CLI entry point: python -m sgraph.cypher <model> [query]"""
    import argparse
    import sys
    import time

    from sgraph.sgraph import SGraph
    from spycy.errors import ExecutionError

    parser = argparse.ArgumentParser(
        prog='python -m sgraph.cypher',
        description='Query sgraph models with Cypher.')
    parser.add_argument('model', help='Path to model file (.xml or .xml.zip)')
    parser.add_argument('query', nargs='?', default=None,
                        help='Cypher query to execute. '
                        'If omitted, starts interactive REPL.')
    parser.add_argument('--no-hierarchy', action='store_true',
                        help='Do not create :CONTAINS edges for the '
                        'element tree')
    parser.add_argument('-f', '--format', default='table',
                        choices=ALL_FORMATS,
                        help='Output format (default: table). '
                        'Graph formats (xml, deps, dot, plantuml, graphml, '
                        'cytoscape) extract a subgraph from Node/Edge '
                        'objects in the result.')
    parser.add_argument('-o', '--output', default=None,
                        help='Output file (default: stdout). '
                        'Required for graphml format.')
    args = parser.parse_args()

    print(f'Loading {args.model}...', file=sys.stderr)
    t0 = time.time()
    try:
        model = SGraph.parse_xml_or_zipped_xml(args.model)
    except Exception as e:
        print(f'Error: {e}', file=sys.stderr)
        sys.exit(1)
    t_load = time.time() - t0

    print(f'Building Cypher index...', file=sys.stderr)
    t0 = time.time()
    include_hierarchy = not args.no_hierarchy
    backend = SGraphCypherBackend(root=model.rootNode,
                                 include_hierarchy=include_hierarchy)
    executor = SGraphCypherExecutor(graph=backend)
    t_index = time.time() - t0

    n_nodes = len(backend._node_data)
    n_edges = len(backend._edge_data)
    print(f'Ready: {n_nodes} nodes, {n_edges} edges '
          f'(load {t_load:.2f}s, index {t_index:.2f}s)', file=sys.stderr)

    if args.query:
        # Single query mode
        try:
            result = executor.exec(args.query)
            _output_result(result, args.format, backend, args.output)
        except ExecutionError as e:
            print(f'Error: {e}', file=sys.stderr)
            sys.exit(1)
    else:
        # Interactive REPL
        _run_repl(executor, backend, args.format, args.output)


def _output_result(result: pd.DataFrame, fmt: str,
                   backend: SGraphCypherBackend,
                   outfile: Optional[str] = None):
    """Route output to the right formatter."""
    if fmt in TABULAR_FORMATS:
        _output_tabular(result, fmt)
    elif fmt in GRAPH_FORMATS:
        _output_graph(result, fmt, backend, outfile)


def _run_repl(executor: SGraphCypherExecutor,
              backend: SGraphCypherBackend,
              fmt: str, outfile: Optional[str]):
    """Interactive Cypher REPL."""
    import sys
    import time
    from spycy.errors import ExecutionError

    try:
        import readline  # noqa: F401 - enables line editing
    except ImportError:
        pass

    print('Enter Cypher queries. End with ; or blank line. '
          'Type "quit" to exit.', file=sys.stderr)

    while True:
        try:
            lines = []
            prompt = 'cypher> '
            while True:
                line = input(prompt)
                stripped = line.strip().lower()
                if stripped in ('quit', 'exit'):
                    return
                # In-session format switch: \format <name>
                if stripped.startswith('\\format'):
                    parts = stripped.split()
                    if len(parts) == 2 and parts[1] in ALL_FORMATS:
                        fmt = parts[1]
                        print(f'Output format: {fmt}', file=sys.stderr)
                    else:
                        print(f'Available formats: '
                              f'{", ".join(ALL_FORMATS)}',
                              file=sys.stderr)
                    lines = []
                    break
                lines.append(line)
                if line.strip().endswith(';'):
                    break
                if line.strip() == '' and lines:
                    break
                prompt = '     > '

            query_str = ' '.join(lines).strip()
            if query_str.endswith(';'):
                query_str = query_str[:-1]
            if not query_str:
                continue

            t0 = time.time()
            result = executor.exec(query_str)
            elapsed = time.time() - t0
            _output_result(result, fmt, backend, outfile)
            print(f'({len(result)} rows, {elapsed:.3f}s)',
                  file=sys.stderr)
        except ExecutionError as e:
            print(f'Error: {e}', file=sys.stderr)
        except EOFError:
            print()
            return


if __name__ == '__main__':
    main()
