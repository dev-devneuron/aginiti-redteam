"""A lightweight directed graph derived from the SSG's CONFIRMED structural
claims -- the substrate for answering exactly the questions a graph-based
red-teaming tool should be able to answer: what path exists from current
access to a mission target, and which trust edge would shorten it. This is
what makes the planner reason over graph structure instead of only ranking
flat claim keys.

Nodes are concept identifiers (the same strings used as claim keys, plus
the virtual START node). Each operator optionally declares
`graph_edge = (from_node, to_node)` (aginiti/operators/library.py): what
confirming its success effect means structurally. An edge only exists in
the graph once the SSG actually confirms that operator's success -- this is
Aginiti's *belief* about connectivity, built up over the campaign, never
the true (unknown in advance) topology.
"""
from __future__ import annotations

from collections import deque

from aginiti.graph.ssg import SecurityStateGraph
from aginiti.operators.library import OperatorLibrary

START = "start"

Graph = dict[str, set[str]]


def _add_edge(graph: Graph, a: str, b: str) -> None:
    graph.setdefault(a, set()).add(b)
    graph.setdefault(b, set())


def build_graph(library: OperatorLibrary, ssg: SecurityStateGraph,
                 extra_edge: tuple[str, str] | None = None) -> Graph:
    """Adjacency list of the currently-CONFIRMED subgraph. `extra_edge`
    hypothetically adds one more edge -- used to ask "what if this specific
    not-yet-run operator succeeded" without mutating the SSG."""
    graph: Graph = {START: set()}
    for op in library:
        if op.graph_edge is None:
            continue
        success_keys = {e.key for e in op.effects_success}
        if any(ssg.is_confirmed(k) for k in success_keys):
            _add_edge(graph, *op.graph_edge)
    if extra_edge:
        _add_edge(graph, *extra_edge)
    return graph


def shortest_distances(graph: Graph, start: str = START) -> dict[str, int]:
    """BFS shortest-hop distance from `start` to every node reachable
    through currently-confirmed edges."""
    distances = {start: 0}
    queue = deque([start])
    while queue:
        node = queue.popleft()
        for neighbor in graph.get(node, ()):
            if neighbor not in distances:
                distances[neighbor] = distances[node] + 1
                queue.append(neighbor)
    return distances


def min_distance_to_any(distances: dict[str, int], targets: tuple[str, ...]) -> int | None:
    reached = [distances[t] for t in targets if t in distances]
    return min(reached) if reached else None
