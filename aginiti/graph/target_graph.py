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


def build_static_graph(library: OperatorLibrary) -> Graph:
    """Every operator's declared graph_edge, regardless of confirmation
    status -- deliberately NOT filtered by ssg.is_confirmed the way
    build_graph() is. This is the library's own FIXED prior structural
    hypothesis about how everything connects (an operator's author wrote
    graph_edge to mean "what confirming this would mean structurally,"
    independent of whether it's been proven yet), the admissible/
    optimistic heuristic surface aginiti_planner.py's potential_progress
    computes Φ over -- same role a relaxed-problem heuristic plays for
    A* search. Never mutated mid-campaign; safe to compute once per
    rank() call and reuse across every candidate."""
    graph: Graph = {START: set()}
    for op in library:
        if op.graph_edge is None:
            continue
        _add_edge(graph, *op.graph_edge)
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


def distance_to_nearest_target(graph: Graph, targets: tuple[str, ...]) -> dict[str, int]:
    """BFS distance from EVERY node to its nearest target, as ONE multi-
    source BFS over the graph's REVERSAL starting from all targets at
    once (O(V+E) total) rather than a separate forward BFS per candidate
    node. This is Φ (negated) from aginiti_planner.py's potential_progress
    -- a node not present in the returned dict has no static path to any
    target at all (callers treat that as "no shaping signal," not an
    error)."""
    reverse_graph: Graph = {node: set() for node in graph}
    for node, neighbors in graph.items():
        for neighbor in neighbors:
            reverse_graph.setdefault(neighbor, set()).add(node)

    distances: dict[str, int] = {}
    queue: deque[str] = deque()
    for target in targets:
        if target not in distances:
            distances[target] = 0
            queue.append(target)
    while queue:
        node = queue.popleft()
        for neighbor in reverse_graph.get(node, ()):
            if neighbor not in distances:
                distances[neighbor] = distances[node] + 1
                queue.append(neighbor)
    return distances


def min_distance_to_any(distances: dict[str, int], targets: tuple[str, ...]) -> int | None:
    reached = [distances[t] for t in targets if t in distances]
    return min(reached) if reached else None
