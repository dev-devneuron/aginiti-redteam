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

from aginiti.core.graph.ssg import SecurityStateGraph
from aginiti.operators.library import OperatorLibrary

START = "start"

Graph = dict[str, set[str]]

# Class-precondition hub nodes (alongside
# aginiti/operators/base.py's ClassPrecondition) -- what makes a
# SEMANTICALLY-gated downstream operator (one that names a claim CLASS,
# not one specific antecedent key) genuinely reachable by graph traversal,
# not merely eligible via preconditions_met()'s scan. A hub is a synthetic
# node identifying "the set of every claim tagged with this category/
# attack_category/boundary-threshold" -- ANY operator's confirmed effect
# carrying that tag gets an edge INTO the hub (wired below, from the
# library/ssg's own effect metadata, not from any per-operator
# declaration), and a ClassPrecondition-gated operator declares its OWN
# graph_edge starting FROM the matching hub name (see
# category_hub/attack_category_hub/boundary_hub). This is what lets
# path_progress/emergent_impact/potential_progress/chain_value/
# budget_feasible -- every one of aginiti_planner.py's graph-reading terms
# -- reason over a discovered, non-hardcoded chain with ZERO changes to
# that module: they all already consume build_graph()/build_static_graph()
# as an abstract adjacency list, never Operator.preconditions/graph_edge
# directly.
#
# COST FIX (same day, found via this module's own composite-score test
# suite): a hub node is NOT a real operator step -- it's a bookkeeping
# annotation ("this claim happens to carry this tag"), free to "traverse."
# Only a genuine `op.graph_edge` represents one real prompt spent. Treating
# every graph edge as an equal-cost hop (plain BFS, the original
# shortest_distances/distance_to_nearest_target) silently OVER-counted
# real cost for any class-gated chain: a path that is actually N real
# operator executions passes through up to N extra hub nodes, so plain BFS
# reported it as needing ~2N hops. budget_feasible (aginiti_planner.py)
# prices remaining hops at the cheapest operator's cost -- with real cost
# doubled, it wrongly pruned a genuinely completable class-gated chain as
# "provably can't fit in budget," breaking that function's own documented
# "admissible/optimistic, never a false negative" contract. Fixed below
# with a 0-1 BFS (Dial's algorithm): an edge INTO a hub node (identified
# by the "class::" prefix every hub name carries) costs 0; every other
# edge -- including a class-gated operator's OWN declared edge OUT of a
# hub -- costs 1, exactly one real operator execution, same as any
# ordinary chain edge always has.

_HUB_PREFIX = "class::"


def _is_hub(node: str) -> bool:
    return node.startswith(_HUB_PREFIX)


def category_hub(category: str) -> str:
    return f"{_HUB_PREFIX}category:{category}"


def attack_category_hub(attack_category: str) -> str:
    return f"{_HUB_PREFIX}attack_category:{attack_category}"


def boundary_hub(min_rank: int) -> str:
    """`min_rank` is a security_boundary rank (aginiti/graph/
    security_boundary.py's rank()) -- "reachable once ANY claim at this
    rank or higher is confirmed." A claim confirmed at rank R is wired
    (below) into every threshold hub 0..R, so a downstream operator gated
    on "boundary >= 2" is satisfied by a rank-2 claim OR a rank-5 one."""
    return f"{_HUB_PREFIX}boundary_ge:{min_rank}"


def _add_edge(graph: Graph, a: str, b: str) -> None:
    graph.setdefault(a, set()).add(b)
    graph.setdefault(b, set())


def _add_hub_edges_for_effect(graph: Graph, key: str, category: str | None,
                               attack_category: str | None, boundary_level: str | None) -> None:
    from aginiti.core.graph.security_boundary import BOUNDARY_UNSPECIFIED, rank as boundary_rank

    if category is not None:
        _add_edge(graph, key, category_hub(category))
    if attack_category is not None:
        _add_edge(graph, key, attack_category_hub(attack_category))
    if boundary_level is not None and boundary_level != BOUNDARY_UNSPECIFIED:
        r = boundary_rank(boundary_level)
        for threshold in range(0, r + 1):
            _add_edge(graph, key, boundary_hub(threshold))


def build_graph(library: OperatorLibrary, ssg: SecurityStateGraph,
                 extra_edge: tuple[str, str] | None = None) -> Graph:
    """Adjacency list of the currently-CONFIRMED subgraph. `extra_edge`
    hypothetically adds one more edge -- used to ask "what if this specific
    not-yet-run operator succeeded" without mutating the SSG.

    Also wires hub edges (see this module's docstring) from every
    currently-CONFIRMED, tagged claim into its matching class hub node(s)
    -- read from the SSG's own recorded tags (ssg.claim_category /
    claim_attack_category / claim_boundary), i.e. what was ACTUALLY
    asserted at runtime, not merely predicted by an operator's declared
    ClaimEffect. This is genuinely emergent: a hub gets an inbound edge
    from WHATEVER claim confirms with that tag, regardless of which
    operator produced it or whether that operator existed when any
    class-gated downstream operator was written."""
    graph: Graph = {START: set()}
    for op in library:
        if op.graph_edge is None:
            continue
        success_keys = {e.key for e in op.effects_success}
        if any(ssg.is_confirmed(k) for k in success_keys):
            _add_edge(graph, *op.graph_edge)
    tagged_keys = set(ssg.claim_category) | set(ssg.claim_attack_category) | set(ssg.claim_boundary)
    for key in tagged_keys:
        if not ssg.is_confirmed(key):
            continue
        _add_hub_edges_for_effect(graph, key, ssg.claim_category.get(key),
                                   ssg.claim_attack_category.get(key), ssg.claim_boundary.get(key))
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
    rank() call and reuse across every candidate.

    Also wires the same class-hub edges as build_graph(), but read from
    the library's own DECLARED effects_success (this function takes no
    ssg -- see its own established "constant per operator for a fixed
    library" contract, unchanged here) rather than from confirmed runtime
    state -- the optimistic/unconfirmed mirror of build_graph()'s hub
    wiring, exactly the same relationship every other declared graph_edge
    already has between these two functions."""
    graph: Graph = {START: set()}
    for op in library:
        if op.graph_edge is not None:
            _add_edge(graph, *op.graph_edge)
        for effect in op.effects_success:
            _add_hub_edges_for_effect(graph, effect.key, effect.category,
                                       effect.attack_category, effect.security_boundary)
    return graph


def shortest_distances(graph: Graph, start: str = START) -> dict[str, int]:
    """Shortest-hop distance from `start` to every node reachable through
    currently-confirmed edges -- REAL operator hops, not raw graph edges.

    0-1 BFS (Dial's algorithm), not plain BFS: an edge INTO a hub node
    (this module's docstring on class hubs) costs 0 (it's a bookkeeping
    annotation, not an operator execution); every other edge costs 1, one
    real prompt. Degenerates to exactly plain BFS whenever the graph has
    no hub nodes at all (every edge costs 1, deque behaves identically to
    a plain FIFO queue) -- every caller/test predating class hubs is
    completely unaffected."""
    distances = {start: 0}
    dq: deque[str] = deque([start])
    while dq:
        node = dq.popleft()
        for neighbor in graph.get(node, ()):
            cost = 0 if _is_hub(neighbor) else 1
            candidate = distances[node] + cost
            if neighbor not in distances or candidate < distances[neighbor]:
                distances[neighbor] = candidate
                if cost == 0:
                    dq.appendleft(neighbor)
                else:
                    dq.append(neighbor)
    return distances


def distance_to_nearest_target(graph: Graph, targets: tuple[str, ...]) -> dict[str, int]:
    """Distance from EVERY node to its nearest target -- REAL operator
    hops, same 0-1 BFS rule as shortest_distances() (see that function's
    own docstring): an edge is free if its DESTINATION (in the graph's
    original, forward direction) is a hub node, costs 1 otherwise. This is
    computed as ONE multi-source 0-1 BFS over the graph's REVERSAL
    starting from all targets at once (O(V+E) total) rather than a
    separate forward search per candidate node. This is Φ (negated) from
    aginiti_planner.py's potential_progress -- a node not present in the
    returned dict has no static path to any target at all (callers treat
    that as "no shaping signal," not an error)."""
    reverse_graph: Graph = {node: set() for node in graph}
    for node, neighbors in graph.items():
        for neighbor in neighbors:
            reverse_graph.setdefault(neighbor, set()).add(node)

    distances: dict[str, int] = {}
    dq: deque[str] = deque()
    for target in targets:
        if target not in distances:
            distances[target] = 0
            dq.append(target)
    while dq:
        node = dq.popleft()
        for neighbor in reverse_graph.get(node, ()):
            # The original forward edge is (neighbor -> node); its cost
            # depends on whether NODE (the forward destination) is a hub.
            cost = 0 if _is_hub(node) else 1
            candidate = distances[node] + cost
            if neighbor not in distances or candidate < distances[neighbor]:
                distances[neighbor] = candidate
                if cost == 0:
                    dq.appendleft(neighbor)
                else:
                    dq.append(neighbor)
    return distances


def min_distance_to_any(distances: dict[str, int], targets: tuple[str, ...]) -> int | None:
    reached = [distances[t] for t in targets if t in distances]
    return min(reached) if reached else None
