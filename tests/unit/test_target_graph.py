from aginiti.core.graph.schema import ClaimStatus, RiskTier
from aginiti.core.graph.security_boundary import BOUNDARY_L2, BOUNDARY_L4
from aginiti.core.graph.ssg import CATEGORY_TRUST_EDGE, SecurityStateGraph
from aginiti.core.graph.target_graph import (
    START,
    attack_category_hub,
    boundary_hub,
    build_graph,
    build_static_graph,
    category_hub,
    distance_to_nearest_target,
    min_distance_to_any,
    shortest_distances,
)
from aginiti.operators.library import ClaimEffect, ClassPrecondition, Operator, OperatorLibrary


def _op(op_id, edge, success_key="win"):
    return Operator(
        id=op_id, description=op_id, prompt="x", channel="direct", preconditions=(),
        effects_success=(ClaimEffect(success_key, ClaimStatus.CONFIRMED),),
        effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW, graph_edge=edge,
    )


def test_build_graph_only_includes_confirmed_edges():
    ssg = SecurityStateGraph()
    library = OperatorLibrary([_op("a", (START, "mid"), success_key="a_done")])
    graph = build_graph(library, ssg)
    assert graph[START] == set()  # nothing confirmed yet

    ssg.assert_claim("a_done", "true", ClaimStatus.CONFIRMED)
    graph = build_graph(library, ssg)
    assert "mid" in graph[START]


def test_shortest_distances_bfs_over_a_chain():
    graph = {START: {"a"}, "a": {"b"}, "b": {"c"}, "c": set()}
    distances = shortest_distances(graph)
    assert distances == {START: 0, "a": 1, "b": 2, "c": 3}


def test_shortest_distances_handles_branching():
    graph = {START: {"a", "b"}, "a": {"target"}, "b": set(), "target": set()}
    distances = shortest_distances(graph)
    assert distances["target"] == 2


def test_min_distance_to_any_picks_the_closer_target():
    distances = {START: 0, "a": 1, "b": 5}
    assert min_distance_to_any(distances, ("b", "a")) == 1


def test_min_distance_to_any_returns_none_when_unreached():
    distances = {START: 0}
    assert min_distance_to_any(distances, ("nowhere",)) is None


def test_extra_edge_lets_you_ask_what_if_hypothetically():
    ssg = SecurityStateGraph()
    library = OperatorLibrary([])
    graph = build_graph(library, ssg, extra_edge=(START, "mission_target"))
    distances = shortest_distances(graph)
    assert distances["mission_target"] == 1


# -- build_static_graph / distance_to_nearest_target (potential-based
# reward shaping's Phi substrate) --------------------------------------

def test_build_static_graph_includes_edges_regardless_of_confirmation():
    # The defining difference from build_graph(): nothing needs to be
    # confirmed, or even have a claim asserted at all.
    library = OperatorLibrary([_op("a", (START, "mid"), success_key="a_done"),
                                _op("b", ("mid", "target"), success_key="b_done")])
    graph = build_static_graph(library)
    assert "mid" in graph[START]
    assert "target" in graph["mid"]


def test_build_static_graph_ignores_operators_with_no_graph_edge_for_reachability():
    # An operator with no declared graph_edge contributes nothing reachable
    # FROM START -- but (2026-08-12) its effect's class-hub edge is still
    # wired, independent of graph_edge: hub wiring exists precisely to
    # decouple "was this claim confirmed" from "did its operator also
    # declare a topological edge" -- see this module's own docstring on
    # class hubs and test_build_static_graph_wires_hub_edges_from_declared_
    # effects_unconditionally below for that behavior directly.
    op = Operator(id="no_edge", description="x", prompt="x", channel="direct", preconditions=(),
                   effects_success=(ClaimEffect("k", ClaimStatus.CONFIRMED),), effects_failure=(),
                   cost_prompts=1, risk_tier=RiskTier.LOW, graph_edge=None)
    graph = build_static_graph(OperatorLibrary([op]))
    assert graph[START] == set()
    assert "k" not in shortest_distances(graph)  # not reachable from START


def test_distance_to_nearest_target_is_a_single_multi_source_reverse_bfs():
    graph = {START: {"a"}, "a": {"b"}, "b": {"target1"}, "target1": set(),
             "c": {"target2"}, "target2": set()}
    distances = distance_to_nearest_target(graph, ("target1", "target2"))
    assert distances["target1"] == 0
    assert distances["target2"] == 0
    assert distances["b"] == 1  # one hop from target1
    assert distances["a"] == 2
    assert distances[START] == 3
    assert distances["c"] == 1  # one hop from target2, via a DIFFERENT branch


def test_distance_to_nearest_target_omits_nodes_with_no_static_path():
    graph = {START: {"a"}, "a": set(), "island": set()}
    distances = distance_to_nearest_target(graph, ("a",))
    assert "island" not in distances


# -- class-precondition hub edges (2026-08-12, multi-step discovery) -----

def test_build_graph_wires_confirmed_claim_into_its_category_hub():
    ssg = SecurityStateGraph()
    library = OperatorLibrary([])
    ssg.assert_claim("some_trust_fact", "true", ClaimStatus.CONFIRMED, category=CATEGORY_TRUST_EDGE)
    graph = build_graph(library, ssg)
    assert category_hub(CATEGORY_TRUST_EDGE) in graph["some_trust_fact"]


def test_build_graph_only_wires_hub_edge_once_confirmed():
    ssg = SecurityStateGraph()
    library = OperatorLibrary([])
    ssg.assert_claim("some_trust_fact", "true", ClaimStatus.HYPOTHESIZED, category=CATEGORY_TRUST_EDGE)
    graph = build_graph(library, ssg)
    assert "some_trust_fact" not in graph or category_hub(CATEGORY_TRUST_EDGE) not in graph.get("some_trust_fact", set())


def test_build_graph_wires_attack_category_hub():
    ssg = SecurityStateGraph()
    library = OperatorLibrary([])
    ssg.assert_claim("k", "true", ClaimStatus.CONFIRMED, attack_category="rag_poisoning")
    graph = build_graph(library, ssg)
    assert attack_category_hub("rag_poisoning") in graph["k"]


def test_build_graph_wires_confirmed_boundary_into_every_threshold_at_or_below_its_rank():
    ssg = SecurityStateGraph()
    library = OperatorLibrary([])
    ssg.assert_claim("k", "true", ClaimStatus.CONFIRMED, security_boundary=BOUNDARY_L4)  # rank 4
    graph = build_graph(library, ssg)
    assert boundary_hub(0) in graph["k"]
    assert boundary_hub(2) in graph["k"]
    assert boundary_hub(4) in graph["k"]
    assert boundary_hub(5) not in graph["k"]  # L4's own rank is 4, not 5


def test_a_class_gated_downstream_operator_is_statically_reachable_via_the_hub():
    # Two DIFFERENT upstream operators both confirm a category=trust_edge
    # effect; a downstream operator's OWN declared graph_edge starts from
    # the shared hub, not from either upstream operator by name -- this is
    # the actual multi-step-discovery mechanism (see discovery_chain_
    # definitions.py for the full real-world version of this shape).
    # build_static_graph (the optimistic, unconfirmed prior PoP/
    # budget_feasible read) already shows the FULL path connecting
    # START -> trust_a -> hub -> exploited before anything is confirmed --
    # this is what lets the planner's shaping terms see the chain's
    # existence up front, exactly as they already do for a normal
    # human-declared two-hop chain, but built here from independently
    # tagged operators that never name each other.
    upstream_a = Operator(
        id="trust_via_a", description="x", prompt="x", channel="direct", preconditions=(),
        effects_success=(ClaimEffect("trust_a", ClaimStatus.CONFIRMED, category=CATEGORY_TRUST_EDGE),),
        effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW, graph_edge=(START, "trust_a"),
    )
    downstream = Operator(
        id="exploit_trust", description="x", prompt="x", channel="direct", preconditions=(),
        precondition_classes=(ClassPrecondition(category=CATEGORY_TRUST_EDGE),),
        effects_success=(ClaimEffect("exploited", ClaimStatus.CONFIRMED),), effects_failure=(),
        cost_prompts=1, risk_tier=RiskTier.LOW,
        graph_edge=(category_hub(CATEGORY_TRUST_EDGE), "exploited"),
    )
    library = OperatorLibrary([upstream_a, downstream])

    static_graph = build_static_graph(library)
    distances = shortest_distances(static_graph)
    # 2 REAL hops (trust_via_a, exploit_trust) -- the hub hop itself is
    # free (0-1 BFS, see shortest_distances' own docstring): traversing it
    # is bookkeeping, not a third operator execution.
    assert distances["exploited"] == 2

    # Nothing about `downstream` ever names `upstream_a` (or vice versa) --
    # the connection exists purely because both happen to touch the same
    # semantic tag.
    assert "trust_via_a" not in downstream.description
    assert "exploit_trust" not in upstream_a.description

    # And preconditions_met() (the actual candidate-eligibility gate) only
    # flips once trust_a is genuinely CONFIRMED on a real SSG.
    ssg = SecurityStateGraph()
    assert not downstream.preconditions_met(ssg)
    ssg.assert_claim("trust_a", "true", ClaimStatus.CONFIRMED, category=CATEGORY_TRUST_EDGE)
    assert downstream.preconditions_met(ssg)


def test_build_static_graph_wires_hub_edges_from_declared_effects_unconditionally():
    op = Operator(
        id="a", description="x", prompt="x", channel="direct", preconditions=(),
        effects_success=(ClaimEffect("a_done", ClaimStatus.CONFIRMED, category=CATEGORY_TRUST_EDGE),),
        effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW, graph_edge=(START, "a_done"),
    )
    graph = build_static_graph(OperatorLibrary([op]))
    assert category_hub(CATEGORY_TRUST_EDGE) in graph["a_done"]
