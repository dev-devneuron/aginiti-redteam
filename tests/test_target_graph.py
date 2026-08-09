from aginiti.graph.schema import ClaimStatus, RiskTier
from aginiti.graph.ssg import SecurityStateGraph
from aginiti.graph.target_graph import (
    START,
    build_graph,
    build_static_graph,
    distance_to_nearest_target,
    min_distance_to_any,
    shortest_distances,
)
from aginiti.operators.library import ClaimEffect, Operator, OperatorLibrary


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


def test_build_static_graph_ignores_operators_with_no_graph_edge():
    op = Operator(id="no_edge", description="x", prompt="x", channel="direct", preconditions=(),
                   effects_success=(ClaimEffect("k", ClaimStatus.CONFIRMED),), effects_failure=(),
                   cost_prompts=1, risk_tier=RiskTier.LOW, graph_edge=None)
    graph = build_static_graph(OperatorLibrary([op]))
    assert graph == {START: set()}


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
