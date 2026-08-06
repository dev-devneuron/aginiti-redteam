from aginiti.graph.schema import ClaimStatus, RiskTier
from aginiti.graph.ssg import SecurityStateGraph
from aginiti.graph.target_graph import START, build_graph, min_distance_to_any, shortest_distances
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
