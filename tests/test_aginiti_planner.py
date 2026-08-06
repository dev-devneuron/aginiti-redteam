from aginiti.graph.schema import ClaimStatus, RiskTier
from aginiti.graph.ssg import SecurityStateGraph
from aginiti.mission import Mission
from aginiti.operators.library import ClaimEffect, Operator, OperatorLibrary
from aginiti.planner.aginiti_planner import AginitiPlanner


def _op(op_id, edge, success_key):
    return Operator(
        id=op_id, description=op_id, prompt="x", channel="direct", preconditions=(),
        effects_success=(ClaimEffect(success_key, ClaimStatus.CONFIRMED),),
        effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW, graph_edge=edge,
    )


def _mission():
    return Mission(goal="test", success_criteria=("target",), budget=20, risk_threshold=RiskTier.LOW)


def test_path_progress_zero_when_operator_has_no_graph_edge():
    op = Operator(id="x", description="x", prompt="x", channel="direct", preconditions=(),
                  effects_success=(), effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW)
    planner = AginitiPlanner()
    ssg = SecurityStateGraph()
    library = OperatorLibrary([op])
    assert planner.path_progress(op, _mission(), ssg, library) == 0.0


def test_path_progress_high_when_operator_makes_target_newly_reachable():
    shortcut = _op("shortcut", ("start", "target"), "shortcut_done")
    library = OperatorLibrary([shortcut])
    ssg = SecurityStateGraph()  # nothing confirmed -- target currently unreachable
    planner = AginitiPlanner()

    assert planner.path_progress(shortcut, _mission(), ssg, library) == 3.0


def test_path_progress_positive_when_operator_shortens_a_known_path():
    op_a = _op("a", ("start", "mid"), "a_done")
    op_long1 = _op("long1", ("mid", "via2"), "long1_done")
    op_long2 = _op("long2", ("via2", "target"), "long2_done")
    shortcut = _op("shortcut", ("mid", "target"), "shortcut_done")  # not yet confirmed
    library = OperatorLibrary([op_a, op_long1, op_long2, shortcut])

    ssg = SecurityStateGraph()
    for key in ("a_done", "long1_done", "long2_done"):
        ssg.assert_claim(key, "true", ClaimStatus.CONFIRMED)
    # baseline: start->mid->via2->target = 3 hops

    planner = AginitiPlanner()
    assert planner.path_progress(shortcut, _mission(), ssg, library) == 1.0


def test_path_progress_zero_for_an_edge_unrelated_to_any_mission_target():
    decoy = _op("decoy", ("start", "nowhere"), "decoy_done")
    library = OperatorLibrary([decoy])
    ssg = SecurityStateGraph()
    planner = AginitiPlanner()
    assert planner.path_progress(decoy, _mission(), ssg, library) == 0.0


def test_rank_includes_path_progress_in_ranked_candidates():
    shortcut = _op("shortcut", ("start", "target"), "shortcut_done")
    library = OperatorLibrary([shortcut])
    ssg = SecurityStateGraph()
    planner = AginitiPlanner()
    ranked = planner.rank(library, ssg, _mission(), prompts_used=0)
    assert len(ranked) == 1
    assert ranked[0].path_progress == 3.0
