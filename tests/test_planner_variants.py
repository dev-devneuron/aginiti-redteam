from aginiti.graph.belief_state import BranchBelief
from aginiti.graph.schema import ClaimStatus, InsightCategory, RiskTier
from aginiti.graph.ssg import SecurityStateGraph
from aginiti.mission import Mission
from aginiti.operators.library import ClaimEffect, Operator, OperatorLibrary
from aginiti.planner.variants import BFSOnlyPlanner, GreedyBusinessImpactPlanner, GreedyInfoGainPlanner


def _op(op_id, edge, success_key, weight=1, branch=None):
    return Operator(
        id=op_id, description=op_id, prompt="x", channel="direct", preconditions=(),
        effects_success=(ClaimEffect(success_key, ClaimStatus.CONFIRMED, weight=weight),),
        effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW, graph_edge=edge, branch=branch,
    )


def _mission():
    return Mission(goal="test", success_criteria=("target",), budget=20, risk_threshold=RiskTier.LOW)


def test_greedy_info_gain_ignores_business_impact_and_path_progress():
    shortcut = _op("shortcut", ("start", "target"), "shortcut_done")  # would make target reachable
    plain = _op("plain", ("start", "elsewhere"), "plain_done", weight=5)  # bigger info-gain weight
    library = OperatorLibrary([shortcut, plain])
    ssg = SecurityStateGraph()
    planner = GreedyInfoGainPlanner()

    ranked = planner.rank(library, ssg, _mission(), prompts_used=0)

    assert ranked[0].operator.id == "plain"  # higher info-gain weight wins, path_progress ignored
    shortcut_candidate = next(r for r in ranked if r.operator.id == "shortcut")
    assert shortcut_candidate.path_progress == 3.0  # still computed/reported...
    assert shortcut_candidate.utility == shortcut_candidate.info_gain  # ...but beta=0 means it never counts


def test_greedy_info_gain_ignores_gap_and_hypothesis_priority():
    op = _op("probe", ("start", "mid"), "probe_done")
    library = OperatorLibrary([op])
    ssg = SecurityStateGraph()
    ssg.record_insight(InsightCategory.KNOWLEDGE_GAP, "gap", importance="high", related_probe_id="probe")
    planner = GreedyInfoGainPlanner()
    ranked = planner.rank(library, ssg, _mission(), prompts_used=0)
    assert ranked[0].utility == ranked[0].info_gain  # gap contributes nothing to utility


def test_greedy_business_impact_prefers_mission_relevant_operator():
    mission_hit = _op("mission_hit", ("start", "a"), "target")  # directly satisfies success_criteria
    recon = _op("recon", ("start", "b"), "recon_done", weight=10)  # much higher info-gain weight
    library = OperatorLibrary([mission_hit, recon])
    ssg = SecurityStateGraph()
    planner = GreedyBusinessImpactPlanner()

    ranked = planner.rank(library, ssg, _mission(), prompts_used=0)

    assert ranked[0].operator.id == "mission_hit"  # business impact wins despite lower info-gain weight


def test_bfs_only_ranks_purely_by_path_progress():
    shortcut = _op("shortcut", ("start", "target"), "shortcut_done")  # newly reaches mission target
    mission_hit = _op("mission_hit", ("start", "a"), "target")  # ALSO directly satisfies mission (business_impact=1)
    library = OperatorLibrary([shortcut, mission_hit])
    ssg = SecurityStateGraph()
    planner = BFSOnlyPlanner()

    ranked = planner.rank(library, ssg, _mission(), prompts_used=0)

    for r in ranked:
        assert r.info_gain == 0.0 or r.utility != r.info_gain  # info_gain not counted toward utility
    # both operators score by path_progress alone; mission_hit's own edge (start->a) doesn't
    # reach "target" so its path_progress is 0, while shortcut's does (=3.0)
    assert ranked[0].operator.id == "shortcut"
    assert ranked[0].utility == ranked[0].path_progress


# -- all three variants must ignore branch_interest, same as gap/hypothesis
# priority -- staying TRUE pure parameterizations of the formula, not
# silently absorbing a term added to AginitiPlanner after they were built.

def test_greedy_info_gain_ignores_branch_interest():
    op = _op("probe", ("start", "mid"), "probe_done", branch="hot_branch")
    library = OperatorLibrary([op])
    ssg = SecurityStateGraph()
    ssg.belief.branches["hot_branch"] = BranchBelief(interest=100.0, confidence=1.0)
    planner = GreedyInfoGainPlanner()
    ranked = planner.rank(library, ssg, _mission(), prompts_used=0)
    assert ranked[0].utility == ranked[0].info_gain


def test_greedy_business_impact_ignores_branch_interest():
    op = _op("mission_hit", ("start", "a"), "target", branch="hot_branch")
    library = OperatorLibrary([op])
    ssg = SecurityStateGraph()
    ssg.belief.branches["hot_branch"] = BranchBelief(interest=100.0, confidence=1.0)
    planner = GreedyBusinessImpactPlanner()
    ranked = planner.rank(library, ssg, _mission(), prompts_used=0)
    assert ranked[0].utility == ranked[0].beta * ranked[0].business_impact


def test_bfs_only_ignores_branch_interest():
    op = _op("shortcut", ("start", "target"), "shortcut_done", branch="hot_branch")
    library = OperatorLibrary([op])
    ssg = SecurityStateGraph()
    ssg.belief.branches["hot_branch"] = BranchBelief(interest=100.0, confidence=1.0)
    planner = BFSOnlyPlanner()
    ranked = planner.rank(library, ssg, _mission(), prompts_used=0)
    assert ranked[0].utility == ranked[0].path_progress


# -- potential_progress (2026-08-08, potential-based reward shaping):
# GreedyInfoGainPlanner needs no explicit override (beta=0 already zeroes
# every beta-scaled term, same precedent as emergent_impact);
# GreedyBusinessImpactPlanner and BFSOnlyPlanner both have beta=1, so they
# DO override it, same reasoning as their emergent_impact overrides.

def test_greedy_info_gain_ignores_potential_progress_via_beta_zero():
    # A two-hop unconfirmed chain -- potential_progress is nonzero for
    # BOTH operators (see test_aginiti_planner.py's core proof), but
    # beta=0 must still zero its contribution here.
    op_a = _op("a", ("start", "mid"), "a_done")
    op_b = _op("b", ("mid", "target"), "b_done")
    library = OperatorLibrary([op_a, op_b])
    ssg = SecurityStateGraph()
    planner = GreedyInfoGainPlanner()
    ranked = planner.rank(library, ssg, _mission(), prompts_used=0)
    for r in ranked:
        assert r.potential_progress > 0.0  # still computed/reported...
        assert r.utility == r.info_gain     # ...but never counted


def test_greedy_business_impact_ignores_potential_progress():
    # mission_hit's own edge (start->target) would give a plain
    # AginitiPlanner a strictly positive potential_progress (one static
    # hop closer) -- GreedyBusinessImpactPlanner must still force it to
    # 0.0, same as it already does for emergent_impact.
    mission_hit = _op("mission_hit", ("start", "target"), "target")
    library = OperatorLibrary([mission_hit])
    ssg = SecurityStateGraph()
    planner = GreedyBusinessImpactPlanner()
    ranked = planner.rank(library, ssg, _mission(), prompts_used=0)
    assert ranked[0].potential_progress == 0.0
    # beta=1, path_progress and business_impact still count (this class
    # doesn't override path_progress), but potential_progress contributes
    # nothing to utility.
    assert ranked[0].utility == ranked[0].business_impact + ranked[0].path_progress


def test_bfs_only_ignores_potential_progress():
    mission_hit = _op("mission_hit", ("start", "target"), "target")
    library = OperatorLibrary([mission_hit])
    ssg = SecurityStateGraph()
    planner = BFSOnlyPlanner()
    ranked = planner.rank(library, ssg, _mission(), prompts_used=0)
    assert ranked[0].potential_progress == 0.0


def test_all_three_variants_ignore_failure_evidence_penalty():
    """2026-08-12 hardening-pass regression: failure_evidence_penalty
    (Issue 4, an unscaled additive term like severity_priority/gap_
    priority/hypothesis_priority/branch_interest) was added to AginitiPlanner
    without a matching override in any of these three "pure parameterization"
    subclasses -- they silently absorbed real demotion behavior for one full
    session, breaking their own documented "never silently absorb a new
    base-class term" contract. This locks the fix in: a candidate whose
    prospective failure would match a CONFIRMED generalizable diagnosis
    elsewhere in the graph must score failure_evidence_penalty == 0.0 under
    all three variants, even though the base AginitiPlanner would demote it."""
    from aginiti.graph.failure_diagnosis import BLOCKED_BY_PRIVILEGE
    from aginiti.operators.library import ClaimEffect

    op = Operator(
        id="candidate", description="x", prompt="x", channel="direct", preconditions=(),
        effects_success=(ClaimEffect("candidate_win", ClaimStatus.CONFIRMED, weight=3),),
        effects_failure=(ClaimEffect("candidate_blocked", ClaimStatus.CONFIRMED, weight=1,
                                      failure_diagnosis=BLOCKED_BY_PRIVILEGE),),
        cost_prompts=1, risk_tier=RiskTier.LOW,
    )
    library = OperatorLibrary([op])
    ssg = SecurityStateGraph()
    ssg.assert_claim("other_op_blocked", "true", ClaimStatus.CONFIRMED, failure_diagnosis=BLOCKED_BY_PRIVILEGE)

    for planner_cls in (GreedyInfoGainPlanner, GreedyBusinessImpactPlanner, BFSOnlyPlanner):
        planner = planner_cls()
        assert planner.failure_evidence_penalty(op, ssg) == 0.0, f"{planner_cls.__name__} should ignore it"

    # Sanity: the BASE planner genuinely would demote this candidate --
    # proves the test fixture actually exercises real demotion evidence,
    # not a no-op scenario that would pass trivially either way.
    from aginiti.planner.aginiti_planner import AginitiPlanner
    assert AginitiPlanner().failure_evidence_penalty(op, ssg) < 0.0
