"""Tests for aginiti/planner/bayesian_planner.py -- the Thompson-Sampling
planner built in direct response to this project's own audit of
AginitiPlanner's ad hoc weighted-sum formula. No live LLM calls anywhere:
every term this planner reuses (gap_priority, budget_feasible, etc.) is
already independently tested in tests/unit/test_aginiti_planner.py; these tests
cover the NEW combination logic only.
"""
from aginiti.core.graph.schema import ClaimStatus, InsightCategory, RiskTier
from aginiti.core.graph.ssg import SecurityStateGraph
from aginiti.core.mission import Mission
from aginiti.operators.library import ClaimEffect, Operator, OperatorLibrary
from aginiti.core.planner.bayesian_planner import BayesianBanditPlanner
from aginiti.core.policies.bayesian_policy import BayesianPolicy


def _op(op_id, edge=None, success_key=None, cost=1):
    return Operator(
        id=op_id, description=op_id, prompt="x", channel="direct", preconditions=(),
        effects_success=(ClaimEffect(success_key or f"{op_id}_done", ClaimStatus.CONFIRMED),),
        effects_failure=(), cost_prompts=cost, risk_tier=RiskTier.LOW, graph_edge=edge,
    )


def _mission(budget=20, targets=("target",)):
    return Mission(goal="test", success_criteria=targets, budget=budget, risk_threshold=RiskTier.LOW)


def test_posterior_is_uniform_beta_1_1_with_no_evidence_and_no_priors():
    op = _op("probe")
    ssg = SecurityStateGraph()
    planner = BayesianBanditPlanner()
    library = OperatorLibrary([op])
    alpha, beta = planner.posterior(op, _mission(), ssg, library)
    assert alpha == 1.0
    assert beta == 1.0


def test_posterior_alpha_increases_with_a_real_confirmed_success():
    op = _op("probe")
    library = OperatorLibrary([op])
    ssg = SecurityStateGraph()
    ssg.record_operator_execution("probe", success=True)
    ssg.record_operator_execution("probe", success=True)
    planner = BayesianBanditPlanner()
    alpha, beta = planner.posterior(op, _mission(), ssg, library)
    assert alpha == 3.0  # 1 (uniform) + 2 real successes
    assert beta == 1.0   # unaffected by successes


def test_posterior_beta_increases_with_a_real_confirmed_failure():
    op = _op("probe")
    library = OperatorLibrary([op])
    ssg = SecurityStateGraph()
    ssg.record_operator_execution("probe", success=False)
    planner = BayesianBanditPlanner()
    alpha, beta = planner.posterior(op, _mission(), ssg, library)
    assert alpha == 1.0
    assert beta == 2.0  # 1 (uniform) + 1 real failure


def test_gap_priority_insight_shifts_alpha_only_never_beta():
    # The core translation this planner makes: an "only ever helps" prior
    # term becomes a PRIOR PSEUDO-COUNT on alpha, never touches beta --
    # exactly preserving gap_priority's own existing "never hurts" contract.
    op = _op("probe")
    library = OperatorLibrary([op])
    ssg = SecurityStateGraph()
    ssg.record_insight(InsightCategory.KNOWLEDGE_GAP, "gap", importance="high", related_probe_id="probe")
    planner = BayesianBanditPlanner()
    alpha, beta = planner.posterior(op, _mission(), ssg, library)
    assert alpha == 5.0  # 1 (uniform) + 4.0 (high-importance gap_priority)
    assert beta == 1.0


def test_rank_excludes_a_budget_infeasible_chain_start_operator():
    # budget_feasible() is reused completely unchanged from AginitiPlanner
    # -- this locks in that the Bayesian planner inherits that fix, not
    # just its own new mechanism.
    plant = _op("plant", edge=("start", "mid"), success_key="plant_done")
    trigger = _op("trigger", edge=("mid", "target"), success_key="trigger_done")
    library = OperatorLibrary([plant, trigger])
    mission = _mission(budget=3)
    ssg = SecurityStateGraph()
    planner = BayesianBanditPlanner(seed=1)

    ranked = planner.rank(library, ssg, mission, prompts_used=2, executed_ids=frozenset())
    assert "plant" not in {c.operator.id for c in ranked}


def test_thompson_sampling_is_reproducible_given_the_same_seed():
    ops = [_op(f"op{i}") for i in range(5)]
    library = OperatorLibrary(ops)
    ssg = SecurityStateGraph()
    mission = _mission()

    planner_a = BayesianBanditPlanner(seed=42)
    planner_b = BayesianBanditPlanner(seed=42)
    ranked_a = [c.operator.id for c in planner_a.rank(library, ssg, mission, prompts_used=0)]
    ranked_b = [c.operator.id for c in planner_b.rank(library, ssg, mission, prompts_used=0)]
    assert ranked_a == ranked_b


def test_thompson_sampling_can_differ_across_seeds_when_posteriors_are_tied():
    # Not a hard guarantee for every seed pair (sampling could coincide),
    # but across a spread of seeds with 5 identically-uniform-prior
    # candidates, at least one different top pick should appear --
    # confirms real exploration is happening, not silent determinism.
    ops = [_op(f"op{i}") for i in range(5)]
    library = OperatorLibrary(ops)
    ssg = SecurityStateGraph()
    mission = _mission()

    top_picks = set()
    for seed in range(20):
        planner = BayesianBanditPlanner(seed=seed)
        ranked = planner.rank(library, ssg, mission, prompts_used=0)
        top_picks.add(ranked[0].operator.id)
    assert len(top_picks) > 1


def test_a_well_evidenced_operator_usually_outranks_a_higher_info_gain_operator():
    # THE core motivating property: AginitiPlanner's architectural ceiling
    # (info_gain's dynamic range up to 4.0 dwarfs gap_priority's up to 2.2,
    # so a strong prior could never overrule a higher-info_gain rival) is
    # exactly what this planner fixes. Construct a rival with a much wider
    # declared info_gain than the real winner, but give the real winner
    # overwhelming REAL evidence (confirmed successes).
    #
    # Tested as a STATISTICAL property across many seeds, deliberately NOT
    # as a single-seed deterministic assertion: Thompson Sampling is
    # stochastic BY DESIGN (that stochasticity is the exploration
    # mechanism, not a flaw), so a well-evidenced operator winning "the
    # large majority of the time, not literally every time" is the
    # statistically honest claim -- and the one AginitiPlanner's linear
    # sum architecturally cannot make AT ALL (its ranking is deterministic
    # and info_gain's larger range would win every single time).
    high_ig_rival = Operator(
        id="high_ig_rival", description="x", prompt="x", channel="direct", preconditions=(),
        effects_success=(ClaimEffect("a", ClaimStatus.CONFIRMED, weight=2.0),
                          ClaimEffect("b", ClaimStatus.CONFIRMED, weight=2.0)),
        effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW,
    )
    proven_winner = _op("proven_winner")
    library = OperatorLibrary([high_ig_rival, proven_winner])
    ssg = SecurityStateGraph()
    for _ in range(15):
        ssg.record_operator_execution("proven_winner", success=True)

    # Sanity: the rival really does have the larger raw info_gain, so this
    # isn't a vacuous test -- AginitiPlanner's own info_gain() would have
    # deterministically favored the rival, not proven_winner, at this state.
    terms = BayesianBanditPlanner().terms
    assert terms.information_gain(high_ig_rival, ssg) > terms.information_gain(proven_winner, ssg)

    n_trials = 200
    wins = sum(
        1 for seed in range(n_trials)
        if BayesianBanditPlanner(seed=seed).rank(library, ssg, _mission(), prompts_used=0)[0].operator.id
        == "proven_winner"
    )
    assert wins / n_trials > 0.8  # large majority, not literally every seed


def test_empty_library_returns_empty_ranking():
    library = OperatorLibrary([])
    ssg = SecurityStateGraph()
    planner = BayesianBanditPlanner(seed=1)
    assert planner.rank(library, ssg, _mission(), prompts_used=0) == []


def test_bayesian_policy_wraps_planner_and_exposes_meta():
    op = _op("probe")
    library = OperatorLibrary([op])
    ssg = SecurityStateGraph()
    policy = BayesianPolicy(seed=1)
    ranked = policy.rank(library, ssg, _mission(), prompts_used=0, executed_ids=frozenset())
    assert len(ranked) == 1
    assert ranked[0].operator.id == "probe"
    assert "alpha" in ranked[0].meta
    assert "thompson_sample" in ranked[0].meta


def test_bayesian_policy_name_is_bayesian():
    assert BayesianPolicy().name == "bayesian"
