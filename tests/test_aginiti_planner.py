from aginiti.graph.belief_state import BranchBelief
from aginiti.graph.schema import ClaimStatus, InsightCategory, RiskTier
from aginiti.graph.ssg import CATEGORY_MISSION_OUTCOME, CATEGORY_TRUST_EDGE, SecurityStateGraph
from aginiti.mission import Mission
from aginiti.operators.library import ClaimEffect, Operator, OperatorLibrary
from aginiti.planner.aginiti_planner import AginitiPlanner


def _op(op_id, edge, success_key, category=None, branch=None):
    return Operator(
        id=op_id, description=op_id, prompt="x", channel="direct", preconditions=(),
        effects_success=(ClaimEffect(success_key, ClaimStatus.CONFIRMED, category=category),),
        effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW, graph_edge=edge, branch=branch,
    )


def _mission():
    return Mission(goal="test", success_criteria=("target",), budget=20, risk_threshold=RiskTier.LOW)


def _op_multi_effect(op_id, weights):
    """An operator declaring len(weights) distinct, still-unresolved
    success effects, each with the given weight -- used to test
    info_gain_normalization's "sum vs mean" behavior directly."""
    effects = tuple(
        ClaimEffect(f"{op_id}_claim_{i}", ClaimStatus.CONFIRMED, weight=w)
        for i, w in enumerate(weights)
    )
    return Operator(
        id=op_id, description=op_id, prompt="x", channel="direct", preconditions=(),
        effects_success=effects, effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW,
    )


def test_planner_defaults_to_sum_normalization():
    assert AginitiPlanner().info_gain_normalization == "sum"


def test_planner_rejects_an_invalid_normalization_mode():
    try:
        AginitiPlanner(info_gain_normalization="max")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_information_gain_sum_mode_rewards_declaring_more_effects():
    # The exact structural bias the ablation exists to test: two operators
    # with the SAME per-effect weight, but one declares 3 effects and the
    # other declares 1 -- under "sum" (default, unchanged), the 3-effect
    # operator scores 3x higher purely from effect count.
    chatty = _op_multi_effect("chatty", weights=[1, 1, 1])       # e.g. indirect_prompt_injection-shaped
    prerequisite = _op_multi_effect("prerequisite", weights=[1])  # e.g. anythingllm_rag_document_plant-shaped
    ssg = SecurityStateGraph()
    planner = AginitiPlanner(info_gain_normalization="sum")
    assert planner.information_gain(chatty, ssg) == 3.0
    assert planner.information_gain(prerequisite, ssg) == 1.0


def test_information_gain_mean_mode_removes_the_effect_count_advantage():
    # Same two operators, same per-effect weight -- under "mean", the
    # count advantage disappears: both score the same per-effect
    # informativeness, exactly the fix the user's plant_canary() example
    # calls for (a sparse-reward prerequisite is no longer structurally
    # outscored just because it teaches fewer things at once).
    chatty = _op_multi_effect("chatty", weights=[1, 1, 1])
    prerequisite = _op_multi_effect("prerequisite", weights=[1])
    ssg = SecurityStateGraph()
    planner = AginitiPlanner(info_gain_normalization="mean")
    assert planner.information_gain(chatty, ssg) == 1.0
    assert planner.information_gain(prerequisite, ssg) == 1.0


def test_information_gain_mean_mode_still_distinguishes_genuinely_higher_value_effects():
    # Mean normalization isn't "ignore weight" -- an operator whose single
    # effect is genuinely more valuable (higher weight) than another's
    # still scores higher; only the EFFECT-COUNT bonus is removed.
    high_value = _op_multi_effect("high_value", weights=[4])
    low_value = _op_multi_effect("low_value", weights=[1])
    ssg = SecurityStateGraph()
    planner = AginitiPlanner(info_gain_normalization="mean")
    assert planner.information_gain(high_value, ssg) > planner.information_gain(low_value, ssg)


def test_information_gain_only_counts_still_unresolved_effects_in_both_modes():
    # A CONFIRMED effect contributes nothing further in either mode --
    # mean-mode's denominator must also only count REMAINING open effects,
    # not the operator's total declared effect count, or a partially-
    # resolved operator would be mis-normalized.
    op = _op_multi_effect("op", weights=[4, 1])
    ssg = SecurityStateGraph()
    ssg.assert_claim("op_claim_0", "true", ClaimStatus.CONFIRMED)  # resolve the weight=4 effect
    planner_sum = AginitiPlanner(info_gain_normalization="sum")
    planner_mean = AginitiPlanner(info_gain_normalization="mean")
    assert planner_sum.information_gain(op, ssg) == 1.0   # only the unresolved weight=1 effect remains
    assert planner_mean.information_gain(op, ssg) == 1.0  # mean of a single remaining effect == itself


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


def test_potential_progress_zero_when_operator_has_no_graph_edge():
    op = Operator(id="x", description="x", prompt="x", channel="direct", preconditions=(),
                  effects_success=(), effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW)
    planner = AginitiPlanner()
    library = OperatorLibrary([op])
    assert planner.potential_progress(op, _mission(), library) == 0.0


def test_potential_progress_zero_when_mission_has_no_success_criteria():
    op = _op("a", ("start", "target"), "a_done")
    library = OperatorLibrary([op])
    planner = AginitiPlanner()
    empty_mission = Mission(goal="x", success_criteria=(), budget=10, risk_threshold=RiskTier.LOW)
    assert planner.potential_progress(op, empty_mission, library) == 0.0


def test_potential_progress_rewards_a_stepping_stone_path_progress_cannot_see():
    # THE core claim this whole mechanism exists to prove: a two-hop chain
    # where NEITHER hop is confirmed yet. path_progress gives BOTH
    # operators 0.0 (op_b's edge doesn't touch the empty confirmed graph;
    # op_a's edge alone doesn't make "target" reachable either, since
    # op_b's edge isn't confirmed) -- indistinguishable from two unrelated
    # dead ends. potential_progress must tell them apart from a real dead
    # end, using the STATIC graph, with no confirmed evidence at all.
    op_a = _op("a", ("start", "mid"), "a_done")     # step 1, unconfirmed
    op_b = _op("b", ("mid", "target"), "b_done")     # step 2, unconfirmed
    library = OperatorLibrary([op_a, op_b])
    ssg = SecurityStateGraph()  # nothing confirmed at all
    planner = AginitiPlanner()

    # path_progress sees nothing -- confirms the gap actually exists.
    assert planner.path_progress(op_a, _mission(), ssg, library) == 0.0
    assert planner.path_progress(op_b, _mission(), ssg, library) == 0.0

    # potential_progress sees both, and ranks the operator CLOSER to the
    # target (b, one static hop away) at least as promising as the one
    # further back (a, two static hops away) -- both strictly positive.
    pop_a = planner.potential_progress(op_a, _mission(), library)
    pop_b = planner.potential_progress(op_b, _mission(), library)
    assert pop_a > 0.0
    assert pop_b > 0.0


def test_potential_progress_zero_for_a_genuine_dead_end():
    decoy = _op("decoy", ("start", "nowhere"), "decoy_done")  # "nowhere" has no path onward
    library = OperatorLibrary([decoy])
    planner = AginitiPlanner()
    assert planner.potential_progress(decoy, _mission(), library) == 0.0


def test_potential_progress_clamps_a_backward_edge_at_zero():
    # target is 0 hops from itself; "detour" is 1 hop from target via a
    # SEPARATE operator -- so the edge (target -> detour) moves AWAY from
    # the target and must be clamped, not scored negative.
    forward = _op("forward", ("start", "target"), "forward_done")
    detour_back = _op("detour_back", ("target", "detour"), "detour_back_done")
    detour_return = _op("detour_return", ("detour", "target"), "detour_return_done")
    library = OperatorLibrary([forward, detour_back, detour_return])
    planner = AginitiPlanner()
    assert planner.potential_progress(detour_back, _mission(), library) == 0.0


def test_potential_progress_is_independent_of_confirmed_evidence():
    # The one term in the whole formula that reads library structure
    # alone -- a constant per operator for a fixed library and mission,
    # unaffected by anything getting confirmed mid-campaign.
    op_a = _op("a", ("start", "mid"), "a_done")
    op_b = _op("b", ("mid", "target"), "b_done")
    library = OperatorLibrary([op_a, op_b])
    planner = AginitiPlanner()

    before = planner.potential_progress(op_b, _mission(), library)
    ssg = SecurityStateGraph()
    ssg.assert_claim("a_done", "true", ClaimStatus.CONFIRMED)
    ssg.assert_claim("b_done", "true", ClaimStatus.CONFIRMED)
    after = planner.potential_progress(op_b, _mission(), library)
    assert before == after


def test_rank_includes_potential_progress_in_ranked_candidates():
    op_a = _op("a", ("start", "mid"), "a_done")
    op_b = _op("b", ("mid", "target"), "b_done")
    library = OperatorLibrary([op_a, op_b])
    ssg = SecurityStateGraph()
    planner = AginitiPlanner()
    ranked = planner.rank(library, ssg, _mission(), prompts_used=0)
    ranked_by_id = {c.operator.id: c for c in ranked}
    assert ranked_by_id["a"].potential_progress > 0.0
    assert ranked_by_id["b"].potential_progress > 0.0


def test_potential_progress_credits_a_stepping_stone_toward_an_unnamed_compromise():
    # Same-day self-review fix: the FIRST version of potential_progress
    # only looked at mission.success_criteria, leaving emergent_impact's
    # exact gap (exp7_consequence_propagation_gap.py) wide open for a
    # stepping stone toward an UNNAMED, library-recognized compromise.
    # Mirrors test_stepping_stone_toward_an_unnamed_compromise_gets_
    # positive_emergent_impact's shape, but STRICTER: that test needs
    # "full_takeover" pre-confirmed to seed emergent_impact's baseline;
    # this one needs NOTHING confirmed at all, since Phi is purely static.
    stepping_stone = _op("probe_admin_panel", ("start", "admin_panel_found"), "admin_panel_found")
    followup = _op("exploit_admin_panel", ("admin_panel_found", "full_takeover"), "full_takeover",
                   category=CATEGORY_MISSION_OUTCOME)
    dead_end = _op("probe_dead_end", ("start", "nowhere"), "nowhere_done")
    library = OperatorLibrary([stepping_stone, followup, dead_end])
    planner = AginitiPlanner()
    # mission.success_criteria=("target",) from _mission() is irrelevant
    # here on purpose -- "full_takeover" is reached ONLY via emergent_targets.

    stepping_pop = planner.potential_progress(stepping_stone, _mission(), library)
    dead_end_pop = planner.potential_progress(dead_end, _mission(), library)

    assert stepping_pop > 0.0
    assert dead_end_pop == 0.0


def test_potential_progress_excludes_emergent_targets_already_named_in_mission():
    # Mirrors emergent_impact's own no-double-counting test -- confirms
    # the union-of-targets construction doesn't create a duplicate seed
    # for a target that's both named AND library-recognized (harmless
    # either way given distance_to_nearest_target's dedup, but pin the
    # actual target SET, not just the resulting score).
    op = _op("reaches_named_target", ("start", "target"), "target", category=CATEGORY_MISSION_OUTCOME)
    library = OperatorLibrary([op])
    planner = AginitiPlanner()
    assert planner.emergent_targets(library) == ("target",)
    # "target" is both a named criterion AND the library's only emergent
    # target -- potential_progress must still work normally (not double
    # or corrupt the distance for landing exactly on it).
    assert planner.potential_progress(op, _mission(), library) == 1.0


def _op_weighted(op_id, edge, success_key, weight=1, category=None):
    return Operator(
        id=op_id, description=op_id, prompt="x", channel="direct", preconditions=(),
        effects_success=(ClaimEffect(success_key, ClaimStatus.CONFIRMED, weight=weight, category=category),),
        effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW, graph_edge=edge,
    )


def test_chain_value_zero_when_operator_has_no_graph_edge():
    op = Operator(id="x", description="x", prompt="x", channel="direct", preconditions=(),
                  effects_success=(), effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW)
    planner = AginitiPlanner()
    ssg = SecurityStateGraph()
    library = OperatorLibrary([op])
    assert planner.chain_value(op, _mission(), ssg, library) == 0.0


def test_chain_value_zero_when_no_downstream_operator_shares_the_endpoint():
    # A plant with a graph_edge but nothing else in the library picks up
    # where it leaves off -- there's no declared downstream operator to
    # borrow value from, so this must stay a true no-op (same "only ever
    # helps, never hurts" rule as potential_progress).
    lone_plant = _op_weighted("lone_plant", ("start", "mid"), "mid_done", weight=1)
    library = OperatorLibrary([lone_plant])
    planner = AginitiPlanner()
    ssg = SecurityStateGraph()
    assert planner.chain_value(lone_plant, _mission(), ssg, library) == 0.0


def test_chain_value_reflects_downstream_operators_own_info_gain_and_business_impact():
    # Exact reproduction of the exp17 shape: a low-weight "plant" whose own
    # effect isn't a mission-outcome claim, chained to a "trigger" whose
    # effect directly satisfies the mission's only success criterion.
    plant = _op_weighted("plant", ("start", "mid"), "mid_planted", weight=1)
    trigger = _op_weighted("trigger", ("mid", "target"), "target", weight=4,
                            category=CATEGORY_MISSION_OUTCOME)
    library = OperatorLibrary([plant, trigger])
    ssg = SecurityStateGraph()  # nothing confirmed yet
    planner = AginitiPlanner()

    trigger_ig = planner.information_gain(trigger, ssg)
    trigger_bi = planner.business_impact(trigger, _mission(), ssg)
    assert (trigger_ig, trigger_bi) == (4.0, 1.0)  # sole unmet criterion -> full business_impact

    cv = planner.chain_value(plant, _mission(), ssg, library)
    assert cv == 0.5 * (trigger_ig + trigger_bi)  # == 2.5, discounted per _CHAIN_VALUE_DISCOUNT


def test_chain_value_picks_the_best_of_several_downstream_operators():
    plant = _op_weighted("plant", ("start", "mid"), "mid_planted", weight=1)
    weak_followup = _op_weighted("weak_followup", ("mid", "somewhere"), "somewhere_done", weight=1)
    strong_followup = _op_weighted("strong_followup", ("mid", "target"), "target", weight=4,
                                    category=CATEGORY_MISSION_OUTCOME)
    library = OperatorLibrary([plant, weak_followup, strong_followup])
    ssg = SecurityStateGraph()
    planner = AginitiPlanner()

    cv = planner.chain_value(plant, _mission(), ssg, library)
    strong_value = planner.information_gain(strong_followup, ssg) + planner.business_impact(
        strong_followup, _mission(), ssg)
    assert cv == 0.5 * strong_value  # takes the max, not the weak option or a sum of both


def test_chain_value_is_one_hop_only_not_a_transitive_walk():
    # Deliberately does NOT look two hops ahead: plant's immediate
    # downstream (mid_step) is itself a low-value setup step, even though
    # ITS downstream (the real prize) is high-value. Confirms the "single
    # Bellman backup, not recursive" design decision in chain_value()'s
    # own docstring.
    plant = _op_weighted("plant", ("start", "mid"), "mid_planted", weight=1)
    mid_step = _op_weighted("mid_step", ("mid", "near_target"), "near_target_done", weight=1)
    prize = _op_weighted("prize", ("near_target", "target"), "target", weight=4,
                          category=CATEGORY_MISSION_OUTCOME)
    library = OperatorLibrary([plant, mid_step, prize])
    ssg = SecurityStateGraph()
    planner = AginitiPlanner()

    cv = planner.chain_value(plant, _mission(), ssg, library)
    mid_step_value = planner.information_gain(mid_step, ssg) + planner.business_impact(
        mid_step, _mission(), ssg)
    assert cv == 0.5 * mid_step_value  # == 0.5, NOT 0.5*(prize's much larger value)
    assert mid_step_value < (planner.information_gain(prize, ssg) + planner.business_impact(prize, _mission(), ssg))


def test_chain_value_only_scales_alpha_never_hurts_when_alpha_is_zero():
    # cv sits in alpha's basket alongside info_gain -- when alpha=0
    # (pure exploitation schedule), it must contribute nothing, matching
    # how info_gain itself is silenced the same way.
    plant = _op_weighted("plant", ("start", "mid"), "mid_planted", weight=1)
    trigger = _op_weighted("trigger", ("mid", "target"), "target", weight=4,
                            category=CATEGORY_MISSION_OUTCOME)
    library = OperatorLibrary([plant, trigger])
    ssg = SecurityStateGraph()
    planner = AginitiPlanner()
    assert planner.chain_value(plant, _mission(), ssg, library) > 0.0  # the term itself is nonzero...
    ranked = planner.rank(library, ssg, _mission(), prompts_used=0)
    # ...but chain_value only ever enters through alpha*(ig+cv); this test
    # documents the contract, the alpha=0 zeroing itself is exercised by
    # GreedyBusinessImpactPlanner's own variant tests.
    by_id = {r.operator.id: r for r in ranked}
    assert by_id["plant"].chain_value > 0.0


def test_rank_lets_a_genuinely_better_chain_beat_a_mediocre_single_step_decoy():
    # THE flip test: before chain_value existed, a plant was structurally
    # incapable of ever outranking an immediately-resolving single-step
    # option, regardless of how good the plant's own downstream chain
    # was -- exactly the exp17 finding. This constructs a mission where
    # the chain is genuinely the better bet (its trigger resolves the
    # mission's only criterion) against a mediocre single-step decoy
    # (moderate info_gain, resolves nothing), and confirms the ranking
    # now reflects that.
    decoy = _op_weighted("decoy", None, "decoy_done", weight=2)  # no graph_edge -- a flat single-step probe
    plant = _op_weighted("plant", ("start", "mid"), "mid_planted", weight=1)
    trigger = _op_weighted("trigger", ("mid", "target"), "target", weight=4,
                            category=CATEGORY_MISSION_OUTCOME)
    library = OperatorLibrary([decoy, plant, trigger])
    ssg = SecurityStateGraph()
    planner = AginitiPlanner()

    ranked = planner.rank(library, ssg, _mission(), prompts_used=0)
    by_id = {r.operator.id: r for r in ranked}

    # decoy's own utility is completely unaffected by this fix (no
    # graph_edge -> chain_value is always 0.0 for it) -- reconstruct what
    # the OLD formula (pre-chain_value) would have scored the plant, using
    # the still-exposed individual terms, to prove this is a genuine flip
    # and not just a coincidental ranking.
    p = by_id["plant"]
    old_plant_utility = p.alpha * p.info_gain + p.beta * (p.business_impact + p.path_progress
                                                            + p.emergent_impact + p.potential_progress)
    assert old_plant_utility < by_id["decoy"].utility  # OLD formula: decoy would have won
    assert p.utility > by_id["decoy"].utility  # NEW formula: plant correctly wins instead


def test_rank_includes_path_progress_in_ranked_candidates():
    shortcut = _op("shortcut", ("start", "target"), "shortcut_done")
    library = OperatorLibrary([shortcut])
    ssg = SecurityStateGraph()
    planner = AginitiPlanner()
    ranked = planner.rank(library, ssg, _mission(), prompts_used=0)
    assert len(ranked) == 1
    assert ranked[0].path_progress == 3.0


def test_gap_priority_zero_when_no_matching_knowledge_gap():
    op = _op("probe", ("start", "mid"), "probe_done")
    ssg = SecurityStateGraph()
    planner = AginitiPlanner()
    assert planner.gap_priority(op, ssg) == 0.0


def test_gap_priority_weighted_by_importance():
    op = _op("probe", ("start", "mid"), "probe_done")
    ssg = SecurityStateGraph()
    ssg.record_insight(InsightCategory.KNOWLEDGE_GAP, "some gap", importance="high", related_probe_id="probe")
    planner = AginitiPlanner()
    assert planner.gap_priority(op, ssg) == 4.0


def test_gap_priority_ignores_gaps_pointing_at_a_different_operator():
    op = _op("probe", ("start", "mid"), "probe_done")
    ssg = SecurityStateGraph()
    ssg.record_insight(InsightCategory.KNOWLEDGE_GAP, "unrelated gap", importance="high",
                        related_probe_id="some_other_operator")
    planner = AginitiPlanner()
    assert planner.gap_priority(op, ssg) == 0.0


def test_gap_priority_sums_multiple_gaps_pointing_at_the_same_operator():
    op = _op("probe", ("start", "mid"), "probe_done")
    ssg = SecurityStateGraph()
    ssg.record_insight(InsightCategory.KNOWLEDGE_GAP, "gap one", importance="low", related_probe_id="probe")
    ssg.record_insight(InsightCategory.KNOWLEDGE_GAP, "gap two", importance="medium", related_probe_id="probe")
    planner = AginitiPlanner()
    assert planner.gap_priority(op, ssg) == 3.0  # 1.0 + 2.0


def test_rank_boosts_utility_for_operator_named_by_a_high_importance_gap():
    # Two candidates with otherwise-identical utility; a knowledge gap
    # naming ONE of them as its related probe should pull it to the top --
    # the whole point of gap_priority reshaping the ranking, not just
    # reporting alongside it.
    plain = _op("plain", ("start", "a"), "plain_done")
    gap_linked = _op("gap_linked", ("start", "b"), "gap_linked_done")
    library = OperatorLibrary([plain, gap_linked])
    ssg = SecurityStateGraph()
    ssg.record_insight(InsightCategory.KNOWLEDGE_GAP, "important unknown", importance="high",
                        related_probe_id="gap_linked")
    planner = AginitiPlanner()

    ranked = planner.rank(library, ssg, _mission(), prompts_used=0)

    assert ranked[0].operator.id == "gap_linked"


def test_hypothesis_priority_zero_when_no_open_hypothesis_names_this_operator():
    op = _op("probe", ("start", "mid"), "probe_done")
    ssg = SecurityStateGraph()
    planner = AginitiPlanner()
    assert planner.hypothesis_priority(op, ssg) == 0.0


def test_hypothesis_priority_peaks_at_maximum_uncertainty():
    op = _op("probe", ("start", "mid"), "probe_done")
    ssg = SecurityStateGraph()
    ssg.form_hypothesis("some hypothesis", "target_key", ClaimStatus.CONFIRMED,
                         experiments=("probe",), prior_confidence=0.5)
    planner = AginitiPlanner()
    assert planner.hypothesis_priority(op, ssg) == 4.0  # uncertainty=1.0 * weight=4.0


def test_hypothesis_priority_zero_once_resolved():
    op = _op("probe", ("start", "mid"), "probe_done")
    ssg = SecurityStateGraph()
    ssg.form_hypothesis("some hypothesis", "target_key", ClaimStatus.CONFIRMED,
                         experiments=("probe",), prior_confidence=0.5)
    ssg.assert_claim("target_key", "true", ClaimStatus.CONFIRMED)  # -> 0.75
    ssg.assert_claim("target_key", "true", ClaimStatus.CONFIRMED)  # -> 1.0, ACCEPTED
    planner = AginitiPlanner()
    assert planner.hypothesis_priority(op, ssg) == 0.0


def test_rank_boosts_utility_for_operator_named_by_an_open_hypothesis():
    plain = _op("plain", ("start", "a"), "plain_done")
    hyp_linked = _op("hyp_linked", ("start", "b"), "hyp_linked_done")
    library = OperatorLibrary([plain, hyp_linked])
    ssg = SecurityStateGraph()
    ssg.form_hypothesis("some hypothesis", "target_key", ClaimStatus.CONFIRMED,
                         experiments=("hyp_linked",), prior_confidence=0.5)
    planner = AginitiPlanner()

    ranked = planner.rank(library, ssg, _mission(), prompts_used=0)

    assert ranked[0].operator.id == "hyp_linked"


def test_emergent_targets_collects_confirmed_mission_outcome_effects_across_the_library():
    named = _op("named", ("start", "target"), "target", category=CATEGORY_MISSION_OUTCOME)
    unnamed = _op("unnamed", ("mid", "other_compromise"), "other_compromise",
                  category=CATEGORY_MISSION_OUTCOME)
    plain = _op("plain", ("start", "mid"), "mid_done")  # default category, not mission_outcome
    library = OperatorLibrary([named, unnamed, plain])
    planner = AginitiPlanner()

    assert planner.emergent_targets(library) == ("other_compromise", "target")


def test_emergent_impact_zero_when_operator_has_no_graph_edge():
    op = Operator(id="x", description="x", prompt="x", channel="direct", preconditions=(),
                  effects_success=(), effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW)
    library = OperatorLibrary([op])
    ssg = SecurityStateGraph()
    planner = AginitiPlanner()
    assert planner.emergent_impact(op, _mission(), ssg, library) == 0.0


def test_emergent_impact_excludes_targets_already_in_mission_success_criteria():
    # "target" is already covered by business_impact/path_progress via
    # mission.success_criteria -- emergent_impact must not double-count it.
    op = _op("reaches_named_target", ("start", "target"), "target", category=CATEGORY_MISSION_OUTCOME)
    library = OperatorLibrary([op])
    ssg = SecurityStateGraph()
    planner = AginitiPlanner()
    assert planner.emergent_impact(op, _mission(), ssg, library) == 0.0


def test_stepping_stone_toward_an_unnamed_compromise_gets_positive_emergent_impact():
    # The exact shape experiments/exp7_consequence_propagation_gap.py found:
    # a stepping-stone operator (no mission-outcome effect of its own) that
    # newly connects toward an UNNAMED mission-outcome-shaped compromise
    # elsewhere in the library should score positive emergent_impact, unlike
    # a structurally identical dead end. The admin_panel_found->full_takeover
    # edge is pre-confirmed here to seed it into the graph's structural
    # belief (build_graph only adds an edge once its confirming operator's
    # effect is CONFIRMED) -- same pattern path_progress's own "shortens a
    # known path" test uses to establish a baseline before testing a
    # not-yet-run candidate against it.
    stepping_stone = _op("probe_admin_panel", ("start", "admin_panel_found"), "admin_panel_found")
    followup = _op("exploit_admin_panel", ("admin_panel_found", "full_takeover"), "full_takeover",
                   category=CATEGORY_MISSION_OUTCOME)
    dead_end = _op("probe_dead_end", ("start", "nowhere"), "nowhere_done")
    library = OperatorLibrary([stepping_stone, followup, dead_end])
    ssg = SecurityStateGraph()
    ssg.assert_claim("full_takeover", "true", ClaimStatus.CONFIRMED)
    planner = AginitiPlanner()

    stepping_ep = planner.emergent_impact(stepping_stone, _mission(), ssg, library)
    dead_end_ep = planner.emergent_impact(dead_end, _mission(), ssg, library)

    assert stepping_ep > 0.0
    assert dead_end_ep == 0.0


def test_rank_now_distinguishes_stepping_stone_from_dead_end():
    # End-to-end regression test for Experiment 7's finding: before
    # emergent_impact existed, these two candidates got IDENTICAL utility.
    stepping_stone = _op("probe_admin_panel", ("start", "admin_panel_found"), "admin_panel_found")
    followup = _op("exploit_admin_panel", ("admin_panel_found", "full_takeover"), "full_takeover",
                   category=CATEGORY_MISSION_OUTCOME)
    dead_end = _op("probe_dead_end", ("start", "nowhere"), "nowhere_done")
    library = OperatorLibrary([stepping_stone, followup, dead_end])
    ssg = SecurityStateGraph()
    ssg.assert_claim("full_takeover", "true", ClaimStatus.CONFIRMED)
    planner = AginitiPlanner()

    ranked = planner.rank(library, ssg, _mission(), prompts_used=0)
    by_id = {r.operator.id: r for r in ranked}

    assert by_id["probe_admin_panel"].utility > by_id["probe_dead_end"].utility


def test_schedule_is_time_based_when_nothing_confirmed_yet():
    ssg = SecurityStateGraph()
    planner = AginitiPlanner()
    alpha, beta = planner._schedule(ssg, prompts_used=0, budget=20)
    assert alpha == 1.0
    assert beta == 0.05


def test_schedule_overrides_toward_exploitation_once_a_trust_edge_is_confirmed():
    # The exact fix for the mock-target RQ1 finding (2026-08-07): a
    # confirmed trust edge should push hard toward exploitation regardless
    # of how little of the budget has actually been consumed.
    ssg = SecurityStateGraph()
    ssg.assert_claim("some_trust", "true", ClaimStatus.CONFIRMED, category=CATEGORY_TRUST_EDGE)
    planner = AginitiPlanner()
    alpha, beta = planner._schedule(ssg, prompts_used=1, budget=20)  # early in the budget
    assert (alpha, beta) == (0.2, 0.8)


def test_schedule_overrides_moderately_once_a_mission_outcome_is_confirmed():
    ssg = SecurityStateGraph()
    ssg.assert_claim("some_win", "true", ClaimStatus.CONFIRMED, category=CATEGORY_MISSION_OUTCOME)
    planner = AginitiPlanner()
    alpha, beta = planner._schedule(ssg, prompts_used=1, budget=20)
    assert (alpha, beta) == (0.4, 0.6)


def test_schedule_trust_edge_takes_priority_over_mission_outcome():
    ssg = SecurityStateGraph()
    ssg.assert_claim("some_win", "true", ClaimStatus.CONFIRMED, category=CATEGORY_MISSION_OUTCOME)
    ssg.assert_claim("some_trust", "true", ClaimStatus.CONFIRMED, category=CATEGORY_TRUST_EDGE)
    planner = AginitiPlanner()
    alpha, beta = planner._schedule(ssg, prompts_used=1, budget=20)
    assert (alpha, beta) == (0.2, 0.8)


def test_schedule_ignores_a_refuted_trust_edge():
    ssg = SecurityStateGraph()
    ssg.assert_claim("some_trust", "true", ClaimStatus.REFUTED, category=CATEGORY_TRUST_EDGE)
    planner = AginitiPlanner()
    alpha, beta = planner._schedule(ssg, prompts_used=1, budget=20)
    assert (alpha, beta) != (0.2, 0.8)  # falls through to the time-based default


def test_schedule_ignores_a_stale_trust_edge_from_long_before_the_recency_window():
    # 2026-08-09 fix: the ORIGINAL "any CONFIRMED claim, ever" behavior
    # would have kept overriding toward exploitation here no matter how
    # much has happened since -- exactly the self-documented v1 gap this
    # test locks in as fixed. budget=5 -> recency_window = max(4, 2*5) =
    # 10; append well over 10 unrelated claims AFTER the trust edge so it
    # falls outside the window, simulating a resumed, long-lived graph
    # where that discovery is no longer "just happened."
    ssg = SecurityStateGraph()
    ssg.assert_claim("some_trust", "true", ClaimStatus.CONFIRMED, category=CATEGORY_TRUST_EDGE)
    for i in range(15):
        ssg.assert_claim(f"unrelated_{i}", "true", ClaimStatus.CONFIRMED)
    planner = AginitiPlanner()
    alpha, beta = planner._schedule(ssg, prompts_used=1, budget=5)
    assert (alpha, beta) != (0.2, 0.8)  # stale -- falls through to the time-based default


def test_schedule_still_honors_a_trust_edge_confirmed_within_the_recency_window():
    # Same shape as above, but with FEWER intervening claims than the
    # window -- must still override, confirming the fix only changes
    # behavior once a claim is genuinely stale, not sooner.
    ssg = SecurityStateGraph()
    ssg.assert_claim("some_trust", "true", ClaimStatus.CONFIRMED, category=CATEGORY_TRUST_EDGE)
    for i in range(3):
        ssg.assert_claim(f"unrelated_{i}", "true", ClaimStatus.CONFIRMED)
    planner = AginitiPlanner()
    alpha, beta = planner._schedule(ssg, prompts_used=1, budget=5)  # recency_window = 10; only 3 elapsed
    assert (alpha, beta) == (0.2, 0.8)


def test_rank_uses_the_new_schedule_signature_end_to_end():
    # Regression test that rank() actually passes ssg through to _schedule
    # now, not just prompts_used/budget.
    op = _op("exploit", ("trust_confirmed", "target"), "target")
    library = OperatorLibrary([op])
    ssg = SecurityStateGraph()
    ssg.assert_claim("some_trust", "true", ClaimStatus.CONFIRMED, category=CATEGORY_TRUST_EDGE)
    planner = AginitiPlanner()

    ranked = planner.rank(library, ssg, _mission(), prompts_used=1)

    assert ranked[0].alpha == 0.2
    assert ranked[0].beta == 0.8


# -- branch_interest (2026-08-08, "planner consumes CampaignBeliefState") ---
# closing the gap a live trace proved was real: three milestones populated
# ssg.belief correctly and NONE of it changed a single ranking decision.

def test_branch_interest_is_zero_for_an_untagged_operator():
    op = _op("x", ("start", "target"), "x_done")  # branch=None (default)
    ssg = SecurityStateGraph()
    ssg.belief.branches["payroll"] = BranchBelief(interest=10.0, confidence=1.0)
    planner = AginitiPlanner()
    assert planner.branch_interest(op, ssg) == 0.0


def test_branch_interest_is_zero_when_the_branch_has_no_belief_entry_yet():
    op = _op("x", ("start", "target"), "x_done", branch="payroll")
    ssg = SecurityStateGraph()  # belief.branches is empty -- nothing confirmed yet
    planner = AginitiPlanner()
    assert planner.branch_interest(op, ssg) == 0.0


def test_branch_interest_matches_the_branchs_exploration_signal():
    op = _op("x", ("start", "target"), "x_done", branch="payroll")
    ssg = SecurityStateGraph()
    ssg.belief.branches["payroll"] = BranchBelief(interest=4.0, confidence=1.0, risk=100.0)
    planner = AginitiPlanner()

    result = planner.branch_interest(op, ssg)

    assert result == ssg.belief.branches["payroll"].exploration_signal
    # and specifically NOT `.priority` -- risk=100 would make priority deeply
    # negative; branch_interest must stay positive regardless, per the same
    # hard-constraints-not-penalties principle risk/budget already follow.
    assert result > 0


def _op_with_boundary(op_id, success_key, security_boundary, weight=1, category=None):
    return Operator(
        id=op_id, description=op_id, prompt="x", channel="direct", preconditions=(),
        effects_success=(ClaimEffect(success_key, ClaimStatus.CONFIRMED, weight=weight,
                                      category=category, security_boundary=security_boundary),),
        effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW,
    )


def test_severity_priority_zero_for_an_untagged_operator():
    op = _op_with_boundary("untagged", "k", security_boundary=None)
    ssg = SecurityStateGraph()
    planner = AginitiPlanner()
    assert planner.severity_priority(op, ssg) == 0.0


def test_severity_priority_zero_for_l0_the_least_severe_class():
    from aginiti.graph.security_boundary import BOUNDARY_L0
    op = _op_with_boundary("l0_op", "k", security_boundary=BOUNDARY_L0)
    ssg = SecurityStateGraph()
    planner = AginitiPlanner()
    assert planner.severity_priority(op, ssg) == 0.0


def test_severity_priority_scales_with_boundary_rank():
    from aginiti.graph.security_boundary import BOUNDARY_L1, BOUNDARY_L3, BOUNDARY_L5
    ssg = SecurityStateGraph()
    planner = AginitiPlanner()
    l1 = planner.severity_priority(_op_with_boundary("l1", "k1", BOUNDARY_L1), ssg)
    l3 = planner.severity_priority(_op_with_boundary("l3", "k3", BOUNDARY_L3), ssg)
    l5 = planner.severity_priority(_op_with_boundary("l5", "k5", BOUNDARY_L5), ssg)
    assert 0.0 < l1 < l3 < l5
    assert l5 == 1.0  # rank 5 * 0.2 -- the documented cap


def test_severity_priority_ignores_an_already_confirmed_effect():
    # Mirrors information_gain's own rule: a resolved claim has nothing
    # left to prove, so it shouldn't keep earning a severity bonus either.
    from aginiti.graph.security_boundary import BOUNDARY_L5
    op = _op_with_boundary("resolved", "already_confirmed_key", BOUNDARY_L5)
    ssg = SecurityStateGraph()
    ssg.assert_claim("already_confirmed_key", "true", ClaimStatus.CONFIRMED)
    planner = AginitiPlanner()
    assert planner.severity_priority(op, ssg) == 0.0


def test_severity_priority_takes_the_max_not_the_sum_across_effects():
    from aginiti.graph.security_boundary import BOUNDARY_L1, BOUNDARY_L5
    op = Operator(
        id="two_effects", description="x", prompt="x", channel="direct", preconditions=(),
        effects_success=(
            ClaimEffect("k_low", ClaimStatus.CONFIRMED, security_boundary=BOUNDARY_L1),
            ClaimEffect("k_high", ClaimStatus.CONFIRMED, security_boundary=BOUNDARY_L5),
        ),
        effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW,
    )
    ssg = SecurityStateGraph()
    planner = AginitiPlanner()
    assert planner.severity_priority(op, ssg) == 1.0  # the L5 effect's rank, not L1+L5 summed


def test_rank_prefers_the_higher_severity_option_when_everything_else_ties():
    from aginiti.graph.security_boundary import BOUNDARY_L1, BOUNDARY_L5
    low_severity = _op_with_boundary("low_severity", "low_key", BOUNDARY_L1, weight=2)
    high_severity = _op_with_boundary("high_severity", "high_key", BOUNDARY_L5, weight=2)
    library = OperatorLibrary([low_severity, high_severity])
    ssg = SecurityStateGraph()
    planner = AginitiPlanner()
    ranked = planner.rank(library, ssg, _mission(), prompts_used=0)
    by_id = {r.operator.id: r for r in ranked}
    # Same info_gain (weight=2 each), same everything else -- only
    # severity_priority differs, and it must be what breaks the tie.
    assert by_id["high_severity"].info_gain == by_id["low_severity"].info_gain
    assert by_id["high_severity"].utility > by_id["low_severity"].utility


def test_rank_reorders_candidates_by_branch_interest_when_everything_else_ties():
    # The concrete "how will we know it worked" proof: two operators with
    # IDENTICAL info_gain/business_impact/path_progress/emergent_impact --
    # only their branch's belief-state interest differs -- must rank in
    # belief-state order, not tie-break arbitrarily.
    quiet = _op("quiet", ("start", "quiet_target"), "quiet_done", branch="quiet_branch")
    hot = _op("hot", ("start", "hot_target"), "hot_done", branch="hot_branch")
    mission = Mission(goal="test", success_criteria=("quiet_target", "hot_target"),
                       budget=20, risk_threshold=RiskTier.LOW)
    library = OperatorLibrary([quiet, hot])
    ssg = SecurityStateGraph()
    ssg.belief.branches["hot_branch"] = BranchBelief(interest=5.0, confidence=1.0)
    # quiet_branch has no belief entry at all -- branch_interest=0.0

    planner = AginitiPlanner()
    ranked = planner.rank(library, ssg, mission, prompts_used=0)

    assert ranked[0].operator.id == "hot"
    assert ranked[0].branch_interest > ranked[1].branch_interest


# -- priority_weight (2026-08-09 fix: fine-grained gap_priority nudge) ------

def test_gap_priority_uses_priority_weight_when_set():
    op = _op("probe", ("start", "mid"), "probe_done")
    ssg = SecurityStateGraph()
    ssg.record_insight(InsightCategory.KNOWLEDGE_GAP, "gap", importance="medium",
                        related_probe_id="probe", priority_weight=2.187)
    planner = AginitiPlanner()
    # NOT 2.0 (medium's bucket weight) -- priority_weight overrides it entirely.
    assert planner.gap_priority(op, ssg) == 2.187


def test_gap_priority_falls_back_to_bucket_weight_when_priority_weight_is_none():
    # Every insight the Reasoning Layer forms today leaves priority_weight
    # unset -- this locks in that that pathway is completely unaffected.
    op = _op("probe", ("start", "mid"), "probe_done")
    ssg = SecurityStateGraph()
    ssg.record_insight(InsightCategory.KNOWLEDGE_GAP, "gap", importance="high", related_probe_id="probe")
    planner = AginitiPlanner()
    assert planner.gap_priority(op, ssg) == 4.0


def test_gap_priority_can_distinguish_two_same_bucket_insights_via_priority_weight():
    # The actual bug this fix closes: a known trap and a real win landing
    # in the SAME bucket ("medium") no longer have to tie.
    trap = _op("trap", ("start", "a"), "trap_done")
    real_win = _op("real_win", ("start", "b"), "real_win_done")
    ssg = SecurityStateGraph()
    ssg.record_insight(InsightCategory.KNOWLEDGE_GAP, "trap gap", importance="medium",
                        related_probe_id="trap", priority_weight=1.8)
    ssg.record_insight(InsightCategory.KNOWLEDGE_GAP, "win gap", importance="medium",
                        related_probe_id="real_win", priority_weight=2.2)
    planner = AginitiPlanner()
    assert planner.gap_priority(real_win, ssg) > planner.gap_priority(trap, ssg)


# -- budget_feasible (2026-08-09 fix: hard chain-completion feasibility) ----

def _chain_op(op_id, edge, key, cost=1):
    return Operator(
        id=op_id, description=op_id, prompt="x", channel="direct", preconditions=(),
        effects_success=(ClaimEffect(key, ClaimStatus.CONFIRMED),),
        effects_failure=(), cost_prompts=cost, risk_tier=RiskTier.LOW, graph_edge=edge,
    )


def test_budget_feasible_true_when_operator_has_no_graph_edge():
    op = Operator(id="x", description="x", prompt="x", channel="direct", preconditions=(),
                  effects_success=(), effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW)
    planner = AginitiPlanner()
    library = OperatorLibrary([op])
    assert planner.budget_feasible(op, _mission(), library, budget_remaining=0) is True


def test_budget_feasible_defers_to_existing_cost_check_when_own_cost_exceeds_budget():
    # eligible_operators() already excludes this candidate on cost alone --
    # budget_feasible isn't the method that should say False here.
    plant = _chain_op("plant", ("start", "mid"), "plant_done", cost=5)
    library = OperatorLibrary([plant])
    planner = AginitiPlanner()
    assert planner.budget_feasible(plant, _mission(), library, budget_remaining=1) is True


def test_budget_feasible_false_when_chain_cannot_complete_within_remaining_budget():
    # The exact live-diagnosed scenario: a 2-step chain (plant, cost 1;
    # trigger, cost 1) with only 1 prompt of budget left after this
    # operator -- starting it is a guaranteed dead end.
    plant = _chain_op("plant", ("start", "mid"), "plant_done")
    trigger = _chain_op("trigger", ("mid", "target"), "trigger_done")
    library = OperatorLibrary([plant, trigger])
    mission = Mission(goal="test", success_criteria=("target",), budget=20, risk_threshold=RiskTier.LOW)
    planner = AginitiPlanner()
    assert planner.budget_feasible(plant, mission, library, budget_remaining=1) is False


def test_budget_feasible_true_when_chain_can_complete_within_remaining_budget():
    plant = _chain_op("plant", ("start", "mid"), "plant_done")
    trigger = _chain_op("trigger", ("mid", "target"), "trigger_done")
    library = OperatorLibrary([plant, trigger])
    mission = Mission(goal="test", success_criteria=("target",), budget=20, risk_threshold=RiskTier.LOW)
    planner = AginitiPlanner()
    assert planner.budget_feasible(plant, mission, library, budget_remaining=2) is True


def test_budget_feasible_true_when_operator_itself_reaches_a_target():
    direct = _chain_op("direct", ("start", "target"), "direct_done")
    library = OperatorLibrary([direct])
    mission = Mission(goal="test", success_criteria=("target",), budget=20, risk_threshold=RiskTier.LOW)
    planner = AginitiPlanner()
    assert planner.budget_feasible(direct, mission, library, budget_remaining=1) is True


def test_budget_feasible_true_when_no_static_path_to_any_target():
    decoy = _chain_op("decoy", ("start", "nowhere"), "decoy_done")
    library = OperatorLibrary([decoy])
    mission = Mission(goal="test", success_criteria=("target",), budget=20, risk_threshold=RiskTier.LOW)
    planner = AginitiPlanner()
    assert planner.budget_feasible(decoy, mission, library, budget_remaining=0) is True


def test_rank_prunes_a_chain_start_operator_that_cannot_complete_within_budget():
    # Integration proof: rank() must not even offer the infeasible chain
    # candidate, and must still offer a genuinely completable alternative.
    plant = _chain_op("plant", ("start", "mid"), "plant_done")
    trigger = _chain_op("trigger", ("mid", "target"), "trigger_done")
    single_step = Operator(
        id="single_step", description="x", prompt="x", channel="direct", preconditions=(),
        effects_success=(ClaimEffect("target", ClaimStatus.CONFIRMED),),
        effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW,
    )
    library = OperatorLibrary([plant, trigger, single_step])
    mission = Mission(goal="test", success_criteria=("target",), budget=3, risk_threshold=RiskTier.LOW)
    planner = AginitiPlanner()

    # 1 prompt of budget left: plant (cost 1) would leave 0 for trigger (cost 1) -- infeasible.
    ranked = planner.rank(library, SecurityStateGraph(), mission, prompts_used=2)

    ranked_ids = {c.operator.id for c in ranked}
    assert "plant" not in ranked_ids
    assert "single_step" in ranked_ids


def test_rank_keeps_a_chain_start_operator_feasible_early_in_the_budget():
    # Same library, but at move 1 (budget_remaining=3) the chain genuinely
    # fits -- must NOT be pruned.
    plant = _chain_op("plant", ("start", "mid"), "plant_done")
    trigger = _chain_op("trigger", ("mid", "target"), "trigger_done")
    library = OperatorLibrary([plant, trigger])
    mission = Mission(goal="test", success_criteria=("target",), budget=3, risk_threshold=RiskTier.LOW)
    planner = AginitiPlanner()

    ranked = planner.rank(library, SecurityStateGraph(), mission, prompts_used=0)

    assert "plant" in {c.operator.id for c in ranked}


# -- budget_feasible stress tests (2026-08-09, internal-audit finding: the --
# -- original test set only ever exercised a 1-hop, 2-operator chain) -------

def test_budget_feasible_false_for_a_3_hop_chain_with_insufficient_budget():
    # A -> B -> C -> D, uniform cost 1. Starting at A needs 4 total (this
    # op + 3 more hops) -- 3 remaining budget after this op is one short.
    a = _chain_op("a", ("start", "b"), "a_done")
    b = _chain_op("b", ("b", "c"), "b_done")
    c = _chain_op("c", ("c", "d"), "c_done")
    d = _chain_op("d", ("d", "target"), "d_done")
    library = OperatorLibrary([a, b, c, d])
    mission = Mission(goal="test", success_criteria=("target",), budget=20, risk_threshold=RiskTier.LOW)
    planner = AginitiPlanner()
    # remaining_after_this = 3, remaining_hops = 3 (b->c->d->target), needs 3 -- exactly enough.
    assert planner.budget_feasible(a, mission, library, budget_remaining=4) is True
    # One less: remaining_after_this = 2, need 3 -- infeasible.
    assert planner.budget_feasible(a, mission, library, budget_remaining=3) is False


def test_budget_feasible_discriminates_between_two_chains_of_different_length():
    # A tight budget that fits the SHORT chain but not the LONG one --
    # budget_feasible must tell them apart, not apply one verdict to both
    # just because they're both "a chain."
    short_start = _chain_op("short_start", ("start", "short_mid"), "short_start_done")
    short_end = _chain_op("short_end", ("short_mid", "short_target"), "short_end_done")
    long_start = _chain_op("long_start", ("start", "long_a"), "long_start_done")
    long_mid1 = _chain_op("long_mid1", ("long_a", "long_b"), "long_mid1_done")
    long_mid2 = _chain_op("long_mid2", ("long_b", "long_target"), "long_mid2_done")
    library = OperatorLibrary([short_start, short_end, long_start, long_mid1, long_mid2])
    mission = Mission(goal="test", success_criteria=("short_target", "long_target"),
                       budget=20, risk_threshold=RiskTier.LOW)
    planner = AginitiPlanner()

    # budget_remaining=2: short chain (1 more hop after this) fits; long chain (2 more hops) doesn't.
    assert planner.budget_feasible(short_start, mission, library, budget_remaining=2) is True
    assert planner.budget_feasible(long_start, mission, library, budget_remaining=2) is False


def test_budget_feasible_bound_is_admissible_not_exact_with_heterogeneous_costs():
    # DOCUMENTS a known, deliberate property rather than leaving it an
    # undiscovered surprise (an internal-audit finding): the bound prices
    # every remaining hop at the CHEAPEST operator in the whole library,
    # which can be far cheaper than the REAL next hop's actual cost. That
    # makes the check "admissible" (never a false NEGATIVE -- see the
    # tests above) but NOT exact -- it can say "feasible" for a path whose
    # real cost is actually higher than the optimistic estimate, which
    # would only be caught later, if at all, when that specific expensive
    # operator is itself evaluated. This is the correct, documented
    # trade-off for a fast, single-pass heuristic (matches PoP's own
    # "relaxed-problem heuristic" framing elsewhere in this module) -- but
    # it is NOT a guarantee that every admitted candidate can truly
    # complete; only that no genuinely-completable one is ever wrongly cut.
    cheap_decoy = _chain_op("cheap_decoy", ("nowhere", "nowhere2"), "cheap_decoy_done", cost=1)
    chain_start = _chain_op("chain_start", ("start", "mid"), "chain_start_done", cost=1)
    expensive_trigger = _chain_op("expensive_trigger", ("mid", "target"), "trigger_done", cost=5)
    library = OperatorLibrary([cheap_decoy, chain_start, expensive_trigger])
    mission = Mission(goal="test", success_criteria=("target",), budget=20, risk_threshold=RiskTier.LOW)
    planner = AginitiPlanner()

    # min_hop_cost across the WHOLE library is 1 (from cheap_decoy, unrelated to this chain at all) --
    # so the optimistic bound thinks 1 more hop costs only 1, and says "feasible" here...
    assert planner.budget_feasible(chain_start, mission, library, budget_remaining=2) is True
    # ...even though the REAL next hop (expensive_trigger) actually costs 5 -- genuinely infeasible
    # in reality with only 1 prompt left after chain_start. The bound does not (and by design cannot,
    # without per-path cost tracking it deliberately omits for speed) catch this on its own.
    real_remaining_after_chain_start = 2 - chain_start.cost_prompts
    assert real_remaining_after_chain_start < expensive_trigger.cost_prompts
