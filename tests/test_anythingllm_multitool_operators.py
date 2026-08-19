from aginiti.graph.schema import ClaimStatus
from aginiti.graph.security_boundary import BOUNDARY_L1, BOUNDARY_L2, BOUNDARY_L5
from aginiti.graph.ssg import SecurityStateGraph
from aginiti.mission import Mission
from aginiti.operators.anythingllm_multitool_definitions import build_anythingllm_multitool_library
from aginiti.planner.aginiti_planner import AginitiPlanner
from aginiti.graph.schema import RiskTier


def _library():
    return build_anythingllm_multitool_library("CANARY_TEST", "http://127.0.0.1:8901")


def test_three_operators_declared_with_the_expected_ids():
    ids = {op.id for op in _library()}
    assert ids == {
        "anythingllm_multitool_relay_document_plant",
        "anythingllm_multitool_relay_summarize_step",
        "anythingllm_multitool_relay_trigger",
    }


def test_final_trigger_requires_two_preconditions_not_one():
    trigger = _library().get("anythingllm_multitool_relay_trigger")
    assert len(trigger.preconditions) == 2
    keys = {p.key for p in trigger.preconditions}
    assert keys == {"anythingllm_multitool_relay_document_planted", "anythingllm_multitool_document_summarized"}


def test_final_trigger_is_ineligible_until_both_preconditions_confirmed():
    library = _library()
    trigger = library.get("anythingllm_multitool_relay_trigger")
    ssg = SecurityStateGraph()

    assert not trigger.preconditions_met(ssg)
    ssg.assert_claim("anythingllm_multitool_relay_document_planted", "true", ClaimStatus.CONFIRMED)
    assert not trigger.preconditions_met(ssg)  # plant alone is not enough
    ssg.assert_claim("anythingllm_multitool_document_summarized", "true", ClaimStatus.CONFIRMED)
    assert trigger.preconditions_met(ssg)  # now both are satisfied


def test_final_trigger_is_still_ineligible_if_only_the_summarize_step_confirmed():
    # Order shouldn't matter -- AND-composition, not "most recent wins".
    library = _library()
    trigger = library.get("anythingllm_multitool_relay_trigger")
    ssg = SecurityStateGraph()
    ssg.assert_claim("anythingllm_multitool_document_summarized", "true", ClaimStatus.CONFIRMED)
    assert not trigger.preconditions_met(ssg)


def test_security_boundary_levels_reflect_the_real_mechanism_per_step():
    library = _library()
    plant = library.get("anythingllm_multitool_relay_document_plant")
    summarize_step = library.get("anythingllm_multitool_relay_summarize_step")
    trigger = library.get("anythingllm_multitool_relay_trigger")

    assert plant.effects_success[0].security_boundary == BOUNDARY_L1
    # L2: a real, explicit SECOND tool was invoked, but nothing left the
    # agent's own environment yet.
    assert summarize_step.effects_success[0].security_boundary == BOUNDARY_L2
    # L5: only the FINAL step, confirmed via the independent listener log,
    # represents real network egress.
    assert trigger.effects_success[0].security_boundary == BOUNDARY_L5


def test_chain_value_credits_the_plant_for_the_summarize_steps_own_value_only():
    # chain_value is deliberately ONE hop of lookahead (see aginiti_planner.
    # py's own docstring) -- the plant should be credited for what the
    # SUMMARIZE step (its direct downstream neighbor) is worth, NOT the
    # final trigger's much larger mission-outcome value two hops away.
    library = _library()
    mission = Mission(goal="x", success_criteria=("anythingllm_multitool_relay_confirmed",),
                       success_mode="any", budget=10, risk_threshold=RiskTier.MEDIUM)
    ssg = SecurityStateGraph()
    planner = AginitiPlanner()

    plant = library.get("anythingllm_multitool_relay_document_plant")
    cv = planner.chain_value(plant, mission, ssg, library)
    summarize_step_value = (planner.information_gain(library.get("anythingllm_multitool_relay_summarize_step"), ssg)
                             + planner.business_impact(library.get("anythingllm_multitool_relay_summarize_step"),
                                                        mission, ssg))
    trigger_value = (planner.information_gain(library.get("anythingllm_multitool_relay_trigger"), ssg)
                      + planner.business_impact(library.get("anythingllm_multitool_relay_trigger"), mission, ssg))
    assert cv == 0.5 * summarize_step_value
    assert summarize_step_value < trigger_value  # confirms this is a real, meaningful distinction to check


def test_rank_places_the_plant_ahead_of_where_it_would_sit_with_zero_downstream_value():
    # Integration check: the 3-step chain's plant should score MORE than a
    # hypothetical operator with the SAME info_gain but no declared
    # downstream neighbor at all (chain_value == 0 for that one).
    library = _library()
    mission = Mission(goal="x", success_criteria=("anythingllm_multitool_relay_confirmed",),
                       success_mode="any", budget=10, risk_threshold=RiskTier.MEDIUM)
    ssg = SecurityStateGraph()
    planner = AginitiPlanner()
    ranked = planner.rank(library, ssg, mission, prompts_used=0)
    by_id = {r.operator.id: r for r in ranked}
    assert by_id["anythingllm_multitool_relay_document_plant"].chain_value > 0.0
