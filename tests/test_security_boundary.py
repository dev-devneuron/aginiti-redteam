from aginiti.graph.schema import ClaimStatus, RiskTier
from aginiti.graph.security_boundary import (
    BOUNDARY_L0,
    BOUNDARY_L1,
    BOUNDARY_L3,
    BOUNDARY_L5,
    BOUNDARY_UNSPECIFIED,
    highest_level,
    rank,
)
from aginiti.graph.ssg import SecurityStateGraph
from aginiti.operators.anythingllm_automatic_definitions import build_anythingllm_automatic_library
from aginiti.operators.anythingllm_definitions import build_anythingllm_library
from aginiti.operators.data_exposure import data_exposure_operators
from aginiti.operators.dvaa_definitions import build_dvaa_library


# --- pure taxonomy logic -----------------------------------------------------

def test_rank_orders_levels_by_severity():
    assert rank(BOUNDARY_L0) < rank(BOUNDARY_L1) < rank(BOUNDARY_L3) < rank(BOUNDARY_L5)


def test_rank_of_unknown_level_is_below_every_real_level():
    assert rank("not_a_real_level") < rank(BOUNDARY_L0)
    assert rank(BOUNDARY_UNSPECIFIED) < rank(BOUNDARY_L0)


def test_highest_level_picks_the_most_severe():
    assert highest_level([BOUNDARY_L0, BOUNDARY_L3, BOUNDARY_L1]) == BOUNDARY_L3


def test_highest_level_ignores_unspecified_and_none_entries():
    assert highest_level([BOUNDARY_UNSPECIFIED, BOUNDARY_L1]) == BOUNDARY_L1


def test_highest_level_of_nothing_real_is_none():
    assert highest_level([]) is None
    assert highest_level([BOUNDARY_UNSPECIFIED]) is None


# --- SecurityStateGraph wiring ------------------------------------------------

def test_assert_claim_records_boundary_only_when_given():
    ssg = SecurityStateGraph()
    ssg.assert_claim("no_boundary_key", "true", ClaimStatus.CONFIRMED)
    ssg.assert_claim("tagged_key", "true", ClaimStatus.CONFIRMED, security_boundary=BOUNDARY_L3)
    assert "no_boundary_key" not in ssg.claim_boundary
    assert ssg.claim_boundary["tagged_key"] == BOUNDARY_L3


def test_confirmed_boundary_crossings_excludes_unconfirmed_claims():
    ssg = SecurityStateGraph()
    ssg.assert_claim("hyp_key", "true", ClaimStatus.HYPOTHESIZED, security_boundary=BOUNDARY_L1)
    ssg.assert_claim("confirmed_key", "true", ClaimStatus.CONFIRMED, security_boundary=BOUNDARY_L3)
    crossings = ssg.confirmed_boundary_crossings()
    assert "hyp_key" not in crossings
    assert crossings["confirmed_key"] == BOUNDARY_L3


def test_confirmed_boundary_crossings_reflects_the_latest_status_after_supersession():
    # A claim confirmed then later REFUTED (e.g. re-checked and found not to
    # hold) must stop counting -- current_claim() always resolves to the
    # LATEST version, and confirmed_boundary_crossings() must honor that,
    # not the first-ever status.
    ssg = SecurityStateGraph()
    ssg.assert_claim("flappy_key", "true", ClaimStatus.CONFIRMED, security_boundary=BOUNDARY_L5)
    assert "flappy_key" in ssg.confirmed_boundary_crossings()
    ssg.assert_claim("flappy_key", "false", ClaimStatus.REFUTED)
    assert "flappy_key" not in ssg.confirmed_boundary_crossings()


def test_highest_boundary_crossed_is_none_before_anything_confirmed():
    ssg = SecurityStateGraph()
    assert ssg.highest_boundary_crossed() is None


def test_highest_boundary_crossed_reports_the_deepest_confirmed_level():
    ssg = SecurityStateGraph()
    ssg.assert_claim("model_behavior_key", "true", ClaimStatus.CONFIRMED, security_boundary=BOUNDARY_L0)
    ssg.assert_claim("exfil_key", "true", ClaimStatus.CONFIRMED, security_boundary=BOUNDARY_L5)
    assert ssg.highest_boundary_crossed() == BOUNDARY_L5


# --- real operator library retrofit -------------------------------------------

def test_data_exposure_disclosures_are_tagged_l0_model_behavior_only():
    trap = next(op for op in data_exposure_operators() if op.id == "system_prompt_extraction")
    fast_win = next(op for op in data_exposure_operators() if op.id == "tool_inventory_full_disclosure")
    assert trap.effects_success[0].security_boundary == BOUNDARY_L0
    assert fast_win.effects_success[0].security_boundary == BOUNDARY_L0


def test_rag_chain_plant_is_l1_context_manipulation():
    plant = next(op for op in build_anythingllm_library("X") if op.id == "anythingllm_rag_document_plant")
    assert plant.effects_success[0].security_boundary == BOUNDARY_L1


def test_rag_chain_trigger_stays_l1_no_network_egress():
    trigger = next(op for op in build_anythingllm_library("X") if op.id == "anythingllm_rag_injection_trigger")
    assert trigger.effects_success[0].security_boundary == BOUNDARY_L1


def test_automatic_chain_trigger_is_l5_network_confirmed_exfiltration():
    trigger = next(op for op in build_anythingllm_automatic_library("X", "http://listener")
                   if op.id == "anythingllm_automatic_indirect_tool_exfil_trigger")
    assert trigger.effects_success[0].security_boundary == BOUNDARY_L5


def test_a2a_identity_spoof_is_l3_privilege_boundary():
    op = next(op for op in build_dvaa_library() if op.id == "a2a_identity_spoof")
    keys = {e.key: e.security_boundary for e in op.effects_success}
    assert keys["a2a_trusts_claimed_identity"] == BOUNDARY_L3
    assert keys["unauthorized_a2a_access_granted"] == BOUNDARY_L3


# --- end-to-end through the real adapter path (deterministic extractor,
# no LLM/judge call needed -- exercises the exact assert_claim call site
# in ObservationAdapter.execute() that now also threads security_boundary
# through) -----------------------------------------------------------------

def test_observation_adapter_propagates_security_boundary_onto_the_ssg_claim():
    from aginiti.adapter.observation_adapter import ObservationAdapter, _effect_id
    from aginiti.adapters.base import SendResult
    from aginiti.operators.library import ClaimEffect, Operator

    effect = ClaimEffect("l3_test_claim", ClaimStatus.CONFIRMED, security_boundary=BOUNDARY_L3)
    op = Operator(
        id="l3_test_op", description="test", prompt="x", channel="direct", preconditions=(),
        effects_success=(effect,), effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW,
        extractor=lambda raw_signal: [_effect_id(effect)],  # deterministic: always "confirms"
    )

    class _StubAdapter:
        def send(self, channel, prompt):
            return SendResult(final_text="it worked")

        def ground_truth_mission_achieved(self):
            return False

    ssg = SecurityStateGraph()
    result = ObservationAdapter().execute(op, ssg, _StubAdapter(), seed=1)

    assert result.overall_success is True
    assert ssg.claim_boundary.get("l3_test_claim") == BOUNDARY_L3
