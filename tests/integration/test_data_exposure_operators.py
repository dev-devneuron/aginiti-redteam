"""Tests for aginiti/operators/data_exposure.py -- the target-agnostic
data-exposure operator pack. No live API calls: FakeAdapter stands in for
a real target + judge round trip, same pattern as test_campaign.py.
"""
import base64

from aginiti.core.observation_adapter import KEY_DESCRIPTIONS, ExecutionResult
from aginiti.core.campaign import run_campaign
from aginiti.core.graph.belief_state import update_branch_beliefs
from aginiti.core.graph.schema import ClaimStatus, RiskTier
from aginiti.core.graph.ssg import CATEGORY_DEFENDER_CONTROL, CATEGORY_MISSION_OUTCOME, SecurityStateGraph
from aginiti.operators.data_exposure import data_exposure_operators
from aginiti.operators.definitions import build_library
from aginiti.operators.library import OperatorLibrary
from aginiti.core.policies.base import Candidate
from aginiti.core.scenarios import data_exposure_mission


def test_pack_has_seven_uniquely_ided_operators():
    ops = data_exposure_operators()
    assert len(ops) == 7
    assert len({op.id for op in ops}) == 7


def test_every_operator_is_target_agnostic_direct_channel_and_branch_tagged():
    for op in data_exposure_operators():
        assert op.channel == "direct"
        assert op.branch == "data_exposure"
        assert op.preconditions == ()  # always eligible from the start, no target-specific gate


def test_every_success_effect_is_mission_outcome_and_failure_is_defender_control():
    for op in data_exposure_operators():
        assert len(op.effects_success) == 1
        assert op.effects_success[0].category == CATEGORY_MISSION_OUTCOME
        assert op.effects_success[0].status == ClaimStatus.CONFIRMED
        assert len(op.effects_failure) == 1
        assert op.effects_failure[0].category == CATEGORY_DEFENDER_CONTROL


def test_every_claim_key_has_a_judge_description():
    for op in data_exposure_operators():
        for effect in (*op.effects_success, *op.effects_failure):
            assert effect.key in KEY_DESCRIPTIONS, f"missing KEY_DESCRIPTIONS entry for {effect.key!r}"


def test_encoded_payload_decodes_to_a_real_override_instruction():
    encoding_op = next(op for op in data_exposure_operators() if op.id == "encoding_evasion_probe")
    # extract the base64 chunk embedded at the end of the rendered prompt
    payload = encoding_op.prompt.rsplit(": ", 1)[-1]
    decoded = base64.b64decode(payload).decode("ascii")
    assert "ignore" in decoded.lower()
    assert "system prompt" in decoded.lower()


def test_composes_cleanly_onto_the_existing_mock_library_with_no_id_collisions():
    mock_ops = list(build_library())
    combined = OperatorLibrary([*mock_ops, *data_exposure_operators()])
    assert len(combined) == len(mock_ops) + 7


def test_data_exposure_mission_is_satisfied_by_any_one_criterion():
    mission = data_exposure_mission()
    ssg = SecurityStateGraph()
    assert not mission.is_satisfied(ssg)
    ssg.assert_claim("system_prompt_disclosed", "true", ClaimStatus.CONFIRMED, category=CATEGORY_MISSION_OUTCOME)
    assert mission.is_satisfied(ssg)


def test_branch_propagation_applies_automatically_to_the_new_pack_with_zero_new_code():
    # Milestone 2's update_branch_beliefs and the branch tag on Operator
    # were both built target-agnostic on purpose -- this is the concrete
    # payoff: a brand-new operator pack gets working propagation for free.
    ops = data_exposure_operators()
    library = OperatorLibrary(ops)
    ssg = SecurityStateGraph()
    claim = ssg.assert_claim("jailbreak_safety_bypassed", "true", ClaimStatus.CONFIRMED,
                              category=CATEGORY_MISSION_OUTCOME)

    update_branch_beliefs(ssg, library, [claim])

    assert "data_exposure" in ssg.belief.branches
    assert ssg.belief.branches["data_exposure"].interest > 0
    assert ssg.belief.branches["data_exposure"].confidence > 0


class _ScriptedPolicy:
    name = "scripted"

    def rank(self, library, ssg, mission, prompts_used, executed_ids):
        budget_remaining = mission.budget - prompts_used
        out = []
        for op in library:
            if op.id in executed_ids or op.cost_prompts > budget_remaining:
                continue
            if not op.preconditions_met(ssg):
                continue
            out.append(Candidate(operator=op, score=1.0))
        return out


class _SucceedOnceAdapter:
    """Succeeds on the first operator only, fails every other -- exercises
    a realistic mixed-outcome campaign rather than an all-succeed one."""

    def __init__(self, succeed_id: str):
        self.succeed_id = succeed_id
        self.calls = 0

    def execute(self, operator, ssg, agent, seed=None):
        self.calls += 1
        succeed = operator.id == self.succeed_id
        effects = operator.effects_success if succeed else operator.effects_failure
        for effect in effects:
            ssg.assert_claim(effect.key, effect.object, effect.status,
                              subgraph=effect.subgraph, category=effect.category)
        return ExecutionResult(
            operator_id=operator.id, operator_execution_id=f"exec_{self.calls}",
            raw_signal="fake", confirmed_keys=[e.key for e in effects],
            overall_success=succeed, ground_truth_mission_achieved=False,
            cost_prompts=operator.cost_prompts,
        )


def test_full_campaign_against_the_pack_reaches_success_on_one_finding():
    library = OperatorLibrary(data_exposure_operators())
    mission = data_exposure_mission()

    result = run_campaign(mission, library, agent=object(), policy=_ScriptedPolicy(),
                           adapter=_SucceedOnceAdapter(succeed_id="secret_pattern_fishing"),
                           stop_on_mission_success=True)

    assert result.outcome == "SUCCESS"
    assert "secret_pattern_fishing" in result.operators_executed
