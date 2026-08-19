"""Milestone 3 (redesigned per the PentestGPT architecture review) tests:
the gated, INCREMENTAL Reasoning Layer. No live API calls anywhere -- the
LLM call is mocked throughout, same pattern as test_insights.py and
test_understanding_loop.py.

Covers, in order: the deterministic gate (should_run_reasoning_pass),
the incremental LLM call itself (run_reasoning_pass), applying its
verdict to CampaignBeliefState (apply_reasoning_verdict), and the full
campaign.py wiring -- including the safety property that
enable_reasoning_layer defaults to False, so no existing caller or test
in this suite is at any risk of an accidental live call.
"""
from unittest.mock import patch

from aginiti.core.observation_adapter import ExecutionResult
from aginiti.core.campaign import run_campaign
from aginiti.core.graph.belief_state import BranchBelief, apply_reasoning_verdict, should_run_reasoning_pass
from aginiti.core.graph.hypothesis import HypothesisStatus
from aginiti.core.graph.insights import ReasoningPassResult, run_reasoning_pass
from aginiti.core.graph.schema import ClaimStatus, RiskTier
from aginiti.core.graph.ssg import CATEGORY_DEFENDER_CONTROL, CATEGORY_MISSION_OUTCOME, CATEGORY_TRUST_EDGE, SecurityStateGraph
from aginiti.core.mission import Mission
from aginiti.operators.library import ClaimEffect, Operator, OperatorLibrary
from aginiti.core.policies.base import Candidate


def _tagged_operator(op_id, branch, effects_success=(), effects_failure=(), preconditions=()):
    return Operator(
        id=op_id, description=op_id, prompt="x", channel="direct",
        preconditions=preconditions, effects_success=effects_success, effects_failure=effects_failure,
        cost_prompts=1, risk_tier=RiskTier.LOW, branch=branch,
    )


# -- should_run_reasoning_pass (deterministic gate, no LLM) -----------------

def test_gate_fires_on_confirmed_trust_edge():
    ssg = SecurityStateGraph()
    claim = ssg.assert_claim("a_trust", "true", ClaimStatus.CONFIRMED, category=CATEGORY_TRUST_EDGE)
    assert should_run_reasoning_pass(ssg, [claim]) is True


def test_gate_fires_on_confirmed_mission_outcome():
    ssg = SecurityStateGraph()
    claim = ssg.assert_claim("win", "true", ClaimStatus.CONFIRMED, category=CATEGORY_MISSION_OUTCOME)
    assert should_run_reasoning_pass(ssg, [claim]) is True


def test_gate_fires_on_confirmed_defender_control():
    ssg = SecurityStateGraph()
    claim = ssg.assert_claim("blocked", "true", ClaimStatus.CONFIRMED, category=CATEGORY_DEFENDER_CONTROL)
    assert should_run_reasoning_pass(ssg, [claim]) is True


def test_gate_does_not_fire_on_a_refuted_trust_edge():
    ssg = SecurityStateGraph()
    claim = ssg.assert_claim("a_trust", "true", ClaimStatus.REFUTED, category=CATEGORY_TRUST_EDGE)
    assert should_run_reasoning_pass(ssg, [claim]) is False


def test_gate_does_not_fire_on_plain_capability_confirmation_below_staleness():
    ssg = SecurityStateGraph()
    claim = ssg.assert_claim("cap", "true", ClaimStatus.CONFIRMED)  # defaults to CATEGORY_CAPABILITY
    assert should_run_reasoning_pass(ssg, [claim], staleness_threshold=8) is False


def test_gate_fires_on_staleness_even_without_a_high_value_category():
    ssg = SecurityStateGraph()
    claims = [ssg.assert_claim(f"cap_{i}", "true", ClaimStatus.CONFIRMED) for i in range(5)]
    assert should_run_reasoning_pass(ssg, claims, staleness_threshold=5) is True
    assert should_run_reasoning_pass(ssg, claims, staleness_threshold=6) is False


def test_gate_staleness_counts_from_reasoned_cursor_not_from_zero():
    ssg = SecurityStateGraph()
    early = [ssg.assert_claim(f"early_{i}", "true", ClaimStatus.CONFIRMED) for i in range(5)]
    ssg.belief.reasoned_cursor = early[-1].id  # already reasoned about everything up to here
    late = [ssg.assert_claim(f"late_{i}", "true", ClaimStatus.CONFIRMED) for i in range(2)]
    assert should_run_reasoning_pass(ssg, late, staleness_threshold=5) is False  # only 2 unreasoned
    more = [ssg.assert_claim(f"more_{i}", "true", ClaimStatus.CONFIRMED) for i in range(3)]
    assert should_run_reasoning_pass(ssg, more, staleness_threshold=5) is True  # 5 unreasoned now


# -- run_reasoning_pass (the incremental LLM call) ---------------------------

def test_run_reasoning_pass_makes_no_llm_call_when_the_diff_is_empty():
    ssg = SecurityStateGraph()
    claim = ssg.assert_claim("cap", "true", ClaimStatus.CONFIRMED)
    library = OperatorLibrary([])

    with patch("aginiti.core.graph.insights.chat_json") as mock_chat:
        result = run_reasoning_pass(ssg, "target", library, since_claim_id=claim.id)  # diff is empty

    mock_chat.assert_not_called()
    assert result == ReasoningPassResult()


def test_run_reasoning_pass_only_shows_the_diff_but_still_grounds_against_the_full_claim_set():
    ssg = SecurityStateGraph()
    old = ssg.assert_claim("old_claim", "true", ClaimStatus.CONFIRMED)
    new = ssg.assert_claim("new_claim", "true", ClaimStatus.CONFIRMED)
    library = OperatorLibrary([])

    fake_verdict = {
        "behavioral_insights": [
            # cites OLD_CLAIM even though it isn't in this round's diff --
            # must still be accepted, since valid_keys is the FULL set.
            {"statement": "combines old and new", "claim_keys": ["old_claim", "new_claim"]},
        ],
        "security_insights": [], "knowledge_gaps": [],
    }
    with patch("aginiti.core.graph.insights.chat_json", return_value=fake_verdict) as mock_chat:
        result = run_reasoning_pass(ssg, "target", library, since_claim_id=old.id)

    assert len(result.insights) == 1
    assert result.insights[0].derived_from == ("old_claim", "new_claim")
    sent_user_message = mock_chat.call_args[0][0][1]["content"]
    assert "new_claim" in sent_user_message
    assert "old_claim" not in sent_user_message  # NOT shown in the prompt text -- only new_claim is the diff


def test_run_reasoning_pass_threads_prior_summary_into_the_prompt():
    ssg = SecurityStateGraph()
    ssg.assert_claim("k", "true", ClaimStatus.CONFIRMED)
    library = OperatorLibrary([])

    with patch("aginiti.core.graph.insights.chat_json", return_value={}) as mock_chat:
        run_reasoning_pass(ssg, "target", library, prior_summary="Slack trusts unverified senders.")

    sent_user_message = mock_chat.call_args[0][0][1]["content"]
    assert "PRIOR UNDERSTANDING" in sent_user_message
    assert "Slack trusts unverified senders." in sent_user_message


def test_run_reasoning_pass_parses_updated_summary_and_branch_signal():
    ssg = SecurityStateGraph()
    ssg.assert_claim("k", "true", ClaimStatus.CONFIRMED)
    library = OperatorLibrary([])
    fake_verdict = {
        "behavioral_insights": [], "security_insights": [], "knowledge_gaps": [],
        "updated_summary": "  Slack trust confirmed; GitHub likely similar.  ",
        "branch_signal": [
            {"branch": "github", "direction": "up", "why": "similar trust pattern"},
            {"branch": "bad", "direction": "sideways", "why": "malformed direction -- dropped"},
        ],
    }
    with patch("aginiti.core.graph.insights.chat_json", return_value=fake_verdict):
        result = run_reasoning_pass(ssg, "target", library)

    assert result.updated_summary == "Slack trust confirmed; GitHub likely similar."
    assert result.branch_signal == ({"branch": "github", "direction": "up", "why": "similar trust pattern"},)


def test_run_reasoning_pass_treats_missing_updated_summary_as_none():
    ssg = SecurityStateGraph()
    ssg.assert_claim("k", "true", ClaimStatus.CONFIRMED)
    library = OperatorLibrary([])

    with patch("aginiti.core.graph.insights.chat_json", return_value={}):
        result = run_reasoning_pass(ssg, "target", library)

    assert result.updated_summary is None
    assert result.branch_signal == ()


# -- apply_reasoning_verdict --------------------------------------------------

def test_apply_reasoning_verdict_updates_summary():
    ssg = SecurityStateGraph()
    library = OperatorLibrary([])
    result = ReasoningPassResult(updated_summary="new understanding")

    apply_reasoning_verdict(ssg, library, result)

    assert ssg.belief.summary == "new understanding"


def test_apply_reasoning_verdict_leaves_summary_alone_when_none_given():
    ssg = SecurityStateGraph()
    ssg.belief.summary = "existing"
    library = OperatorLibrary([])

    apply_reasoning_verdict(ssg, library, ReasoningPassResult(updated_summary=None))

    assert ssg.belief.summary == "existing"


def test_apply_reasoning_verdict_applies_branch_signal_up_and_down():
    ssg = SecurityStateGraph()
    op = _tagged_operator("probe", "github")
    library = OperatorLibrary([op])
    ssg.belief.branches["github"] = BranchBelief(interest=1.0)

    apply_reasoning_verdict(ssg, library, ReasoningPassResult(
        branch_signal=({"branch": "github", "direction": "up", "why": "x"},),
    ))
    assert ssg.belief.branches["github"].interest > 1.0

    boosted = ssg.belief.branches["github"].interest
    apply_reasoning_verdict(ssg, library, ReasoningPassResult(
        branch_signal=({"branch": "github", "direction": "down", "why": "x"},),
    ))
    assert ssg.belief.branches["github"].interest < boosted


def test_apply_reasoning_verdict_ignores_an_unknown_branch_name():
    ssg = SecurityStateGraph()
    library = OperatorLibrary([_tagged_operator("probe", "github")])

    apply_reasoning_verdict(ssg, library, ReasoningPassResult(
        branch_signal=({"branch": "not_a_real_branch", "direction": "up", "why": "x"},),
    ))

    assert "not_a_real_branch" not in ssg.belief.branches


def test_apply_reasoning_verdict_interest_floors_at_zero():
    ssg = SecurityStateGraph()
    library = OperatorLibrary([_tagged_operator("probe", "github")])
    ssg.belief.branches["github"] = BranchBelief(interest=0.5)

    apply_reasoning_verdict(ssg, library, ReasoningPassResult(
        branch_signal=({"branch": "github", "direction": "down", "why": "x"},),
    ))

    assert ssg.belief.branches["github"].interest == 0.0


def test_apply_reasoning_verdict_rebuilds_open_questions_from_knowledge_gap_insights():
    ssg = SecurityStateGraph()
    library = OperatorLibrary([])
    ssg.record_insight(__import__("aginiti.core.graph.schema", fromlist=["InsightCategory"]).InsightCategory.KNOWLEDGE_GAP,
                        "memory persistence: unknown", importance="high", related_probe_id="probe_memory")

    apply_reasoning_verdict(ssg, library, ReasoningPassResult())

    assert len(ssg.belief.open_questions) == 1
    q = ssg.belief.open_questions[0]
    assert q.topic == "memory persistence"
    assert q.importance == "high"
    assert q.related_probe_id == "probe_memory"


def test_apply_reasoning_verdict_rebuilds_hypothesis_links_by_branch():
    ssg = SecurityStateGraph()
    op = _tagged_operator("probe_slack", "payroll")
    library = OperatorLibrary([op])
    ssg.form_hypothesis("slack trust exists", "planner_trusts_slack", ClaimStatus.CONFIRMED,
                         experiments=("probe_slack",))

    apply_reasoning_verdict(ssg, library, ReasoningPassResult())

    assert "payroll" in ssg.belief.hypothesis_links
    assert len(ssg.belief.hypothesis_links["payroll"]) == 1


# -- campaign.py wiring -------------------------------------------------------

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


class _SucceedAdapter:
    def __init__(self):
        self.calls = 0

    def execute(self, operator, ssg, agent, seed=None):
        self.calls += 1
        for effect in operator.effects_success:
            ssg.assert_claim(effect.key, effect.object, effect.status,
                              subgraph=effect.subgraph, category=effect.category)
        return ExecutionResult(
            operator_id=operator.id, operator_execution_id=f"exec_{self.calls}",
            raw_signal="fake", confirmed_keys=[e.key for e in operator.effects_success],
            overall_success=True, ground_truth_mission_achieved=False,
            cost_prompts=operator.cost_prompts,
        )


def test_campaign_never_calls_the_llm_when_reasoning_layer_disabled():
    op = _tagged_operator("probe", "payroll",
                           effects_success=(ClaimEffect("trust", ClaimStatus.CONFIRMED, category=CATEGORY_TRUST_EDGE),))
    library = OperatorLibrary([op])
    mission = Mission(goal="test", success_criteria=("unreachable",), budget=10, risk_threshold=RiskTier.LOW)

    with patch("aginiti.core.graph.insights.chat_json") as mock_chat:
        run_campaign(mission, library, agent=object(), policy=_ScriptedPolicy(),
                     adapter=_SucceedAdapter(), stop_on_mission_success=False)
                     # enable_reasoning_layer defaults to False

    mock_chat.assert_not_called()


def test_campaign_calls_the_llm_exactly_once_when_a_trust_edge_confirms_and_layer_is_enabled():
    trust_op = _tagged_operator("probe_trust", "payroll",
                                 effects_success=(ClaimEffect("trust", ClaimStatus.CONFIRMED, category=CATEGORY_TRUST_EDGE),))
    capability_op = _tagged_operator("probe_cap", "github",
                                      effects_success=(ClaimEffect("cap", ClaimStatus.CONFIRMED),))
    library = OperatorLibrary([trust_op, capability_op])
    mission = Mission(goal="test-target", success_criteria=("unreachable",), budget=10, risk_threshold=RiskTier.LOW)
    ssg = SecurityStateGraph()

    with patch("aginiti.core.graph.insights.chat_json", return_value={
        "behavioral_insights": [], "security_insights": [], "knowledge_gaps": [],
        "updated_summary": "payroll trust confirmed",
    }) as mock_chat:
        run_campaign(mission, library, agent=object(), policy=_ScriptedPolicy(),
                     adapter=_SucceedAdapter(), ssg=ssg, stop_on_mission_success=False,
                     enable_reasoning_layer=True)

    mock_chat.assert_called_once()  # only the trust_edge step triggers it, not the plain capability step
    assert ssg.belief.summary == "payroll trust confirmed"
    assert ssg.belief.reasoned_cursor is not None
