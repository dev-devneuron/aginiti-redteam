"""Milestones 1 and 2 tests for aginiti/graph/belief_state.py.

Milestone 1: pure plumbing, no behavior change. Confirms: the object
exists, defaults empty, `priority` derives rather than drifts,
SecurityStateGraph carries one by default, and persistence deliberately
does NOT serialize it (see persistence.py's own comment for why).

Milestone 2: deterministic branch propagation. Confirms the three rules
in update_branch_beliefs' own docstring, including against the REAL mock
operator library (aginiti/operators/definitions.py) -- proving the exact
scenario that motivated this milestone: a confirmed Slack trust edge
propagating interest to GitHub's and Helpdesk's still-unresolved trust
edges, with zero LLM calls.
"""
import pytest

from aginiti.adapter.observation_adapter import ExecutionResult
from aginiti.campaign import run_campaign
from aginiti.graph.belief_state import (
    BranchBelief,
    BranchSignal,
    CampaignBeliefState,
    OpenQuestion,
    apply_reasoning_verdict,
    update_branch_beliefs,
)
from aginiti.graph.insights import ReasoningPassResult
from aginiti.graph.persistence import load_ssg, save_ssg
from aginiti.graph.schema import ClaimStatus, RiskTier
from aginiti.graph.ssg import CATEGORY_DEFENDER_CONTROL, CATEGORY_TRUST_EDGE, SUBGRAPH_DEFENDER, SecurityStateGraph
from aginiti.mission import Mission
from aginiti.operators.definitions import build_library
from aginiti.operators.library import ClaimEffect, Operator, OperatorLibrary
from aginiti.policies.base import Candidate


def _operator(op_id, effects_success=()):
    return Operator(
        id=op_id, description=op_id, prompt="x", channel="direct",
        preconditions=(), effects_success=effects_success, effects_failure=(),
        cost_prompts=1, risk_tier=RiskTier.LOW,
    )


class _ScriptedPolicy:
    name = "scripted"

    def rank(self, library, ssg, mission, prompts_used, executed_ids):
        budget_remaining = mission.budget - prompts_used
        return [Candidate(operator=op, score=1.0) for op in library
                if op.id not in executed_ids and op.cost_prompts <= budget_remaining]


class _FakeAdapter:
    def __init__(self):
        self.calls = 0

    def execute(self, operator, ssg, agent, seed=None):
        self.calls += 1
        for effect in operator.effects_success:
            ssg.assert_claim(effect.key, effect.object, effect.status, subgraph=effect.subgraph)
        return ExecutionResult(
            operator_id=operator.id, operator_execution_id=f"exec_{self.calls}",
            raw_signal="fake", confirmed_keys=[e.key for e in operator.effects_success],
            overall_success=True, ground_truth_mission_achieved=False,
            cost_prompts=operator.cost_prompts,
        )


def test_campaign_belief_state_starts_empty():
    belief = CampaignBeliefState()
    assert belief.branches == {}
    assert belief.open_questions == []
    assert belief.hypothesis_links == {}
    assert belief.summary == ""
    assert belief.cursor is None


def test_branch_belief_priority_is_derived_not_stored():
    branch = BranchBelief(interest=4.0, confidence=1.0, risk=1.0)
    # interest * (0.5 + 0.5*confidence) - risk = 4.0 * 1.0 - 1.0 = 3.0
    assert branch.priority == 3.0
    branch.interest = 8.0
    # No stale cached value -- priority reflects the mutation immediately.
    assert branch.priority == 7.0


def test_branch_belief_priority_damped_by_low_confidence_and_risk():
    confident = BranchBelief(interest=2.0, confidence=1.0, risk=0.0)
    murky = BranchBelief(interest=2.0, confidence=0.0, risk=0.0)
    risky = BranchBelief(interest=2.0, confidence=1.0, risk=1.5)
    assert confident.priority > murky.priority
    assert confident.priority > risky.priority


def test_branch_belief_exploration_signal_excludes_risk():
    # What the planner actually reads (2026-08-08) -- must stay positive
    # regardless of risk, unlike `priority`, which folds risk in as a
    # subtraction and is for reporting only.
    branch = BranchBelief(interest=4.0, confidence=1.0, risk=100.0)
    assert branch.exploration_signal == 4.0  # 4.0 * (0.5 + 0.5*1.0)
    assert branch.exploration_signal > 0
    assert branch.priority < 0  # confirms priority WOULD have gone negative here


def test_branch_belief_exploration_signal_matches_priority_when_risk_is_zero():
    branch = BranchBelief(interest=3.0, confidence=0.5, risk=0.0)
    assert branch.exploration_signal == branch.priority


def test_open_question_carries_no_prose_statement_field():
    q = OpenQuestion(topic="memory_persistence", branch="payroll",
                      importance="high", related_probe_id=None)
    assert not hasattr(q, "statement")
    assert q.related_probe_id is None  # meaningful: no operator tests this yet


def test_ssg_carries_a_belief_state_by_default():
    ssg = SecurityStateGraph()
    assert isinstance(ssg.belief, CampaignBeliefState)
    assert ssg.belief.cursor is None


def test_two_fresh_ssgs_do_not_share_a_belief_state_instance():
    # default_factory correctness -- a shared mutable default would leak
    # belief state between unrelated campaigns/graphs.
    a, b = SecurityStateGraph(), SecurityStateGraph()
    a.belief.summary = "a's understanding"
    assert b.belief.summary == ""


def test_run_campaign_advances_belief_cursor_after_a_confirming_step():
    op = _operator("recon", effects_success=(ClaimEffect("goal_achieved", ClaimStatus.CONFIRMED),))
    library = OperatorLibrary([op])
    mission = Mission(goal="test", success_criteria=("unreachable",), budget=10, risk_threshold=RiskTier.LOW)
    ssg = SecurityStateGraph()
    assert ssg.belief.cursor is None

    run_campaign(mission, library, agent=object(), policy=_ScriptedPolicy(),
                  adapter=_FakeAdapter(), ssg=ssg, stop_on_mission_success=False)

    assert ssg.belief.cursor is not None
    assert ssg.belief.cursor == ssg.claims[-1].id


def test_run_campaign_does_not_populate_branches_or_open_questions_yet():
    # Milestone 1 is plumbing only -- confirms no behavior change snuck in.
    op = _operator("recon", effects_success=(ClaimEffect("goal_achieved", ClaimStatus.CONFIRMED),))
    library = OperatorLibrary([op])
    mission = Mission(goal="test", success_criteria=("unreachable",), budget=10, risk_threshold=RiskTier.LOW)
    ssg = SecurityStateGraph()

    run_campaign(mission, library, agent=object(), policy=_ScriptedPolicy(),
                  adapter=_FakeAdapter(), ssg=ssg, stop_on_mission_success=False)

    assert ssg.belief.branches == {}
    assert ssg.belief.open_questions == []


def _tagged_operator(op_id, branch, effects_success=(), effects_failure=()):
    return Operator(
        id=op_id, description=op_id, prompt="x", channel="direct",
        preconditions=(), effects_success=effects_success, effects_failure=effects_failure,
        cost_prompts=1, risk_tier=RiskTier.LOW, branch=branch,
    )


def test_branch_of_finds_the_declaring_operators_branch():
    from aginiti.graph.belief_state import _branch_of
    op = _tagged_operator("probe", "payroll",
                           effects_success=(ClaimEffect("trusts_slack", ClaimStatus.CONFIRMED, category=CATEGORY_TRUST_EDGE),))
    library = OperatorLibrary([op])
    assert _branch_of(library, "trusts_slack") == "payroll"
    assert _branch_of(library, "unrelated_key") is None


def test_confidence_rises_on_confirmation_regardless_of_direction():
    ssg = SecurityStateGraph()
    op_confirm = _tagged_operator("a", "payroll", effects_success=(ClaimEffect("x", ClaimStatus.CONFIRMED),))
    op_refute = _tagged_operator("b", "github", effects_success=(ClaimEffect("y", ClaimStatus.REFUTED),))
    library = OperatorLibrary([op_confirm, op_refute])
    c1 = ssg.assert_claim("x", "true", ClaimStatus.CONFIRMED)
    c2 = ssg.assert_claim("y", "true", ClaimStatus.REFUTED)

    update_branch_beliefs(ssg, library, [c1, c2])

    assert ssg.belief.branches["payroll"].confidence > 0
    assert ssg.belief.branches["github"].confidence > 0


def test_confirmed_trust_edge_boosts_own_branch_interest():
    ssg = SecurityStateGraph()
    op = _tagged_operator("probe_a", "payroll",
                           effects_success=(ClaimEffect("a_trust", ClaimStatus.CONFIRMED, category=CATEGORY_TRUST_EDGE),))
    library = OperatorLibrary([op])
    claim = ssg.assert_claim("a_trust", "true", ClaimStatus.CONFIRMED, category=CATEGORY_TRUST_EDGE)

    update_branch_beliefs(ssg, library, [claim])

    assert ssg.belief.branches["payroll"].interest > 0


def test_branch_interest_never_exceeds_the_cap_under_repeated_same_branch_confirmations():
    # 2026-08-09 fix: a real bug found by a live full-system dry run, not a
    # theoretical worry -- interest previously had NO cap, and its
    # steady-state ceiling under repeated same-branch confirmations
    # (boost / (1 - decay) = 2.0 / 0.1 = 20.0) was ~5x every other
    # planner term's own deliberately-bounded max. Confirmed live:
    # BayesianBanditPlanner's alpha reached 19.9 for an UNTRIED operator
    # purely from this one term. This test repeats the exact mechanism
    # (many same-branch mission_outcome confirmations in a row) and
    # asserts interest now stays capped at IMPORTANCE_WEIGHT["high"], the
    # same ceiling gap_priority/hypothesis_priority already use.
    from aginiti.graph.schema import IMPORTANCE_WEIGHT

    ssg = SecurityStateGraph()
    ops = [
        _tagged_operator(f"probe_{i}", "payroll",
                          effects_success=(ClaimEffect(f"trust_{i}", ClaimStatus.CONFIRMED,
                                                        category=CATEGORY_TRUST_EDGE),))
        for i in range(15)
    ]
    library = OperatorLibrary(ops)

    for i in range(15):
        claim = ssg.assert_claim(f"trust_{i}", "true", ClaimStatus.CONFIRMED, category=CATEGORY_TRUST_EDGE)
        update_branch_beliefs(ssg, library, [claim])

    assert ssg.belief.branches["payroll"].interest <= IMPORTANCE_WEIGHT["high"]
    # And it's not trivially zero either -- the cap should actually bind
    # (be reached), not just happen to never matter for this scenario.
    assert ssg.belief.branches["payroll"].interest == IMPORTANCE_WEIGHT["high"]


def test_confirmed_trust_edge_propagates_to_a_branch_with_an_unresolved_trust_edge():
    ssg = SecurityStateGraph()
    confirmed_op = _tagged_operator("probe_a", "payroll",
                                     effects_success=(ClaimEffect("a_trust", ClaimStatus.CONFIRMED, category=CATEGORY_TRUST_EDGE),))
    unresolved_op = _tagged_operator("probe_b", "github",
                                      effects_success=(ClaimEffect("b_trust", ClaimStatus.CONFIRMED, category=CATEGORY_TRUST_EDGE),))
    library = OperatorLibrary([confirmed_op, unresolved_op])
    claim = ssg.assert_claim("a_trust", "true", ClaimStatus.CONFIRMED, category=CATEGORY_TRUST_EDGE)

    update_branch_beliefs(ssg, library, [claim])

    assert ssg.belief.branches["github"].interest > 0
    # weaker than the direct, own-branch confirmation -- an echo elsewhere,
    # not the same as evidence in that branch itself:
    assert ssg.belief.branches["github"].interest < ssg.belief.branches["payroll"].interest


def test_confirmed_trust_edge_does_not_propagate_to_a_branch_with_nothing_of_that_category():
    ssg = SecurityStateGraph()
    confirmed_op = _tagged_operator("probe_a", "payroll",
                                     effects_success=(ClaimEffect("a_trust", ClaimStatus.CONFIRMED, category=CATEGORY_TRUST_EDGE),))
    unrelated_op = _tagged_operator("probe_c", "helpdesk",
                                     effects_success=(ClaimEffect("c_capability", ClaimStatus.CONFIRMED),))  # capability, not trust_edge
    library = OperatorLibrary([confirmed_op, unrelated_op])
    claim = ssg.assert_claim("a_trust", "true", ClaimStatus.CONFIRMED, category=CATEGORY_TRUST_EDGE)

    update_branch_beliefs(ssg, library, [claim])

    assert "helpdesk" not in ssg.belief.branches


def test_confirmed_trust_edge_does_not_propagate_to_an_already_resolved_branch():
    ssg = SecurityStateGraph()
    confirmed_op = _tagged_operator("probe_a", "payroll",
                                     effects_success=(ClaimEffect("a_trust", ClaimStatus.CONFIRMED, category=CATEGORY_TRUST_EDGE),))
    already_resolved_op = _tagged_operator("probe_b", "github",
                                            effects_success=(ClaimEffect("b_trust", ClaimStatus.CONFIRMED, category=CATEGORY_TRUST_EDGE),))
    library = OperatorLibrary([confirmed_op, already_resolved_op])
    ssg.assert_claim("b_trust", "true", ClaimStatus.REFUTED, category=CATEGORY_TRUST_EDGE)  # already settled
    claim = ssg.assert_claim("a_trust", "true", ClaimStatus.CONFIRMED, category=CATEGORY_TRUST_EDGE)

    update_branch_beliefs(ssg, library, [claim])

    assert "github" not in ssg.belief.branches  # nothing left there to be interested in


def test_confirmed_defender_control_raises_own_branch_risk_only():
    ssg = SecurityStateGraph()
    blocked_op = _tagged_operator(
        "attempt", "payroll",
        effects_success=(ClaimEffect("filter_present", ClaimStatus.CONFIRMED,
                                      subgraph=SUBGRAPH_DEFENDER, category=CATEGORY_DEFENDER_CONTROL),),
    )
    other_op = _tagged_operator("other", "github", effects_success=(ClaimEffect("z", ClaimStatus.CONFIRMED),))
    library = OperatorLibrary([blocked_op, other_op])
    claim = ssg.assert_claim("filter_present", "true", ClaimStatus.CONFIRMED,
                              subgraph=SUBGRAPH_DEFENDER, category=CATEGORY_DEFENDER_CONTROL)

    update_branch_beliefs(ssg, library, [claim])

    assert ssg.belief.branches["payroll"].risk > 0
    # no cross-branch defender propagation -- deliberately ambiguous,
    # reserved for the Reasoning Layer (milestone 3), not guessed at here:
    assert "github" not in ssg.belief.branches


def test_untagged_operator_is_a_no_op_not_an_error():
    ssg = SecurityStateGraph()
    op = Operator(id="untagged", description="x", prompt="x", channel="direct",
                  preconditions=(), effects_success=(ClaimEffect("k", ClaimStatus.CONFIRMED, category=CATEGORY_TRUST_EDGE),),
                  effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW)  # branch left at default None
    library = OperatorLibrary([op])
    claim = ssg.assert_claim("k", "true", ClaimStatus.CONFIRMED, category=CATEGORY_TRUST_EDGE)

    update_branch_beliefs(ssg, library, [claim])  # must not raise

    assert ssg.belief.branches == {}


def test_real_mock_library_propagates_slack_trust_to_github_and_helpdesk():
    # The exact scenario that motivated milestone 2: "Slack trusts external
    # users... if Slack trusts outsiders, GitHub's release-bot probably has
    # similar trust assumptions" -- reproduced against the REAL operator
    # library (aginiti/operators/definitions.py), not a hand-rolled stand-in.
    library = build_library()
    ssg = SecurityStateGraph()
    claim = ssg.assert_claim("planner_trusts_slack", "true", ClaimStatus.CONFIRMED, category=CATEGORY_TRUST_EDGE)

    update_branch_beliefs(ssg, library, [claim])

    assert ssg.belief.branches["payroll"].interest > 0
    # release_bot_trusted (github) and admin_bot_trusted (helpdesk) are both
    # still-unresolved trust_edge claims in the real library -- both pick
    # up the cross-branch signal, with zero LLM calls.
    assert ssg.belief.branches["github"].interest > 0
    assert ssg.belief.branches["helpdesk"].interest > 0
    assert "decoy" not in ssg.belief.branches  # decoys declare no trust_edge effects at all
    assert ssg.belief.branches["payroll"].interest > ssg.belief.branches["github"].interest


def test_run_campaign_with_real_library_updates_branch_beliefs_end_to_end():
    library = build_library()
    mission = Mission(goal="test", success_criteria=("payroll_write_unauthorized",),
                       budget=20, risk_threshold=RiskTier.LOW)
    ssg = SecurityStateGraph()

    class _ScriptedRealPolicy:
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

    run_campaign(mission, library, agent=object(), policy=_ScriptedRealPolicy(),
                  adapter=_SucceedAdapter(), ssg=ssg, stop_on_mission_success=True)

    assert "payroll" in ssg.belief.branches
    assert ssg.belief.branches["payroll"].confidence > 0


def test_save_and_load_ssg_does_not_persist_belief_state(tmp_path):
    ssg = SecurityStateGraph()
    ssg.assert_claim("access", "true", ClaimStatus.CONFIRMED)
    ssg.belief.cursor = ssg.claims[-1].id
    ssg.belief.summary = "this must not survive a round trip"
    ssg.belief.branches["payroll"] = BranchBelief(interest=5.0)

    path = tmp_path / "graph.json"
    save_ssg(ssg, path)

    # The persisted file itself must not even contain a belief-state key --
    # not just "loading ignores it," but "it was never written."
    raw = path.read_text(encoding="utf-8")
    assert "must not survive a round trip" not in raw

    reloaded = load_ssg(path)
    assert reloaded.claims  # the actual evidence DID round-trip
    assert reloaded.belief == CampaignBeliefState()  # fresh, empty -- not the mutated one


# -- 2026-08-08 design tightening: encapsulated planner-facing access via
# branch_signal()/BranchSignal, and interest decay so stale evidence
# doesn't permanently bias the planner. --------------------------------

def test_branch_signal_is_the_all_zero_default_for_an_untagged_or_unknown_branch():
    belief = CampaignBeliefState()
    assert belief.branch_signal(None) == BranchSignal(0.0, 1.0, 0)
    assert belief.branch_signal("never_seen") == BranchSignal(0.0, 1.0, 0)


def test_branch_signal_reflects_a_populated_branch():
    belief = CampaignBeliefState()
    belief.branches["payroll"] = BranchBelief(interest=4.0, confidence=0.7, risk=100.0)

    signal = belief.branch_signal("payroll")

    assert signal.exploration_signal == belief.branches["payroll"].exploration_signal
    assert signal.uncertainty == pytest.approx(0.3)  # 1 - confidence
    assert signal.exploration_signal >= 0  # risk-excluded, per exploration_signal's own contract


def test_branch_signal_counts_only_open_questions_for_that_branch():
    belief = CampaignBeliefState()
    belief.branches["payroll"] = BranchBelief(interest=1.0)
    belief.open_questions = [
        OpenQuestion(topic="a", branch="payroll", importance="high", related_probe_id=None),
        OpenQuestion(topic="b", branch="payroll", importance="low", related_probe_id=None),
        OpenQuestion(topic="c", branch="github", importance="high", related_probe_id=None),
        OpenQuestion(topic="d", branch=None, importance="high", related_probe_id=None),
    ]
    assert belief.branch_signal("payroll").open_gap_count == 2
    assert belief.branch_signal("github").open_gap_count == 1


def test_apply_reasoning_verdict_branch_scopes_open_questions_via_related_probe_id():
    library = OperatorLibrary([
        Operator(id="probe_x", description="x", prompt="x", channel="direct", preconditions=(),
                 effects_success=(), effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW, branch="payroll"),
    ])
    ssg = SecurityStateGraph()
    from aginiti.graph.schema import InsightCategory
    ssg.record_insight(InsightCategory.KNOWLEDGE_GAP, "some gap", importance="high", related_probe_id="probe_x")

    apply_reasoning_verdict(ssg, library, ReasoningPassResult())

    assert len(ssg.belief.open_questions) == 1
    assert ssg.belief.open_questions[0].branch == "payroll"


def test_apply_reasoning_verdict_leaves_branch_none_when_no_probe_matched():
    library = OperatorLibrary([])
    ssg = SecurityStateGraph()
    from aginiti.graph.schema import InsightCategory
    ssg.record_insight(InsightCategory.KNOWLEDGE_GAP, "some gap", importance="high", related_probe_id=None)

    apply_reasoning_verdict(ssg, library, ReasoningPassResult())

    assert ssg.belief.open_questions[0].branch is None


def test_interest_decays_across_steps_with_no_new_reinforcement():
    op = Operator(id="unrelated", description="x", prompt="x", channel="direct", preconditions=(),
                   effects_success=(ClaimEffect("noise", ClaimStatus.CONFIRMED),), effects_failure=(),
                   cost_prompts=1, risk_tier=RiskTier.LOW, branch="other")
    library = OperatorLibrary([op])
    ssg = SecurityStateGraph()
    ssg.belief.branches["payroll"] = BranchBelief(interest=10.0, confidence=1.0)

    # A step that produces evidence for a DIFFERENT branch -- "payroll"
    # gets no reinforcement, only decay.
    claim = ssg.assert_claim("noise", "true", ClaimStatus.CONFIRMED)
    update_branch_beliefs(ssg, library, [claim])

    assert ssg.belief.branches["payroll"].interest == 9.0  # 10.0 * 0.9
    assert ssg.belief.branches["payroll"].confidence == 1.0  # confidence does NOT decay
    assert ssg.belief.branches["payroll"].risk == 0.0


def test_interest_decay_does_not_apply_to_confidence_or_risk():
    op = Operator(id="unrelated", description="x", prompt="x", channel="direct", preconditions=(),
                   effects_success=(ClaimEffect("noise", ClaimStatus.CONFIRMED),), effects_failure=(),
                   cost_prompts=1, risk_tier=RiskTier.LOW, branch="other")
    library = OperatorLibrary([op])
    ssg = SecurityStateGraph()
    ssg.belief.branches["payroll"] = BranchBelief(interest=5.0, confidence=0.5, risk=3.0)

    claim = ssg.assert_claim("noise", "true", ClaimStatus.CONFIRMED)
    update_branch_beliefs(ssg, library, [claim])

    assert ssg.belief.branches["payroll"].confidence == 0.5
    assert ssg.belief.branches["payroll"].risk == 3.0


def test_repeated_reinforcement_outweighs_decay_a_stale_branch_fades():
    # A branch that keeps getting hit every step stays elevated; one that
    # got a single hit long ago fades toward zero -- the concrete
    # "lifecycle" property the design question asked for.
    reinforced_op = Operator(id="reinforced", description="x", prompt="x", channel="direct", preconditions=(),
                              effects_success=(ClaimEffect("hot_trust", ClaimStatus.CONFIRMED, category="trust_edge"),),
                              effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW, branch="hot")
    filler_op = Operator(id="filler", description="x", prompt="x", channel="direct", preconditions=(),
                          effects_success=(ClaimEffect("filler_done", ClaimStatus.CONFIRMED),), effects_failure=(),
                          cost_prompts=1, risk_tier=RiskTier.LOW, branch="other")
    library = OperatorLibrary([reinforced_op, filler_op])
    ssg = SecurityStateGraph()

    # "hot" gets one real confirmation, then nothing but filler steps for a while.
    hot_claim = ssg.assert_claim("hot_trust", "true", ClaimStatus.CONFIRMED, category="trust_edge")
    update_branch_beliefs(ssg, library, [hot_claim])
    hot_after_hit = ssg.belief.branches["hot"].interest

    for i in range(5):
        filler_claim = ssg.assert_claim(f"filler_{i}", "true", ClaimStatus.CONFIRMED)
        # filler_op's own declared key is "filler_done", but any claim
        # resolving in an unrelated branch is enough to trigger decay.
        update_branch_beliefs(ssg, library, [filler_claim])

    assert ssg.belief.branches["hot"].interest < hot_after_hit
    assert ssg.belief.branches["hot"].interest == pytest.approx(hot_after_hit * (0.9 ** 5))
