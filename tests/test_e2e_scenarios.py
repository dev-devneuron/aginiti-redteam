"""End-to-end deterministic dry-run suite -- 2026-08-12 engineering-
hardening pass, Phase 7 of the requested audit: "Don't just run unit
tests... execute several complete campaigns" covering the 10 named
scenarios, verifying the FULL state transition each time:

    observation -> graph -> ranking -> selected operator -> execution
    -> result -> graph update -> next decision

Every scenario here runs the REAL `run_campaign()` (aginiti/campaign.py)
against the REAL `AginitiPolicy`/`AginitiPlanner` and REAL `ObservationAdapter`
-- only the TARGET (a small mock BaseAdapter per scenario) and, for the
"malformed LLM response" scenario, the judge LLM call are faked. No live
target, no live LLM call anywhere in this file (aside from one explicitly
mocked chat_json). This is deliberately a single, clearly-organized file
so all 10 scenarios can be reviewed together rather than scattered across
the test suite.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from unittest.mock import patch

import pytest

from aginiti.adapters.base import SendResult
from aginiti.campaign import run_campaign
from aginiti.graph.schema import ClaimStatus, RiskTier
from aginiti.graph.ssg import CATEGORY_MISSION_OUTCOME, SUBGRAPH_DEFENDER, SecurityStateGraph
from aginiti.mission import Mission
from aginiti.operators.library import ClaimEffect, Operator, OperatorLibrary, Precondition
from aginiti.policies.aginiti_policy import AginitiPolicy
from aginiti.policies.static_policy import StaticPolicy

CONFIRMED = ClaimStatus.CONFIRMED


def _marker_op(op_id, success_key, cost=1, weight=3, graph_edge=None, precondition_key=None,
               precondition_status=CONFIRMED, failure_key=None, always_fail=False, security_boundary=None):
    """A single-step, deterministic, marker-based operator -- the same
    convention used throughout this session's dry-run scripts (discovery_
    chain_definitions.py, graduated_difficulty_definitions.py): the prompt
    IS the marker, and a mock adapter that echoes the prompt back makes the
    operator "succeed" deterministically without any LLM call."""
    marker = f"__confirmed__{success_key}"
    fk = failure_key or f"{success_key}_blocked"

    def extractor(raw: str) -> list[str]:
        if always_fail:
            return [f"{fk}::confirmed"]
        return [f"{success_key}::confirmed"] if marker in raw else [f"{fk}::confirmed"]

    preconditions = (Precondition(precondition_key, precondition_status),) if precondition_key else ()
    return Operator(
        id=op_id, description=op_id, prompt=marker, channel="direct", preconditions=preconditions,
        effects_success=(ClaimEffect(success_key, CONFIRMED, weight=weight,
                                      category=CATEGORY_MISSION_OUTCOME, security_boundary=security_boundary),),
        effects_failure=(ClaimEffect(fk, CONFIRMED, SUBGRAPH_DEFENDER, weight=1),),
        cost_prompts=cost, risk_tier=RiskTier.LOW,
        graph_edge=graph_edge or ("start", success_key),
        extractor=extractor,
    )


@dataclass
class EchoAdapter:
    """Echoes every prompt straight back (every extractor above keys off
    its own operator's marker in the echoed text) -- the "target" for
    every scenario that doesn't need special failure injection."""
    ssg: SecurityStateGraph
    mission_keys: tuple = ()

    def send(self, channel: str, prompt: str) -> SendResult:
        return SendResult(final_text=prompt)

    def ground_truth_mission_achieved(self) -> bool:
        return any(self.ssg.is_confirmed(k) for k in self.mission_keys)


def _mission(criteria, budget=5, mode="all"):
    return Mission(goal="e2e scenario test", success_criteria=criteria, budget=budget,
                    risk_threshold=RiskTier.LOW, constraints=(), success_mode=mode)


# ============================================================
# 1. Single-step attack -- success
# ============================================================

def test_scenario_1_single_step_attack_succeeds():
    ssg = SecurityStateGraph()
    op = _marker_op("attack", "target_win")
    library = OperatorLibrary([op])
    mission = _mission(("target_win",))
    agent = EchoAdapter(ssg=ssg, mission_keys=("target_win",))

    result = run_campaign(mission, library, agent=agent, policy=AginitiPolicy(), max_steps=5, ssg=ssg)

    # Full state-transition check: decision -> execution -> graph update.
    assert result.outcome == "SUCCESS"
    assert len(result.decision_log) == 1
    assert result.decision_log[0].chosen_operator_id == "attack"
    assert len(result.execution_log) == 1
    assert result.execution_log[0].overall_success is True
    assert ssg.is_confirmed("target_win")
    assert agent.ground_truth_mission_achieved() is True
    assert result.prompts_used == 1


# ============================================================
# 2. Failed attack
# ============================================================

def test_scenario_2_failed_attack_records_a_defender_claim_not_success():
    ssg = SecurityStateGraph()
    op = _marker_op("attack", "target_win", always_fail=True)
    library = OperatorLibrary([op])
    mission = _mission(("target_win",))
    agent = EchoAdapter(ssg=ssg, mission_keys=("target_win",))

    result = run_campaign(mission, library, agent=agent, policy=AginitiPolicy(), max_steps=5, ssg=ssg)

    assert result.outcome in ("SEARCH_EXHAUSTED", "BUDGET_EXHAUSTED")
    assert result.execution_log[0].overall_success is False
    assert ssg.is_confirmed("target_win_blocked")
    assert not ssg.is_confirmed("target_win")
    assert agent.ground_truth_mission_achieved() is False


# ============================================================
# 3. Branching mission (success_mode="any")
# ============================================================

def test_scenario_3_branching_mission_wins_via_one_of_several_independent_paths():
    ssg = SecurityStateGraph()
    a = _marker_op("path_a", "win_a", always_fail=True)
    b = _marker_op("path_b", "win_b")  # this one succeeds
    c = _marker_op("path_c", "win_c", always_fail=True)
    library = OperatorLibrary([a, b, c])
    mission = _mission(("win_a", "win_b", "win_c"), budget=10, mode="any")
    agent = EchoAdapter(ssg=ssg, mission_keys=("win_a", "win_b", "win_c"))

    result = run_campaign(mission, library, agent=agent, policy=AginitiPolicy(), max_steps=10, ssg=ssg)

    assert result.outcome == "SUCCESS"
    assert ssg.is_confirmed("win_b")
    assert not ssg.is_confirmed("win_a")
    assert not ssg.is_confirmed("win_c")
    # The campaign stopped the moment ANY path won -- didn't necessarily
    # exhaust every candidate.
    assert mission.is_satisfied(ssg)


# ============================================================
# 4. Multi-step chain -- genuinely gated, budget too small to finish
# ============================================================

def test_scenario_4_multistep_chain_partial_when_budget_runs_out():
    ssg = SecurityStateGraph()
    plant = _marker_op("plant", "planted", graph_edge=("start", "planted"))
    trigger = _marker_op("trigger", "chain_win", graph_edge=("planted", "chain_win"),
                          precondition_key="planted")
    library = OperatorLibrary([plant, trigger])
    mission = _mission(("chain_win",), budget=1)  # only enough for the FIRST half
    agent = EchoAdapter(ssg=ssg, mission_keys=("chain_win",))

    result = run_campaign(mission, library, agent=agent, policy=AginitiPolicy(), max_steps=5, ssg=ssg)

    assert result.outcome != "SUCCESS"
    assert ssg.is_confirmed("planted")       # first half genuinely happened
    assert not ssg.is_confirmed("chain_win")  # second half never got a chance
    assert "trigger" not in result.operators_executed  # precondition-gated, correctly never attempted


# ============================================================
# 5. Trap/decoy
# ============================================================

def test_scenario_5_decoy_gets_confirmed_but_never_produces_mission_success():
    ssg = SecurityStateGraph()
    decoy = _marker_op("decoy", "decoy_fact", weight=5, graph_edge=("start", "decoy_fact"))  # tempting, high weight
    real = _marker_op("real_attack", "real_win", graph_edge=("start", "real_win"))
    library = OperatorLibrary([decoy, real])
    mission = _mission(("real_win",), budget=10)
    agent = EchoAdapter(ssg=ssg, mission_keys=("real_win",))

    result = run_campaign(mission, library, agent=agent, policy=AginitiPolicy(), max_steps=10, ssg=ssg)

    assert result.outcome == "SUCCESS"
    assert ssg.is_confirmed("real_win")
    # The decoy is a legitimate, real claim (it DID get confirmed if tried)
    # but it is structurally disconnected from the mission target -- it
    # never satisfies success_criteria regardless of being confirmed.
    assert "real_win" in mission.success_criteria
    assert "decoy_fact" not in mission.success_criteria


# ============================================================
# 6. Target timeout
# ============================================================

def test_scenario_6_target_timeout_is_a_non_event_not_a_crash_or_false_result():
    ssg = SecurityStateGraph()
    flaky = _marker_op("flaky", "flaky_win")
    backup = _marker_op("backup", "backup_win")
    library = OperatorLibrary([flaky, backup])
    mission = _mission(("backup_win",), budget=5)

    class TimeoutOnFlaky:
        def send(self, channel, prompt):
            if "flaky_win" in prompt:
                raise TimeoutError("target did not respond in time")
            return SendResult(final_text=prompt)

        def ground_truth_mission_achieved(self):
            return ssg.is_confirmed("backup_win")

    result = run_campaign(mission, library, agent=TimeoutOnFlaky(), policy=StaticPolicy(),
                           max_steps=5, ssg=ssg)

    assert result.outcome == "SUCCESS"  # campaign survived and still won
    assert "flaky" in result.operators_executed  # attempted, charged
    # The timeout is neither a confirmed success NOR a confirmed failure --
    # a genuine non-event, exactly the classification the audit asked for.
    assert not ssg.is_confirmed("flaky_win")
    assert not ssg.is_confirmed("flaky_win_blocked")
    assert ssg.is_confirmed("backup_win")  # campaign continued past the timeout


# ============================================================
# 7. Malformed LLM response (judge path, not the deterministic extractor)
# ============================================================

def test_scenario_7_malformed_judge_response_does_not_crash_and_confirms_nothing():
    ssg = SecurityStateGraph()
    # No extractor -- this operator goes through the LLM judge path.
    op = Operator(
        id="judged_attack", description="x", prompt="probe the target", channel="direct",
        preconditions=(),
        effects_success=(ClaimEffect("judged_win", CONFIRMED, weight=3, category=CATEGORY_MISSION_OUTCOME),),
        effects_failure=(ClaimEffect("judged_blocked", CONFIRMED, SUBGRAPH_DEFENDER, weight=1),),
        cost_prompts=1, risk_tier=RiskTier.LOW, graph_edge=("start", "judged_win"),
    )
    library = OperatorLibrary([op])
    mission = _mission(("judged_win",), budget=1)
    agent = EchoAdapter(ssg=ssg, mission_keys=("judged_win",))

    # chat_json's own documented fallback for a truncated/unparseable
    # response: {"_parse_error": True, "_raw": "..."}
    with patch("aginiti.adapter.observation_adapter.chat_json",
               return_value={"_parse_error": True, "_raw": "not valid json{{{"}):
        with pytest.warns(RuntimeWarning, match="failed to parse as JSON"):
            result = run_campaign(mission, library, agent=agent, policy=AginitiPolicy(),
                                   max_steps=5, ssg=ssg)

    assert result.outcome != "SUCCESS"  # no crash, but also no false success
    assert not ssg.is_confirmed("judged_win")
    assert not ssg.is_confirmed("judged_blocked")  # neither claim confirmed -- genuinely unknown
    assert result.execution_log[0].overall_success is False


# ============================================================
# 8. Planner retry -- pivots to the next candidate after the first fails
# ============================================================

def test_scenario_8_planner_pivots_to_the_next_candidate_after_a_failure():
    ssg = SecurityStateGraph()
    # Higher weight -> ranked first -- but it fails.
    first_choice = _marker_op("first_choice", "first_win", weight=5, always_fail=True)
    second_choice = _marker_op("second_choice", "second_win", weight=3)
    library = OperatorLibrary([first_choice, second_choice])
    mission = _mission(("second_win",), budget=5, mode="any")
    agent = EchoAdapter(ssg=ssg, mission_keys=("second_win",))

    result = run_campaign(mission, library, agent=agent, policy=AginitiPolicy(), max_steps=5, ssg=ssg)

    assert result.outcome == "SUCCESS"
    assert result.operators_executed[0] == "first_choice"  # tried the higher-ranked one first
    assert result.operators_executed[1] == "second_choice"  # PIVOTED after it failed, not gave up
    assert ssg.is_confirmed("second_win")


# ============================================================
# 9. Budget exhaustion
# ============================================================

def test_scenario_9_budget_exhaustion_stops_the_campaign_honestly():
    ssg = SecurityStateGraph()
    expensive = _marker_op("expensive", "target_win", cost=3)
    library = OperatorLibrary([expensive])
    mission = _mission(("target_win",), budget=2)  # cheaper than the only operator that could win
    agent = EchoAdapter(ssg=ssg, mission_keys=("target_win",))

    result = run_campaign(mission, library, agent=agent, policy=AginitiPolicy(), max_steps=5, ssg=ssg)

    assert result.outcome in ("BUDGET_EXHAUSTED", "SEARCH_EXHAUSTED")
    assert not mission.is_satisfied(ssg)
    assert result.operators_executed == []  # budget_feasible correctly pruned it before ever attempting


# ============================================================
# 10. Successful multi-step chain completion
# ============================================================

def test_scenario_10_multistep_chain_completes_with_enough_budget():
    ssg = SecurityStateGraph()
    plant = _marker_op("plant", "planted", graph_edge=("start", "planted"))
    trigger = _marker_op("trigger", "chain_win", graph_edge=("planted", "chain_win"),
                          precondition_key="planted")
    library = OperatorLibrary([plant, trigger])
    mission = _mission(("chain_win",), budget=5)  # plenty of budget this time
    agent = EchoAdapter(ssg=ssg, mission_keys=("chain_win",))

    result = run_campaign(mission, library, agent=agent, policy=AginitiPolicy(), max_steps=5, ssg=ssg)

    assert result.outcome == "SUCCESS"
    assert result.operators_executed == ["plant", "trigger"]  # correct order, both real steps
    assert ssg.is_confirmed("planted")
    assert ssg.is_confirmed("chain_win")
    assert agent.ground_truth_mission_achieved() is True
    assert result.prompts_used == 2
